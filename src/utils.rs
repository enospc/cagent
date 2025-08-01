use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::constants::*;

pub struct Utils {
    config: Config,
}

impl Utils {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn log(&self, message: &str) {
        // Only log to file, not to terminal
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_file)
        {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            writeln!(file, "[{}] {}", timestamp, message).ok();
        }
    }

    pub fn error_exit(&self, message: &str) -> ! {
        eprintln!("{}ERROR: {}{}", RED, message, NC);
        eprintln!("Check log file: {}", self.config.log_file.display());
        self.log(&format!("ERROR: {}", message));
        std::process::exit(1);
    }

    pub fn log_command(&self, cmd: &Command) {
        let cmd_string = format!(
            "{} {}",
            cmd.get_program().to_string_lossy(),
            cmd.get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );

        // Log to terminal only in verbose mode
        if self.config.verbose_mode {
            println!("[EXEC] {}", cmd_string);
        }

        // Always log to file
        self.log(&format!("[EXEC] {}", cmd_string));
    }

    pub fn run_command(&self, cmd: &mut Command, error_msg: &str) -> Result<(), String> {
        self.log_command(cmd);

        let output = cmd.output().map_err(|e| format!("{}: {}", error_msg, e))?;

        if !output.status.success() {
            return Err(format!("{}: {:?}", error_msg, output.status.code()));
        }

        Ok(())
    }

    pub fn run_command_with_log(&self, cmd: &mut Command, error_msg: &str) -> Result<(), String> {
        self.log_command(cmd);

        let output = cmd.output().map_err(|e| format!("{}: {}", error_msg, e))?;

        if !output.status.success() {
            self.log(&format!("Command failed: {:?}", cmd));
            self.log(&format!(
                "stdout: {}",
                String::from_utf8_lossy(&output.stdout)
            ));
            self.log(&format!(
                "stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
            return Err(format!("{}: {:?}", error_msg, output.status.code()));
        }

        Ok(())
    }

    pub fn run_command_in_dir(
        &self,
        cmd: &mut Command,
        dir: &str,
        error_msg: &str,
    ) -> Result<(), String> {
        cmd.current_dir(dir);
        self.run_command(cmd, error_msg)
    }

    pub fn run_systemd_nspawn(&self, args: &[&str], error_msg: &str) -> Result<(), String> {
        let mut cmd = Command::new("sudo");
        cmd.arg("systemd-nspawn");
        cmd.arg("-q");
        cmd.arg("-D");
        cmd.arg(self.config.container_path.to_str().unwrap());
        cmd.arg("--pipe");

        for arg in args {
            cmd.arg(arg);
        }

        self.run_command_with_log(&mut cmd, error_msg)
    }

    pub fn write_file_as_root(&self, path: &Path, content: &str) -> Result<(), String> {
        let mut cmd = Command::new("sudo");
        cmd.arg("tee");
        cmd.arg(path);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::null());

        self.log_command(&cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn sudo tee: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(content.as_bytes())
                .map_err(|e| format!("Failed to write content: {}", e))?;
        }

        let status = child
            .wait()
            .map_err(|e| format!("Failed to wait for sudo tee: {}", e))?;

        if !status.success() {
            return Err("Failed to write file as root".to_string());
        }

        Ok(())
    }

    pub fn get_ulimit_nproc(&self) -> String {
        let mut cmd = Command::new("bash");
        cmd.args(&["-c", "ulimit -u"]);
        self.log_command(&cmd);
        cmd.output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn validate_host_dir(&self, dir: &Path) -> Result<std::path::PathBuf, String> {
        // Get real path
        let real_path = dir
            .canonicalize()
            .map_err(|_| "Invalid directory path: does not exist")?;

        // Security: Ensure in /home
        let path_str = real_path.to_string_lossy();
        if !path_str.starts_with("/home/") {
            return Err(format!("Path not in /home: {}", path_str));
        }

        // Security: Check for valid characters
        if !path_str
            .chars()
            .all(|c| c.is_alphanumeric() || "/_-.".contains(c))
        {
            return Err(format!("Invalid characters in path: {}", path_str));
        }

        // Must exist and be readable
        if !real_path.is_dir() {
            return Err(format!("Directory does not exist: {}", path_str));
        }

        Ok(real_path)
    }

    pub fn is_package_installed(&self, package: &str) -> bool {
        let mut cmd = Command::new("dpkg");
        cmd.args(&["-l", package]);
        self.log_command(&cmd);
        cmd.output().map(|o| o.status.success()).unwrap_or(false)
    }

    pub fn calculate_file_checksum(&self, file_path: &Path) -> Result<String, String> {
        let mut cmd = Command::new("sha256sum");
        cmd.arg(file_path);
        self.log_command(&cmd);
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to calculate checksum: {}", e))?;

        if !output.status.success() {
            return Err("Failed to calculate checksum".to_string());
        }

        let checksum_string = String::from_utf8_lossy(&output.stdout);
        Ok(checksum_string
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string())
    }
}