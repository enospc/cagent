use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::constants::*;

// External dependency for better timestamp formatting
use chrono::DateTime;

// Global flag to disable monitoring
static MONITORING_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub struct Utils {
    config: Config,
}

impl Utils {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn log(&self, message: &str) {
        self.log_with_level("INFO", message);
    }

    pub fn log_with_level(&self, level: &str, message: &str) {
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
            let local_time = DateTime::from_timestamp(timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| timestamp.to_string());
            writeln!(file, "[{local_time}] [{level}] {message}").ok();
        }
    }

    pub fn log_command_start(&self, cmd: &Command) {
        let cmd_string = self.format_command(cmd);

        // Log to terminal only in verbose mode
        if self.config.verbose_mode {
            println!(
                "{}[EXEC]{} {}",
                crate::constants::BLUE,
                crate::constants::NC,
                cmd_string
            );
        }

        // Always log to file
        self.log_with_level("EXEC", &format!("Starting: {cmd_string}"));
    }

    pub fn log_command_output(&self, level: &str, source: &str, line: &str) {
        let message = format!("{source}: {line}");

        // Log to terminal only in verbose mode
        if self.config.verbose_mode {
            let color = if source == "stdout" {
                crate::constants::GREEN
            } else {
                crate::constants::YELLOW
            };
            println!(
                "{}[{}]{} {}",
                color,
                source.to_uppercase(),
                crate::constants::NC,
                line
            );
        }

        // Always log to file
        self.log_with_level(level, &message);
    }

    pub fn log_command_end(&self, cmd: &Command, success: bool, duration: Duration) {
        let cmd_string = self.format_command(cmd);
        let status = if success { "SUCCESS" } else { "FAILED" };
        let message = format!(
            "Completed: {} - {} (took {:.2}s)",
            cmd_string,
            status,
            duration.as_secs_f64()
        );

        // Log to terminal only in verbose mode
        if self.config.verbose_mode {
            let color = if success {
                crate::constants::GREEN
            } else {
                crate::constants::RED
            };
            println!(
                "{}[{}]{} {} (took {:.2}s)",
                color,
                status,
                crate::constants::NC,
                cmd_string,
                duration.as_secs_f64()
            );
        }

        // Always log to file
        self.log_with_level("EXEC", &message);
    }

    fn format_command(&self, cmd: &Command) -> String {
        format!(
            "{} {}",
            cmd.get_program().to_string_lossy(),
            cmd.get_args()
                .map(|arg| {
                    let arg_str = arg.to_string_lossy();
                    // Quote arguments that contain spaces or special characters
                    if arg_str.contains(' ') || arg_str.contains('&') || arg_str.contains('|') {
                        format!("'{arg_str}'")
                    } else {
                        arg_str.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    pub fn error_exit(&self, message: &str) -> ! {
        eprintln!("{RED}ERROR: {message}{NC}");
        let log_file = self.config.log_file.display();
        eprintln!("Check log file: {log_file}");
        self.log(&format!("ERROR: {message}"));
        std::process::exit(1);
    }

    pub fn disable_monitoring(&self) {
        MONITORING_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn log_command(&self, cmd: &Command) {
        // Just log the command without monitoring (legacy method)
        self.log_command_start(cmd);
    }

    pub fn run_command(&self, cmd: &mut Command, error_msg: &str) -> Result<(), String> {
        if self.config.verbose_mode {
            self.run_command_with_realtime_logging(cmd, error_msg)
        } else {
            // Use legacy implementation for non-verbose mode
            self.log_command_start(cmd);
            let start = Instant::now();

            let output = cmd.output().map_err(|e| format!("{error_msg}: {e}"))?;
            let duration = start.elapsed();

            if !output.status.success() {
                self.log_command_end(cmd, false, duration);
                return Err(format!("{error_msg}: {:?}", output.status.code()));
            }

            self.log_command_end(cmd, true, duration);
            Ok(())
        }
    }

    pub fn run_command_with_log(&self, cmd: &mut Command, error_msg: &str) -> Result<(), String> {
        // Always use enhanced logging for this method
        self.run_command_with_realtime_logging(cmd, error_msg)
    }

    pub fn run_command_with_realtime_logging(
        &self,
        cmd: &mut Command,
        error_msg: &str,
    ) -> Result<(), String> {
        self.run_command_with_realtime_logging_and_monitoring(cmd, error_msg, true)
    }

    fn run_command_with_realtime_logging_and_monitoring(
        &self,
        cmd: &mut Command,
        error_msg: &str,
        enable_monitoring: bool,
    ) -> Result<(), String> {
        self.log_command_start(cmd);
        let start = Instant::now();

        // Configure command for real-time output capture
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::inherit()); // Allow interactive input

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("{error_msg}: Failed to spawn process: {e}"))?;

        // Take stdout and stderr pipes
        let stdout = child.stdout.take().ok_or("Failed to get stdout")?;
        let stderr = child.stderr.take().ok_or("Failed to get stderr")?;

        // Create shared state for tracking output
        let log_file = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.config.log_file)
                .map_err(|e| format!("Failed to open log file: {e}"))?,
        ));

        let config = self.config.clone();
        let error_occurred = Arc::new(Mutex::new(false));
        let last_output = Arc::new(Mutex::new(Instant::now()));

        // Shared flag to signal when container shell is ready
        let shell_ready = Arc::new(Mutex::new(false));

        // Spawn thread for stdout
        let _stdout_log_file = Arc::clone(&log_file);
        let stdout_config = config.clone();
        let stdout_error = Arc::clone(&error_occurred);
        let stdout_last_output = Arc::clone(&last_output);
        let stdout_shell_ready = Arc::clone(&shell_ready);
        let stdout_handle = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        *stdout_last_output.lock().unwrap() = Instant::now();
                        let utils = Utils::new(stdout_config.clone());
                        utils.log_command_output("OUT", "stdout", &line);

                        // Check if this line indicates the container shell is ready
                        if line.contains("SECURE CONTAINER READY")
                            || line.contains("Available directories:")
                            || line.contains("HOW TO EXIT:")
                            || line.contains("Audio status:")
                            || line.contains("exec bash --login")
                            || line.contains("[agent@container]")
                        {
                            *stdout_shell_ready.lock().unwrap() = true;
                        }
                    }
                    Err(_) => {
                        *stdout_error.lock().unwrap() = true;
                        break;
                    }
                }
            }
        });

        // Spawn thread for stderr
        let _stderr_log_file = Arc::clone(&log_file);
        let stderr_config = config.clone();
        let stderr_error = Arc::clone(&error_occurred);
        let stderr_last_output = Arc::clone(&last_output);
        let stderr_handle = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        *stderr_last_output.lock().unwrap() = Instant::now();
                        let utils = Utils::new(stderr_config.clone());
                        utils.log_command_output("ERR", "stderr", &line);
                    }
                    Err(_) => {
                        *stderr_error.lock().unwrap() = true;
                        break;
                    }
                }
            }
        });

        // Monitor process for potential hangs (only if monitoring is enabled)
        let _monitor_handle = if enable_monitoring {
            let monitor_last_output = Arc::clone(&last_output);
            let monitor_config = config.clone();
            let monitor_shell_ready = Arc::clone(&shell_ready);
            Some(thread::spawn(move || {
                let mut wait_reported = false;
                loop {
                    thread::sleep(Duration::from_secs(5));

                    // Stop monitoring if globally disabled
                    if MONITORING_DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    // Stop monitoring if shell is ready
                    if *monitor_shell_ready.lock().unwrap() {
                        break;
                    }

                    let time_since_output = monitor_last_output.lock().unwrap().elapsed();

                    if time_since_output > Duration::from_secs(10) && !wait_reported {
                        if monitor_config.verbose_mode {
                            println!("{}[WAIT]{} Process appears to be waiting for input (no output for {:.1}s)", 
                                   crate::constants::YELLOW, crate::constants::NC, time_since_output.as_secs_f64());
                        }
                        let utils = Utils::new(monitor_config.clone());
                        utils.log_with_level(
                            "WAIT",
                            &format!(
                                "Process appears to be waiting for input (no output for {:.1}s)",
                                time_since_output.as_secs_f64()
                            ),
                        );
                        wait_reported = true;
                    }

                    // Stop monitoring after 30 seconds of no output (likely interactive)
                    if time_since_output > Duration::from_secs(30) {
                        break;
                    }
                }
            }))
        } else {
            None
        };

        // Wait for process to complete
        let exit_status = child
            .wait()
            .map_err(|e| format!("{error_msg}: Failed to wait for process: {e}"))?;
        let duration = start.elapsed();

        // Stop monitoring
        // Note: We don't join the monitor thread as it may be sleeping

        // Wait for output threads to complete
        stdout_handle.join().ok();
        stderr_handle.join().ok();

        let success = exit_status.success();
        self.log_command_end(cmd, success, duration);

        if !success {
            let exit_code = exit_status.code().unwrap_or(-1);
            return Err(format!(
                "{error_msg}: Process exited with code {exit_code}"
            ));
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

        // Only add quiet flag if not in verbose mode
        if !self.config.verbose_mode {
            cmd.arg("-q");
        }

        cmd.arg("-D");
        cmd.arg(self.config.container_path.to_str().unwrap());
        cmd.arg("--pipe");

        for arg in args {
            cmd.arg(arg);
        }

        self.run_command_with_realtime_logging(&mut cmd, error_msg)
    }

    pub fn run_systemd_nspawn_with_network(
        &self,
        args: &[&str],
        error_msg: &str,
    ) -> Result<(), String> {
        let mut cmd = Command::new("sudo");
        cmd.arg("systemd-nspawn");

        // Only add quiet flag if not in verbose mode
        if !self.config.verbose_mode {
            cmd.arg("-q");
        }

        cmd.arg("-D");
        cmd.arg(self.config.container_path.to_str().unwrap());

        // Enable network access for setup operations
        cmd.arg("--capability=CAP_NET_RAW");

        // Allow internet access during setup
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
            // For newer systemd, use more permissive settings during setup
            cmd.arg("--rlimit=NPROC=4096");
            cmd.arg("--rlimit=NOFILE=4096");
        }

        for arg in args {
            cmd.arg(arg);
        }

        self.run_command_with_realtime_logging(&mut cmd, error_msg)
    }

    pub fn run_systemd_nspawn_with_output(
        &self,
        args: &[&str],
        error_msg: &str,
    ) -> Result<String, String> {
        let mut cmd = Command::new("sudo");
        cmd.arg("systemd-nspawn");

        // Only add quiet flag if not in verbose mode
        if !self.config.verbose_mode {
            cmd.arg("-q");
        }

        cmd.arg("-D");
        cmd.arg(self.config.container_path.to_str().unwrap());

        // Allow internet access during setup
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
            // For newer systemd, use more permissive settings during setup
            cmd.arg("--rlimit=NPROC=4096");
            cmd.arg("--rlimit=NOFILE=4096");
        }

        for arg in args {
            cmd.arg(arg);
        }

        self.log_command_start(&cmd);
        let start = std::time::Instant::now();

        let output = cmd.output().map_err(|e| format!("{error_msg}: {e}"))?;
        let duration = start.elapsed();

        if !output.status.success() {
            self.log_command_end(&cmd, false, duration);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "{error_msg}: Command failed with stderr: {stderr}"
            ));
        }

        self.log_command_end(&cmd, true, duration);
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn write_file_as_root(&self, path: &Path, content: &str) -> Result<(), String> {
        let mut cmd = Command::new("sudo");
        cmd.arg("tee");
        cmd.arg(path);
        cmd.stdin(Stdio::piped());

        // In verbose mode, show output; otherwise suppress it
        if self.config.verbose_mode {
            cmd.stdout(Stdio::piped());
        } else {
            cmd.stdout(Stdio::null());
        }

        self.log_command_start(&cmd);
        let start = Instant::now();

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn sudo tee: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(content.as_bytes())
                .map_err(|e| format!("Failed to write content: {e}"))?;
        }

        // Capture output if in verbose mode
        if self.config.verbose_mode {
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        self.log_command_output("OUT", "stdout", &line);
                    }
                }
            }
        }

        let status = child
            .wait()
            .map_err(|e| format!("Failed to wait for sudo tee: {e}"))?;

        let duration = start.elapsed();
        let success = status.success();
        self.log_command_end(&cmd, success, duration);

        if !success {
            return Err("Failed to write file as root".to_string());
        }

        Ok(())
    }

    pub fn get_ulimit_nproc(&self) -> String {
        let mut cmd = Command::new("bash");
        cmd.args(&["-c", "ulimit -u"]);
        self.log_command_start(&cmd);

        let start = Instant::now();
        let result = cmd
            .output()
            .ok()
            .and_then(|o| {
                let duration = start.elapsed();
                let success = o.status.success();
                self.log_command_end(&cmd, success, duration);

                if success {
                    String::from_utf8(o.stdout).ok()
                } else {
                    None
                }
            })
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        result
    }

    pub fn validate_host_dir(&self, dir: &Path) -> Result<std::path::PathBuf, String> {
        // Get real path
        let real_path = dir
            .canonicalize()
            .map_err(|_| "Invalid directory path: does not exist")?;

        // Security: Ensure in /home
        let path_str = real_path.to_string_lossy();
        if !path_str.starts_with("/home/") {
            return Err(format!("Path not in /home: {path_str}"));
        }

        // Security: Check for valid characters
        if !path_str
            .chars()
            .all(|c| c.is_alphanumeric() || "/_-.".contains(c))
        {
            return Err(format!("Invalid characters in path: {path_str}"));
        }

        // Must exist and be readable
        if !real_path.is_dir() {
            return Err(format!("Directory does not exist: {path_str}"));
        }

        Ok(real_path)
    }

    pub fn is_package_installed(&self, package: &str) -> bool {
        let mut cmd = Command::new("dpkg");
        cmd.args(&["-l", package]);
        self.log_command_start(&cmd);

        let start = Instant::now();
        let result = cmd
            .output()
            .map(|o| {
                let duration = start.elapsed();
                let success = o.status.success();
                self.log_command_end(&cmd, success, duration);
                success
            })
            .unwrap_or(false);

        result
    }

    pub fn calculate_file_checksum(&self, file_path: &Path) -> Result<String, String> {
        let mut cmd = Command::new("sha256sum");
        cmd.arg(file_path);
        self.log_command_start(&cmd);

        let start = Instant::now();
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to calculate checksum: {e}"))?;

        let duration = start.elapsed();
        let success = output.status.success();
        self.log_command_end(&cmd, success, duration);

        if !success {
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
