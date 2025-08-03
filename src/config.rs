use std::env;
use std::path::PathBuf;
use std::process::Command;
use tempfile::Builder;

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityMode {
    High,
    Medium,
    Low,
}

impl SecurityMode {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "high" => Ok(SecurityMode::High),
            "medium" => Ok(SecurityMode::Medium),
            "low" => Ok(SecurityMode::Low),
            _ => Err(format!("Invalid security mode: {s}")),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub container_path: PathBuf,
    pub host_dir: PathBuf,
    pub log_dir: PathBuf,
    pub log_file: PathBuf,
    pub cache_dir: PathBuf,
    pub security_mode: SecurityMode,
    pub debug_mode: bool,
    pub verbose_mode: bool,
    pub systemd_version: u32,
}

impl Config {
    pub fn new() -> Result<Self, String> {
        let home = env::var("HOME").map_err(|_| "HOME environment variable not set")?;
        let home_path = PathBuf::from(&home);

        let container_path = home_path.join(".config/cagent/container");
        let host_dir = env::var("HOST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_path.clone());

        let log_dir = home_path.join(".config/cagent/logs");
        let cache_dir = home_path.join(".config/cagent/cache");

        // Create logs directory if it doesn't exist
        std::fs::create_dir_all(&log_dir).map_err(|e| format!("Failed to create log dir: {e}"))?;

        // Create secure random log file using tempfile
        let log_file = Self::create_secure_log_file(&log_dir)?;

        let security_mode = env::var("SECURITY_MODE").unwrap_or_else(|_| "high".to_string());
        let security_mode = SecurityMode::from_str(&security_mode)?;

        let debug_mode = env::var("DEBUG_MODE").map(|v| v == "1").unwrap_or(false);
        let args: Vec<String> = env::args().collect();
        let verbose_mode = args.iter().any(|arg| arg == "-v" || arg == "--verbose");

        let systemd_version = Self::get_systemd_version();

        Ok(Config {
            container_path,
            host_dir,
            log_dir,
            log_file,
            cache_dir,
            security_mode,
            debug_mode,
            verbose_mode,
            systemd_version,
        })
    }

    fn get_systemd_version() -> u32 {
        let mut cmd = Command::new("systemd-nspawn");
        cmd.arg("--version");

        // Log command for diagnostic purposes (only if verbose is set via env args)
        let args: Vec<String> = env::args().collect();
        if args.iter().any(|arg| arg == "-v" || arg == "--verbose") {
            println!("[EXEC] systemd-nspawn --version");
        }

        let output = cmd
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        output
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().find_map(|s| s.parse::<u32>().ok()))
            .unwrap_or(0)
    }

    fn create_secure_log_file(log_dir: &PathBuf) -> Result<PathBuf, String> {
        // Use tempfile to create a secure log file with guaranteed uniqueness
        let temp_file = Builder::new()
            .prefix("log-")
            .suffix(".log")
            .tempfile_in(log_dir)
            .map_err(|e| format!("Failed to create secure log file: {e}"))?;

        // Persist the tempfile so it won't be deleted when dropped
        let (_, path) = temp_file
            .keep()
            .map_err(|e| format!("Failed to persist log file: {e}"))?;

        Ok(path)
    }
}
