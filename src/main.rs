use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, exit, Stdio};
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

const RED: &str = "\x1b[0;31m";
const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[0;33m";
const BLUE: &str = "\x1b[0;34m";
const NC: &str = "\x1b[0m";

const ARCH_MIRROR: &str = "https://mirror.rackspace.com/archlinux";
const ARCH_BOOTSTRAP_FILE_NAME: &str = "archlinux-bootstrap-x86_64.tar.zst";
const CONTAINER_USER: &str = "agent";

struct Config {
    container_path: PathBuf,
    host_dir: PathBuf,
    log_dir: PathBuf,
    log_file: PathBuf,
    security_mode: SecurityMode,
    debug_mode: bool,
    systemd_version: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum SecurityMode {
    High,
    Medium,
    Low,
}

impl SecurityMode {
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "high" => Ok(SecurityMode::High),
            "medium" => Ok(SecurityMode::Medium),
            "low" => Ok(SecurityMode::Low),
            _ => Err(format!("Invalid security mode: {}", s)),
        }
    }
}

struct CageManager {
    config: Config,
}

impl CageManager {
    fn new() -> Result<Self, String> {
        let home = env::var("HOME").map_err(|_| "HOME environment variable not set")?;
        let home_path = PathBuf::from(&home);
        
        let container_path = home_path.join(".config/cagent/container");
        let host_dir = env::var("HOST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_path.clone());
        
        let log_dir = home_path.join(".config/cagent/logs");
        
        // Create timestamp for log file
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_file = log_dir.join(format!("log-{}.log", timestamp));
        
        let security_mode = env::var("SECURITY_MODE")
            .unwrap_or_else(|_| "high".to_string());
        let security_mode = SecurityMode::from_str(&security_mode)?;
        
        let debug_mode = env::var("DEBUG_MODE")
            .map(|v| v == "1")
            .unwrap_or(false);
        
        let systemd_version = Self::get_systemd_version();
        
        Ok(CageManager {
            config: Config {
                container_path,
                host_dir,
                log_dir,
                log_file,
                security_mode,
                debug_mode,
                systemd_version,
            },
        })
    }
    
    fn get_systemd_version() -> u32 {
        let output = Command::new("systemd-nspawn")
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        
        output.lines()
            .next()
            .and_then(|line| {
                line.split_whitespace()
                    .find_map(|s| s.parse::<u32>().ok())
            })
            .unwrap_or(0)
    }
    
    fn log(&self, message: &str) {
        println!("{}", message);
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
    
    fn error_exit(&self, message: &str) -> ! {
        eprintln!("{}ERROR: {}{}", RED, message, NC);
        eprintln!("Check log file: {}", self.config.log_file.display());
        self.log(&format!("ERROR: {}", message));
        exit(1);
    }
    
    fn check_prerequisites(&self) -> Result<(), String> {
        println!("Checking prerequisites...");
        
        // Check if running as non-root
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return Err("Please run this script as a normal user, not as root".to_string());
        }
        
        // Check for suspicious environment
        if env::var("LD_PRELOAD").is_ok() || env::var("LD_LIBRARY_PATH").is_ok() {
            return Err("Suspicious environment detected (LD_PRELOAD/LD_LIBRARY_PATH set)".to_string());
        }
        
        // Check Ubuntu/Debian
        if !Path::new("/etc/debian_version").exists() {
            return Err("This script is designed for Ubuntu/Debian systems".to_string());
        }
        
        // Check systemd
        if Command::new("systemctl").arg("--version").output().is_err() {
            return Err("systemd is required but not found".to_string());
        }
        
        // Check X11
        let display = env::var("DISPLAY")
            .map_err(|_| "DISPLAY variable not set. Are you running in an X11 session?")?;
        
        // Validate DISPLAY format
        if !display.starts_with(':') || !display[1..].chars().all(|c| c.is_numeric() || c == '.') {
            return Err(format!("Invalid DISPLAY format: {}", display));
        }
        
        // Validate host directory
        self.validate_host_dir(&self.config.host_dir)?;
        
        self.log(&format!("Detected systemd version: {}", self.config.systemd_version));
        
        // Check system resource limits for systemd 254+
        if self.config.systemd_version >= 254 {
            let nproc_limit = self.get_ulimit_nproc();
            if nproc_limit != "unlimited" && nproc_limit.parse::<u32>().unwrap_or(0) < 10000 {
                println!("{}Warning: Your system process limit is low ({}){}", YELLOW, nproc_limit, NC);
                println!("{}This might cause 'Resource temporarily unavailable' errors{}", YELLOW, NC);
                println!("{}Consider increasing it with: ulimit -u 30000{}", YELLOW, NC);
            }
        }
        
        self.log("Prerequisites check passed");
        Ok(())
    }
    
    fn get_ulimit_nproc(&self) -> String {
        Command::new("bash")
            .args(&["-c", "ulimit -u"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
    
    fn validate_host_dir(&self, dir: &Path) -> Result<PathBuf, String> {
        // Get real path
        let real_path = dir.canonicalize()
            .map_err(|_| "Invalid directory path: does not exist")?;
        
        // Security: Ensure in /home
        let path_str = real_path.to_string_lossy();
        if !path_str.starts_with("/home/") {
            return Err(format!("Path not in /home: {}", path_str));
        }
        
        // Security: Check for valid characters
        if !path_str.chars().all(|c| c.is_alphanumeric() || "/_-.".contains(c)) {
            return Err(format!("Invalid characters in path: {}", path_str));
        }
        
        // Must exist and be readable
        if !real_path.is_dir() {
            return Err(format!("Directory does not exist: {}", path_str));
        }
        
        Ok(real_path)
    }
    
    fn install_dependencies(&self) -> Result<(), String> {
        println!("Installing dependencies...");
        
        // Update package list
        self.run_command_with_log(
            Command::new("sudo")
                .args(&["apt", "update"]),
            "Failed to update package list"
        )?;
        
        // Install required packages
        let packages = ["systemd-container", "wget", "xz-utils"];
        for pkg in &packages {
            if !self.is_package_installed(pkg) {
                println!("Installing {}...", pkg);
                self.run_command_with_log(
                    Command::new("sudo")
                        .args(&["apt", "install", "-y", pkg]),
                    &format!("Failed to install {}", pkg)
                )?;
            }
        }
        
        // Verify commands are available
        let required_commands = ["systemd-nspawn", "wget", "xauth"];
        for cmd in &required_commands {
            if Command::new("which").arg(cmd).output().is_err() {
                return Err(format!("Required command '{}' not found after installation", cmd));
            }
        }
        
        self.log("Dependencies installed successfully");
        Ok(())
    }
    
    fn is_package_installed(&self, package: &str) -> bool {
        Command::new("dpkg")
            .args(&["-l", package])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    
    fn download_with_verification(&self, url: &str, output: &Path) -> Result<(), String> {
        println!("Downloading from {}...", url);
        
        // Create temp file
        let temp_path = format!("/tmp/download_{}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        
        // Download with wget
        self.run_command(
            Command::new("wget")
                .args(&[
                    "--timeout=30",
                    "--tries=3",
                    "--max-redirect=2",
                    "--secure-protocol=TLSv1_2",
                    "-O", &temp_path,
                    url
                ]),
            "Download failed"
        )?;
        
        // Verify file size
        let metadata = fs::metadata(&temp_path)
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let file_size = metadata.len();
        
        if file_size < 100_000_000 || file_size > 500_000_000 {
            fs::remove_file(&temp_path).ok();
            return Err(format!("Downloaded file size suspicious: {} bytes", file_size));
        }
        
        // Get and verify checksum
        println!("Verifying download integrity...");
        let checksum_url = format!("{}/sha256sums.txt", 
            url.rsplit('/').nth(1).unwrap_or(""));
        
        if let Ok(output) = Command::new("wget")
            .args(&["-qO-", "--timeout=10", &checksum_url])
            .output()
        {
            if output.status.success() {
                if let Ok(checksums) = String::from_utf8(output.stdout) {
                    if let Some(line) = checksums.lines()
                        .find(|l| l.contains(ARCH_BOOTSTRAP_FILE_NAME)) 
                    {
                        let expected_hash = line.split_whitespace().next().unwrap_or("");
                        
                        // Calculate actual hash
                        let output = Command::new("sha256sum")
                            .arg(&temp_path)
                            .output()
                            .map_err(|e| format!("Failed to calculate checksum: {}", e))?;
                        
                        let actual_hash_string = String::from_utf8_lossy(&output.stdout);
                        let actual_hash = actual_hash_string
                            .split_whitespace()
                            .next()
                            .unwrap_or("");
                        
                        if expected_hash != actual_hash {
                            fs::remove_file(&temp_path).ok();
                            return Err(format!(
                                "Checksum verification failed! Expected: {}, Got: {}",
                                expected_hash, actual_hash
                            ));
                        }
                        println!("Checksum verified successfully");
                    } else {
                        println!("{}Warning: Could not find checksum for file{}", YELLOW, NC);
                    }
                }
            } else {
                println!("{}Warning: Could not download checksums for verification{}", YELLOW, NC);
            }
        }
        
        // Move to final location
        fs::rename(&temp_path, output)
            .map_err(|e| format!("Failed to move file: {}", e))?;
        
        Ok(())
    }
    
    fn setup_container(&self) -> Result<(), String> {
        println!("{}Setting up Arch Linux container with security hardening...{}", GREEN, NC);
        self.log("Starting secure container setup");
        
        // Create container directory
        println!("Creating container directory...");
        self.run_command(
            Command::new("sudo")
                .args(&["mkdir", "-p", self.config.container_path.to_str().unwrap()]),
            "Failed to create container directory"
        )?;
        
        // Set restrictive permissions
        if let Some(parent_dir) = self.config.container_path.parent() {
            self.run_command(
                Command::new("sudo")
                    .args(&["chmod", "700", parent_dir.to_str().unwrap()]),
                "Failed to set permissions"
            )?;
        }
        
        // Download and extract Arch Linux
        let arch_file = PathBuf::from("/tmp").join(ARCH_BOOTSTRAP_FILE_NAME);
        let download_url = format!("{}/iso/latest/{}", ARCH_MIRROR, ARCH_BOOTSTRAP_FILE_NAME);
        self.download_with_verification(&download_url, &arch_file)?;
        
        println!("Extracting Arch Linux securely...");
        
        // Extract tarball
        self.run_command_in_dir(
            Command::new("sudo")
                .args(&["tar", "--use-compress-program=zstd", "-xf", 
                    arch_file.to_str().unwrap()]),
            "/tmp",
            "Failed to extract Arch Linux bootstrap"
        )?;
        
        // Move files to container path
        self.run_command(
            Command::new("bash")
                .args(&["-c", &format!("sudo mv /tmp/root.x86_64/* {} 2>/dev/null", 
                    self.config.container_path.to_str().unwrap())]),
            "Failed to move files to container directory"
        )?;
        
        // Cleanup
        Command::new("sudo").args(&["rmdir", "/tmp/root.x86_64"]).output().ok();
        fs::remove_file(&arch_file).ok();
        
        // Configure pacman
        println!("Configuring package manager...");
        let mirrorlist = self.config.container_path.join("etc/pacman.d/mirrorlist");
        let mirror_content = format!("Server = {}/$repo/os/$arch", ARCH_MIRROR);
        
        self.run_command(
            Command::new("bash")
                .args(&["-c", &format!("echo '{}' | sudo tee {} > /dev/null", 
                    mirror_content, mirrorlist.display())]),
            "Failed to configure pacman mirrorlist"
        )?;
        
        // Initialize pacman keyring
        println!("Initializing pacman keyring...");
        self.run_systemd_nspawn(&["pacman-key", "--init"], 
            "Failed to initialize pacman keyring")?;
        self.run_systemd_nspawn(&["pacman-key", "--populate", "archlinux"], 
            "Failed to populate pacman keyring")?;
        
        // Update base system
        println!("Updating base system...");
        self.run_systemd_nspawn(&["pacman", "-Syu", "--noconfirm"], 
            "Failed to update base system")?;
        
        // Install essential packages
        println!("Installing essential packages...");
        let mut packages = vec![
            "base", "sudo", "nano", "wget",
            "xorg-xauth", "mesa", "gtk3", "nss",
            "ttf-liberation", "noto-fonts",
            "pulseaudio", "alsa-utils", "libpulse"  // Audio support
        ];
        
        if self.config.security_mode != SecurityMode::High {
            packages.push("chromium");
        }
        
        let mut pacman_args = vec!["pacman", "-S", "--noconfirm"];
        pacman_args.extend(packages.iter().map(|s| *s));
        
        self.run_systemd_nspawn(&pacman_args, "Failed to install essential packages")?;
        
        // Create agent user
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        
        println!("Creating user '{}' ({}:{})...", CONTAINER_USER, uid, gid);
        
        // Create group
        self.run_systemd_nspawn(
            &["groupadd", "-g", &gid.to_string(), CONTAINER_USER],
            "Group may already exist"
        ).ok();
        
        // Create user
        self.run_systemd_nspawn(
            &["useradd", "-m", "-u", &uid.to_string(), "-g", &gid.to_string(), 
             "-s", "/bin/bash", CONTAINER_USER],
            "Failed to create user"
        )?;
        
        // Add user to audio group for sound support
        self.run_systemd_nspawn(
            &["groupadd", "-r", "audio"],
            "Audio group may already exist"
        ).ok();
        
        self.run_systemd_nspawn(
            &["usermod", "-a", "-G", "audio", CONTAINER_USER],
            "Failed to add user to audio group"
        )?;
        
        // Setup sudo configuration
        let sudoers_content = format!(
            "# Restricted sudo for container user - package management only\n\
             Defaults env_reset\n\
             Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
             {} ALL=(ALL) NOPASSWD: /usr/bin/pacman -S *, /usr/bin/pacman -Syu, /usr/bin/pacman -R *\n",
            CONTAINER_USER
        );
        
        let sudoers_file = self.config.container_path.join("etc/sudoers.d/99-container-user");
        if let Some(parent) = sudoers_file.parent() {
            self.run_command(
                Command::new("sudo")
                    .args(&["mkdir", "-p", parent.to_str().unwrap()]),
                "Failed to create sudoers.d directory"
            )?;
        }
        
        self.write_file_as_root(&sudoers_file, &sudoers_content)?;
        
        self.run_command(
            Command::new("sudo")
                .args(&["chmod", "440", sudoers_file.to_str().unwrap()]),
            "Failed to set sudoers permissions"
        )?;
        
        // Create user directories
        let user_home = format!("/home/{}", CONTAINER_USER);
        for dir in &["Documents", "Downloads", "Desktop", ".config", ".config/pulse", "work"] {
            self.run_systemd_nspawn(
                &["mkdir", "-p", &format!("{}/{}", user_home, dir)],
                "Failed to create user directory"
            )?;
        }
        
        // Fix ownership
        self.run_systemd_nspawn(
            &["chown", "-R", &format!("{}:{}", CONTAINER_USER, CONTAINER_USER), &user_home],
            "Failed to set ownership for user home"
        )?;
        
        // Set permissions
        self.run_systemd_nspawn(
            &["chmod", "755", &user_home],
            "Failed to set permissions on user home"
        )?;
        
        // Create container integrity file
        let integrity_content = format!("{}:container", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        let integrity_file = self.config.container_path.join(".container-integrity");
        self.write_file_as_root(&integrity_file, &integrity_content)?;
        
        println!("{}Secure container setup complete!{}", GREEN, NC);
        self.log("Container setup completed successfully");
        Ok(())
    }
    
    fn enter_container(&self) -> Result<(), String> {
        println!("{}Entering hardened container as user '{}'...{}", GREEN, CONTAINER_USER, NC);
        println!("{}Security Mode: {:?}{}", YELLOW, self.config.security_mode, NC);
        println!("{}systemd version: {}{}", YELLOW, self.config.systemd_version, NC);
        
        // Verify container exists
        if !self.config.container_path.join("etc/os-release").exists() {
            return Err(format!("Container not found at {}", 
                self.config.container_path.display()));
        }
        
        // Setup X11 authentication
        let temp_xauth = format!("/tmp/xauth_{}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        
        // Export display auth
        let display = env::var("DISPLAY").unwrap_or(":0".to_string());
        
        // Create xauth file
        self.run_command(
            Command::new("bash")
                .args(&["-c", &format!(
                    "xauth nlist {} | sed -e 's/^..../ffff/' | xauth -f {} nmerge -",
                    display, temp_xauth
                )]),
            "Failed to setup X11 auth"
        )?;
        
        // Set permissions
        fs::set_permissions(&temp_xauth, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set xauth permissions: {}", e))?;
        
        // Create container xauth file
        let xauth_name = format!(".Xauthority.{}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let container_xauth = self.config.container_path
            .join("tmp")
            .join(&xauth_name);
        
        self.run_command(
            Command::new("sudo")
                .args(&["cp", &temp_xauth, container_xauth.to_str().unwrap()]),
            "Failed to copy xauth to container"
        )?;
        
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        
        self.run_command(
            Command::new("sudo")
                .args(&["chown", &format!("{}:{}", uid, gid), 
                    container_xauth.to_str().unwrap()]),
            "Failed to set xauth ownership"
        )?;
        
        self.run_command(
            Command::new("sudo")
                .args(&["chmod", "600", container_xauth.to_str().unwrap()]),
            "Failed to set xauth permissions"
        )?;
        
        // Build systemd-nspawn command
        let mut cmd = Command::new("sudo");
        cmd.arg("systemd-nspawn");
        
        if !self.config.debug_mode {
            cmd.arg("--quiet");
        }
        
        cmd.arg("--directory").arg(self.config.container_path.to_str().unwrap());
        
        // Add security options based on systemd version
        self.add_security_options(&mut cmd);
        
        // Add bind mounts
        self.add_bind_mounts(&mut cmd)?;
        
        // Set environment variables
        cmd.arg("--setenv").arg(format!("DISPLAY={}", display));
        cmd.arg("--setenv").arg(format!("XAUTHORITY=/home/{}/.Xauthority", CONTAINER_USER));
        cmd.arg("--setenv").arg(format!("SECURITY_MODE={:?}", self.config.security_mode));
        cmd.arg("--setenv").arg(format!("HOME=/home/{}", CONTAINER_USER));
        cmd.arg("--setenv").arg(format!("USER={}", CONTAINER_USER));
        cmd.arg("--setenv").arg("SHELL=/bin/bash");
        cmd.arg("--setenv").arg("TERM=xterm-256color");
        
        // Audio environment variables
        let uid = unsafe { libc::getuid() };
        cmd.arg("--setenv").arg(format!("PULSE_SERVER=/run/user/{}/pulse/native", uid));
        cmd.arg("--setenv").arg(format!("PULSE_RUNTIME_PATH=/run/user/{}/pulse", uid));
        
        // Create container script
        let container_script = self.create_container_script(&display, &xauth_name);
        
        if self.config.systemd_version >= 254 {
            // For systemd 254+, use --user directly
            cmd.arg("--user").arg(CONTAINER_USER);
            cmd.arg("/bin/bash");
            cmd.arg("-c");
            cmd.arg(&container_script);
        } else {
            // For older versions, use runuser
            cmd.arg("runuser");
            cmd.arg("-u").arg(CONTAINER_USER);
            cmd.arg("--");
            cmd.arg("bash");
            cmd.arg("-c");
            cmd.arg(&container_script);
        }
        
        // Execute
        let status = cmd.status()
            .map_err(|e| format!("Failed to execute systemd-nspawn: {}", e))?;
        
        // Cleanup
        fs::remove_file(&temp_xauth).ok();
        
        if !status.success() {
            if self.config.systemd_version >= 254 {
                println!("{}Resource limit error detected. Possible solutions:{}", YELLOW, NC);
                println!("{}1. Increase your user process limit: ulimit -u 30000{}", YELLOW, NC);
                println!("{}2. Try medium security mode: SECURITY_MODE=medium{}", YELLOW, NC);
                println!("{}3. Check system resources: free -h && ps aux | wc -l{}", YELLOW, NC);
                println!("{}4. Restart systemd-logind: sudo systemctl restart systemd-logind{}", YELLOW, NC);
            }
            return Err(format!("Failed to enter container (exit code: {:?})", status.code()));
        }
        
        Ok(())
    }
    
    fn add_security_options(&self, cmd: &mut Command) {
        if self.config.systemd_version >= 254 {
            // For systemd 254+, minimal security options
            cmd.arg("--personality=x86-64");
            cmd.arg("--link-journal=no");
        } else {
            // For older versions
            cmd.arg("--drop-capability=all");
            cmd.arg("--no-new-privileges=yes");
            cmd.arg("--as-pid2");
            cmd.arg("--personality=x86-64");
            cmd.arg("--link-journal=no");
        }
        
        // Add version-specific options
        if self.config.systemd_version < 254 {
            cmd.arg("--keep-unit");
            cmd.arg("--register=no");
        }
        
        // Resource limits
        if self.config.systemd_version >= 254 {
            // Higher limits for systemd 254+
            cmd.arg("--rlimit=NPROC=4096");
            cmd.arg("--rlimit=NOFILE=4096");
            cmd.arg("--rlimit=MEMLOCK=256M");
            cmd.arg("--rlimit=MSGQUEUE=32M");
        } else {
            cmd.arg("--rlimit=NPROC=512");
            cmd.arg("--rlimit=NOFILE=1024");
            cmd.arg("--rlimit=MEMLOCK=64M");
            cmd.arg("--rlimit=MSGQUEUE=8M");
        }
        
        cmd.arg("--rlimit=NICE=0");
        cmd.arg("--rlimit=RTPRIO=0");
        
        // Apply security mode specific options
        match self.config.security_mode {
            SecurityMode::High => {
                if self.config.systemd_version < 254 {
                    cmd.arg("--capability=CAP_SETUID,CAP_SETGID");
                    cmd.arg("--private-network");
                }
            },
            SecurityMode::Medium => {
                if self.config.systemd_version < 254 {
                    cmd.arg("--capability=CAP_SETUID,CAP_SETGID,CAP_NET_RAW");
                }
            },
            SecurityMode::Low => {
                if self.config.systemd_version < 254 {
                    cmd.arg("--capability=CAP_SETUID,CAP_SETGID,CAP_NET_RAW,CAP_SYS_PTRACE");
                }
            },
        }
    }
    
    fn add_bind_mounts(&self, cmd: &mut Command) -> Result<(), String> {
        // X11 socket
        cmd.arg("--bind-ro=/tmp/.X11-unix");
        
        // Audio support - Only for medium/low security modes
        if self.config.security_mode != SecurityMode::High {
            // PulseAudio socket
            let pulse_socket = format!("/run/user/{}/pulse", unsafe { libc::getuid() });
            if Path::new(&pulse_socket).exists() {
                cmd.arg(format!("--bind={}", pulse_socket));
                println!("{}Audio: PulseAudio socket bound{}", GREEN, NC);
            } else {
                println!("{}Warning: PulseAudio socket not found at {}{}", YELLOW, pulse_socket, NC);
            }
            
            // PulseAudio cookie
            let pulse_cookie = format!("{}/.config/pulse/cookie", env::var("HOME").unwrap_or_default());
            if Path::new(&pulse_cookie).exists() {
                cmd.arg(format!("--bind-ro={}:/home/{}/.config/pulse/cookie", 
                    pulse_cookie, CONTAINER_USER));
            }
            
            // ALSA devices
            if Path::new("/dev/snd").exists() {
                cmd.arg("--bind=/dev/snd");
                println!("{}Audio: ALSA devices bound{}", GREEN, NC);
            }
            
            // DRI devices (for hardware acceleration and audio)
            if Path::new("/dev/dri").exists() {
                cmd.arg("--bind=/dev/dri");
            }
        } else {
            println!("{}High security mode: Audio devices not bound{}", YELLOW, NC);
        }
        
        // Tmpfs mounts
        if self.config.systemd_version >= 254 {
            cmd.arg("--tmpfs=/tmp:size=500M");
            cmd.arg("--tmpfs=/dev/shm:size=256M");
        } else {
            cmd.arg("--tmpfs=/tmp:size=100M,mode=1777,nosuid,nodev");
            cmd.arg("--tmpfs=/dev/shm:size=64M,mode=1777,nosuid,nodev,noexec");
            cmd.arg("--tmpfs=/run:size=32M,mode=755,nosuid,nodev");
        }
        
        // Bind host directories
        let docs_path = self.config.host_dir.join("Documents");
        if docs_path.exists() {
            cmd.arg(format!("--bind-ro={}:/home/{}/documents", 
                docs_path.display(), CONTAINER_USER));
        }
        
        let downloads_path = self.config.host_dir.join("Downloads");
        if downloads_path.exists() {
            cmd.arg(format!("--bind-ro={}:/home/{}/downloads", 
                downloads_path.display(), CONTAINER_USER));
        }
        
        // Work directory
        if self.config.systemd_version >= 254 {
            cmd.arg(format!("--tmpfs=/home/{}/work:size=2G", CONTAINER_USER));
        } else {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            cmd.arg(format!("--tmpfs=/home/{}/work:size=1G,mode=700,uid={},gid={}", 
                CONTAINER_USER, uid, gid));
        }
        
        Ok(())
    }
    
    fn create_container_script(&self, display: &str, xauth_name: &str) -> String {
        let security_mode_str = match self.config.security_mode {
            SecurityMode::High => "High",
            SecurityMode::Medium => "Medium", 
            SecurityMode::Low => "Low",
        };
        
        format!(r#"
# Setup X11 authentication
if [ -f '/tmp/{}' ]; then
    cp '/tmp/{}' ~/.Xauthority 2>/dev/null
    chmod 600 ~/.Xauthority 2>/dev/null
    rm -f '/tmp/{}' 2>/dev/null
fi

# Set up environment
export DISPLAY='{}'
export XAUTHORITY="$HOME/.Xauthority"

# Audio setup
mkdir -p ~/.config/pulse 2>/dev/null
export PULSE_SERVER=/run/user/$(id -u)/pulse/native
export PULSE_RUNTIME_PATH=/run/user/$(id -u)/pulse

# Browser flags if available
if command -v chromium &>/dev/null; then
    export CHROME_FLAGS='--no-sandbox --disable-setuid-sandbox --disable-gpu-sandbox --enable-features=UseOzonePlatform --ozone-platform=x11 --use-gl=swiftshader'
fi

# Change to home directory
cd ~ || cd /

# Create audio fix script
cat > ~/fix-audio.sh << 'AUDIOFIX'
#!/bin/bash
echo "Checking audio setup..."
# Check if we're in audio group
if groups | grep -q audio; then
    echo "✓ User is in audio group"
else
    echo "✗ User not in audio group"
fi
# Check PulseAudio
if pactl info &>/dev/null; then
    echo "✓ PulseAudio is working"
    pactl info | grep "Server Name"
else
    echo "✗ PulseAudio not connected"
    echo "Trying to connect..."
    export PULSE_SERVER=/run/user/$(id -u)/pulse/native
    if pactl info &>/dev/null; then
        echo "✓ Connected to PulseAudio"
    else
        echo "✗ Still can't connect. Check if PulseAudio is running on host"
    fi
fi
# Check ALSA
if aplay -l &>/dev/null; then
    echo "✓ ALSA devices found:"
    aplay -l | grep "card"
else
    echo "✗ No ALSA devices found"
fi
echo ""
echo "To test: speaker-test -c 2 -t wav"
AUDIOFIX
chmod +x ~/fix-audio.sh

# Display container info
echo '=================================================='
echo 'SECURE CONTAINER READY'
echo 'Security Mode: {}'
echo 'systemd version: {}'
echo 'Filesystem: Read-only bind mounts'
echo '=================================================='
echo 'Available directories:'
[ -d ~/documents ] && echo '  ~/documents (Documents - read-only)'
[ -d ~/downloads ] && echo '  ~/downloads (Downloads - read-only)'
[ -d ~/work ] && echo '  ~/work (Workspace - writable)'
echo '=================================================='
echo 'Audio status:'
if [ "{}" = "High" ]; then
    echo '  ✗ Audio disabled in high security mode'
    echo '    Run with SECURITY_MODE=medium for audio support'
else
    if [ -S "/run/user/$(id -u)/pulse/native" ]; then
        echo '  ✓ PulseAudio socket connected'
    else
        echo '  ✗ PulseAudio socket not found'
    fi
    if [ -d "/dev/snd" ]; then
        echo '  ✓ ALSA devices available'
    else
        echo '  ✗ ALSA devices not found'
    fi
fi
echo '=================================================='
if command -v chromium &>/dev/null; then
    echo 'To test audio: chromium https://www.youtube.com'
    echo ''
    echo 'If audio is not working, try inside the container:'
    echo '  1. ./fix-audio.sh                # Run audio diagnostic'
    echo '  2. pactl info                    # Check PulseAudio connection'
    echo '  3. aplay -l                      # List ALSA devices'
    echo '  4. speaker-test -c 2             # Test speakers'
    echo '  5. chromium --enable-logging=stderr --v=1  # Debug Chromium audio'
fi
echo '=================================================='
exec bash --login
"#, xauth_name, xauth_name, xauth_name, display, 
    security_mode_str, self.config.systemd_version, security_mode_str)
    }
    
    fn run_command(&self, cmd: &mut Command, error_msg: &str) -> Result<(), String> {
        let output = cmd.output()
            .map_err(|e| format!("{}: {}", error_msg, e))?;
        
        if !output.status.success() {
            return Err(format!("{}: {:?}", error_msg, output.status.code()));
        }
        
        Ok(())
    }
    
    fn run_command_with_log(&self, cmd: &mut Command, error_msg: &str) -> Result<(), String> {
        let output = cmd.output()
            .map_err(|e| format!("{}: {}", error_msg, e))?;
        
        if !output.status.success() {
            self.log(&format!("Command failed: {:?}", cmd));
            self.log(&format!("stdout: {}", String::from_utf8_lossy(&output.stdout)));
            self.log(&format!("stderr: {}", String::from_utf8_lossy(&output.stderr)));
            return Err(format!("{}: {:?}", error_msg, output.status.code()));
        }
        
        Ok(())
    }
    
    fn run_command_in_dir(&self, cmd: &mut Command, dir: &str, error_msg: &str) -> Result<(), String> {
        cmd.current_dir(dir);
        self.run_command(cmd, error_msg)
    }
    
    fn run_systemd_nspawn(&self, args: &[&str], error_msg: &str) -> Result<(), String> {
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
    
    fn write_file_as_root(&self, path: &Path, content: &str) -> Result<(), String> {
        let mut cmd = Command::new("sudo");
        cmd.arg("tee");
        cmd.arg(path);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::null());
        
        let mut child = cmd.spawn()
            .map_err(|e| format!("Failed to spawn sudo tee: {}", e))?;
        
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(content.as_bytes())
                .map_err(|e| format!("Failed to write content: {}", e))?;
        }
        
        let status = child.wait()
            .map_err(|e| format!("Failed to wait for sudo tee: {}", e))?;
        
        if !status.success() {
            return Err("Failed to write file as root".to_string());
        }
        
        Ok(())
    }
    
    fn run(&mut self) -> Result<(), String> {
        println!("{}=== Secure Caged Agent Container Manager ==={}", BLUE, NC);
        println!("{}Security-hardened container with enhanced isolation{}", GREEN, NC);
        println!("{}Security Mode: {:?}{}", YELLOW, self.config.security_mode, NC);
        println!("{}Usage: SECURITY_MODE=medium cargo run{}", YELLOW, NC);
        println!("{}Note: Audio requires 'medium' or 'low' security mode{}", YELLOW, NC);
        if self.config.debug_mode {
            println!("{}Debug Mode: ENABLED{}", YELLOW, NC);
        }
        println!();
        
        // Create log directory
        fs::create_dir_all(&self.config.log_dir)
            .map_err(|e| format!("Failed to create log directory: {}", e))?;
        
        println!("Log file: {}", self.config.log_file.display());
        
        // Initialize log
        self.log(&format!("Secure container started at {:?}", SystemTime::now()));
        self.log(&format!("User: {} ({}:{})", 
            env::var("USER").unwrap_or_default(),
            unsafe { libc::getuid() },
            unsafe { libc::getgid() }
        ));
        
        // Check prerequisites
        if let Err(e) = self.check_prerequisites() {
            self.error_exit(&e);
        }
        
        // Check if container exists
        let container_exists = self.config.container_path.join("etc/os-release").exists();
        
        if container_exists {
            println!("{}Container already exists. Entering...{}", YELLOW, NC);
            println!("{}Note: If audio wasn't working, you may need to recreate the container{}", YELLOW, NC);
            println!("{}      to install audio packages. Remove it with:{}", YELLOW, NC);
            println!("{}      sudo rm -rf ~/.config/cagent/container{}", YELLOW, NC);
            
            // Verify container integrity
            if !self.verify_container() {
                println!("{}Container appears to be corrupted{}", RED, NC);
                print!("Would you like to recreate it? (y/N) ");
                io::stdout().flush().unwrap();
                
                let mut response = String::new();
                io::stdin().read_line(&mut response).unwrap();
                
                if response.trim().to_lowercase() == "y" {
                    println!("Removing old container...");
                    self.run_command(
                        Command::new("sudo")
                            .args(&["rm", "-rf", self.config.container_path.to_str().unwrap()]),
                        "Failed to remove container"
                    )?;
                    
                    self.install_dependencies()?;
                    self.setup_container()?;
                } else {
                    return Err("Container is corrupted. Please remove it manually or choose to recreate".to_string());
                }
            }
        } else {
            self.install_dependencies()?;
            self.setup_container()?;
        }
        
        self.enter_container()
    }
    
    fn verify_container(&self) -> bool {
        Command::new("sudo")
            .args(&[
                "systemd-nspawn", "-q", "-D",
                self.config.container_path.to_str().unwrap(),
                "--pipe", "/bin/true"
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn main() {
    // Set restrictive umask
    unsafe {
        libc::umask(0o077);
    }
    
    let mut manager = match CageManager::new() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}ERROR: {}{}", RED, e, NC);
            exit(1);
        }
    };
    
    if let Err(e) = manager.run() {
        manager.error_exit(&e);
    }
}
