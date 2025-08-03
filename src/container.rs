use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{Config, SecurityMode};
use crate::constants::*;
use crate::utils::Utils;

pub struct CageManager {
    config: Config,
    utils: Utils,
}

impl CageManager {
    pub fn new() -> Result<Self, String> {
        let config = Config::new()?;
        let utils = Utils::new(config.clone());

        Ok(CageManager { config, utils })
    }

    pub fn check_prerequisites(&self) -> Result<(), String> {
        println!("🔍 Checking system prerequisites...");

        // Check if running as non-root
        print!("  Checking user permissions... ");
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            println!("❌");
            return Err("Please run this script as a normal user, not as root".to_string());
        }
        println!("✓");

        // Check for suspicious environment
        print!("  Checking environment security... ");
        if env::var("LD_PRELOAD").is_ok() || env::var("LD_LIBRARY_PATH").is_ok() {
            println!("❌");
            return Err(
                "Suspicious environment detected (LD_PRELOAD/LD_LIBRARY_PATH set)".to_string(),
            );
        }
        println!("✓");

        // Check Ubuntu/Debian
        print!("  Checking operating system... ");
        if !Path::new("/etc/debian_version").exists() {
            println!("❌");
            return Err("This script is designed for Ubuntu/Debian systems".to_string());
        }
        println!("✓");

        // Check systemd
        print!("  Checking systemd availability... ");
        let mut cmd = Command::new("systemctl");
        cmd.arg("--version");
        let args: Vec<String> = env::args().collect();
        if args.iter().any(|arg| arg == "-v" || arg == "--verbose") {
            println!("[EXEC] systemctl --version");
        }
        if cmd.output().is_err() {
            println!("❌");
            return Err("systemd is required but not found".to_string());
        }
        println!("✓");

        // Check X11
        print!("  Checking X11 session... ");
        let display = env::var("DISPLAY").map_err(|_| {
            println!("❌");
            "DISPLAY variable not set. Are you running in an X11 session?"
        })?;

        // Validate DISPLAY format
        if !display.starts_with(':') || !display[1..].chars().all(|c| c.is_numeric() || c == '.') {
            println!("❌");
            return Err(format!("Invalid DISPLAY format: {display}"));
        }
        println!("✓");

        // Validate host directory
        print!("  Validating host directory... ");
        self.utils.validate_host_dir(&self.config.host_dir)?;
        println!("✓");

        self.utils.log(&format!(
            "Detected systemd version: {}",
            self.config.systemd_version
        ));

        // Check system resource limits for systemd 254+
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
            let nproc_limit = self.utils.get_ulimit_nproc();
            if nproc_limit != "unlimited" && nproc_limit.parse::<u32>().unwrap_or(0) < 10000 {
                println!(
                    "{YELLOW}Warning: Your system process limit is low ({nproc_limit}){NC}"
                );
                println!(
                    "{YELLOW}This might cause 'Resource temporarily unavailable' errors{NC}"
                );
                println!(
                    "{YELLOW}Consider increasing it with: ulimit -u 30000{NC}"
                );
            }
        }

        println!("✓ All prerequisites validated successfully");
        self.utils.log("Prerequisites check passed");
        Ok(())
    }

    pub fn install_dependencies(&self) -> Result<(), String> {
        println!("Installing dependencies...");

        // Check if any packages need installation
        let packages_to_install: Vec<&str> = REQUIRED_HOST_PACKAGES
            .iter()
            .filter(|&&pkg| !self.utils.is_package_installed(pkg))
            .copied()
            .collect();

        // Only update package list if we need to install packages
        if !packages_to_install.is_empty() {
            println!("🔄 Updating package list...");
            self.utils.run_command_with_log(
                Command::new("sudo").args(&["apt", "update"]),
                "Failed to update package list",
            )?;
            println!("✓ Package list updated");

            // Install required packages
            for (i, pkg) in packages_to_install.iter().enumerate() {
                println!(
                    "📦 Installing {} ({}/{})...",
                    pkg,
                    i + 1,
                    packages_to_install.len()
                );
                self.utils.run_command_with_log(
                    Command::new("sudo").args(&["apt", "install", "-y", pkg]),
                    &format!("Failed to install {pkg}"),
                )?;
                println!("✓ {pkg} installed successfully");
            }
        }

        // Verify commands are available
        println!("🔍 Verifying required commands...");
        for (i, cmd) in REQUIRED_HOST_COMMANDS.iter().enumerate() {
            print!(
                "  Checking {} ({}/{})... ",
                cmd,
                i + 1,
                REQUIRED_HOST_COMMANDS.len()
            );
            let mut check_cmd = Command::new("which");
            check_cmd.arg(cmd);
            self.utils.log_command(&check_cmd);
            if check_cmd.output().is_err() {
                println!("❌");
                return Err(format!(
                    "Required command '{cmd}' not found after installation"
                ));
            }
            println!("✓");
        }
        println!("✓ All required commands verified");

        self.utils.log("Dependencies installed successfully");
        Ok(())
    }

    pub fn download_checksums(&self, base_url: &str) -> Result<String, String> {
        let checksum_url = format!("{base_url}/sha256sums.txt");

        if self.config.debug_mode {
            println!("Fetching checksums from: {checksum_url}");
        } else {
            println!("Fetching checksums...");
        }

        let mut cmd = Command::new("curl");
        cmd.args(&[
            "-sSL",
            "--connect-timeout",
            "10",
            "--retry",
            "2",
            &checksum_url,
        ]);
        self.utils.log_command(&cmd);
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute curl for checksums: {e}"))?;

        if !output.status.success() {
            return Err("Failed to download checksums".to_string());
        }

        println!("✓ Checksums fetched successfully");
        String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in checksums: {e}"))
    }

    pub fn get_expected_checksum(&self, checksums: &str, filename: &str) -> Option<String> {
        checksums
            .lines()
            .find(|line| line.contains(filename))
            .and_then(|line| line.split_whitespace().next())
            .map(|s| s.to_string())
    }

    pub fn download_with_cache(&self, url: &str, filename: &str) -> Result<PathBuf, String> {
        let cached_file = self.config.cache_dir.join(filename);
        let cached_checksum_file = self.config.cache_dir.join(format!("{filename}.sha256"));

        // Always download latest checksums to detect updates
        let base_url = url.rsplitn(2, '/').nth(1).unwrap_or("");
        let checksums = self.download_checksums(base_url)?;

        // Get expected checksum for our file
        let expected_checksum = self
            .get_expected_checksum(&checksums, filename)
            .ok_or_else(|| format!("Could not find checksum for {filename}"))?;

        // Check if we have a cached file
        if cached_file.exists() {
            println!("Found cached file: {}", cached_file.display());

            // Check if we have a stored checksum
            if let Ok(stored_checksum) = fs::read_to_string(&cached_checksum_file) {
                let stored_checksum = stored_checksum.trim();

                // If stored checksum matches expected, validate the file
                if stored_checksum == expected_checksum {
                    // Verify the actual file still matches
                    let actual_checksum = self.utils.calculate_file_checksum(&cached_file)?;

                    if actual_checksum == expected_checksum {
                        println!("Cache hit: File checksum matches, using cached version");
                        return Ok(cached_file);
                    } else {
                        println!("Cache corrupted: File checksum mismatch, re-downloading");
                    }
                } else {
                    println!("Cache outdated: New version available, re-downloading");
                }
            } else {
                println!("No stored checksum found, re-downloading");
            }
        }

        // Download the file
        println!("Downloading {filename} from {url}...");
        let temp_path = self.config.cache_dir.join(format!("{filename}.tmp"));

        let mut cmd = Command::new("curl");
        cmd.args(&[
            "--connect-timeout",
            "30",
            "--retry",
            "3",
            "--location",
            "--progress-bar",
            "--output",
            temp_path.to_str().unwrap(),
            url,
        ]);

        self.utils.log_command(&cmd);

        // Execute with real-time progress display
        let status = cmd
            .status()
            .map_err(|e| format!("Download failed: {e}"))?;

        if !status.success() {
            return Err("Download failed".to_string());
        }

        println!("✓ Download completed: {filename}");

        // Verify downloaded file
        println!("Verifying file integrity...");
        let actual_checksum = self.utils.calculate_file_checksum(&temp_path)?;

        if actual_checksum != expected_checksum {
            fs::remove_file(&temp_path).ok();
            return Err(format!(
                "Checksum verification failed! Expected: {expected_checksum}, Got: {actual_checksum}"
            ));
        }

        println!("✓ File integrity verified");

        // Move to cache and save checksum
        fs::rename(&temp_path, &cached_file)
            .map_err(|e| format!("Failed to move file to cache: {e}"))?;

        fs::write(&cached_checksum_file, &expected_checksum)
            .map_err(|e| format!("Failed to save checksum: {e}"))?;

        Ok(cached_file)
    }

    pub fn setup_container(&self) -> Result<(), String> {
        println!(
            "{GREEN}Setting up Arch Linux container with security hardening...{NC}"
        );
        self.utils.log("Starting secure container setup");

        // Create container directory
        println!("🔧 Creating container directory...");
        self.utils.run_command(
            Command::new("sudo").args(&[
                "mkdir",
                "-p",
                self.config.container_path.to_str().unwrap(),
            ]),
            "Failed to create container directory",
        )?;
        println!("✓ Container directory created");

        // Set restrictive permissions
        if let Some(parent_dir) = self.config.container_path.parent() {
            println!("🔒 Setting secure permissions...");
            self.utils.run_command(
                Command::new("sudo").args(&["chmod", "700", parent_dir.to_str().unwrap()]),
                "Failed to set permissions",
            )?;
            println!("✓ Secure permissions set");
        }

        // Download and extract Arch Linux using cache
        let download_url = format!("{ARCH_MIRROR}/iso/latest/{ARCH_BOOTSTRAP_FILE_NAME}");
        let arch_file = self.download_with_cache(&download_url, ARCH_BOOTSTRAP_FILE_NAME)?;

        println!("📦 Extracting Arch Linux securely...");

        // Copy cached file to /tmp for extraction
        println!("🔄 Preparing archive for extraction...");
        let temp_arch_file = PathBuf::from("/tmp").join(ARCH_BOOTSTRAP_FILE_NAME);
        self.utils.run_command(
            Command::new("cp").args(&[
                arch_file.to_str().unwrap(),
                temp_arch_file.to_str().unwrap(),
            ]),
            "Failed to copy archive to temp directory",
        )?;
        println!("✓ Archive prepared");

        // Extract tarball
        println!("📂 Extracting bootstrap filesystem...");
        self.utils.run_command_in_dir(
            Command::new("sudo").args(&[
                "tar",
                "--use-compress-program=zstd",
                "-xf",
                temp_arch_file.to_str().unwrap(),
            ]),
            "/tmp",
            "Failed to extract Arch Linux bootstrap",
        )?;
        println!("✓ Bootstrap filesystem extracted");

        // Move files to container path
        println!("🚚 Moving files to container directory...");
        self.utils.run_command(
            Command::new("bash").args(&[
                "-c",
                &format!(
                    "sudo mv /tmp/root.x86_64/* {} 2>/dev/null",
                    self.config.container_path.to_str().unwrap()
                ),
            ]),
            "Failed to move files to container directory",
        )?;
        println!("✓ Files moved to container");

        // Cleanup
        println!("🧹 Cleaning up temporary files...");
        let mut cleanup_cmd = Command::new("sudo");
        cleanup_cmd.args(&["rmdir", "/tmp/root.x86_64"]);
        self.utils.log_command(&cleanup_cmd);
        cleanup_cmd.output().ok();
        fs::remove_file(&temp_arch_file).ok();
        println!("✓ Temporary files cleaned");

        // Configure pacman
        println!("⚙️  Configuring package manager...");
        let mirrorlist = self.config.container_path.join("etc/pacman.d/mirrorlist");
        let mirror_content = format!("Server = {ARCH_MIRROR}/$repo/os/$arch");

        self.utils.run_command(
            Command::new("bash").args(&[
                "-c",
                &format!(
                    "echo '{}' | sudo tee {} > /dev/null",
                    mirror_content,
                    mirrorlist.display()
                ),
            ]),
            "Failed to configure pacman mirrorlist",
        )?;
        println!("✓ Package manager configured");

        // Initialize pacman keyring
        println!("🔑 Initializing pacman keyring...");
        println!("  Setting up keyring...");
        self.utils.run_systemd_nspawn(
            &["pacman-key", "--init"],
            "Failed to initialize pacman keyring",
        )?;
        println!("  Populating Arch Linux keys...");
        self.utils.run_systemd_nspawn(
            &["pacman-key", "--populate", "archlinux"],
            "Failed to populate pacman keyring",
        )?;
        println!("✓ Pacman keyring initialized");

        // Update base system
        println!("📦 Updating base system...");
        self.utils.run_systemd_nspawn(
            &["pacman", "-Syu", "--noconfirm"],
            "Failed to update base system",
        )?;
        println!("✓ Base system updated");

        // Install essential packages
        println!("📦 Installing essential packages...");
        
        println!(
            "  Installing {} packages: {}",
            ESSENTIAL_CONTAINER_PACKAGES.len(),
            ESSENTIAL_CONTAINER_PACKAGES.join(", ")
        );
        let mut pacman_args = vec!["pacman", "-S", "--noconfirm"];
        pacman_args.extend(ESSENTIAL_CONTAINER_PACKAGES.iter().copied());

        self.utils
            .run_systemd_nspawn(&pacman_args, "Failed to install essential packages")?;
        println!("✓ Essential packages installed");

        // Create agent user
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        println!("👤 Creating user '{CONTAINER_USER}' ({uid}:{gid})...");

        // Create group
        println!("  Setting up group...");
        self.utils
            .run_systemd_nspawn(
                &["groupadd", "-g", &gid.to_string(), CONTAINER_USER],
                "Group may already exist",
            )
            .ok();

        // Create user
        println!("  Creating user account...");
        self.utils.run_systemd_nspawn(
            &[
                "useradd",
                "-m",
                "-u",
                &uid.to_string(),
                "-g",
                &gid.to_string(),
                "-s",
                "/bin/bash",
                CONTAINER_USER,
            ],
            "Failed to create user",
        )?;

        // Add user to audio group for sound support
        println!("  Setting up audio permissions...");
        self.utils
            .run_systemd_nspawn(
                &["groupadd", "-r", "audio"],
                "Audio group may already exist",
            )
            .ok();

        self.utils.run_systemd_nspawn(
            &["usermod", "-a", "-G", "audio", CONTAINER_USER],
            "Failed to add user to audio group",
        )?;
        println!("✓ User '{CONTAINER_USER}' created successfully");

        // Install yay AUR helper (only for medium/low security modes)
        if self.config.security_mode != SecurityMode::High {
            println!("📦 Installing yay AUR helper...");

            // Set up build directory with proper ownership
            println!("  Setting up build environment...");
            self.utils.run_systemd_nspawn(
                &["mkdir", "-p", &format!("/home/{CONTAINER_USER}/build")],
                "Failed to create build directory",
            )?;

            self.utils.run_systemd_nspawn(
                &[
                    "chown",
                    &format!("{CONTAINER_USER}:{CONTAINER_USER}"),
                    &format!("/home/{CONTAINER_USER}/build"),
                ],
                "Failed to set build directory ownership",
            )?;

            // Configure makepkg for the container user
            println!("  Configuring makepkg for container user...");
            let makepkg_config = format!(
                "# Makepkg configuration for container\n\
                 BUILDDIR=/home/{CONTAINER_USER}/build\n\
                 PKGDEST=/home/{CONTAINER_USER}/build/packages\n\
                 SRCPKGDEST=/home/{CONTAINER_USER}/build/srcpackages\n\
                 LOGDEST=/home/{CONTAINER_USER}/build/logs\n\
                 PACKAGER=\"Container User <container@localhost>\"\n"
            );

            let makepkg_config_path = self
                .config
                .container_path
                .join("home")
                .join(CONTAINER_USER)
                .join(".makepkg.conf");

            self.utils
                .write_file_as_root(&makepkg_config_path, &makepkg_config)?;

            // Set ownership of makepkg config
            self.utils.run_systemd_nspawn(
                &[
                    "chown",
                    &format!("{CONTAINER_USER}:{CONTAINER_USER}"),
                    &format!("/home/{CONTAINER_USER}/.makepkg.conf"),
                ],
                "Failed to set makepkg config ownership",
            )?;

            // Install Go dependency first (required for yay)
            println!("  Installing Go compiler for yay build...");
            self.utils.run_systemd_nspawn_with_network(
                &["pacman", "-S", "--noconfirm", "go"],
                "Failed to install Go compiler",
            )?;

            // Clone yay repository as the user
            println!("  Cloning yay repository...");
            self.utils.run_systemd_nspawn_with_network(
                &[
                    "sudo",
                    "-u",
                    CONTAINER_USER,
                    "bash",
                    "-c",
                    &format!(
                        "cd /home/{CONTAINER_USER}/build && git clone https://aur.archlinux.org/yay.git"
                    ),
                ],
                "Failed to clone yay repository",
            )?;

            // Build yay package (without installing)
            println!("  Building yay AUR helper...");
            self.utils.run_systemd_nspawn_with_network(
                &[
                    "sudo",
                    "-u",
                    CONTAINER_USER,
                    "bash",
                    "-c",
                    &format!(
                        "cd /home/{CONTAINER_USER}/build/yay && makepkg -s --noconfirm"
                    ),
                ],
                "Failed to build yay",
            )?;

            // Find the actual package files generated by makepkg
            println!("  Finding generated package files...");
            let package_files = self.utils.run_systemd_nspawn_with_output(
                &["bash", "-c", &format!(
                    "find /home/{CONTAINER_USER}/build/packages -name 'yay-*.pkg.tar.*' -type f 2>/dev/null || find /home/{CONTAINER_USER}/build/yay -name 'yay-*.pkg.tar.*' -type f"
                )],
                "Failed to find yay package files",
            )?;

            if package_files.trim().is_empty() {
                return Err("No yay package files found after makepkg build".to_string());
            }

            // Install each found package file
            println!("  Installing yay package(s)...");
            for package_file in package_files.lines() {
                let package_file = package_file.trim();
                if !package_file.is_empty() {
                    println!("    Installing: {package_file}");
                    self.utils.run_systemd_nspawn_with_network(
                        &[
                            "bash",
                            "-c",
                            &format!("sudo pacman -U --noconfirm '{package_file}'"),
                        ],
                        &format!("Failed to install yay package: {package_file}"),
                    )?;
                }
            }

            // Verify yay installation
            println!("  Verifying yay installation...");
            match self.utils.run_systemd_nspawn(
                &["sudo", "-u", CONTAINER_USER, "yay", "--version"],
                "yay verification failed",
            ) {
                Ok(_) => println!("✓ yay installed and working"),
                Err(_) => {
                    println!("❌ yay verification failed, but continuing...");
                }
            }

            // Clean up build directory
            println!("  Cleaning up build files...");
            self.utils.run_systemd_nspawn(
                &["rm", "-rf", &format!("/home/{CONTAINER_USER}/build")],
                "Failed to clean up build directory",
            )?;

            println!("✓ yay AUR helper installed successfully");
        } else {
            println!("📦 Skipping AUR helper installation (high security mode)");
        }

        // Setup sudo configuration
        println!("🔐 Configuring sudo permissions...");
        let mut sudoers_content = format!(
            "# Restricted sudo for container user - package management only\n\
             Defaults env_reset\n\
             Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\
             # Allow package installation\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -S *\n\
             # Allow system updates\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -Syu *\n\
             # Allow package removal\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -R *\n\
             # Allow file database updates\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -Fy *\n\
             # Allow file searches\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -F *\n\
             # Allow package queries\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -Q *\n\
             # Allow package info queries\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -Si *\n\
             # Allow package file listing\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -Ql *\n\
             # Allow installing local packages (needed for AUR)\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -U *\n\
             # Allow dependency installation (needed for makepkg)\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -S --asdeps *\n\
             # Allow dependency installation with confirmation (needed for makepkg)\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -S --asdeps --noconfirm *\n\
             # Allow regular installation with no confirmation\n\
             {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/pacman -S --noconfirm *\n"
        );

        // Add AUR helper permissions for medium/low security modes
        if self.config.security_mode != SecurityMode::High {
            sudoers_content.push_str(&format!(
                "# AUR helper permissions (medium/low security modes only)\n\
                 # Allow yay to install packages\n\
                 {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/yay -S *\n\
                 # Allow yay to update AUR packages\n\
                 {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/yay -Syu *\n\
                 # Allow yay to remove packages\n\
                 {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/yay -R *\n\
                 # Allow yay queries\n\
                 {CONTAINER_USER} ALL=(ALL) NOPASSWD: /usr/bin/yay -Q *\n"
            ));
        }

        let sudoers_file = self
            .config
            .container_path
            .join("etc/sudoers.d/99-container-user");
        if let Some(parent) = sudoers_file.parent() {
            self.utils.run_command(
                Command::new("sudo").args(&["mkdir", "-p", parent.to_str().unwrap()]),
                "Failed to create sudoers.d directory",
            )?;
        }

        self.utils
            .write_file_as_root(&sudoers_file, &sudoers_content)?;

        self.utils.run_command(
            Command::new("sudo").args(&["chmod", "440", sudoers_file.to_str().unwrap()]),
            "Failed to set sudoers permissions",
        )?;
        println!("✓ Sudo configuration complete");

        // Create user directories
        println!("📁 Setting up user directories...");
        let user_home = format!("/home/{CONTAINER_USER}");
        let directories = [
            "Documents",
            "Downloads",
            "Desktop",
            ".config",
            ".config/pulse",
            "work",
        ];

        for (i, dir) in directories.iter().enumerate() {
            println!(
                "  Creating {}/{} ({}/{})...",
                user_home,
                dir,
                i + 1,
                directories.len()
            );
            self.utils.run_systemd_nspawn(
                &["mkdir", "-p", &format!("{user_home}/{dir}")],
                "Failed to create user directory",
            )?;
        }

        // Fix ownership
        println!("  Setting file ownership...");
        self.utils.run_systemd_nspawn(
            &[
                "chown",
                "-R",
                &format!("{CONTAINER_USER}:{CONTAINER_USER}"),
                &user_home,
            ],
            "Failed to set ownership for user home",
        )?;

        // Set permissions
        println!("  Setting directory permissions...");
        self.utils.run_systemd_nspawn(
            &["chmod", "755", &user_home],
            "Failed to set permissions on user home",
        )?;
        println!("✓ User directories configured");

        // Create container integrity file
        println!("📝 Creating container integrity marker...");
        let integrity_content = format!(
            "{}:container",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let integrity_file = self.config.container_path.join(".container-integrity");
        self.utils
            .write_file_as_root(&integrity_file, &integrity_content)?;
        println!("✓ Container integrity marker created");

        println!("{GREEN}🎉 Secure container setup complete!{NC}");
        self.utils.log("Container setup completed successfully");
        Ok(())
    }

    pub fn verify_container(&self) -> bool {
        println!("🔍 Verifying container integrity...");
        let mut cmd = Command::new("sudo");
        cmd.args(&[
            "systemd-nspawn",
            "-q",
            "-D",
            self.config.container_path.to_str().unwrap(),
            "--pipe",
            "/bin/true",
        ]);
        self.utils.log_command(&cmd);
        let result = cmd.output().map(|o| o.status.success()).unwrap_or(false);
        if result {
            println!("✓ Container verification completed");
        } else {
            println!("❌ Container verification failed");
        }
        result
    }

    pub fn run(&mut self) -> Result<(), String> {
        println!("{BLUE}=== Secure Caged Agent Container Manager ==={NC}");
        println!("{GREEN}Security-hardened container with enhanced isolation{NC}");
        println!(
            "{}Security Mode: {:?}{}",
            YELLOW, self.config.security_mode, NC
        );
        println!("{YELLOW}Usage: SECURITY_MODE=medium cargo run{NC}");
        println!("{YELLOW}Note: Audio requires 'medium' or 'low' security mode{NC}");
        if self.config.debug_mode {
            println!("{YELLOW}Debug Mode: ENABLED{NC}");
        }
        println!();

        // Create log directory
        println!("📁 Creating log directory...");
        fs::create_dir_all(&self.config.log_dir)
            .map_err(|e| format!("Failed to create log directory: {e}"))?;
        println!("✓ Log directory created");

        // Create cache directory
        println!("📁 Creating cache directory...");
        fs::create_dir_all(&self.config.cache_dir)
            .map_err(|e| format!("Failed to create cache directory: {e}"))?;
        println!("✓ Cache directory created");

        let log_file = self.config.log_file.display();
        println!("Log file: {log_file}");

        // Initialize log
        self.utils.log(&format!(
            "Secure container started at {:?}",
            SystemTime::now()
        ));
        self.utils.log(&format!(
            "User: {} ({}:{})",
            env::var("USER").unwrap_or_default(),
            unsafe { libc::getuid() },
            unsafe { libc::getgid() }
        ));

        // Check prerequisites
        if let Err(e) = self.check_prerequisites() {
            self.utils.error_exit(&e);
        }

        // Check if container exists
        let container_exists = self.config.container_path.join("etc/os-release").exists();

        if container_exists {
            println!("{YELLOW}Container already exists. Entering...{NC}");
            println!("{YELLOW}Note: If audio wasn't working, you may need to recreate the container{NC}");
            println!("{YELLOW}      to install audio packages. Remove it with:{NC}");
            println!("{YELLOW}      sudo rm -rf ~/.config/cagent/container{NC}");

            // Verify container integrity
            if !self.verify_container() {
                println!("{RED}Container appears to be corrupted{NC}");
                print!("Would you like to recreate it? (y/N) ");
                io::stdout().flush().unwrap();

                let mut response = String::new();
                io::stdin().read_line(&mut response).unwrap();

                if response.trim().to_lowercase() == "y" {
                    println!("Removing old container...");
                    self.utils.run_command(
                        Command::new("sudo").args(&[
                            "rm",
                            "-rf",
                            self.config.container_path.to_str().unwrap(),
                        ]),
                        "Failed to remove container",
                    )?;

                    self.install_dependencies()?;
                    self.setup_container()?;
                } else {
                    return Err(
                        "Container is corrupted. Please remove it manually or choose to recreate"
                            .to_string(),
                    );
                }
            }
        } else {
            self.install_dependencies()?;
            self.setup_container()?;
        }

        self.enter_container()
    }

    pub fn enter_container(&self) -> Result<(), String> {
        println!("{GREEN}Entering hardened container as user '{CONTAINER_USER}'...{NC}");
        println!(
            "{}Security Mode: {:?}{}",
            YELLOW, self.config.security_mode, NC
        );
        println!(
            "{}systemd version: {}{}",
            YELLOW, self.config.systemd_version, NC
        );

        // Verify container exists
        if !self.config.container_path.join("etc/os-release").exists() {
            return Err(format!(
                "Container not found at {}",
                self.config.container_path.display()
            ));
        }

        // Setup X11 authentication
        let temp_xauth = format!(
            "/tmp/xauth_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        // Export display auth
        println!("🖥️  Setting up X11 forwarding...");
        let display = env::var("DISPLAY").unwrap_or(":0".to_string());
        println!("  Using display: {display}");

        // Create xauth file
        println!("  Generating X11 authentication...");
        self.utils.run_command(
            Command::new("bash").args(&[
                "-c",
                &format!("xauth nlist {display} | sed -e 's/^..../ffff/' | xauth -f {temp_xauth} nmerge -"),
            ]),
            "Failed to setup X11 auth",
        )?;

        // Set permissions
        println!("  Setting authentication permissions...");
        fs::set_permissions(&temp_xauth, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set xauth permissions: {e}"))?;

        // Create container xauth file
        println!("  Copying authentication to container...");
        let xauth_name = format!(
            ".Xauthority.{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let container_xauth = self.config.container_path.join("tmp").join(&xauth_name);

        self.utils.run_command(
            Command::new("sudo").args(&["cp", &temp_xauth, container_xauth.to_str().unwrap()]),
            "Failed to copy xauth to container",
        )?;

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        println!("  Setting container authentication permissions...");
        self.utils.run_command(
            Command::new("sudo").args(&[
                "chown",
                &format!("{uid}:{gid}"),
                container_xauth.to_str().unwrap(),
            ]),
            "Failed to set xauth ownership",
        )?;

        self.utils.run_command(
            Command::new("sudo").args(&["chmod", "600", container_xauth.to_str().unwrap()]),
            "Failed to set xauth permissions",
        )?;
        println!("✓ X11 forwarding configured");

        // Build systemd-nspawn command
        let mut cmd = Command::new("sudo");
        cmd.arg("systemd-nspawn");

        if !self.config.debug_mode {
            cmd.arg("--quiet");
        }

        cmd.arg("--directory")
            .arg(self.config.container_path.to_str().unwrap());

        // Add security options based on systemd version
        self.add_security_options(&mut cmd);

        // Add bind mounts
        self.add_bind_mounts(&mut cmd)?;

        // Set environment variables
        cmd.arg("--setenv").arg(format!("DISPLAY={display}"));
        cmd.arg("--setenv")
            .arg(format!("XAUTHORITY=/home/{CONTAINER_USER}/.Xauthority"));
        cmd.arg("--setenv")
            .arg(format!("SECURITY_MODE={:?}", self.config.security_mode));
        cmd.arg("--setenv")
            .arg(format!("HOME=/home/{CONTAINER_USER}"));
        cmd.arg("--setenv").arg(format!("USER={CONTAINER_USER}"));
        cmd.arg("--setenv").arg("SHELL=/bin/bash");
        cmd.arg("--setenv").arg("TERM=xterm-256color");

        // Audio environment variables
        let uid = unsafe { libc::getuid() };
        cmd.arg("--setenv")
            .arg(format!("PULSE_SERVER=/run/user/{uid}/pulse/native"));
        cmd.arg("--setenv")
            .arg(format!("PULSE_RUNTIME_PATH=/run/user/{uid}/pulse"));

        // Create container script
        let container_script = self.create_container_script(&display, &xauth_name);

        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
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
        println!("🚀 Starting secure container...");
        println!("  Security mode: {:?}", self.config.security_mode);
        let systemd_version = self.config.systemd_version;
        println!("  Systemd version: {systemd_version}");

        // Disable monitoring for interactive container
        self.utils.disable_monitoring();

        let status = cmd
            .status()
            .map_err(|e| format!("Failed to execute systemd-nspawn: {e}"))?;

        // Cleanup
        fs::remove_file(&temp_xauth).ok();

        if status.success() {
            println!("{GREEN}✓ Container exited successfully{NC}");
            println!("{YELLOW}Returned to host system{NC}");
        } else if !status.success() {
            if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
                println!("{YELLOW}Resource limit error detected. Possible solutions:{NC}");
                println!("{YELLOW}1. Increase your user process limit: ulimit -u 30000{NC}");
                println!("{YELLOW}2. Try medium security mode: SECURITY_MODE=medium{NC}");
                println!("{YELLOW}3. Check system resources: free -h && ps aux | wc -l{NC}");
                println!("{YELLOW}4. Restart systemd-logind: sudo systemctl restart systemd-logind{NC}");
            }
            return Err(format!(
                "Failed to enter container (exit code: {:?})",
                status.code()
            ));
        }

        Ok(())
    }

    fn add_security_options(&self, cmd: &mut Command) {
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
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
        if self.config.systemd_version < SYSTEMD_NEW_FEATURES_VERSION {
            cmd.arg("--keep-unit");
            cmd.arg("--register=no");
        }

        // Resource limits based on security mode
        let nproc_limit = self.config.security_mode.nproc_limit();
        let nofile_limit = self.config.security_mode.nofile_limit();
        let memlock_mb = self.config.security_mode.memlock_mb();
        
        cmd.arg(format!("--rlimit=NPROC={nproc_limit}"));
        cmd.arg(format!("--rlimit=NOFILE={nofile_limit}"));
        cmd.arg(format!("--rlimit=MEMLOCK={memlock_mb}M"));
        
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
            cmd.arg("--rlimit=MSGQUEUE=32M");
        } else {
            cmd.arg("--rlimit=MSGQUEUE=8M");
        }

        cmd.arg("--rlimit=NICE=0");
        cmd.arg("--rlimit=RTPRIO=0");

        // Apply security mode specific options
        match self.config.security_mode {
            SecurityMode::High => {
                // Maximum isolation - minimal capabilities
                cmd.arg("--capability=CAP_SETUID,CAP_SETGID");
                if !self.config.security_mode.allows_network() {
                    cmd.arg("--private-network");
                }
            }
            SecurityMode::Medium => {
                // Balanced security with network access
                cmd.arg("--capability=CAP_SETUID,CAP_SETGID,CAP_NET_RAW");
            }
            SecurityMode::Low => {
                // Development-friendly with debugging capabilities
                cmd.arg("--capability=CAP_SETUID,CAP_SETGID,CAP_NET_RAW,CAP_SYS_PTRACE");
                // Allow broader access for development
                if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
                    cmd.arg("--capability=CAP_SYS_ADMIN");
                }
            }
        }
    }

    fn add_bind_mounts(&self, cmd: &mut Command) -> Result<(), String> {
        // X11 socket
        cmd.arg(format!("--bind-ro={X11_SOCKET_PATH}"));

        // Audio support - Only for medium/low security modes
        if self.config.security_mode.allows_audio() {
            // PulseAudio socket
            let pulse_socket = format!("/run/user/{}/pulse", unsafe { libc::getuid() });
            if Path::new(&pulse_socket).exists() {
                cmd.arg(format!("--bind={pulse_socket}"));
                println!("{GREEN}Audio: PulseAudio socket bound{NC}");
            } else {
                println!("{YELLOW}Warning: PulseAudio socket not found at {pulse_socket}{NC}");
            }

            // PulseAudio cookie
            let pulse_cookie = format!(
                "{}/.config/pulse/cookie",
                env::var("HOME").unwrap_or_default()
            );
            if Path::new(&pulse_cookie).exists() {
                cmd.arg(format!("--bind-ro={pulse_cookie}:/home/{CONTAINER_USER}/.config/pulse/cookie"));
            }

            // ALSA devices
            if Path::new(ALSA_DEVICE_PATH).exists() {
                cmd.arg(format!("--bind={ALSA_DEVICE_PATH}"));
                println!("{GREEN}Audio: ALSA devices bound{NC}");
            }

            // DRI devices (for hardware acceleration and audio)
            if Path::new(DRI_DEVICE_PATH).exists() {
                cmd.arg(format!("--bind={DRI_DEVICE_PATH}"));
            }
        } else {
            println!("{YELLOW}High security mode: Audio devices not bound{NC}");
        }

        // Tmpfs mounts
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
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
            cmd.arg(format!(
                "--bind-ro={}:/home/{}/documents",
                docs_path.display(),
                CONTAINER_USER
            ));
        }

        let downloads_path = self.config.host_dir.join("Downloads");
        if downloads_path.exists() {
            cmd.arg(format!(
                "--bind-ro={}:/home/{}/downloads",
                downloads_path.display(),
                CONTAINER_USER
            ));
        }

        // Work directory
        if self.config.systemd_version >= SYSTEMD_NEW_FEATURES_VERSION {
            cmd.arg(format!("--tmpfs=/home/{CONTAINER_USER}/work:size=2G"));
        } else {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            cmd.arg(format!(
                "--tmpfs=/home/{CONTAINER_USER}/work:size=1G,mode=700,uid={uid},gid={gid}"
            ));
        }

        Ok(())
    }

    fn create_container_script(&self, display: &str, xauth_name: &str) -> String {
        let security_mode_str = match self.config.security_mode {
            SecurityMode::High => "High",
            SecurityMode::Medium => "Medium",
            SecurityMode::Low => "Low",
        };

        format!(
            r#"
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

# Change to home directory
cd ~ || cd /

# Set up custom bash prompt with exit reminder
export PS1='\[\e[32m\][\u@container]\[\e[0m\]:\[\e[34m\]\w\[\e[0m\]\$ '
echo 'export PS1='"'"'\[\e[32m\][\u@container]\[\e[0m\]:\[\e[34m\]\w\[\e[0m\]\$ '"'"'' >> ~/.bashrc

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

# Create container info script
cat > ~/container-help.sh << 'CONTAINERHELP'
#!/bin/bash
echo "=================================================="
echo "CONTAINER HELP & STATUS"
echo "=================================================="
echo "Exit Instructions:"
echo "  • Type 'exit' or press Ctrl+D to leave container"
echo "  • For emergency exit: Press Ctrl+C then type 'exit'"
echo "  • Container will shutdown and return to host system"
echo ""
echo "Available Commands:"
echo "  • ./fix-audio.sh     - Check and fix audio issues"
echo "  • ./container-help.sh - Show this help message"
echo "  • sudo pacman -S <pkg> - Install packages from official repos"
if [ "{}" != "High" ]; then
echo "  • yay -S <pkg>       - Install packages from AUR (requires network)"
echo "  • yay -Syu           - Update all packages including AUR"
echo "  • yay -Q             - List installed packages"
echo "  • yay google-chrome  - Example: Install Google Chrome from AUR"
echo "  • yay --version      - Check if yay is working properly"
fi
echo "  • ls ~/downloads     - View host Downloads (read-only)"
echo "  • ls ~/documents     - View host Documents (read-only)"
echo "  • cd ~/work          - Access temporary workspace"
echo ""
echo "Troubleshooting:"
echo "  • If audio doesn't work: run ./fix-audio.sh"
echo "  • If container feels slow: check host system resources"
echo "  • If GUI apps won't start: check DISPLAY variable"
if [ "{}" != "High" ]; then
echo "  • If yay fails: check 'yay --version' and network connectivity"
echo "  • If makepkg fails: check sudo permissions with 'sudo -l'"
echo "  • If Go build fails: try 'go version' to verify Go installation"
fi
echo ""
echo "Security Mode: $(echo $SECURITY_MODE)"
echo "=================================================="
CONTAINERHELP
chmod +x ~/container-help.sh

# Display container info
echo '=================================================='
echo 'SECURE CONTAINER READY'
echo 'Security Mode: {}'
echo 'systemd version: {}'
echo 'Filesystem: Read-only bind mounts'
echo '=================================================='
echo 'HOW TO EXIT:'
echo '  • Type "exit" or press Ctrl+D to leave container'
echo '  • For emergency exit: Press Ctrl+C then type "exit"'
echo '  • Container will shutdown and return to host system'
echo ''
echo 'QUICK HELP:'
echo '  • Type "./container-help.sh" for detailed help'
echo '  • Type "./fix-audio.sh" to check audio setup'
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
if [ "{}" != "High" ]; then
    echo 'AUR (Arch User Repository) Support:'
    echo '  ✓ yay AUR helper installed'
    echo '  ✓ Build tools (base-devel) available'
    echo '  • yay -S google-chrome    # Install Google Chrome'
    echo '  • yay -S discord          # Install Discord'
    echo '  • yay -S spotify          # Install Spotify'
    echo '  • yay -S visual-studio-code-bin  # Install VS Code'
    echo ''
fi
echo '=================================================='
exec bash --login
"#,
            xauth_name,
            xauth_name,
            xauth_name,
            display,
            security_mode_str,
            self.config.systemd_version,
            security_mode_str,
            security_mode_str,
            security_mode_str,
            security_mode_str
        )
    }
}
