// Color constants
pub const RED: &str = "\x1b[0;31m";
pub const GREEN: &str = "\x1b[0;32m";
pub const YELLOW: &str = "\x1b[0;33m";
pub const BLUE: &str = "\x1b[0;34m";
pub const CYAN: &str = "\x1b[0;36m";
pub const NC: &str = "\x1b[0m";

// Container configuration
pub const ARCH_MIRROR: &str = "https://mirror.rackspace.com/archlinux";
pub const ARCH_BOOTSTRAP_FILE_NAME: &str = "archlinux-bootstrap-x86_64.tar.zst";
pub const CONTAINER_USER: &str = "agent";

// Security constants
pub const RESTRICTIVE_UMASK: u32 = 0o077;
pub const SYSTEMD_NEW_FEATURES_VERSION: u32 = 254;

// Resource limits
pub const HIGH_SECURITY_NPROC_LIMIT: u32 = 512;
pub const HIGH_SECURITY_NOFILE_LIMIT: u32 = 1024;
pub const MEDIUM_SECURITY_NPROC_LIMIT: u32 = 2048;
pub const MEDIUM_SECURITY_NOFILE_LIMIT: u32 = 2048;
pub const LOW_SECURITY_NPROC_LIMIT: u32 = 4096;
pub const LOW_SECURITY_NOFILE_LIMIT: u32 = 4096;

// Memory limits (in MB)
pub const HIGH_SECURITY_MEMLOCK_MB: u32 = 64;
pub const MEDIUM_SECURITY_MEMLOCK_MB: u32 = 128;
pub const LOW_SECURITY_MEMLOCK_MB: u32 = 256;

// Required packages
pub const REQUIRED_HOST_PACKAGES: &[&str] = &["systemd-container", "curl", "xz-utils"];
pub const REQUIRED_HOST_COMMANDS: &[&str] = &["systemd-nspawn", "curl", "xauth"];

// Essential container packages
pub const ESSENTIAL_CONTAINER_PACKAGES: &[&str] = &[
    "base", "base-devel", "sudo", "git", "nano", "curl", "xorg-xauth", "mesa", "gtk3", 
    "nss", "ttf-liberation", "noto-fonts", "pulseaudio", "alsa-utils", "libpulse"
];

// X11 and audio paths
pub const X11_SOCKET_PATH: &str = "/tmp/.X11-unix";
pub const ALSA_DEVICE_PATH: &str = "/dev/snd";
pub const DRI_DEVICE_PATH: &str = "/dev/dri";
