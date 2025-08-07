# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About the Project

Caged Agent (cagent) is a security-hardened container manager that creates isolated systemd-nspawn containers with X11 forwarding and audio support. It provides a secure environment for running GUI applications with configurable security modes.

## Development Commands

### Building and Running
```bash
# Build the project
cargo build

# Run with default settings (high security mode)
cargo run

# Run with medium security mode (enables audio)
SECURITY_MODE=medium cargo run

# Run with verbose command logging
cargo run -- -v

# Run with debug mode enabled
DEBUG_MODE=1 cargo run

# Build optimized release
cargo build --release
```

### Testing
```bash
# Run tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture

# Run specific test module
cargo test config::tests

# Note: This project currently has minimal test coverage and relies on integration testing
# through manual container lifecycle verification and system prerequisite checks
```

### Code Quality
```bash
# Check code formatting
cargo fmt --check

# Format code
cargo fmt

# Run clippy lints
cargo clippy

# Run clippy with all features and strict warnings
cargo clippy -- -D warnings

# Check for unused dependencies (requires cargo-machete installation)
cargo machete
```

## Architecture Overview

### Module Structure
- **main.rs**: Entry point, handles CLI arguments and initializes CageManager
- **container.rs**: Core container management functionality including setup, verification, and execution
- **config.rs**: Configuration management with security modes and systemd version detection
- **utils.rs**: Utility functions for command execution, logging, and file operations
- **constants.rs**: Color constants and system configuration values
- **help.rs**: Help text and usage information

### Key Design Patterns

**Security-First Design**: The application implements multiple security modes (High/Medium/Low) with different isolation levels and capabilities.

**systemd Integration**: Uses systemd-nspawn for containerization with version-specific feature detection and compatibility handling.

**Resource Management**: Implements caching for downloaded artifacts with integrity verification and automatic cleanup.

**Logging Strategy**: Dual logging system - verbose terminal output for debugging and persistent file logging for troubleshooting.

### Container Lifecycle
1. **Prerequisites Check**: Validates system requirements, user permissions, and environment
2. **Dependency Installation**: Installs required packages (systemd-container, curl, xz-utils)
3. **Container Setup**: Downloads and extracts Arch Linux bootstrap, configures base system
4. **Security Configuration**: Sets up user accounts, sudo rules, and directory permissions  
5. **Container Entry**: Launches systemd-nspawn with security options and bind mounts

### Critical Code Paths
- **Container initialization**: `CageManager::new()` → `Config::new()` → security mode detection
- **Container setup flow**: `CageManager::run()` → `check_prerequisites()` → `install_packages()` → `setup_container()` → `enter_container()`
- **Command execution**: `Utils::run_command()` with logging to `~/.config/cagent/logs/`

### Security Features
- **User Isolation**: Runs as non-root with matching host UID/GID
- **Filesystem Security**: Read-only bind mounts for host directories
- **Network Isolation**: Configurable network access based on security mode
- **Resource Limits**: Process and memory limits via systemd cgroups
- **Audio Sandboxing**: Optional audio support with PulseAudio socket binding

## Configuration

### Environment Variables
- `SECURITY_MODE`: high/medium/low (default: high)
- `DEBUG_MODE`: Enable debug output (set to '1')
- `HOST_DIR`: Host directory to bind mount (default: $HOME)

### File System Layout
- `~/.config/cagent/container/`: Container root filesystem
- `~/.config/cagent/cache/`: Downloaded packages cache with checksums
- `~/.config/cagent/logs/`: Application log files with timestamps

### Security Modes
- **High**: Maximum isolation, no network, no audio, restricted capabilities
- **Medium**: Balanced security with audio support and limited network
- **Low**: Development-friendly with full network access and debugging tools

## Key Implementation Details

### systemd Version Compatibility
The code detects systemd version and adjusts container options accordingly. systemd 254+ uses different resource limit syntax and security options. Version detection happens in `Config::get_systemd_version()` and affects container launch parameters in `CageManager::enter_container()`.

### X11 Forwarding
Implements secure X11 authentication using xauth with temporary files and proper permission handling.

### Audio System Integration
Supports both PulseAudio and ALSA with proper device binding and permission setup for medium/low security modes.

### Cache Management
Downloads are cached with SHA256 verification, automatic staleness detection, and atomic file operations.

### Error Handling
Comprehensive error handling with user-friendly messages and detailed logging for troubleshooting.

## Dependencies

- `libc = "0.2"`: Low-level system calls for UID/GID operations and umask setting
- `chrono = "0.4"`: Time formatting and manipulation for logging timestamps  
- `tempfile = "3.8"`: Secure temporary file creation for X11 authentication

## Platform Requirements

- Ubuntu/Debian host system
- systemd with systemd-nspawn support  
- X11 display server
- sudo privileges for container management
- Minimum systemd version 240 (version 254+ recommended)

## Container System

The application creates an Arch Linux container with:
- Base system packages and development tools
- User account matching host credentials
- Sudo access for package management only
- Audio group membership for sound support
- Temporary workspace with size limits
- Integrity markers for corruption detection

## Common Troubleshooting

### Build Issues
- Ensure Rust toolchain is installed: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Update dependencies if build fails: `cargo update`

### Runtime Issues  
- Check logs at `~/.config/cagent/logs/` for detailed error information
- Verify systemd-nspawn is installed: `sudo apt install systemd-container`
- For X11 issues, ensure `DISPLAY` variable is set and xauth is available
- For permission errors, verify user is in sudo group: `groups $USER`