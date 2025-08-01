# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based security container manager called "cagent" (Caged Agent) that creates hardened systemd-nspawn containers with X11 forwarding, audio support, and configurable security modes. The application is designed to run GUI applications in an isolated environment on Ubuntu/Debian systems.

## Development Commands

### Build and Test
```bash
cargo build                     # Debug build
cargo build --release          # Optimized release build
cargo check                     # Fast syntax and type checking
cargo clippy                    # Linting with helpful suggestions
cargo fmt                       # Format code
```

### Run Application
```bash
cargo run                       # Basic execution

# Command-line options
cargo run -- -v                # Enable verbose command logging  
cargo run -- --help            # Show detailed help information

# Environment variables
SECURITY_MODE=medium cargo run # Options: high, medium, low (default: high)
DEBUG_MODE=1 cargo run         # Enable debug output with extra info
HOST_DIR=/path/to/dir cargo run # Specify host directory to bind mount

# Combined usage examples
SECURITY_MODE=medium DEBUG_MODE=1 cargo run -- -v
HOST_DIR=/home/user/projects SECURITY_MODE=low cargo run
```

### Clean
```bash
cargo clean                     # Remove build artifacts
```

## Architecture Overview

This is a modular Rust application with a clean separation of concerns across multiple specialized modules. The application implements a security container manager that creates isolated environments for running applications.

### Core Modules

1. **Config** (src/config.rs) - Configuration and security modes:
   - **SecurityMode**: High/Medium/Low isolation levels with FromStr parsing
   - **Config**: Path management, environment variable integration, logging setup
   - Derives paths from HOME environment, supports command-line flags

2. **Container** (src/container.rs) - Main orchestration engine:
   - **CageManager**: Container lifecycle management, prerequisite checking
   - References to hybrid container execution and mount management systems
   - **User Management**: Container user creation and namespace validation
   - **Container Setup**: Arch Linux bootstrap download with caching

3. **Utils** (src/utils.rs) - Utility functions and command execution:
   - **Utils**: Logging, command execution, and error handling
   - **Command Logging**: All commands logged to timestamped files
   - **Error Handling**: Centralized error reporting with log file references

4. **Constants** (src/constants.rs) - Application constants:
   - Color codes for terminal output
   - Arch Linux mirror and bootstrap file configuration
   - Container user name constants

5. **Help** (src/help.rs) - Command-line help and usage information

6. **Main** (src/main.rs) - Application entry point:
   - Command-line argument parsing
   - Subcommand routing: remove, status, diagnose
   - Main container execution flow

### Application Flow

The application follows this execution model:
1. **Initialization**: Config creation, argument parsing, command routing (remove/status/diagnose)
2. **Prerequisites**: User namespace validation (/etc/subuid, /etc/subgid), system dependency checks
3. **Container Setup**: Arch Linux bootstrap download with caching, user creation, package installation
4. **Container Execution**: Main container orchestration through CageManager

### Command Line Interface

The application supports several subcommands:
- **Default**: Run the main container application
- **remove/rm/clean/cleanup**: Remove container and cleanup resources
- **status**: Show container status and active mounts
- **diagnose/diag**: Run mount diagnostics and troubleshooting

### Command Execution Architecture

Commands are executed through the utilities system (src/utils.rs):
- **Utils::log()**: Logs messages to timestamped files in ~/.config/cagent/logs/
- **Utils::log_command()**: Logs all command executions
- **Utils::error_exit()**: Centralized error handling with log file references

### Security Implementation

The application implements several security features:
- **User Namespace Validation**: Checks /etc/subuid and /etc/subgid configuration
- **Security Modes**: High/Medium/Low security levels (configured via SECURITY_MODE env var)
- **Path Validation**: All paths derived from HOME environment variable
- **Restrictive umask**: Sets 0o077 umask for secure file creation

## Key Constants and Configuration

```rust
const ARCH_MIRROR: &str = "https://mirror.rackspace.com/archlinux";
const ARCH_BOOTSTRAP_FILE_NAME: &str = "archlinux-bootstrap-x86_64.tar.zst";
const CONTAINER_USER: &str = "agent";
```

## Dependencies

The application uses these key Rust crates:
- **libc**: System calls and C library bindings
- **nix**: Safe Rust bindings to POSIX APIs (process, user, fs, sched, mount, hostname, signal features)

## File Structure and Paths

The application follows this directory structure:
- **Container**: `~/.config/cagent/container/` - Container root filesystem
- **Logs**: `~/.config/cagent/logs/` - Timestamped log files
- **Cache**: `~/.config/cagent/cache/` - Downloaded bootstrap files and cache
