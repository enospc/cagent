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

This is a single-file Rust application (~1564 lines) with a well-structured monolithic design. The core architecture revolves around three main components working together to provide secure containerization.

### Core Components

1. **Config** (src/main.rs:105-117) - Configuration management:
   - Derives paths from HOME environment variable
   - Handles systemd version detection and compatibility
   - Manages security mode settings and directory paths
   - Supports both environment variables and command-line flags

2. **SecurityMode** (src/main.rs:118-133) - Security level enumeration:
   - **High**: Maximum isolation, no network, no audio access
   - **Medium**: Balanced security with audio support enabled  
   - **Low**: Relaxed security for development workflows
   - Implements FromStr for environment variable parsing

3. **CageManager** (src/main.rs:135-1537) - Main orchestration engine:
   - **Container Lifecycle**: setup_container(), enter_container(), verify_container()
   - **Security Configuration**: Systemd version-aware security options and resource limits
   - **External Integration**: X11 forwarding, audio binding, file system mounts
   - **Command Execution**: Unified logging and execution framework

### Application Flow

The application follows a linear execution model:
1. **Initialization**: Config creation, argument parsing, prerequisite checks
2. **Container Setup**: Download Arch Linux bootstrap, extract, configure user/permissions  
3. **Container Entry**: X11 auth setup, bind mounts, systemd-nspawn execution with security options
4. **Verification**: Container integrity checking before each use

### Systemd Version Compatibility

Critical architectural decision: The application detects systemd version and adapts behavior:
- **systemd 254+**: Uses `--user` flag directly, higher resource limits, minimal security options
- **Pre-254**: Uses `runuser` wrapper, stricter capabilities, lower resource limits
- This affects security options, resource limits, and command execution paths

### Command Execution Architecture

All external commands flow through a unified logging and execution system:
- **log_command()**: Logs all commands to file, conditionally to terminal with verbose mode
- **run_command()**: Standard execution with error handling 
- **run_command_with_log()**: Execution with stdout/stderr capture
- **run_systemd_nspawn()**: Specialized systemd-nspawn execution wrapper

### Network Downloads and Caching

The application implements a sophisticated download system:
- **Checksum Verification**: Downloads SHA256 checksums and verifies all files
- **Caching Layer**: Local cache in ~/.config/cagent/cache/ with checksum validation
- **Progress Indicators**: Real-time download progress using curl's --progress-bar
- **Retry Logic**: Connection timeouts and retry mechanisms for reliability

## Key Constants and Configuration

```rust
const ARCH_MIRROR: &str = "https://mirror.rackspace.com/archlinux";
const ARCH_BOOTSTRAP_FILE_NAME: &str = "archlinux-bootstrap-x86_64.tar.zst";
const CONTAINER_USER: &str = "agent";
```

## Progress Indicator System  

The application features comprehensive progress feedback:
- **Emoji-based Visual Indicators**: 🔍 🔄 ✓ ❌ 📦 🔧 👤 🖥️ 🚀 for different operation types
- **Step Counters**: Multi-step operations show progress like "Installing package (2/3)..."
- **Real-time Updates**: Uses Command::status() instead of Command::output() for live progress
- **Failure Feedback**: Clear error indicators when operations fail

## Security Implementation Details

- **Path Validation**: All paths are canonicalized and restricted to /home/ directory
- **Resource Limits**: NPROC, NOFILE, MEMLOCK limits based on systemd version  
- **Capability Management**: Minimal capabilities based on security mode
- **User Isolation**: Container user matches host UID/GID for proper file permissions
- **Audit Trail**: All operations logged to ~/.config/cagent/logs/ with timestamps
