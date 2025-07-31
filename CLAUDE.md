# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based security container manager called "cagent" (Caged Agent) that creates hardened systemd-nspawn containers with X11 forwarding, audio support, and configurable security modes. The application is designed to run GUI applications in an isolated environment on Ubuntu/Debian systems.

## Development Commands

### Build
```bash
cargo build
cargo build --release  # For optimized build
```

### Run
```bash
cargo run

# With environment variables
SECURITY_MODE=medium cargo run  # Options: high, medium, low (default: high)
DEBUG_MODE=1 cargo run          # Enable debug output
HOST_DIR=/path/to/dir cargo run # Specify host directory to bind mount
```

### Format and Lint
```bash
cargo fmt      # Format code
cargo clippy   # Lint code
```

### Clean
```bash
cargo clean    # Remove build artifacts
```

## Architecture

### Core Components

1. **CageManager** (src/main.rs:47-1048) - Main application struct that orchestrates all operations:
   - Container lifecycle management (setup, enter, verify)
   - Security configuration based on systemd version
   - X11 and audio setup
   - Bind mount management

2. **Config** (src/main.rs:19-27) - Configuration struct containing:
   - Container paths and directories
   - Security mode settings
   - Debug mode flag
   - Systemd version detection

3. **SecurityMode** (src/main.rs:29-45) - Enum defining three security levels:
   - High: Maximum isolation, no network, no audio
   - Medium: Balanced security with audio support
   - Low: Relaxed security for development

### Key Security Features

- Runs as non-root user with minimal capabilities
- Uses systemd-nspawn for container isolation
- Implements bind mounts for controlled file access
- Configures resource limits based on systemd version
- Validates paths and prevents directory traversal
- Creates temporary workspaces with size limits

### Container Environment

- Base: Arch Linux bootstrap
- X11 forwarding via xauth
- Audio support via PulseAudio/ALSA (medium/low security only)
- Read-only bind mounts for host directories
- Writable tmpfs workspace
- Restricted sudo for package management only

## Important Implementation Details

- The application detects systemd version and adjusts security options accordingly (systemd 254+ requires different handling)
- Audio setup is conditional based on security mode
- Container integrity is verified before each use
- All operations are logged to ~/.config/cagent/logs/
- The container user matches the host user's UID/GID for proper file permissions
