use std::env;
use std::process::exit;

mod config;
mod constants;
mod container;
mod help;
mod utils;

use constants::*;
use container::CageManager;
use help::show_help;

fn main() {
    // Set restrictive umask
    unsafe {
        libc::umask(0o077);
    }

    // Check for help flags first
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        show_help();
        exit(0);
    }

    let mut manager = match CageManager::new() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{RED}ERROR: {e}{NC}");
            exit(1);
        }
    };

    if let Err(e) = manager.run() {
        eprintln!("{RED}ERROR: {e}{NC}");
        exit(1);
    }
}
