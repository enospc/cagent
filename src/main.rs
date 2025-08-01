use std::env;
use std::process::exit;

mod constants;
mod help;
mod config;
mod utils;
mod container;

use constants::*;
use help::show_help;
use container::CageManager;

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
            eprintln!("{}ERROR: {}{}", RED, e, NC);
            exit(1);
        }
    };

    if let Err(e) = manager.run() {
        eprintln!("{}ERROR: {}{}", RED, e, NC);
        exit(1);
    }
}
