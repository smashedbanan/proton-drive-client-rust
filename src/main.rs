mod api;
mod cli;
mod commands;
mod config;
mod conflict;
mod crypto;
mod drive;
mod error;
mod session;
mod srp;

use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Login => commands::login::run(),
        Command::Logout => commands::logout::run(),
        Command::Upload { local, remote } => commands::upload::run(&local, &remote),
        // ponytail: stub, Task 3 only adds the CLI variant — real dispatch lands in Task 11.
        Command::Download { .. } => todo!("wire up in Task 11"),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
