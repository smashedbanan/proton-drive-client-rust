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
        Command::Download { remote, local, conflict_strategy } => {
            commands::download::run(&remote, &local, conflict_strategy)
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
