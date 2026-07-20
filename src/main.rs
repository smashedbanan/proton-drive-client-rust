mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod srp;

use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Login => todo_login(),
        Command::Logout => todo_logout(),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn todo_login() -> error::Result<()> {
    println!("login: not wired up yet (see later tasks)");
    Ok(())
}

fn todo_logout() -> error::Result<()> {
    println!("logout: not wired up yet (see later tasks)");
    Ok(())
}
