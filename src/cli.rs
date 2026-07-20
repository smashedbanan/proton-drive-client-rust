use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "proton-drive")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Command {
    Login,
    Logout,
    Upload {
        local: String,
        remote: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login() {
        let cli = Cli::try_parse_from(["proton-drive", "login"]).unwrap();
        assert_eq!(cli.command, Command::Login);
    }

    #[test]
    fn parses_logout() {
        let cli = Cli::try_parse_from(["proton-drive", "logout"]).unwrap();
        assert_eq!(cli.command, Command::Logout);
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(Cli::try_parse_from(["proton-drive", "bogus"]).is_err());
    }

    #[test]
    fn parses_upload_with_local_and_remote_args() {
        let cli = Cli::try_parse_from(["proton-drive", "upload", "./file.txt", "/my-files/docs"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Upload { local: "./file.txt".to_string(), remote: "/my-files/docs".to_string() }
        );
    }
}
