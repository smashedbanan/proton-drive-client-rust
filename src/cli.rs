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
    Download {
        remote: String,
        local: String,
        #[arg(long)]
        conflict_strategy: Option<crate::conflict::ConflictChoice>,
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

    #[test]
    fn parses_download_with_remote_and_local_args() {
        let cli = Cli::try_parse_from(["proton-drive", "download", "/my-files/docs/file.txt", "./file.txt"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Download {
                remote: "/my-files/docs/file.txt".to_string(),
                local: "./file.txt".to_string(),
                conflict_strategy: None,
            }
        );
    }

    #[test]
    fn parses_download_with_conflict_strategy_flag() {
        let cli = Cli::try_parse_from([
            "proton-drive", "download", "/my-files/docs/file.txt", "./file.txt", "--conflict-strategy", "keep-both",
        ])
        .unwrap();
        assert_eq!(
            cli.command,
            Command::Download {
                remote: "/my-files/docs/file.txt".to_string(),
                local: "./file.txt".to_string(),
                conflict_strategy: Some(crate::conflict::ConflictChoice::KeepBoth),
            }
        );
    }
}
