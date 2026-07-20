#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("network error: {0}")]
    Network(String),
    #[error("API error {code}: {message}")]
    Api { code: i64, message: String },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("this account uses two-password mode, which this client does not support yet")]
    TwoPasswordModeUnsupported,
    #[error("not logged in — run `login` first")]
    NotLoggedIn,
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
