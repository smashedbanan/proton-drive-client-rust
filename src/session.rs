use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

const SERVICE: &str = "ch.proton.drive/drive-sdk-cli-rust";
const ACCOUNT: &str = "session";

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Not the login password — the derived passphrase that unlocks the
    /// account's private key (see srp::compute_key_password). Re-derived
    /// once at login; re-used on every subsequent command that needs keys.
    pub user_key_password: String,
}

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| Error::Keyring(e.to_string()))
}

pub fn save(creds: &Credentials) -> Result<()> {
    let json = serde_json::to_string(creds)
        .map_err(|e| Error::Keyring(format!("failed to serialize session: {e}")))?;
    entry()?
        .set_password(&json)
        .map_err(|e| Error::Keyring(e.to_string()))
}

pub fn load() -> Result<Credentials> {
    let json = entry()?.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => Error::NotLoggedIn,
        other => Error::Keyring(other.to_string()),
    })?;
    serde_json::from_str(&json)
        .map_err(|e| Error::Keyring(format!("stored session is corrupt: {e}")))
}

pub fn clear() -> Result<()> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::Keyring(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips through the real OS keyring. If this test can't reach a
    /// usable credential store in the environment it runs in (e.g. a bare CI
    /// container with no Secret Service/D-Bus session), it will fail with a
    /// Keyring error — that's an environment limitation, not a code bug; run
    /// it locally on a real desktop session to validate.
    #[test]
    fn save_load_clear_round_trip() {
        clear().ok(); // best-effort cleanup from any previous failed run
        assert!(matches!(load(), Err(Error::NotLoggedIn)));

        let creds = Credentials {
            uid: "test-uid".into(),
            access_token: "test-token".into(),
            refresh_token: "test-refresh".into(),
            user_key_password: "test-key-password".into(),
        };
        save(&creds).unwrap();
        let loaded = load().unwrap();
        assert_eq!(loaded.uid, creds.uid);
        assert_eq!(loaded.access_token, creds.access_token);
        assert_eq!(loaded.refresh_token, creds.refresh_token);
        assert_eq!(loaded.user_key_password, creds.user_key_password);

        clear().unwrap();
        assert!(matches!(load(), Err(Error::NotLoggedIn)));
    }
}
