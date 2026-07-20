use crate::error::{Error, Result};
use pgp::composed::{Deserializable, SignedSecretKey};
use pgp::types::Password;

/// Attempts to unlock an armored OpenPGP private key with the given
/// passphrase, discarding the result. Used purely to validate that a
/// derived key password is correct — if this fails, the password (or the
/// key material) is wrong.
pub fn unlock_private_key(armored: &str, passphrase: &str) -> Result<()> {
    let (secret_key, _headers) = SignedSecretKey::from_string(armored)
        .map_err(|e| Error::Crypto(format!("could not parse private key: {e}")))?;
    let outer = secret_key.unlock(&Password::from(passphrase), |_pub_params, _plain| Ok(()));
    match outer {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(Error::Crypto(format!("failed to unlock private key: {e}"))),
        Err(e) => Err(Error::Crypto(format!(
            "failed to unlock private key (wrong password?): {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{KeyType, SecretKeyParamsBuilder};

    #[test]
    fn unlocks_a_freshly_generated_key_with_the_right_password() {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .primary_user_id("Test <test@example.com>".to_string())
            .passphrase(Some("correct password".to_string()));
        let params = key_params.build().expect("valid key params");
        // generate() returns an already-signed SignedSecretKey directly (it
        // signs internally) — no separate .sign() call needed or available
        // on this return type.
        let signed_secret_key = params
            .generate(rand08::rngs::OsRng)
            .expect("key generation should succeed");
        let armored = signed_secret_key
            .to_armored_string(Default::default())
            .expect("armor should succeed");

        assert!(unlock_private_key(&armored, "correct password").is_ok());
        assert!(unlock_private_key(&armored, "wrong password").is_err());
    }
}
