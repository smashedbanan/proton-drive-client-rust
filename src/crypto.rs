use crate::error::{Error, Result};
use pgp::composed::{Deserializable, Message, SignedSecretKey};
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

/// A parsed OpenPGP secret key plus the passphrase that unlocks it, held
/// together so repeated decrypt/sign operations don't each re-parse the
/// armored text. Used for the account's address key, and for every node key
/// encountered while walking a Drive path (the "My files" share key, and
/// each folder's own key going down the tree).
pub struct UnlockedKey {
    secret_key: SignedSecretKey,
    passphrase: String,
}

impl UnlockedKey {
    /// Parses `armored_key` and eagerly verifies `passphrase` actually
    /// unlocks it (same "fail fast, not on first use" posture as the
    /// existing `unlock_private_key`) before returning.
    pub fn new(armored_key: &str, passphrase: String) -> Result<Self> {
        let (secret_key, _headers) = SignedSecretKey::from_string(armored_key)
            .map_err(|e| Error::Crypto(format!("could not parse private key: {e}")))?;
        let outer = secret_key.unlock(&Password::from(passphrase.as_str()), |_pub_params, _plain| Ok(()));
        match outer {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(Error::Crypto(format!("failed to unlock key: {e}"))),
            Err(e) => return Err(Error::Crypto(format!("failed to unlock key (wrong passphrase?): {e}"))),
        }
        Ok(Self { secret_key, passphrase })
    }
}

/// Decrypts an armored OpenPGP message (a node's `Name`, `NodePassphrase`,
/// or a share's `Passphrase`) using an already-unlocked key, returning the
/// plaintext as a UTF-8 string. All three of those fields are always
/// UTF-8 plaintext in Proton's protocol (a name, or a passphrase string) —
/// never arbitrary binary — so a single string-returning function covers
/// all of them.
pub fn decrypt_message(armored_message: &str, key: &UnlockedKey) -> Result<String> {
    let (message, _headers) = Message::from_reader(armored_message.as_bytes())
        .map_err(|e| Error::Crypto(format!("bad encrypted message: {e}")))?;
    let mut decrypted = message
        .decrypt(&Password::from(key.passphrase.as_str()), &key.secret_key)
        .map_err(|e| Error::Crypto(format!("failed to decrypt message: {e}")))?;
    let bytes = decrypted
        .as_data_vec()
        .map_err(|e| Error::Crypto(format!("failed to read decrypted message: {e}")))?;
    String::from_utf8(bytes).map_err(|e| Error::Crypto(format!("decrypted message was not valid UTF-8: {e}")))
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

#[cfg(test)]
mod node_key_tests {
    use super::*;
    use pgp::composed::{KeyType, SecretKeyParamsBuilder};

    // RSA, not Ed25519Legacy (the module `tests` key type): the round-trip
    // test below needs a key that can both unlock *and* receive an
    // encrypted message. Ed25519Legacy is signing-only — encrypting to it
    // fails at runtime with "EdDSALegacy is only used for signing" (verified
    // by running this test); RSA supports both from a single primary key.
    fn generate_test_key(passphrase: &str) -> SignedSecretKey {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .primary_user_id("Test <test@example.com>".to_string())
            .passphrase(Some(passphrase.to_string()));
        let params = key_params.build().expect("valid key params");
        params.generate(rand08::rngs::OsRng).expect("key generation should succeed")
    }

    #[test]
    fn unlocked_key_rejects_wrong_passphrase() {
        let signed_secret_key = generate_test_key("correct passphrase");
        let armored = signed_secret_key.to_armored_string(Default::default()).unwrap();
        assert!(UnlockedKey::new(&armored, "wrong passphrase".to_string()).is_err());
        assert!(UnlockedKey::new(&armored, "correct passphrase".to_string()).is_ok());
    }

    #[test]
    fn decrypt_message_round_trips_through_a_freshly_generated_key() {
        let signed_secret_key = generate_test_key("correct passphrase");
        let armored_key = signed_secret_key.to_armored_string(Default::default()).unwrap();
        let public_key = signed_secret_key.public_key();

        let plaintext = "a Drive node's decrypted name";
        let armored_message = {
            let mut builder = pgp::composed::MessageBuilder::from_bytes("", plaintext.as_bytes())
                .seipd_v1(rand08::rngs::OsRng, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
            builder
                .encrypt_to_key(rand08::rngs::OsRng, &public_key)
                .expect("adding recipient should succeed");
            builder
                .to_armored_string(rand08::rngs::OsRng, Default::default())
                .expect("armoring should succeed")
        };

        let key = UnlockedKey::new(&armored_key, "correct passphrase".to_string()).unwrap();
        let decrypted = decrypt_message(&armored_message, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
