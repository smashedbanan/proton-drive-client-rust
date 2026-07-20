use crate::error::{Error, Result};
use base64::Engine;
use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::Password;
use rand::Rng;

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

/// A freshly generated node keypair (for a new file or folder), plus the
/// two wire-ready artifacts needed to send it in a node-creation request:
/// the passphrase encrypted to the parent folder's key, and that
/// passphrase's signature from the address key.
pub struct NewNodeKey {
    pub secret_key: SignedSecretKey,
    /// wire field `NodeKey`
    pub armored_key: String,
    /// wire field `NodePassphrase`
    pub encrypted_passphrase_armored: String,
    /// wire field `NodePassphraseSignature`
    pub passphrase_signature_armored: String,
    /// The passphrase generated below, locking `secret_key`. Kept so
    /// `generate_content_key` can unlock `secret_key.primary_key` to sign
    /// with it — confirmed necessary empirically: `SecretKeyParamsBuilder`
    /// encrypts the primary's secret material with this passphrase as part
    /// of generation, so signing with an empty password fails with
    /// "invalid input" rather than succeeding as if unprotected.
    passphrase: String,
}

/// Generates a new node keypair locked by a fresh random passphrase, then
/// produces the two artifacts a node-creation request needs: that
/// passphrase encrypted to `parent`'s key, and its detached signature from
/// `address_signing_key`.
///
/// A single `Ed25519Legacy` key is **sign/certify-only in the `pgp` crate —
/// it cannot receive encrypted messages** (confirmed empirically in Task 3:
/// attempting to encrypt to one panics with "EdDSALegacy is only used for
/// signing"). Real OpenPGP "Ed25519Legacy" keys are a primary signing key
/// *plus* a separate Curve25519 encryption subkey — matching Proton's own
/// "dual-subkey" node key format confirmed during design research, and
/// matching the `pgp` crate's own `examples/generate_key.rs`, which builds
/// exactly this shape (primary + a `KeyType::ECDH(ECCCurve::Curve25519Legacy)`
/// subkey with `can_encrypt(EncryptionCaps::All)`). This node key needs no
/// separate authentication subkey (Drive has no use for one), so it's a
/// two-key setup: primary (certifies + signs) plus one encryption subkey.
pub fn generate_node_key(parent: &UnlockedKey, address_signing_key: &UnlockedKey) -> Result<NewNodeKey> {
    let mut passphrase_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut passphrase_bytes);
    let passphrase = base64::engine::general_purpose::STANDARD.encode(passphrase_bytes);

    let mut encryption_subkey = SubkeyParamsBuilder::default();
    encryption_subkey
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false)
        .passphrase(Some(passphrase.clone()));

    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519Legacy)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Drive key <no-reply@proton.me>".to_string())
        .passphrase(Some(passphrase.clone()))
        .subkeys(vec![encryption_subkey
            .build()
            .map_err(|e| Error::Crypto(format!("invalid encryption subkey params: {e}")))?]);
    let params = key_params
        .build()
        .map_err(|e| Error::Crypto(format!("invalid node key params: {e}")))?;
    let secret_key = params
        .generate(rand08::rngs::OsRng)
        .map_err(|e| Error::Crypto(format!("node key generation failed: {e}")))?;
    let armored_key = secret_key
        .to_armored_string(Default::default())
        .map_err(|e| Error::Crypto(format!("failed to armor node key: {e}")))?;

    let encrypted_passphrase_armored = encrypt_to_key(passphrase.as_bytes(), parent)?;
    let passphrase_signature_armored = sign_detached(passphrase.as_bytes(), address_signing_key)?;

    Ok(NewNodeKey {
        secret_key,
        armored_key,
        encrypted_passphrase_armored,
        passphrase_signature_armored,
        passphrase,
    })
}

/// Encrypts `plaintext` to `key`'s public half, armored — used for
/// `NodePassphrase` (Task 5) and, later, the content-key packet
/// self-encryption and the extended-attributes blob (Task 9).
///
/// `seipd_v1`/`encrypt_to_key`/`to_armored_string` live on `MessageBuilder`
/// (a.k.a. `Builder`), not on `Message` itself — `Message` is the type for
/// already-parsed messages (see `decrypt_message` above). This mirrors the
/// pattern already proven in `node_key_tests::decrypt_message_round_trips_...`.
///
/// `key`'s *primary* public key (what `.public_key()` would return via
/// `Deref`) is wrong to encrypt to here: real node/parent keys are
/// "dual-subkey" (see `generate_node_key`) — an Ed25519Legacy primary that
/// is sign/certify-only, plus a Curve25519 encryption subkey — so the
/// primary alone can't encrypt (confirmed empirically in Task 3: "EdDSALegacy
/// is only used for signing"). `to_public_key()` surfaces every subkey
/// (including ones held only as secret material, e.g. our own freshly
/// generated ones) via `public_subkeys`; prefer the first one, falling back
/// to the primary for single-key shapes (e.g. this module's RSA test keys).
fn encrypt_to_key(plaintext: &[u8], key: &UnlockedKey) -> Result<String> {
    let rng = rand08::rngs::OsRng;
    let mut builder = pgp::composed::MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rng, SymmetricKeyAlgorithm::AES256);

    let public_key = key.secret_key.to_public_key();
    match public_key.public_subkeys.first() {
        Some(subkey) => builder.encrypt_to_key(rng, subkey),
        None => builder.encrypt_to_key(rng, &public_key),
    }
    .map_err(|e| Error::Crypto(format!("failed to encrypt to recipient: {e}")))?;

    builder
        .to_armored_string(rng, Default::default())
        .map_err(|e| Error::Crypto(format!("failed to armor encrypted message: {e}")))
}

/// Detached-signs `data` with `key`, armored — used for `NodePassphraseSignature`
/// (Task 5), the content-key packet signature, and the manifest signature (Task 9).
fn sign_detached(data: &[u8], key: &UnlockedKey) -> Result<String> {
    let rng = rand08::rngs::OsRng;
    let signature = pgp::composed::DetachedSignature::sign_binary_data(
        rng,
        &key.secret_key.primary_key,
        &Password::from(key.passphrase.as_str()),
        HashAlgorithm::Sha256,
        data,
    )
    .map_err(|e| Error::Crypto(format!("failed to sign data: {e}")))?;
    signature
        .to_armored_string(Default::default())
        .map_err(|e| Error::Crypto(format!("failed to armor signature: {e}")))
}

/// A per-file content key: a fresh AES-256 session key, plus a
/// self-signed "content key packet" (the session key encrypted to the
/// node's own key, with a self-signature over the raw key bytes) ready for
/// the `ContentKeyPacket`/`ContentKeyPacketSignature` wire fields.
pub struct ContentKeyPacket {
    pub content_key: pgp::composed::RawSessionKey,
    /// wire field `ContentKeyPacket` (base64 of the raw PKESK packet bytes)
    pub packet_b64: String,
    pub packet_signature_armored: String,
}

/// Generates a new content key for a file, self-encrypted and self-signed
/// to `node_key` (the file's own freshly-generated node key from
/// `generate_node_key`) — matching the reference SDKs' `nodeKey.EncryptSessionKey(contentKey)`
/// / `nodeKey.Sign(contentKey.Export())`.
pub fn generate_content_key(node_key: &NewNodeKey) -> Result<ContentKeyPacket> {
    let rng = rand08::rngs::OsRng;
    let content_key = SymmetricKeyAlgorithm::AES256.new_session_key(rng);

    // Same "primary can't encrypt, use the subkey" reasoning as
    // `encrypt_to_key` above — except here there's no legitimate fallback:
    // `generate_node_key` always attaches exactly one encryption subkey, so
    // its absence means a real bug, not an alternate (e.g. RSA) key shape.
    let public_key = node_key.secret_key.to_public_key();
    let encryption_key = public_key
        .public_subkeys
        .first()
        .ok_or_else(|| Error::Crypto("node key has no encryption subkey".to_string()))?;
    let packet = pgp::packet::PublicKeyEncryptedSessionKey::from_session_key_v3(
        rng,
        &content_key,
        SymmetricKeyAlgorithm::AES256,
        encryption_key,
    )
    .map_err(|e| Error::Crypto(format!("failed to encrypt content key: {e}")))?;
    let mut packet_bytes = Vec::new();
    packet
        .to_writer(&mut packet_bytes)
        .map_err(|e| Error::Crypto(format!("failed to serialize content key packet: {e}")))?;
    let packet_b64 = base64::engine::general_purpose::STANDARD.encode(&packet_bytes);

    // An empty password here fails with "invalid input" (confirmed by
    // running this function's test): `generate_node_key` locks the primary
    // key's secret material with `node_key.passphrase` at generation time,
    // so signing must unlock with that same passphrase, not an empty one.
    let signature = pgp::composed::DetachedSignature::sign_binary_data(
        rng,
        &node_key.secret_key.primary_key,
        &Password::from(node_key.passphrase.as_str()),
        HashAlgorithm::Sha256,
        content_key.as_ref(),
    )
    .map_err(|e| Error::Crypto(format!("failed to sign content key: {e}")))?;
    let packet_signature_armored = signature
        .to_armored_string(Default::default())
        .map_err(|e| Error::Crypto(format!("failed to armor content key signature: {e}")))?;

    Ok(ContentKeyPacket {
        content_key,
        packet_b64,
        packet_signature_armored,
    })
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

#[cfg(test)]
mod content_key_tests {
    use super::*;

    // KeyType::Rsa(2048), not Ed25519Legacy: this key stands in for a
    // parent/address key that things get *encrypted to* (`generate_node_key`
    // below calls `encrypt_to_key` against it) — a solo Ed25519Legacy key
    // can only sign, and panics if anything tries to encrypt to it (found
    // empirically in Task 3; see that task's `node_key_tests` for the
    // real panic message). RSA-2048 can do both from one key, with none of
    // the dual-subkey ceremony `generate_node_key`'s own *production* keys
    // need — this is a test stand-in, not a production code path.
    fn generate_test_parent(passphrase: &str) -> UnlockedKey {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .primary_user_id("Parent <parent@example.com>".to_string())
            .passphrase(Some(passphrase.to_string()));
        let params = key_params.build().expect("valid key params");
        let signed_secret_key = params.generate(rand08::rngs::OsRng).expect("key generation should succeed");
        let armored = signed_secret_key.to_armored_string(Default::default()).unwrap();
        UnlockedKey::new(&armored, passphrase.to_string()).unwrap()
    }

    #[test]
    fn generate_node_key_produces_a_decryptable_passphrase() {
        let parent = generate_test_parent("parent passphrase");
        let address_signing_key = generate_test_parent("address passphrase");

        let new_key = generate_node_key(&parent, &address_signing_key).unwrap();
        let recovered_passphrase = decrypt_message(&new_key.encrypted_passphrase_armored, &parent).unwrap();

        // The recovered passphrase must actually unlock the generated key.
        assert!(UnlockedKey::new(&new_key.armored_key, recovered_passphrase).is_ok());
    }

    #[test]
    fn generate_content_key_produces_a_usable_aes256_session_key() {
        let parent = generate_test_parent("parent passphrase");
        let address_signing_key = generate_test_parent("address passphrase");
        let node_key = generate_node_key(&parent, &address_signing_key).unwrap();

        let content_key_packet = generate_content_key(&node_key).unwrap();
        assert_eq!(content_key_packet.content_key.as_ref().len(), 32); // AES-256 key size
    }

    // The two tests above only prove that generation *doesn't error* — that
    // isn't quite the same as proving the packet is actually decryptable
    // with the node key's own encryption subkey (a bug that silently
    // targeted the wrong sub/key with a still-valid-shaped key could slip
    // through). This test closes that gap by decrypting back.
    //
    // `content_key_packet.packet_b64` can't be re-parsed directly: its
    // `to_writer` (see `generate_content_key`) serializes only the PKESK's
    // body, with no packet header/framing to parse back. So this
    // reconstructs a packet the same way `generate_content_key` does
    // (same content key bytes, same subkey), and decrypts *that* — still a
    // genuine test of "is this the key that can decrypt what we encrypt to
    // it", just not a byte-for-byte replay of the wire artifact.
    #[test]
    fn generate_content_key_packet_decrypts_back_via_the_node_keys_own_secret_subkey() {
        use pgp::types::DecryptionKey;

        let parent = generate_test_parent("parent passphrase");
        let address_signing_key = generate_test_parent("address passphrase");
        let node_key = generate_node_key(&parent, &address_signing_key).unwrap();
        let content_key_packet = generate_content_key(&node_key).unwrap();

        let public_key = node_key.secret_key.to_public_key();
        let public_subkey = public_key
            .public_subkeys
            .first()
            .expect("node key has an encryption subkey");
        let packet = pgp::packet::PublicKeyEncryptedSessionKey::from_session_key_v3(
            rand08::rngs::OsRng,
            &content_key_packet.content_key,
            SymmetricKeyAlgorithm::AES256,
            public_subkey,
        )
        .expect("encrypting to the node key's own subkey should succeed");
        let values = match packet {
            pgp::packet::PublicKeyEncryptedSessionKey::V3 { values, .. } => values,
            other => panic!("expected a v3 PKESK, got {other:?}"),
        };

        let secret_subkey = &node_key
            .secret_key
            .secret_subkeys
            .first()
            .expect("node key has a secret encryption subkey")
            .key;
        // Regression guard for the bug fixed in ae96368: `SecretSubkey::decrypt`
        // (called below) ignores whatever `Password` it's given when the
        // secret material is still `SecretParams::Plain` (unencrypted) — it
        // only checks the password once the key is genuinely `Encrypted`. So
        // if `.passphrase(Some(passphrase.clone()))` were ever dropped again
        // from the `encryption_subkey` builder in `generate_node_key`, the
        // decrypt-and-compare assertions below would keep passing unchanged.
        // This checks the actual lock state directly, independent of that.
        assert!(secret_subkey.secret_params().is_encrypted());
        // The encryption subkey is locked with the same freshly-generated
        // passphrase as the primary key (see `generate_node_key`), so it
        // must be unlocked with that real passphrase, not an empty one.
        let decrypted = secret_subkey
            .decrypt(&Password::from(node_key.passphrase.as_str()), &values, pgp::types::EskType::V3_4)
            .expect("decrypt should not error")
            .expect("decrypted session key should be valid");
        let pgp::composed::PlainSessionKey::V3_4 { ref key, .. } = decrypted else {
            panic!("expected a v3/v4 plain session key");
        };
        assert_eq!(key.as_ref(), content_key_packet.content_key.as_ref());
    }
}
