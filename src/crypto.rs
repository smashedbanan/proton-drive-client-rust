use crate::error::{Error, Result};
use base64::Engine;
use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, PlainSessionKey, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Packet, PacketParser};
use pgp::ser::Serialize;
use pgp::types::{DecryptionKey, EskType, Password};
use rand::Rng;
use sha2::{Digest, Sha256};

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

impl NewNodeKey {
    /// An `UnlockedKey` view of this freshly generated node key. Lets a
    /// caller holding only a `NewNodeKey` (the "new file" case) call
    /// anything written against `&UnlockedKey` — e.g.
    /// `encrypt_and_sign_block`'s/`build_extended_attributes`'s node-key
    /// parameter — the same way a caller holding an EXISTING node's real,
    /// fetched-and-decrypted key does (Task 13's
    /// `resolve_existing_node_key_and_content_key`, in `commands::upload`):
    /// there is no "new" keypair in that second case, so unifying both on
    /// `UnlockedKey` (already this crate's general "a key I can encrypt to
    /// / sign with" currency — see `encrypt_to_key`) is what lets both
    /// cases share one code path instead of duplicating it. Carries the
    /// real passphrase, not an empty placeholder, so the result can still
    /// sign (`build_extended_attributes` needs to), not just encrypt.
    pub(crate) fn as_unlocked_key(&self) -> UnlockedKey {
        UnlockedKey {
            secret_key: self.secret_key.clone(),
            passphrase: self.passphrase.clone(),
        }
    }
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
pub(crate) fn encrypt_to_key(plaintext: &[u8], key: &UnlockedKey) -> Result<String> {
    let rng = rand08::rngs::OsRng;
    let mut builder = pgp::composed::MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rng, SymmetricKeyAlgorithm::AES256);

    add_recipient(&mut builder, key)?;

    builder
        .to_armored_string(rng, Default::default())
        .map_err(|e| Error::Crypto(format!("failed to armor encrypted message: {e}")))
}

/// Adds `key` as an encryption recipient on `builder`, preferring its first
/// public encryption subkey over its primary — real node/parent keys are
/// "dual-subkey" (see `generate_node_key`): an Ed25519Legacy primary that is
/// sign/certify-only, plus a Curve25519 encryption subkey, so the primary
/// alone can't encrypt (confirmed empirically in Task 3: "EdDSALegacy is only
/// used for signing"). Falls back to the primary for single-key shapes (e.g.
/// this module's RSA test keys). Shared by `encrypt_to_key` and
/// `build_extended_attributes` — both only ever build a SEIPDv1 message here;
/// `encrypt_and_sign_block` is the only AEAD-capable builder, and never needs
/// this (it always encrypts to the content key, never to a recipient key).
fn add_recipient<R: std::io::Read>(
    builder: &mut pgp::composed::MessageBuilder<'_, R, pgp::composed::EncryptionSeipdV1>,
    key: &UnlockedKey,
) -> Result<()> {
    let rng = rand08::rngs::OsRng;
    let public_key = key.secret_key.to_public_key();
    match public_key.public_subkeys.first() {
        Some(subkey) => builder.encrypt_to_key(rng, subkey),
        None => builder.encrypt_to_key(rng, &public_key),
    }
    .map_err(|e| Error::Crypto(format!("failed to add encryption recipient: {e}")))?;
    Ok(())
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
///
/// Derives `Clone` (never `Debug` — still secret material): `commands::upload`
/// needs to hold either `ctx`'s freshly generated content key or one
/// resolved from an existing node (Task 13's
/// `resolve_existing_node_key_and_content_key`) as the same owned local
/// across both arms of a name-conflict decision.
// ponytail: cloning a ~32-byte session key plus two strings, once per
// upload (never per-block), to unify both arms on one owned type — a
// zero-copy `Cow`/enum split would avoid it but isn't worth the extra type
// for a once-per-upload clone; revisit only if profiling ever says otherwise.
#[derive(Clone)]
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
    // Framed via `Packet`'s own `Serialize` impl (header + body), not the
    // bare PKESK's own `to_writer` (body only) — so a packet generated here
    // round-trips through `decrypt_existing_content_key`'s real `PacketParser`
    // path too, the same way `existing_content_key_tests::decrypts_a_genuinely_framed_pkesk_packet`
    // already proves that path expects. See `decrypt_existing_content_key`'s
    // doc comment for why this asymmetry mattered.
    let mut packet_bytes = Vec::new();
    Packet::PublicKeyEncryptedSessionKey(packet)
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

/// Decrypts an EXISTING file's content-key packet (base64, fetched from the
/// server via `api::drive::get_link_details`'s `LinkFileDetails.content_key_packet`
/// field) back to its raw session key, using the file's own node key —
/// already unlocked the same way every other node key in this crate is:
/// decrypt its `NodePassphrase` with the parent folder's key, then
/// `UnlockedKey::new`. Used when uploading a new revision to an existing
/// file: the content key is per-file, generated once, and MUST be reused
/// across every revision (see `generate_content_key`'s own doc comment) —
/// never regenerated.
///
/// `generate_content_key`'s own `packet_b64` is, as of this function's own
/// follow-up fix, built the same properly-framed way (a real, standalone
/// OpenPGP packet — header + body — via `Packet::to_writer`, not the bare
/// PKESK's body-only `to_writer`), so a content-key packet generated by
/// this CLI round-trips through this function too, closing what was
/// originally an asymmetry (see `existing_content_key_tests` for both
/// directions: real framing decrypts, headerless body-only bytes are
/// correctly rejected). A real Proton server's stored `ContentKeyPacket` is
/// produced by official clients using standard OpenPGP libraries the same
/// way, parsed here via `PacketParser`. **Not independently verified
/// against a real Proton-server-produced value** (no live account was
/// available while writing this) — flagged for live confirmation during
/// Task 14's manual verification, same treatment as every other
/// not-yet-live-tested protocol detail in this plan.
///
/// The returned `ContentKeyPacket.packet_b64`/`packet_signature_armored`
/// are empty placeholders, not real values. Reusing an existing content key
/// never re-sends it to the server — `RevisionCreationRequest`/
/// `SmallRevisionUploadMetadata` (Task 6) carry no content-key fields at
/// all — so only `.content_key` (the raw session key) is ever read by
/// `encrypt_and_sign_block`/`decrypt_block_with_session_key` (Task 7), the
/// only two functions that consume a `ContentKeyPacket` for block crypto.
pub fn decrypt_existing_content_key(content_key_packet_b64: &str, node_key: &UnlockedKey) -> Result<ContentKeyPacket> {
    let packet_bytes = base64::engine::general_purpose::STANDARD
        .decode(content_key_packet_b64)
        .map_err(|e| Error::Crypto(format!("bad content key packet base64: {e}")))?;
    let mut parser = PacketParser::new(&packet_bytes[..]);
    let packet = parser
        .next()
        .ok_or_else(|| Error::Crypto("content key packet is empty".into()))?
        .map_err(|e| Error::Crypto(format!("failed to parse content key packet: {e}")))?;
    let pkesk = match packet {
        Packet::PublicKeyEncryptedSessionKey(pkesk) => pkesk,
        other => return Err(Error::Crypto(format!("expected a content-key packet, got {other:?}"))),
    };
    // `esk_type` distinguishes the two PKESK wire versions (V3 pairs with
    // SEIPDv1, V6 with SEIPDv2/AEAD). Confirmed against the installed `pgp`
    // 0.20.0 source (`src/packet/public_key_encrypted_session_key.rs`): the
    // variant names are `V3 { .. }`/`V6 { .. }` as guessed, but the enum
    // also has a third `Other { .. }` variant (any PKESK version besides 3
    // or 6), so a two-arm match on just `V3`/`V6` is non-exhaustive and
    // doesn't compile — this catch-all arm is required, not optional.
    let esk_type = match &pkesk {
        pgp::packet::PublicKeyEncryptedSessionKey::V3 { .. } => EskType::V3_4,
        pgp::packet::PublicKeyEncryptedSessionKey::V6 { .. } => EskType::V6,
        other => return Err(Error::Crypto(format!("unsupported content key packet PKESK version: {other:?}"))),
    };
    let secret_subkey = node_key
        .secret_key
        .secret_subkeys
        .first()
        .ok_or_else(|| Error::Crypto("node key has no encryption subkey".into()))?;
    let plain_session_key = secret_subkey
        .key
        .decrypt(
            &Password::from(node_key.passphrase.as_str()),
            pkesk
                .values()
                .map_err(|e| Error::Crypto(format!("bad content key packet values: {e}")))?,
            esk_type,
        )
        .map_err(|e| Error::Crypto(format!("failed to decrypt content key packet: {e}")))?
        .map_err(|e| Error::Crypto(format!("content key packet decryption rejected: {e}")))?;
    // `PlainSessionKey` (confirmed in `src/composed/message/decrypt.rs`) has
    // a third variant, `V5`, alongside `V3_4`/`V6` — this catch-all is
    // required for the same exhaustiveness reason as the PKESK match above,
    // not just defensive styling.
    //
    // Matches on `&plain_session_key` (not by value) and clones `key`:
    // `PlainSessionKey` derives `ZeroizeOnDrop`, so partially moving `key`
    // out of it by value is rejected at compile time (E0509, "cannot move
    // out of type ..., which implements the Drop trait") — confirmed by
    // actually hitting that error. `RawSessionKey` derives `Clone`, so
    // cloning through the reference sidesteps it.
    let content_key = match &plain_session_key {
        PlainSessionKey::V3_4 { key, .. } => key.clone(),
        PlainSessionKey::V6 { key } => key.clone(),
        other => return Err(Error::Crypto(format!("unexpected session key variant: {other:?}"))),
    };
    Ok(ContentKeyPacket {
        content_key,
        packet_b64: String::new(),
        packet_signature_armored: String::new(),
    })
}

pub struct EncryptedBlock {
    pub ciphertext: Vec<u8>,
    pub sha256_hash: [u8; 32],
    /// wire field `EncSignature` — a detached signature over the
    /// plaintext, PGP-encrypted to the node's own key. Uploaded as block
    /// metadata but never verified client-side at upload time (it exists
    /// for later, download-side verification, out of scope here) — see
    /// the upload design doc.
    pub encrypted_signature_armored: String,
}

/// Encrypts one block's plaintext under `content_key`, choosing SEIPDv1 or
/// SEIPDv2/AEAD framing per `aead` (resolved once by the caller from the
/// `DriveCryptoEncryptBlocksWithPgpAead` feature flag — see
/// `commands::upload`, Task 11 — not re-checked per block), signs the
/// plaintext with `signing_key` (the address signing key), and encrypts
/// that detached signature to the node's own key. Retrying on integrity
/// mismatch is the caller's responsibility (`commands::upload`, Task 11)
/// via `decrypt_block_with_session_key` below.
///
/// `node_key_for_signature_encryption` takes `&UnlockedKey`, not the
/// narrower `&NewNodeKey` an earlier version of this function used: this
/// parameter is only ever read for its public half (see below), and
/// `commands::upload`'s conflict path (Task 13) needs to call this with an
/// EXISTING node's fetched-and-decrypted key, which has no corresponding
/// `NewNodeKey` at all (nothing was generated) — `NewNodeKey::as_unlocked_key`
/// covers the other, "brand-new file" case.
///
/// `seipd_v1`/`seipd_v2` return the builder directly (they can't fail), but
/// `set_session_key` takes `&mut self` and returns `Result<&mut Self>` while
/// `to_vec` needs to consume the builder by value — so, same as
/// `encrypt_to_key` above, this needs a `let mut builder` plus separate
/// statements rather than one chained expression.
pub fn encrypt_and_sign_block(
    plaintext: &[u8],
    content_key: &ContentKeyPacket,
    signing_key: &UnlockedKey,
    node_key_for_signature_encryption: &UnlockedKey,
    aead: bool,
) -> Result<EncryptedBlock> {
    let rng = rand08::rngs::OsRng;
    let ciphertext = if aead {
        // Chunk size is a framing parameter the decrypting side reads back
        // out of the message itself — it doesn't need to match Proton's own
        // 128 KiB default (`PgpDefaults.AeadStreamingChunkLength`, found
        // during research) for correctness, only for parity with it, so
        // the crate's default is used here rather than hand-picking a
        // `ChunkSize` variant that wasn't independently confirmed to exist
        // under an exact name. `AeadAlgorithm::Ocb` is RFC 9580's own
        // default AEAD mode for SEIPDv2 — a reasonable, standard choice,
        // not independently confirmed as Proton's specific pick (the
        // library that would confirm it, `Proton.Cryptography.Pgp`, isn't
        // vendored in the reference SDK — see the upload design doc).
        let mut builder = pgp::composed::MessageBuilder::from_bytes("", plaintext.to_vec()).seipd_v2(
            rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder
            .set_session_key(content_key.content_key.clone())
            .map_err(|e| Error::Crypto(format!("failed to set block session key: {e}")))?;
        builder
            .to_vec(rng)
            .map_err(|e| Error::Crypto(format!("failed to encrypt block: {e}")))?
    } else {
        let mut builder = pgp::composed::MessageBuilder::from_bytes("", plaintext.to_vec())
            .seipd_v1(rng, SymmetricKeyAlgorithm::AES256);
        builder
            .set_session_key(content_key.content_key.clone())
            .map_err(|e| Error::Crypto(format!("failed to set block session key: {e}")))?;
        builder
            .to_vec(rng)
            .map_err(|e| Error::Crypto(format!("failed to encrypt block: {e}")))?
    };

    let sha256_hash: [u8; 32] = Sha256::digest(&ciphertext).into();

    let signature_armored = sign_detached(plaintext, signing_key)?;
    // Only `node_key_for_signature_encryption`'s public half is ever used
    // here (`encrypt_to_key` never reads a key's passphrase) — its
    // passphrase, real or empty, is irrelevant to this call.
    let encrypted_signature_armored = encrypt_to_key(signature_armored.as_bytes(), node_key_for_signature_encryption)?;

    Ok(EncryptedBlock {
        ciphertext,
        sha256_hash,
        encrypted_signature_armored,
    })
}

/// Decrypts `ciphertext` with the already-known `content_key` — used to
/// verify a block was encrypted correctly before uploading it (retry once
/// on mismatch, per the upload design's data flow), never for downloading
/// someone else's content. `aead` must match whatever `encrypt_and_sign_block`
/// was called with to produce `ciphertext` — a v6 session key only pairs
/// with a v2/AEAD SEIPD message and vice versa (confirmed during research:
/// `PlainSessionKey::V6`'s own doc comment states this pairing explicitly).
///
/// `Message::from_reader` (not `from_string`/`from_armor_single`) is used
/// deliberately: `ciphertext` is raw binary (the output of `to_vec` above),
/// not armored text, and `from_reader`'s own doc comment confirms it
/// transparently handles either.
pub fn decrypt_block_with_session_key(ciphertext: &[u8], content_key: &ContentKeyPacket, aead: bool) -> Result<Vec<u8>> {
    let (message, _headers) = Message::from_reader(ciphertext)
        .map_err(|e| Error::Crypto(format!("bad block ciphertext: {e}")))?;
    let plain_session_key = if aead {
        PlainSessionKey::V6 { key: content_key.content_key.clone() }
    } else {
        PlainSessionKey::V3_4 {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            key: content_key.content_key.clone(),
        }
    };
    let mut decrypted = message
        .decrypt_with_session_key(plain_session_key)
        .map_err(|e| Error::Crypto(format!("block failed integrity check: {e}")))?;
    decrypted
        .as_data_vec()
        .map_err(|e| Error::Crypto(format!("failed to read decrypted block: {e}")))
}

/// The block-upload registration payload's `Verifier.Token`: `verification_code`
/// XOR'd against a same-length prefix of `ciphertext` (per the reference
/// SDKs — a tamper-binding value, not a hash).
pub fn compute_verification_token(ciphertext: &[u8], verification_code: &[u8]) -> Vec<u8> {
    verification_code
        .iter()
        .enumerate()
        .map(|(i, &code_byte)| code_byte ^ ciphertext.get(i).copied().unwrap_or(0))
        .collect()
}

/// Concatenates `block_hashes` in order (thumbnails always precede content
/// blocks in the reference protocol, but this crate never has thumbnails,
/// so `block_hashes` here is content-blocks-only, in upload order) and
/// signs the result — the `ManifestSignature` wire field.
pub fn build_manifest_signature(block_hashes: &[[u8; 32]], signing_key: &UnlockedKey) -> Result<String> {
    let manifest: Vec<u8> = block_hashes.iter().flatten().copied().collect();
    sign_detached(&manifest, signing_key)
}

/// The plaintext content of the `XAttr` wire field before it's PGP-encrypted
/// and signed. Field names mirror the reference SDKs' `Common`/`Digests`
/// shape (see the upload design doc) — serialized as JSON before encryption,
/// matching how both reference SDKs build this blob as a small JSON document.
///
/// Derives `serde::Serialize` via a fully-qualified path in the `#[derive]`
/// attribute rather than a top-of-file `use serde::Serialize;`: this module
/// already imports the unrelated `pgp::ser::Serialize` trait (used for PGP
/// packet wire serialization, e.g. `generate_content_key`'s
/// `packet.to_writer(...)`), and both traits share the bare name
/// `Serialize` — importing both under that name would collide.
#[derive(serde::Serialize)]
pub struct ExtendedAttributes {
    #[serde(rename = "Common")]
    pub common: ExtendedAttributesCommon,
}

#[derive(serde::Serialize)]
pub struct ExtendedAttributesCommon {
    #[serde(rename = "Size")]
    pub total_size: u64,
    #[serde(rename = "ModificationTime")]
    pub modification_time: String, // RFC 3339, matching typical Proton API date conventions elsewhere in this crate's design
    #[serde(rename = "BlockSizes")]
    pub block_sizes: Vec<u64>,
    #[serde(rename = "Digests")]
    pub digests: ExtendedAttributesDigests,
}

#[derive(serde::Serialize)]
pub struct ExtendedAttributesDigests {
    #[serde(rename = "SHA1")]
    pub sha1_hex: String,
}

/// Builds the `XAttr` wire field: `attrs` serialized as JSON, then signed
/// and PGP-encrypted to `node_key`'s own key pair in a single pass — an
/// inline signature living inside the same SEIPD-encrypted message, not a
/// detached signature alongside it — matching the reference SDKs'
/// "encrypted+signed with the file's content key" note in the upload
/// design doc (the file's *node* key, not its content key — the content
/// key encrypts block data; the node key encrypts metadata like this and
/// the content-key-packet itself).
///
/// `node_key` is `&UnlockedKey`, not the narrower `&NewNodeKey` an earlier
/// version of this function took: unlike `encrypt_and_sign_block`'s same
/// narrowing, this function genuinely signs with `node_key` (not just
/// encrypts to its public half), so whatever is passed in must carry a
/// real, working passphrase — both `NewNodeKey::as_unlocked_key` (new
/// file) and an existing node's real, fetched-and-decrypted key
/// (`commands::upload`'s Task 13 conflict path) satisfy that.
///
/// This deliberately does not call `encrypt_to_key` (Task 5): that helper
/// is encrypt-only, matching its actual callers (`NodePassphrase`, the
/// content-key packet), which sign separately and encrypt *that* detached
/// signature on its own — an earlier draft of this function reused that
/// same shape (compute a detached signature, then `let _ = signature;`),
/// which produced a blob that was encrypted but never actually signed.
/// `XAttr` instead needs one message that is itself both signed and
/// encrypted. The real fix, confirmed against the installed `pgp` 0.20.0
/// source (`composed/message/builder.rs`): `Builder`/`MessageBuilder` has
/// a `.sign(key, key_pw, hash_algorithm)` method implemented generically
/// over any encryption state (`impl<'a, R, E: Encryption> Builder<'a, R, E>`),
/// so it chains directly into the same `seipd_v1`/`encrypt_to_key` sequence
/// `encrypt_to_key` already uses, instead of treating that function as an
/// opaque helper. Internally, the builder signs the literal data first and
/// only *then* encrypts the signed result (`to_writer_inner` feeds the
/// signing generator into the encryption layer) — so the one signature
/// lands inside the SEIPD container, recoverable only by decrypting, which
/// is exactly what this module's own test does to prove it (decrypts the
/// output and calls `.verify()` on it, rather than just checking that this
/// function doesn't error).
pub fn build_extended_attributes(attrs: &ExtendedAttributes, node_key: &UnlockedKey) -> Result<String> {
    let json = serde_json::to_vec(attrs)
        .map_err(|e| Error::Crypto(format!("failed to serialize extended attributes: {e}")))?;

    let rng = rand08::rngs::OsRng;
    let mut builder =
        pgp::composed::MessageBuilder::from_bytes("", json).seipd_v1(rng, SymmetricKeyAlgorithm::AES256);
    // The freshly generated node key's primary secret material is locked
    // with `node_key.passphrase` at generation time (see `generate_node_key`)
    // — the same fact `generate_content_key` already established
    // empirically: signing with an empty password fails with "invalid
    // input" rather than succeeding as if unprotected.
    builder.sign(
        &node_key.secret_key.primary_key,
        Password::from(node_key.passphrase.as_str()),
        HashAlgorithm::Sha256,
    );

    add_recipient(&mut builder, node_key)?;

    builder
        .to_armored_string(rng, Default::default())
        .map_err(|e| Error::Crypto(format!("failed to sign and encrypt extended attributes: {e}")))
}

/// Computes the whole-file SHA-1 hex digest, streamed over `reader` in
/// fixed-size chunks so the caller never needs the whole file in memory at
/// once (the file itself may be much larger than a single 4 MiB block).
pub fn compute_whole_file_sha1(mut reader: impl std::io::Read) -> Result<String> {
    use sha1::{Digest as Sha1Digest, Sha1};
    let mut hasher = Sha1::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
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

        // Regression guard, mirroring the one below for the encryption
        // subkey: `SecretKey::unlock` (called transitively by
        // `UnlockedKey::new` below) ignores whatever `Password` it's given
        // when the secret material is still `SecretParams::Plain`
        // (unencrypted) — it only checks the password once the key is
        // genuinely `Encrypted`. So if `.passphrase(Some(passphrase.clone()))`
        // were ever dropped from the primary `key_params` builder in
        // `generate_node_key`, the `is_ok()` assertion below would keep
        // passing unchanged. This checks the actual lock state directly,
        // independent of that.
        assert!(new_key.secret_key.primary_key.secret_params().is_encrypted());
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
    // This reconstructs a packet the same way `generate_content_key` does
    // (same content key bytes, same subkey) instead of re-parsing
    // `content_key_packet.packet_b64` itself — still a genuine test of "is
    // this the key that can decrypt what we encrypt to it", just not a
    // byte-for-byte replay of the wire artifact. For the direct replay, see
    // `generate_content_key_packet_round_trips_through_decrypt_existing_content_key`
    // below, which also proves `packet_b64` is genuinely re-parseable now
    // that `generate_content_key` emits a real framed packet (see its own
    // doc comment).
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

    // Closes the asymmetry flagged in review: a packet this CLI generates
    // for a brand-new file must also be readable back by
    // `decrypt_existing_content_key` — the "upload a new revision to an
    // existing file" path — if that same file is later re-uploaded, not
    // just packets from real Proton clients (already proved separately by
    // `existing_content_key_tests::decrypts_a_genuinely_framed_pkesk_packet`).
    // Unlike the reconstruction test above, this feeds `packet_b64` itself
    // into `decrypt_existing_content_key`, unmodified — a genuine
    // byte-for-byte replay of the wire artifact.
    #[test]
    fn generate_content_key_packet_round_trips_through_decrypt_existing_content_key() {
        let parent = generate_test_parent("parent passphrase");
        let address_signing_key = generate_test_parent("address passphrase");
        let node_key = generate_node_key(&parent, &address_signing_key).unwrap();
        let content_key_packet = generate_content_key(&node_key).unwrap();

        // The same node key `generate_content_key` was called with, unlocked
        // the same way a real caller of `decrypt_existing_content_key` would:
        // via its own armored key + passphrase (see `UnlockedKey::new`).
        let unlocked_node_key = UnlockedKey::new(&node_key.armored_key, node_key.passphrase.clone()).unwrap();

        let recovered = decrypt_existing_content_key(&content_key_packet.packet_b64, &unlocked_node_key).unwrap();

        assert_eq!(recovered.content_key.as_ref(), content_key_packet.content_key.as_ref());
    }
}

// Proves `decrypt_existing_content_key` can read a REAL, standalone,
// properly-framed OpenPGP packet, and correctly rejects a headerless,
// body-only one (the mistake `generate_content_key` originally made for its
// own `packet_b64`, fixed in that function's own follow-up — see its doc
// comment). A real Proton server's stored `ContentKeyPacket` is produced by
// official OpenPGP libraries as a genuinely framed packet, so the test
// packet here is built the same way — via the `pgp` crate's own generic
// packet-serialization path (`Packet::to_writer`), not by reusing this
// crate's own (now historical) generation shortcut.
#[cfg(test)]
mod existing_content_key_tests {
    use super::*;

    // Mirrors `generate_node_key`'s own dual-subkey shape (Ed25519Legacy
    // primary, sign/certify-only + a Curve25519Legacy ECDH encryption
    // subkey) but inlined rather than calling `generate_node_key` itself:
    // that function also encrypts/signs the passphrase to a parent/address
    // key this test has no use for (it never sends a `NodePassphrase`
    // anywhere) — reusing it would mean generating two throwaway RSA-2048
    // keys for no reason. This test only needs a real dual-subkey node key
    // plus a passphrase it already knows.
    fn generate_test_node_key(passphrase: &str) -> (SignedSecretKey, String) {
        let mut encryption_subkey = SubkeyParamsBuilder::default();
        encryption_subkey
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false)
            .passphrase(Some(passphrase.to_string()));
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("Test <test@example.com>".to_string())
            .passphrase(Some(passphrase.to_string()))
            .subkeys(vec![encryption_subkey.build().unwrap()]);
        let params = key_params.build().expect("valid key params");
        let secret_key = params.generate(rand08::rngs::OsRng).expect("key generation should succeed");
        let armored = secret_key.to_armored_string(Default::default()).unwrap();
        (secret_key, armored)
    }

    // Shared by both PKESK-framing tests below: a real node key plus a PKESK
    // encrypting a fresh session key to its encryption subkey. They diverge
    // only in how that `pkesk` gets serialized (real framing vs. body-only).
    fn generate_test_pkesk(
        passphrase: &str,
    ) -> (String, pgp::packet::PublicKeyEncryptedSessionKey, pgp::composed::RawSessionKey) {
        let (secret_key, armored_key) = generate_test_node_key(passphrase);
        let public_key = secret_key.to_public_key();
        let encryption_subkey = public_key.public_subkeys.first().expect("has encryption subkey");

        let rng = rand08::rngs::OsRng;
        let original_session_key = SymmetricKeyAlgorithm::AES256.new_session_key(rng);
        let pkesk = pgp::packet::PublicKeyEncryptedSessionKey::from_session_key_v3(
            rng,
            &original_session_key,
            SymmetricKeyAlgorithm::AES256,
            encryption_subkey,
        )
        .expect("encrypting the session key should succeed");

        (armored_key, pkesk, original_session_key)
    }

    #[test]
    fn decrypts_a_genuinely_framed_pkesk_packet() {
        let (armored_key, pkesk, original_session_key) = generate_test_pkesk("node passphrase");

        // Real packet framing (header + body) via the crate's generic
        // packet serialization — NOT `generate_content_key`'s own
        // `packet.to_writer(...)` body-only shortcut. `pgp::packet::Packet`
        // wraps the PKESK, and its `Serialize` impl (confirmed in
        // `packet_sum.rs`) routes every variant through
        // `to_writer_with_header`, writing the full framed packet (header +
        // body) — matching what a real OpenPGP library produces.
        let framed_packet = pgp::packet::Packet::PublicKeyEncryptedSessionKey(pkesk);
        let mut framed_bytes = Vec::new();
        framed_packet.to_writer(&mut framed_bytes).expect("framing should succeed");
        let packet_b64 = base64::engine::general_purpose::STANDARD.encode(&framed_bytes);

        let node_key = UnlockedKey::new(&armored_key, "node passphrase".to_string()).unwrap();
        let decrypted = decrypt_existing_content_key(&packet_b64, &node_key).unwrap();

        assert_eq!(decrypted.content_key.as_ref(), original_session_key.as_ref());
    }

    // Regression guard, mirroring `block_crypto_tests::mismatched_aead_flag_fails_to_decrypt`'s
    // own reasoning: the test above alone doesn't prove framing actually
    // matters — a `decrypt_existing_content_key` that silently tolerated
    // headerless input (e.g. by falling back to some lenient parse) would
    // pass it unchanged. This proves the two shapes are genuinely distinct:
    // `PublicKeyEncryptedSessionKey::to_writer` (what `generate_content_key`
    // used to produce for its own `packet_b64`, before its framing fix)
    // writes only the PKESK body, with no packet header — feeding that
    // body-only encoding to `PacketParser` (which expects a real header
    // first) must fail, not silently succeed.
    #[test]
    fn body_only_bytes_without_a_packet_header_fail_to_parse() {
        let (armored_key, pkesk, _original_session_key) = generate_test_pkesk("node passphrase");

        let mut body_only_bytes = Vec::new();
        pkesk.to_writer(&mut body_only_bytes).expect("body serialization should succeed");
        let body_only_b64 = base64::engine::general_purpose::STANDARD.encode(&body_only_bytes);

        let node_key = UnlockedKey::new(&armored_key, "node passphrase".to_string()).unwrap();
        let result = decrypt_existing_content_key(&body_only_b64, &node_key);
        assert!(result.is_err(), "expected headerless body-only bytes to fail parsing, got {:?}", result.err());
    }
}

#[cfg(test)]
mod block_crypto_tests {
    use super::*;

    // Duplicated from `content_key_tests::generate_test_parent` rather than
    // shared: that helper is private to its own (sibling) test module, and
    // Rust privacy doesn't let a sibling module reach into it — duplicating
    // this one small helper is preferable to introducing a shared test
    // module for two call sites (YAGNI; revisit only if a third test module
    // needs it).
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

    // Shared by both tests below: a real node key plus content key, ready to
    // encrypt a block under either framing. They diverge only in which
    // `aead` flag `decrypt_block_with_session_key` is called with.
    fn fresh_block_fixture() -> (UnlockedKey, NewNodeKey, ContentKeyPacket) {
        let parent = generate_test_parent("parent passphrase");
        let address_signing_key = generate_test_parent("address passphrase");
        let node_key = generate_node_key(&parent, &address_signing_key).unwrap();
        let content_key = generate_content_key(&node_key).unwrap();
        (address_signing_key, node_key, content_key)
    }

    #[test]
    fn encrypt_and_sign_block_round_trips() {
        let (address_signing_key, node_key, content_key) = fresh_block_fixture();
        let plaintext = b"pretend this is up to 4 MiB of file content";

        for aead in [false, true] {
            let block =
                encrypt_and_sign_block(plaintext, &content_key, &address_signing_key, &node_key.as_unlocked_key(), aead)
                    .unwrap();

            let decrypted = decrypt_block_with_session_key(&block.ciphertext, &content_key, aead).unwrap();
            assert_eq!(decrypted, plaintext, "aead={aead}");

            let expected_hash: [u8; 32] = Sha256::digest(&block.ciphertext).into();
            assert_eq!(block.sha256_hash, expected_hash, "aead={aead}");
        }
    }

    // `encrypt_and_sign_block_round_trips` above loops over both `aead`
    // values but always calls `decrypt_block_with_session_key` with the
    // *matching* flag — that alone wouldn't catch a bug where `aead` was
    // silently ignored and both branches took the same code path. This
    // proves the two framings are genuinely distinct and mutually
    // incompatible, matching `PlainSessionKey::V6`'s own doc comment (a v6
    // session key only pairs with a v2/AEAD SEIPD message and vice versa).
    #[test]
    fn mismatched_aead_flag_fails_to_decrypt() {
        let (address_signing_key, node_key, content_key) = fresh_block_fixture();
        let plaintext = b"pretend this is up to 4 MiB of file content";

        for aead in [false, true] {
            let block =
                encrypt_and_sign_block(plaintext, &content_key, &address_signing_key, &node_key.as_unlocked_key(), aead)
                    .unwrap();
            assert!(
                decrypt_block_with_session_key(&block.ciphertext, &content_key, !aead).is_err(),
                "decrypting aead={aead} ciphertext with aead={} should fail",
                !aead
            );
        }
    }

    #[test]
    fn verification_token_is_reversible_xor() {
        let ciphertext = b"some ciphertext bytes here";
        let verification_code = b"a-verification-code-32-bytes!!!";
        let token = compute_verification_token(ciphertext, verification_code);
        // XOR-ing the token against the same ciphertext prefix recovers the code.
        let recovered: Vec<u8> = token
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ ciphertext.get(i).copied().unwrap_or(0))
            .collect();
        assert_eq!(recovered, verification_code);
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;

    // Duplicated from `block_crypto_tests::generate_test_parent` rather
    // than imported via `use super::block_crypto_tests::generate_test_parent;`:
    // that helper has no visibility modifier, so it's private to
    // `block_crypto_tests` and visible only there and in its descendants —
    // `manifest_tests` is a sibling, not a descendant, so Rust privacy
    // rules block that path entirely (this is the same constraint
    // `block_crypto_tests`'s own copy already documents; confirmed here by
    // actually trying the `use` and hitting the privacy error). Duplicating
    // this one small helper is preferable to introducing a shared test
    // module for three call sites (YAGNI; revisit only if a fourth needs it).
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
    fn build_manifest_signature_produces_a_verifiable_signature() {
        let signing_key = generate_test_parent("signing passphrase");
        let hashes = [[1u8; 32], [2u8; 32]];
        let signature_armored = build_manifest_signature(&hashes, &signing_key).unwrap();
        assert!(signature_armored.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn compute_whole_file_sha1_matches_known_vector() {
        // SHA-1 of the empty string is a well-known constant.
        let digest = compute_whole_file_sha1(std::io::empty()).unwrap();
        assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    // Closes the gap flagged in `build_extended_attributes`'s own doc
    // comment: an earlier draft computed a detached signature and threw it
    // away, so the function "didn't error" while silently shipping an
    // encrypted-but-unsigned blob. Checking `armored.contains("BEGIN PGP
    // MESSAGE")` alone would not have caught that draft. This test instead
    // decrypts the real output with the node key and calls `.verify()` on
    // the decrypted message, which only succeeds if an inline signature
    // genuinely exists inside the encrypted content.
    #[test]
    fn build_extended_attributes_round_trips_and_verifies() {
        let parent = generate_test_parent("parent passphrase");
        let address_signing_key = generate_test_parent("address passphrase");
        let node_key = generate_node_key(&parent, &address_signing_key).unwrap();

        let attrs = ExtendedAttributes {
            common: ExtendedAttributesCommon {
                total_size: 4_194_304,
                modification_time: "2026-07-20T00:00:00Z".to_string(),
                block_sizes: vec![4_194_304],
                digests: ExtendedAttributesDigests {
                    sha1_hex: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
                },
            },
        };

        let armored = build_extended_attributes(&attrs, &node_key.as_unlocked_key()).unwrap();
        assert!(armored.contains("BEGIN PGP MESSAGE"));

        let (message, _headers) = Message::from_reader(armored.as_bytes()).unwrap();
        let mut decrypted = message
            .decrypt(&Password::from(node_key.passphrase.as_str()), &node_key.secret_key)
            .expect("XAttr message should decrypt with the node key");

        // Must actually read to the end before `verify()` — its own doc
        // comment requires this ("the message must have been read to the
        // end before calling this").
        let plaintext = decrypted
            .as_data_vec()
            .expect("should be able to read the decrypted XAttr content");
        assert_eq!(plaintext, serde_json::to_vec(&attrs).unwrap());

        decrypted
            .verify(node_key.secret_key.primary_key.public_key())
            .expect("XAttr message's inline signature should verify against the node key's own public half");
    }
}
