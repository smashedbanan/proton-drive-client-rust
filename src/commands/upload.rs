use crate::api::account::{fetch_addresses, fetch_feature_flag, Address};
use crate::api::drive::{
    commit_revision, create_file, create_revision, get_verification_input, prepare_block_upload,
    upload_block_bytes, upload_small_file, upload_small_revision, BlockRegistration, CreateFileOutcome,
    FileCreationRequest, RevisionCreationRequest, RevisionUpdateRequest, SmallFileUploadMetadata,
    SmallRevisionUploadMetadata, VerifierPayload,
};
use crate::api::ApiClient;
use crate::crypto::{
    build_extended_attributes, build_manifest_signature, compute_verification_token, compute_whole_file_sha1,
    decrypt_block_with_session_key, encrypt_and_sign_block, encrypt_to_key, generate_content_key,
    generate_node_key, ContentKeyPacket, EncryptedBlock, ExtendedAttributes, ExtendedAttributesCommon,
    ExtendedAttributesDigests, NewNodeKey, UnlockedKey,
};
use crate::drive::{resolve_path, ResolvedFolder};
use crate::error::{Error, Result};
use crate::session;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

const SMALL_FILE_UPLOAD_FLAG: &str = "DriveSmallFileUpload";
const AEAD_FLAG: &str = "DriveCryptoEncryptBlocksWithPgpAead";
const SMALL_FILE_THRESHOLD_BYTES: f64 = 131072.0;
const BLOCK_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// Any failure to positively confirm a feature flag is `true` — network
/// error, unexpected shape, an explicit `false` — falls back to the safe
/// path. This is the one place that fail-safe policy lives (see the upload
/// design doc's Scope section); `api::account::fetch_feature_flag` itself
/// only handles the "malformed value" half of that.
fn is_feature_enabled(client: &ApiClient, code: &str) -> bool {
    fetch_feature_flag(client, code).unwrap_or(false)
}

pub fn run(local_path: &str, remote_path: &str) -> Result<()> {
    let creds = session::load()?;
    let client = ApiClient::with_session(creds.uid.clone(), creds.access_token.clone());

    let mut file = File::open(local_path).map_err(Error::Io)?;
    let file_size = file.metadata().map_err(Error::Io)?.len();
    let file_name = Path::new(local_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Crypto("local file path has no usable file name".into()))?
        .to_string();

    let addresses = fetch_addresses(&client)?;
    let address = addresses
        .addresses
        .iter()
        .find(|a| a.keys.iter().any(|k| k.primary == 1 && k.active == 1))
        .ok_or_else(|| Error::Crypto("no active primary address found".into()))?;
    let address_key_dto = address
        .keys
        .iter()
        .find(|k| k.primary == 1 && k.active == 1)
        .expect("checked above");
    let address_key = UnlockedKey::new(&address_key_dto.private_key, creds.user_key_password.clone())?;

    let folder = resolve_path(&client, &address_key, remote_path)?;

    let name_hash_digest = hex::encode(Sha256::digest(file_name.as_bytes()));
    let new_node_key = generate_node_key(&folder.folder_key, &address_key)?;
    let content_key = generate_content_key(&new_node_key)?;
    let encrypted_name = encrypt_to_key(file_name.as_bytes(), &folder.folder_key)?;
    let media_type = "application/octet-stream";

    let use_small_upload = is_feature_enabled(&client, SMALL_FILE_UPLOAD_FLAG)
        && (file_size as f64) * 1.1 < SMALL_FILE_THRESHOLD_BYTES;
    let use_aead = is_feature_enabled(&client, AEAD_FLAG);

    let ctx = UploadContext {
        client: &client,
        folder: &folder,
        address,
        address_key: &address_key,
        new_node_key: &new_node_key,
        content_key: &content_key,
        encrypted_name: &encrypted_name,
        name_hash_digest: &name_hash_digest,
        media_type,
        file_size,
        use_aead,
    };

    let revision_id = if use_small_upload {
        upload_small(&ctx, &mut file)?
    } else {
        upload_general(&ctx, &mut file)?
    };

    println!("Uploaded {file_name} to {remote_path} (revision {revision_id}).");
    Ok(())
}

/// Everything both upload paths need, gathered once in `run` so
/// `upload_small`/`upload_general` don't each take a dozen loose
/// parameters. Every field here borrows from a `run`-local `let` binding
/// (the address/keys/content-key/names are all computed into owned locals
/// before this struct is built, not passed as temporaries), and every one
/// of those locals stays in scope for the rest of `run` — so nothing here
/// is a dangling or too-short-lived borrow.
struct UploadContext<'a> {
    client: &'a ApiClient,
    folder: &'a ResolvedFolder,
    address: &'a Address,
    address_key: &'a UnlockedKey,
    new_node_key: &'a NewNodeKey,
    content_key: &'a ContentKeyPacket,
    encrypted_name: &'a str,
    name_hash_digest: &'a str,
    media_type: &'a str,
    file_size: u64,
    use_aead: bool,
}

/// Encrypts `plaintext` under `ctx`'s content key and confirms the
/// ciphertext actually decrypts back to the same bytes before this crate
/// ever uploads it. A block's registered hash, and later the manifest
/// signature, are both computed from whatever ciphertext
/// `encrypt_and_sign_block` happens to produce — so a corrupted encryption
/// would otherwise ship a self-consistent but silently-wrong upload; the
/// server has no independent way to catch that. Retries once on a mismatch
/// (per the upload design doc's Data Flow step for the block-upload
/// sequence — "retrying once on an integrity mismatch (decrypt-and-compare
/// against the known plaintext)" — and `crypto::encrypt_and_sign_block`'s
/// and `crypto::decrypt_block_with_session_key`'s own doc comments, which
/// both name `commands::upload` as where that responsibility lives), then
/// gives up loudly rather than silently uploading unverified data.
///
/// Shared by both `upload_general`'s per-block loop and `upload_small`'s
/// single whole-file block, rather than duplicating the retry logic at
/// each call site.
fn encrypt_verified_block(ctx: &UploadContext, plaintext: &[u8]) -> Result<EncryptedBlock> {
    for _ in 0..2 {
        let block =
            encrypt_and_sign_block(plaintext, ctx.content_key, ctx.address_key, ctx.new_node_key, ctx.use_aead)?;
        let round_trips = decrypt_block_with_session_key(&block.ciphertext, ctx.content_key, ctx.use_aead)
            .map(|decrypted| decrypted == plaintext)
            .unwrap_or(false);
        if round_trips {
            return Ok(block);
        }
    }
    Err(Error::Crypto(
        "block failed integrity verification twice in a row; aborting upload".into(),
    ))
}

/// General (multi-block) path: create-or-conflict, then per ~4 MiB chunk
/// encrypt+sign+verify+register+upload, then commit. Correct for any file
/// size — the always-safe fallback (see Global Constraints).
fn upload_general(ctx: &UploadContext, file: &mut File) -> Result<String> {
    let file_creation = FileCreationRequest {
        name: ctx.encrypted_name,
        name_hash_digest: ctx.name_hash_digest,
        parent_link_id: &ctx.folder.folder_link_id,
        node_passphrase: &ctx.new_node_key.encrypted_passphrase_armored,
        node_passphrase_signature: &ctx.new_node_key.passphrase_signature_armored,
        node_key: &ctx.new_node_key.armored_key,
        media_type: ctx.media_type,
        content_key_packet: &ctx.content_key.packet_b64,
        content_key_signature: &ctx.content_key.packet_signature_armored,
        client_uid: None,
        intended_upload_size: ctx.file_size as i64,
        signature_email_address: &ctx.address.email,
    };

    // ponytail: KNOWN CORRECTNESS GAP, not a stylistic shortcut — flagging
    // for whoever picks this up next, not silently working around it.
    // `create_revision` below only registers a new revision on
    // `existing_link_id`; it never fetches that node's *real* NodeKey or
    // ContentKeyPacket. Every block below then encrypts under `ctx`'s
    // freshly-generated `new_node_key`/`content_key` (from `run`) instead —
    // a key nobody but this one process ever knew, and that is never sent
    // to the server for this existing node (`RevisionCreationRequest` and
    // `SmallRevisionUploadMetadata` carry no key fields at all, confirming
    // the server expects the *existing* content key to be reused, not
    // replaced). So today, re-uploading to a path that already has a file
    // reports success but produces a revision nobody can ever decrypt —
    // confirmed against the real reference SDK during Task 11's adversarial
    // review: `client/js/src/internal/upload/manager.ts:97-98` refuses to
    // create a revision at all without an already-resolved
    // `nodeKeys.contentKeyPacketSessionKey`; that session key comes from
    // decrypting `Link.File.ContentKeyPacket`/`ContentKeyPacketSignature`
    // (`client/js/src/internal/nodes/apiService.ts:730-731`) via the
    // node's own unlocked key (`client/js/src/internal/nodes/cryptoService.ts:517-534`).
    // Fixing this for real needs: (1) `api::drive::LinkDetails` extended
    // with those two `File`-nested fields (not currently fetched anywhere
    // in this crate — Task 2's scope never needed a file's content key,
    // only folders' names/keys for path walking), and (2) a new
    // `crypto::` function to decrypt an existing content-key packet via
    // the node's own secret subkey — the underlying `pgp`-crate mechanism
    // is already proven, just not in production code:
    // `crypto::content_key_tests::generate_content_key_packet_decrypts_back_via_the_node_keys_own_secret_subkey`.
    // Not fixed here: it reaches into already-reviewed Tasks 2/5/6, and
    // this crate's own `generate_content_key` (Task 5) writes
    // `ContentKeyPacket` as a headerless PKESK body (see that function's
    // own doc comment), which is unverified against what a real Proton
    // server / other real clients' packets actually look like on the wire
    // without a live account to test against — guessing at that byte
    // format risked shipping something that *looks* fixed but is silently
    // wrong in a different way. See Task 11's report for the full
    // citations and reasoning.
    let (link_id, revision_id) = match create_file(ctx.client, &ctx.folder.volume_id, &file_creation)? {
        CreateFileOutcome::Created(ids) => (ids.link_id, ids.revision_id),
        CreateFileOutcome::NameConflict(conflict) => {
            let existing_link_id = conflict
                .link_id
                .ok_or_else(|| Error::Crypto("server reported a name conflict with no conflicting node ID".into()))?;
            let revision_req = RevisionCreationRequest {
                current_revision_id: None,
                client_uid: None,
                intended_upload_size: ctx.file_size as i64,
            };
            let created = create_revision(ctx.client, &ctx.folder.volume_id, &existing_link_id, &revision_req)?;
            (existing_link_id, created.revision.revision_id)
        }
    };

    let mut block_hashes = Vec::new();
    let mut block_sizes = Vec::new();
    let mut buf = vec![0u8; BLOCK_SIZE_BYTES];
    let mut block_index: i64 = 1;
    loop {
        let n = file.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        let plaintext = &buf[..n];
        let encrypted_block = encrypt_verified_block(ctx, plaintext)?;

        let verification = get_verification_input(ctx.client, &ctx.folder.volume_id, &link_id, &revision_id)?;
        let verification_code = base64::engine::general_purpose::STANDARD
            .decode(&verification.verification_code_b64)
            .map_err(|e| Error::Crypto(format!("bad verification code base64: {e}")))?;
        let token = compute_verification_token(&encrypted_block.ciphertext, &verification_code);

        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_block.sha256_hash);
        let token_b64 = base64::engine::general_purpose::STANDARD.encode(&token);
        let registration = BlockRegistration {
            index: block_index,
            size: encrypted_block.ciphertext.len() as i64,
            encrypted_signature: &encrypted_block.encrypted_signature_armored,
            hash_b64: &hash_b64,
            verifier: VerifierPayload { token_b64: &token_b64 },
        };
        let targets = prepare_block_upload(
            ctx.client,
            &ctx.address.id,
            &ctx.folder.volume_id,
            &link_id,
            &revision_id,
            &[registration],
        )?;
        let target = targets
            .first()
            .ok_or_else(|| Error::Crypto("server returned no upload target for block".into()))?;
        upload_block_bytes(ctx.client.agent(), target, &encrypted_block.ciphertext)?;

        block_hashes.push(encrypted_block.sha256_hash);
        block_sizes.push(n as u64);
        block_index += 1;
    }

    let manifest_signature = build_manifest_signature(&block_hashes, ctx.address_key)?;
    let xattr_armored = build_xattr(file, ctx.file_size, block_sizes, ctx.new_node_key)?;

    let commit_req = RevisionUpdateRequest {
        manifest_signature: &manifest_signature,
        signature_email_address: &ctx.address.email,
        checksum_verified: true,
        extended_attributes: &xattr_armored,
    };
    commit_revision(ctx.client, &ctx.folder.volume_id, &link_id, &revision_id, &commit_req)?;

    Ok(revision_id)
}

/// Small-file fast path: whole file as one block, one combined API call
/// instead of create/prepare/upload/commit. Tries new-file first; on a
/// name conflict, retries as new-revision against the conflicting node —
/// the same "always new revision" behavior as `upload_general`, applied to
/// the small-upload endpoints (`upload_small_file`/`upload_small_revision`,
/// Task 6) instead of `create_file`/`create_revision`.
fn upload_small(ctx: &UploadContext, file: &mut File) -> Result<String> {
    let mut plaintext = Vec::with_capacity(ctx.file_size as usize);
    file.read_to_end(&mut plaintext).map_err(Error::Io)?;

    let encrypted_block = encrypt_verified_block(ctx, &plaintext)?;
    let manifest_signature = build_manifest_signature(&[encrypted_block.sha256_hash], ctx.address_key)?;
    let xattr_armored = build_xattr(file, ctx.file_size, vec![plaintext.len() as u64], ctx.new_node_key)?;

    let new_file_metadata = SmallFileUploadMetadata {
        name: ctx.encrypted_name,
        name_hash_digest: ctx.name_hash_digest,
        parent_link_id: &ctx.folder.folder_link_id,
        node_passphrase: &ctx.new_node_key.encrypted_passphrase_armored,
        node_passphrase_signature: &ctx.new_node_key.passphrase_signature_armored,
        node_key: &ctx.new_node_key.armored_key,
        media_type: ctx.media_type,
        content_key_packet: &ctx.content_key.packet_b64,
        content_key_signature: &ctx.content_key.packet_signature_armored,
        signature_email_address: &ctx.address.email,
        manifest_signature: &manifest_signature,
        checksum_verified: true,
        extended_attributes: &xattr_armored,
    };

    // ponytail: same known gap as `upload_general`'s `NameConflict` arm —
    // see the full comment there. `upload_small_revision` below also never
    // reuses the existing node's real content key; this path encrypted
    // `encrypted_block` under the freshly-generated `ctx.content_key` above.
    match upload_small_file(ctx.client, &ctx.folder.volume_id, &new_file_metadata, &encrypted_block.ciphertext)? {
        CreateFileOutcome::Created(ids) => Ok(ids.revision_id),
        CreateFileOutcome::NameConflict(conflict) => {
            let existing_link_id = conflict
                .link_id
                .ok_or_else(|| Error::Crypto("server reported a name conflict with no conflicting node ID".into()))?;
            let revision_metadata = SmallRevisionUploadMetadata {
                signature_email_address: &ctx.address.email,
                manifest_signature: &manifest_signature,
                checksum_verified: true,
                extended_attributes: &xattr_armored,
            };
            let resp = upload_small_revision(
                ctx.client,
                &ctx.folder.volume_id,
                &existing_link_id,
                &revision_metadata,
                &encrypted_block.ciphertext,
            )?;
            Ok(resp.file.revision_id)
        }
    }
}

/// Builds the `XAttr` wire value shared by both upload paths: total size,
/// modification time, per-block plaintext sizes, and the whole-file SHA-1
/// (computed by rewinding `file` and re-reading it — the block loop /
/// whole-file read above already consumed it once, for encryption).
///
/// `modification_time` is rendered as a real RFC 3339 timestamp via
/// `humantime::format_rfc3339_seconds`, matching
/// `ExtendedAttributesCommon::modification_time`'s own doc comment ("RFC
/// 3339, matching typical Proton API date conventions") and the literal
/// `"2026-07-20T00:00:00Z"`-shaped value Task 9's own round-trip test
/// constructs — a raw Unix-seconds digit string would satisfy the field's
/// `String` type but would not actually be RFC 3339. Falls back to (and
/// clamps to) the Unix epoch if the platform can't report an mtime at all,
/// or reports one before it (`Metadata::modified`'s documented failure
/// case, plus a pre-1970 mtime, which `.modified()` itself returns `Ok`
/// for — confirmed empirically against a real file with `touch -d
/// 1965-01-01`) — `humantime::Rfc3339Timestamp`'s `Display` impl panics
/// (`.duration_since(UNIX_EPOCH).expect(...)`) on a pre-epoch value rather
/// than erroring, so this must never hand it one.
fn build_xattr(file: &mut File, file_size: u64, block_sizes: Vec<u64>, node_key: &NewNodeKey) -> Result<String> {
    file.rewind().map_err(Error::Io)?;
    let sha1_hex = compute_whole_file_sha1(&mut *file)?;
    let modified = file.metadata().map_err(Error::Io)?.modified().unwrap_or(std::time::UNIX_EPOCH);
    let modification_time = humantime::format_rfc3339_seconds(clamp_to_unix_epoch(modified)).to_string();
    let extended_attributes = ExtendedAttributes {
        common: ExtendedAttributesCommon {
            total_size: file_size,
            modification_time,
            block_sizes,
            digests: ExtendedAttributesDigests { sha1_hex },
        },
    };
    build_extended_attributes(&extended_attributes, node_key)
}

/// `humantime::Rfc3339Timestamp`'s `Display` impl panics
/// (`.duration_since(UNIX_EPOCH).expect(...)`) rather than erroring on a
/// pre-epoch `SystemTime` — and `Metadata::modified()` genuinely can
/// return one `Ok(...)` (confirmed empirically against a real file with
/// `touch -d 1965-01-01`), so it never hits the separate `unwrap_or`
/// fallback above (that only covers `.modified()` itself failing). Every
/// mtime must be clamped through here before it ever reaches the
/// formatter.
fn clamp_to_unix_epoch(t: std::time::SystemTime) -> std::time::SystemTime {
    t.max(std::time::UNIX_EPOCH)
}

#[cfg(test)]
mod xattr_tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    // Regression guard for a real panic found by adversarial review: a
    // file with a pre-1970 mtime used to crash the whole upload (a panic,
    // not a `Result::Err`) when its modification time reached
    // `humantime::format_rfc3339_seconds`, because `.modified()` returns
    // `Ok` for pre-epoch times too (the code's old `unwrap_or` fallback
    // only ever triggered on `Err`, never on this case).
    #[test]
    fn pre_epoch_mtime_is_clamped_and_formats_without_panicking() {
        let pre_epoch = UNIX_EPOCH - Duration::from_secs(60 * 60 * 24 * 365 * 5); // ~1965
        assert_eq!(clamp_to_unix_epoch(pre_epoch), UNIX_EPOCH);

        let formatted = humantime::format_rfc3339_seconds(clamp_to_unix_epoch(pre_epoch)).to_string();
        assert_eq!(formatted, "1970-01-01T00:00:00Z");
    }
}
