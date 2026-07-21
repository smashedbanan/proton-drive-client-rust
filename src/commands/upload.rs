use crate::api::account::{fetch_addresses, fetch_feature_flag, Address, AddressesResponse};
use crate::api::drive::{
    commit_revision, create_file, create_revision, fetch_my_files_share, get_link_details, get_verification_input,
    prepare_block_upload, upload_block_bytes, upload_small_file, upload_small_revision, BlockRegistration,
    CreateFileOutcome, FileCreationRequest, NewNodeMetadata, RevisionCreationRequest, RevisionUpdateRequest,
    SmallFileUploadMetadata, VerifierPayload,
};
use crate::api::ApiClient;
use crate::crypto::{
    build_extended_attributes, build_manifest_signature, compute_verification_token, compute_whole_file_sha1,
    decrypt_block_with_session_key, decrypt_existing_content_key, decrypt_message, encrypt_and_sign_block,
    encrypt_to_key, generate_content_key, generate_node_key, ContentKeyPacket, EncryptedBlock, ExtendedAttributes,
    ExtendedAttributesCommon, ExtendedAttributesDigests, NewNodeKey, UnlockedKey,
};
use crate::drive::{resolve_path, verify_claim, warn_on_signature_failure, ResolvedFolder};
use crate::error::{Error, Result};
use crate::session;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
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

    let share = fetch_my_files_share(&client)?;
    let addresses = fetch_addresses(&client)?;
    let address = addresses
        .addresses
        .iter()
        .find(|a| a.id == share.share.membership_address_id)
        .ok_or_else(|| {
            Error::Crypto(format!(
                "no address found matching the My Files share's owning address ({})",
                share.share.membership_address_id
            ))
        })?;
    let address_key_dto = address
        .keys
        .iter()
        .find(|k| k.primary == 1 && k.active == 1)
        .ok_or_else(|| {
            Error::Crypto(format!("address {} (My Files share owner) has no active primary key", address.id))
        })?;
    let address_key = UnlockedKey::new(&address_key_dto.private_key, creds.user_key_password.clone())?;

    let folder = resolve_path(&client, share, &address_key, &addresses, &creds.user_key_password, remote_path)?;

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
        addresses: &addresses,
        key_password: &creds.user_key_password,
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
    addresses: &'a AddressesResponse,
    key_password: &'a str,
    new_node_key: &'a NewNodeKey,
    content_key: &'a ContentKeyPacket,
    encrypted_name: &'a str,
    name_hash_digest: &'a str,
    media_type: &'a str,
    file_size: u64,
    use_aead: bool,
}

/// Encrypts `plaintext` under `node_key`/`content_key` and confirms the
/// ciphertext actually decrypts back to the same bytes before this crate
/// ever uploads it. `node_key`/`content_key` are explicit parameters,
/// rather than read off `ctx` directly, because which ones are correct
/// varies per call: a freshly generated key/content-key for a brand-new
/// file (`ctx.new_node_key.as_unlocked_key()`/`ctx.content_key`), or an
/// existing node's real, fetched-and-decrypted ones on a name conflict
/// (Task 13's `resolve_existing_node_key_and_content_key`) — see that
/// function's own doc comment for why reusing the existing content key is
/// required, not optional. A block's registered hash, and later the
/// manifest signature, are both computed from whatever ciphertext
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
/// whole-file block (including its conflict-path re-encryption, Task 13),
/// rather than duplicating the retry logic at each call site.
fn encrypt_verified_block(
    ctx: &UploadContext,
    node_key: &UnlockedKey,
    content_key: &ContentKeyPacket,
    plaintext: &[u8],
) -> Result<EncryptedBlock> {
    for _ in 0..2 {
        let block = encrypt_and_sign_block(plaintext, content_key, ctx.address_key, node_key, ctx.use_aead)?;
        let round_trips = decrypt_block_with_session_key(&block.ciphertext, content_key, ctx.use_aead)
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

/// Resolves an EXISTING node's own key and content key, for the
/// conflict-to-new-revision path: reusing the existing content key is
/// required (see `crypto::generate_content_key`'s doc comment — a content
/// key is per-file, generated once, reused across every revision), not
/// optional. Unlocks the node's key using `ctx.folder.folder_key` — the
/// PARENT folder's already-unlocked key, the same one that encrypted this
/// existing node's `NodePassphrase`/`Name` in the first place — exactly
/// mirroring the decrypt-passphrase-then-`UnlockedKey::new` pattern
/// `drive::resolve_path` already uses for every folder it walks through.
fn resolve_existing_node_key_and_content_key(
    ctx: &UploadContext,
    existing_link_id: &str,
) -> Result<(UnlockedKey, ContentKeyPacket)> {
    let details = get_link_details(ctx.client, &ctx.folder.volume_id, &[existing_link_id.to_string()])?;
    let link = details
        .links
        .first()
        .ok_or_else(|| Error::Crypto("server returned no details for the conflicting node".into()))?;
    let node_passphrase = decrypt_message(&link.node_passphrase, &ctx.folder.folder_key)?;
    warn_on_signature_failure(
        &format!("conflicting node {existing_link_id}'s passphrase"),
        verify_claim(
            link.signature_email.as_deref(),
            ctx.addresses,
            ctx.key_password,
            Some(&ctx.folder.folder_key),
            link.node_passphrase_signature.as_deref(),
            node_passphrase.as_bytes(),
        ),
    );
    let node_key = UnlockedKey::new(&link.node_key, node_passphrase)?;
    let file_details = link
        .file
        .as_ref()
        .ok_or_else(|| Error::Crypto("conflicting node has no file content-key material".into()))?;
    let content_key = decrypt_existing_content_key(&file_details.content_key_packet, &node_key)?;
    warn_on_signature_failure(
        &format!("conflicting node {existing_link_id}'s content-key packet"),
        verify_claim(
            link.signature_email.as_deref(),
            ctx.addresses,
            ctx.key_password,
            Some(&ctx.folder.folder_key),
            Some(file_details.content_key_packet_signature.as_str()),
            content_key.content_key.as_ref(),
        ),
    );
    Ok((node_key, content_key))
}

/// The new-node fields both upload paths need on a brand-new file: `ctx`'s
/// freshly generated node key/content key, not yet anything server-assigned.
fn new_node_metadata<'a>(ctx: &UploadContext<'a>) -> NewNodeMetadata<'a> {
    NewNodeMetadata {
        name: ctx.encrypted_name,
        name_hash_digest: ctx.name_hash_digest,
        parent_link_id: &ctx.folder.folder_link_id,
        node_passphrase: &ctx.new_node_key.encrypted_passphrase_armored,
        node_passphrase_signature: &ctx.new_node_key.passphrase_signature_armored,
        node_key: &ctx.new_node_key.armored_key,
        media_type: ctx.media_type,
        content_key_packet: &ctx.content_key.packet_b64,
        content_key_signature: &ctx.content_key.packet_signature_armored,
    }
}

/// General (multi-block) path: create-or-conflict, then per ~4 MiB chunk
/// encrypt+sign+verify+register+upload, then commit. Correct for any file
/// size — the always-safe fallback (see Global Constraints).
fn upload_general(ctx: &UploadContext, file: &mut File) -> Result<String> {
    let file_creation = FileCreationRequest {
        node: new_node_metadata(ctx),
        client_uid: None,
        intended_upload_size: ctx.file_size as i64,
        signature_email_address: &ctx.address.email,
    };

    // Reuses the existing node's real key/content-key on a name conflict
    // (Task 13) instead of `ctx`'s freshly-generated ones: `create_revision`
    // below only registers a new revision, it never resolves key material
    // by itself — see `resolve_existing_node_key_and_content_key`'s doc
    // comment for why the existing content key specifically must be
    // reused, never replaced (confirmed against the real reference SDK
    // during Task 11's adversarial review; see that task's report).
    let (link_id, revision_id, node_key_for_blocks, content_key_for_blocks) =
        match create_file(ctx.client, &ctx.folder.volume_id, &file_creation)? {
            CreateFileOutcome::Created(ids) => {
                (ids.link_id, ids.revision_id, ctx.new_node_key.as_unlocked_key(), ctx.content_key.clone())
            }
            CreateFileOutcome::NameConflict(conflict) => {
                let existing_link_id = conflict.link_id.ok_or_else(|| {
                    Error::Crypto("server reported a name conflict with no conflicting node ID".into())
                })?;
                let revision_req = RevisionCreationRequest {
                    current_revision_id: None,
                    client_uid: None,
                    intended_upload_size: ctx.file_size as i64,
                };
                let created = create_revision(ctx.client, &ctx.folder.volume_id, &existing_link_id, &revision_req)?;
                let (node_key, content_key) = resolve_existing_node_key_and_content_key(ctx, &existing_link_id)?;
                (existing_link_id, created.revision.revision_id, node_key, content_key)
            }
        };

    use sha1::{Digest as Sha1Digest, Sha1};

    let mut block_hashes = Vec::new();
    let mut block_sizes = Vec::new();
    let mut sha1_hasher = Sha1::new();
    let mut buf = vec![0u8; BLOCK_SIZE_BYTES];
    let mut block_index: i64 = 1;
    loop {
        let n = file.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        let plaintext = &buf[..n];
        sha1_hasher.update(plaintext);
        let encrypted_block = encrypt_verified_block(ctx, &node_key_for_blocks, &content_key_for_blocks, plaintext)?;

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

    let sha1_hex: String = sha1_hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let total_size = block_sizes.iter().sum::<u64>();
    let manifest_signature = build_manifest_signature(&block_hashes, ctx.address_key)?;
    let xattr_armored = build_xattr(file, total_size, block_sizes, sha1_hex, &node_key_for_blocks)?;

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
/// Task 6) instead of `create_file`/`create_revision`. On conflict, the
/// whole-file block is genuinely re-encrypted under the existing node's
/// real key/content-key (Task 13) — the first, optimistic encryption below
/// used the wrong key and can't be reused; see the `NameConflict` arm.
fn upload_small(ctx: &UploadContext, file: &mut File) -> Result<String> {
    let mut plaintext = Vec::with_capacity(ctx.file_size as usize);
    file.read_to_end(&mut plaintext).map_err(Error::Io)?;
    let total_size = plaintext.len() as u64;
    let sha1_hex = compute_whole_file_sha1(plaintext.as_slice())?;

    let node_key = ctx.new_node_key.as_unlocked_key();
    let encrypted_block = encrypt_verified_block(ctx, &node_key, ctx.content_key, &plaintext)?;
    let manifest_signature = build_manifest_signature(&[encrypted_block.sha256_hash], ctx.address_key)?;
    let xattr_armored = build_xattr(file, total_size, vec![total_size], sha1_hex.clone(), &node_key)?;

    let new_file_metadata = SmallFileUploadMetadata {
        node: new_node_metadata(ctx),
        revision: RevisionUpdateRequest {
            manifest_signature: &manifest_signature,
            signature_email_address: &ctx.address.email,
            checksum_verified: true,
            extended_attributes: &xattr_armored,
        },
    };

    match upload_small_file(ctx.client, &ctx.folder.volume_id, &new_file_metadata, &encrypted_block.ciphertext)? {
        CreateFileOutcome::Created(ids) => Ok(ids.revision_id),
        CreateFileOutcome::NameConflict(conflict) => {
            let existing_link_id = conflict
                .link_id
                .ok_or_else(|| Error::Crypto("server reported a name conflict with no conflicting node ID".into()))?;

            // The optimistic encryption above used `ctx`'s freshly-generated
            // key/content-key, sent with the new-file attempt that just
            // turned out to conflict — that ciphertext can't be reused (it
            // was encrypted under the wrong key entirely). Re-encrypt the
            // same plaintext under the existing node's real key/content-key
            // (Task 13), then rebuild the manifest signature and XAttr from
            // THAT encryption — both depend on the actual ciphertext
            // produced, which changes with the key, even though
            // `block_sizes`/`file_size` don't (same file, same size). Real,
            // deliberate duplicate work: the common (no-conflict) case above
            // pays none of it.
            let (existing_node_key, existing_content_key) =
                resolve_existing_node_key_and_content_key(ctx, &existing_link_id)?;
            let encrypted_block = encrypt_verified_block(ctx, &existing_node_key, &existing_content_key, &plaintext)?;
            let manifest_signature = build_manifest_signature(&[encrypted_block.sha256_hash], ctx.address_key)?;
            let xattr_armored = build_xattr(file, total_size, vec![total_size], sha1_hex, &existing_node_key)?;

            let revision_metadata = RevisionUpdateRequest {
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
/// modification time, per-block plaintext sizes, and the whole-file SHA-1.
/// `total_size`/`sha1_hex` are passed in already computed by the caller from
/// the bytes actually encrypted (the block loop / whole-file read above),
/// not re-read from `file` here — `file` is only used for its `.metadata()`
/// (the mtime).
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
fn build_xattr(
    file: &File,
    total_size: u64,
    block_sizes: Vec<u64>,
    sha1_hex: String,
    node_key: &UnlockedKey,
) -> Result<String> {
    let modified = file.metadata().map_err(Error::Io)?.modified().unwrap_or(std::time::UNIX_EPOCH);
    let modification_time = humantime::format_rfc3339_seconds(clamp_to_unix_epoch(modified)).to_string();
    let extended_attributes = ExtendedAttributes {
        common: ExtendedAttributesCommon {
            total_size,
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

    // Regression guard for `upload_general`'s chunked SHA-1 accumulation
    // fix: feeding sequential chunks through repeated `.update()` calls on
    // one `Sha1` hasher must produce the same digest as hashing the
    // concatenation of those chunks in a single pass. This is the exact
    // property the block loop's fix relies on (accumulating over the same
    // `plaintext` chunks handed to encryption, instead of re-reading the
    // whole file from disk afterward) — `upload_general` itself isn't
    // unit-testable (no `ApiClient` mock seam), so this tests the hashing
    // property directly.
    #[test]
    fn chunked_sha1_accumulation_matches_whole_buffer_hash() {
        use sha1::{Digest as Sha1Digest, Sha1};

        let whole = b"the quick brown fox jumps over the lazy dog";
        let a = whole.len() / 3;
        let b = 2 * whole.len() / 3;
        let chunks: [&[u8]; 3] = [&whole[..a], &whole[a..b], &whole[b..]];

        let mut hasher = Sha1::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        let chunked_hex: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();

        let whole_hex = compute_whole_file_sha1(&whole[..]).unwrap();

        assert_eq!(chunked_hex, whole_hex);
    }
}
