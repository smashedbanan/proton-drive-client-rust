use crate::api::account::{fetch_addresses, AddressesResponse};
use crate::api::drive::{
    download_block_bytes, fetch_my_files_share, get_revision, ActiveRevisionDetails, LinkFileDetails,
};
use crate::api::ApiClient;
use crate::conflict::{resolve_conflict, ConflictChoice};
use crate::crypto::{
    decrypt_and_verify_xattr, decrypt_block_auto, decrypt_existing_content_key, decrypt_message, verify_manifest,
    verify_signature_any, ContentKeyPacket, SignatureCheck, UnlockedKey,
};
use crate::drive::{resolve_file_path, resolve_verifying_key, verify_claim, warn_on_signature_failure, ResolvedFolder};
use crate::error::{Error, Result};
use crate::session;
use base64::Engine;
use sha2::Sha256;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const BLOCK_PAGE_SIZE: i64 = 20;

pub fn run(remote_path: &str, local_path: &str, conflict_strategy: Option<ConflictChoice>) -> Result<()> {
    let creds = session::load()?;
    let client = ApiClient::with_session(creds.uid.clone(), creds.access_token.clone());

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

    let (folder, file_link) =
        resolve_file_path(&client, share, &address_key, &addresses, &creds.user_key_password, remote_path)?;

    let node_passphrase = decrypt_message(&file_link.node_passphrase, &folder.folder_key)?;
    warn_on_signature_failure(
        &format!("file {}'s passphrase", file_link.link_id),
        verify_claim(
            file_link.signature_email.as_deref(),
            &addresses,
            &creds.user_key_password,
            Some(&folder.folder_key),
            file_link.node_passphrase_signature.as_deref(),
            node_passphrase.as_bytes(),
        ),
    );
    let node_key = UnlockedKey::new(&file_link.node_key, node_passphrase)?;

    let file_details: &LinkFileDetails = file_link
        .file
        .as_ref()
        .ok_or_else(|| Error::Crypto(format!("'{remote_path}' is a folder, not a file")))?;
    let content_key = decrypt_existing_content_key(&file_details.content_key_packet, &node_key)?;
    let claimed_content_key_signer =
        resolve_verifying_key(file_link.signature_email.as_deref(), &addresses, &creds.user_key_password, None).ok();
    let mut verifiers: Vec<&UnlockedKey> = vec![&node_key];
    if let Some(ref key) = claimed_content_key_signer {
        verifiers.push(key);
    }
    warn_on_signature_failure(
        &format!("file {}'s content-key packet", file_link.link_id),
        verify_signature_any(
            file_details.content_key_packet_signature.as_deref(),
            content_key.content_key.as_ref(),
            &verifiers,
        ),
    );

    let Some(target_path) = resolve_conflict(Path::new(local_path), conflict_strategy)? else {
        println!("Skipped: {local_path} already exists.");
        return Ok(());
    };

    let ctx = DownloadContext {
        client: &client,
        folder: &folder,
        link_id: &file_link.link_id,
        node_key: &node_key,
        content_key: &content_key,
        addresses: &addresses,
        key_password: &creds.user_key_password,
        revision: &file_details.active_revision,
    };

    match download_to_file(&ctx, &target_path) {
        Ok(()) => {
            println!("Downloaded {remote_path} to {}.", target_path.display());
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&target_path);
            Err(e)
        }
    }
}

/// Everything `download_to_file` needs, gathered once in `run` — mirrors
/// `commands::upload`'s own `UploadContext`, built for the identical reason
/// ("so upload_small/upload_general don't each take a dozen loose
/// parameters" — see that struct's own doc comment in `commands/upload.rs`).
struct DownloadContext<'a> {
    client: &'a ApiClient,
    folder: &'a ResolvedFolder,
    link_id: &'a str,
    node_key: &'a UnlockedKey,
    content_key: &'a ContentKeyPacket,
    addresses: &'a AddressesResponse,
    key_password: &'a str,
    revision: &'a ActiveRevisionDetails,
}

/// Downloads and decrypts every block of `ctx.revision` into a freshly
/// created `target_path`, then performs the two fatal checks: manifest
/// signature (over the concatenated, locally-computed block hashes) and,
/// if the XAttr's own signature verifies, the whole-file SHA-1. `run`
/// above deletes the partial `target_path` if this returns `Err`, matching
/// the reference CLI's own catch-and-`unlink` behavior.
fn download_to_file(ctx: &DownloadContext, target_path: &Path) -> Result<()> {
    use sha1::{Digest as Sha1Digest, Sha1};

    let mut output = File::create(target_path).map_err(Error::Io)?;

    let mut block_hashes = Vec::new();
    let mut sha1_hasher = Sha1::new();
    let mut from_block_index: i64 = 1;
    // Captured from the *first* page of `get_revision` (not from `ctx.revision`,
    // an `ActiveRevisionDetails` fetched earlier via link details) — the reference
    // SDKs source the manifest signature, its signer claim, and the XAttr blob
    // from this endpoint's response (`RevisionReader.cs`'s `VerifyManifestAsync`
    // reads `_state.RevisionDto.ManifestSignature`; TS's `fileDownloader.ts`
    // captures `armoredManifestSignature` from `iterateRevisionBlocks`'s first
    // page), never from the link-details endpoint. Every page repeats the same
    // revision-level values, so capturing them once, from the first page seen
    // (including a zero-block revision's only page), is correct.
    let mut manifest_signature: Option<String> = None;
    let mut signature_email: Option<String> = None;
    let mut extended_attributes: Option<String> = None;

    loop {
        let page = get_revision(
            ctx.client,
            &ctx.folder.volume_id,
            ctx.link_id,
            &ctx.revision.revision_id,
            from_block_index,
            BLOCK_PAGE_SIZE,
        )?;
        if from_block_index == 1 {
            manifest_signature = page.manifest_signature.clone();
            signature_email = page.signature_email.clone();
            extended_attributes = page.extended_attributes.clone();
        }
        if page.blocks.is_empty() {
            break;
        }
        for block in &page.blocks {
            let ciphertext = download_block_bytes(ctx.client.agent(), &block.bare_url, &block.token)?;
            let actual_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
            let actual_hash_b64 = base64::engine::general_purpose::STANDARD.encode(actual_hash);
            if actual_hash_b64 != block.hash_b64 {
                return Err(Error::Crypto(format!("block {} failed integrity check: hash mismatch", block.index)));
            }
            let plaintext = decrypt_block_auto(&ciphertext, ctx.content_key)?;
            output.write_all(&plaintext).map_err(Error::Io)?;
            sha1_hasher.update(&plaintext);
            block_hashes.push(actual_hash);
            from_block_index = block.index + 1;
        }
    }
    output.flush().map_err(Error::Io)?;

    let manifest_verifying_key = resolve_verifying_key(
        signature_email.as_deref(),
        ctx.addresses,
        ctx.key_password,
        Some(ctx.node_key),
    )
    .map_err(|reason| Error::Crypto(format!("cannot verify manifest: {reason}")))?;
    verify_manifest(&block_hashes, manifest_signature.as_deref(), &manifest_verifying_key)?;

    let actual_sha1_hex: String = sha1_hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if let Some(xattr_armored) = extended_attributes.as_deref() {
        match decrypt_and_verify_xattr(xattr_armored, ctx.node_key) {
            Ok((attrs, SignatureCheck::Verified)) => {
                if attrs.common.digests.sha1_hex != actual_sha1_hex {
                    return Err(Error::Crypto(format!(
                        "downloaded content failed integrity check: expected SHA-1 {}, got {actual_sha1_hex}",
                        attrs.common.digests.sha1_hex
                    )));
                }
            }
            Ok((_, SignatureCheck::Failed(reason))) => {
                eprintln!("warning: XAttr signature did not verify ({reason}); skipping whole-file integrity check");
            }
            Err(e) => {
                eprintln!("warning: could not decrypt XAttr ({e}); skipping whole-file integrity check");
            }
        }
    }

    Ok(())
}
