use crate::api::account::AddressesResponse;
use crate::api::drive::{get_link_details, list_folder_children, ShareResponse};
use crate::api::ApiClient;
use crate::crypto::{decrypt_and_verify_name, decrypt_message, verify_signature, SignatureCheck, UnlockedKey};
use crate::error::{Error, Result};

/// An existing Drive folder, resolved and ready to create a node under:
/// its volume, its own link ID, and its already-unlocked node key (needed
/// to encrypt a new child's name/passphrase, or to decrypt existing
/// children's names while walking further).
pub struct ResolvedFolder {
    pub volume_id: String,
    pub folder_link_id: String,
    pub folder_key: UnlockedKey,
}

/// Resolves `claimed_email` (a node/name's `SignatureEmail`/
/// `NameSignatureEmail`, or a share's `Creator`) to a verifying key. An
/// empty or absent claim falls back to `fallback_key` (the parent
/// folder's key for node passphrase/name/content-key packet; `None` for a
/// share, which has no parent) — matching the reference SDKs' anonymous
/// -signer fallback exactly. `Err(reason)` covers every case this crate
/// can't verify: no claim and no fallback, a claimed address not found
/// among this account's own `addresses`, or one with no active primary
/// key — none of these are hard errors, but the caller needs the specific
/// reason for its warning.
pub fn resolve_verifying_key(
    claimed_email: Option<&str>,
    addresses: &AddressesResponse,
    key_password: &str,
    fallback_key: Option<&UnlockedKey>,
) -> std::result::Result<UnlockedKey, String> {
    match claimed_email.filter(|e| !e.is_empty()) {
        None => fallback_key.cloned().ok_or_else(|| "no claimed signer and no verifier available".to_string()),
        Some(email) => {
            let address = addresses
                .addresses
                .iter()
                .find(|a| a.email == email)
                .ok_or_else(|| format!("claimed signer '{email}' is not one of this account's addresses"))?;
            let key_dto = address
                .keys
                .iter()
                .find(|k| k.primary == 1 && k.active == 1)
                .ok_or_else(|| format!("address '{email}' has no active primary key"))?;
            UnlockedKey::new(&key_dto.private_key, key_password.to_string())
                .map_err(|e| format!("could not unlock claimed signer's key: {e}"))
        }
    }
}

/// Combines `resolve_verifying_key` with `crypto::verify_signature` for
/// every detached-signature call site (share passphrase, node passphrase,
/// content-key packet) — the name's embedded signature is checked
/// differently (`crypto::decrypt_and_verify_name`), so it calls
/// `resolve_verifying_key` directly instead of through this wrapper.
pub fn verify_claim(
    claimed_email: Option<&str>,
    addresses: &AddressesResponse,
    key_password: &str,
    fallback_key: Option<&UnlockedKey>,
    armored_signature: Option<&str>,
    content: &[u8],
) -> SignatureCheck {
    match resolve_verifying_key(claimed_email, addresses, key_password, fallback_key) {
        Err(reason) => SignatureCheck::Failed(reason),
        Ok(key) => verify_signature(armored_signature, content, &key),
    }
}

/// Prints a warning and does nothing else. Every verification call site in
/// this file and in `commands::upload` handles `SignatureCheck`
/// identically — proceed with the already-decrypted plaintext regardless,
/// only `what` differs — matching the reference SDK/CLI's confirmed
/// non-fatal verification model (see the design doc's Background section).
pub fn warn_on_signature_failure(what: &str, check: SignatureCheck) {
    if let SignatureCheck::Failed(reason) = check {
        eprintln!("warning: signature verification failed for {what}: {reason}");
    }
}

/// Resolves a leading-slash, section-rooted path (e.g. `/my-files/foo/bar`)
/// to an existing folder. Only the `my-files` section is supported. There
/// is no server-side "resolve path" endpoint — every reference client
/// decrypts and scans each folder's children looking for a name match, so
/// this does the same: one API round trip (list children) plus one details
/// fetch per candidate, per path segment.
pub fn resolve_path(
    client: &ApiClient,
    share: ShareResponse,
    address_key: &UnlockedKey,
    addresses: &AddressesResponse,
    key_password: &str,
    path: &str,
) -> Result<ResolvedFolder> {
    let mut segments = path.trim_matches('/').split('/');
    let section = segments.next().unwrap_or("");
    if section != "my-files" {
        return Err(Error::Crypto(format!(
            "unsupported path section '{section}' (only /my-files/... is supported)"
        )));
    }

    let share_passphrase = decrypt_message(&share.share.passphrase, address_key)?;
    warn_on_signature_failure(
        "the My Files share's passphrase",
        verify_claim(
            Some(share.share.creator.as_str()),
            addresses,
            key_password,
            None,
            Some(share.share.passphrase_signature.as_str()),
            share_passphrase.as_bytes(),
        ),
    );
    let share_key = UnlockedKey::new(&share.share.key, share_passphrase)?;

    let root_passphrase = decrypt_message(&share.link.node_passphrase, &share_key)?;
    warn_on_signature_failure(
        "the My Files root folder's passphrase",
        verify_claim(
            share.link.signature_email.as_deref(),
            addresses,
            key_password,
            Some(&share_key),
            share.link.node_passphrase_signature.as_deref(),
            root_passphrase.as_bytes(),
        ),
    );
    let mut current_key = UnlockedKey::new(&share.link.node_key, root_passphrase)?;
    let mut current_link_id = share.link.link_id;
    let volume_id = share.volume.id;

    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        let child = find_child_by_name(client, &volume_id, &current_link_id, &current_key, segment, addresses, key_password)?
            .ok_or_else(|| Error::Crypto(format!("no such folder: '{segment}' does not exist under this path")))?;
        let child_passphrase = decrypt_message(&child.node_passphrase, &current_key)?;
        warn_on_signature_failure(
            &format!("folder '{segment}'s passphrase"),
            verify_claim(
                child.signature_email.as_deref(),
                addresses,
                key_password,
                Some(&current_key),
                child.node_passphrase_signature.as_deref(),
                child_passphrase.as_bytes(),
            ),
        );
        current_key = UnlockedKey::new(&child.node_key, child_passphrase)?;
        current_link_id = child.link_id;
    }

    Ok(ResolvedFolder {
        volume_id,
        folder_link_id: current_link_id,
        folder_key: current_key,
    })
}

/// Lists `parent_link_id`'s children (paginating via `AnchorID`/`More`),
/// decrypting each candidate's name with the already-unlocked `parent_key`
/// until `target_name` matches, or every page is exhausted.
fn find_child_by_name(
    client: &ApiClient,
    volume_id: &str,
    parent_link_id: &str,
    parent_key: &UnlockedKey,
    target_name: &str,
    addresses: &AddressesResponse,
    key_password: &str,
) -> Result<Option<crate::api::drive::LinkDetails>> {
    let mut anchor: Option<String> = None;
    loop {
        let children = list_folder_children(client, volume_id, parent_link_id, anchor.as_deref())?;
        if children.link_ids.is_empty() {
            return Ok(None);
        }
        let details = get_link_details(client, volume_id, &children.link_ids)?;
        for link in details.links {
            let verifier = resolve_verifying_key(link.name_signature_email.as_deref(), addresses, key_password, Some(parent_key));
            let (name, check) = decrypt_and_verify_name(&link.name, parent_key, verifier)?;
            warn_on_signature_failure(&format!("link {}'s name", link.link_id), check);
            if name == target_name {
                return Ok(Some(link));
            }
        }
        if !children.more || children.anchor_id.is_none() {
            return Ok(None);
        }
        anchor = children.anchor_id;
    }
}

#[cfg(test)]
mod resolve_verifying_key_tests {
    use super::*;
    use crate::api::account::Address;
    use crate::api::KeyEntry;
    use pgp::composed::{KeyType, SecretKeyParamsBuilder};

    fn generate_test_key(name: &str, passphrase: &str) -> (UnlockedKey, String) {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .primary_user_id(format!("{name} <{name}@example.com>"))
            .passphrase(Some(passphrase.to_string()));
        let params = key_params.build().expect("valid key params");
        let signed_secret_key = params.generate(rand08::rngs::OsRng).expect("key generation should succeed");
        let armored = signed_secret_key.to_armored_string(Default::default()).unwrap();
        let key = UnlockedKey::new(&armored, passphrase.to_string()).unwrap();
        (key, armored)
    }

    fn addresses_with_one(email: &str, armored_private_key: &str) -> AddressesResponse {
        AddressesResponse {
            addresses: vec![Address {
                id: "addr-1".into(),
                email: email.into(),
                keys: vec![KeyEntry {
                    id: "key-1".into(),
                    private_key: armored_private_key.into(),
                    primary: 1,
                    active: 1,
                }],
            }],
        }
    }

    // `UnlockedKey`'s fields are private to `crypto.rs` — this test (living
    // in `drive.rs`) can't compare the resolved key's bytes against
    // `parent`'s directly, and doesn't need to: `resolve_verifying_key`'s
    // anonymous branch is a plain `fallback_key.cloned()`, so proving the
    // branch returns `Ok` at all is sufficient; there's no other value it
    // could structurally produce. Crypto-level correctness of a resolved
    // key is Task 1's job (`verify_signature`/`decrypt_and_verify_name`'s
    // own tests), not this resolution-branching function's.
    #[test]
    fn anonymous_claim_falls_back_to_the_parent_key() {
        let (parent, _armored) = generate_test_key("parent", "parent passphrase");
        let addresses = AddressesResponse { addresses: vec![] };
        assert!(resolve_verifying_key(None, &addresses, "irrelevant", Some(&parent)).is_ok());
    }

    #[test]
    fn empty_string_claim_is_treated_the_same_as_absent() {
        let (parent, _armored) = generate_test_key("parent", "parent passphrase");
        let addresses = AddressesResponse { addresses: vec![] };
        assert!(resolve_verifying_key(Some(""), &addresses, "irrelevant", Some(&parent)).is_ok());
    }

    #[test]
    fn no_claim_and_no_fallback_fails_closed() {
        let addresses = AddressesResponse { addresses: vec![] };
        assert!(resolve_verifying_key(None, &addresses, "irrelevant", None).is_err());
    }

    #[test]
    fn claim_matching_a_known_address_resolves_its_key() {
        let (_signer, armored) = generate_test_key("signer", "signer passphrase");
        let addresses = addresses_with_one("signer@example.com", &armored);
        assert!(resolve_verifying_key(Some("signer@example.com"), &addresses, "signer passphrase", None).is_ok());
    }

    // `.unwrap_err()` needs `T: Debug` (the `Ok` type, for its panic
    // message) — `UnlockedKey` deliberately doesn't derive `Debug` (it
    // holds a live passphrase), so `.err().unwrap()` is used instead: same
    // "must be Err" assertion, but only needs `E: Debug` (`String`, which
    // already has it).
    #[test]
    fn claim_naming_an_unknown_address_fails_closed_with_a_specific_reason() {
        let addresses = AddressesResponse { addresses: vec![] };
        let err = resolve_verifying_key(Some("nobody@example.com"), &addresses, "irrelevant", None)
            .err()
            .unwrap();
        assert!(err.contains("nobody@example.com"));
    }
}
