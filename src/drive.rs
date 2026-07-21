use crate::api::drive::{get_link_details, list_folder_children, ShareResponse};
use crate::api::ApiClient;
use crate::crypto::{decrypt_message, UnlockedKey};
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

/// Resolves a leading-slash, section-rooted path (e.g. `/my-files/foo/bar`)
/// to an existing folder. Only the `my-files` section is supported. There
/// is no server-side "resolve path" endpoint — every reference client
/// decrypts and scans each folder's children looking for a name match, so
/// this does the same: one API round trip (list children) plus one details
/// fetch per candidate, per path segment.
pub fn resolve_path(client: &ApiClient, share: ShareResponse, address_key: &UnlockedKey, path: &str) -> Result<ResolvedFolder> {
    let mut segments = path.trim_matches('/').split('/');
    let section = segments.next().unwrap_or("");
    if section != "my-files" {
        return Err(Error::Crypto(format!(
            "unsupported path section '{section}' (only /my-files/... is supported)"
        )));
    }

    let share_passphrase = decrypt_message(&share.share.passphrase, address_key)?;
    let share_key = UnlockedKey::new(&share.share.key, share_passphrase)?;

    let root_passphrase = decrypt_message(&share.link.node_passphrase, &share_key)?;
    let mut current_key = UnlockedKey::new(&share.link.node_key, root_passphrase)?;
    let mut current_link_id = share.link.link_id;
    let volume_id = share.volume.id;

    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        let child = find_child_by_name(client, &volume_id, &current_link_id, &current_key, segment)?
            .ok_or_else(|| Error::Crypto(format!("no such folder: '{segment}' does not exist under this path")))?;
        let child_passphrase = decrypt_message(&child.node_passphrase, &current_key)?;
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
) -> Result<Option<crate::api::drive::LinkDetails>> {
    let mut anchor: Option<String> = None;
    loop {
        let children = list_folder_children(client, volume_id, parent_link_id, anchor.as_deref())?;
        if children.link_ids.is_empty() {
            return Ok(None);
        }
        let details = get_link_details(client, volume_id, &children.link_ids)?;
        for link in details.links {
            let name = decrypt_message(&link.name, parent_key)?;
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
