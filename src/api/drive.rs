use super::ApiClient;
use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct ShareVolume {
    #[serde(rename = "VolumeID")]
    pub id: String,
}

#[derive(Deserialize)]
pub struct Share {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Passphrase")]
    pub passphrase: String,
    #[serde(rename = "PassphraseSignature")]
    pub passphrase_signature: String,
    #[serde(rename = "AddressID")]
    pub membership_address_id: String,
}

/// The subset of a link's details needed to decrypt its name and descend
/// into it. `node_passphrase`/`node_key` are absent for a link this account
/// only has read access to via a different key chain — not a case we need
/// to handle (`/my-files/...` only, this account's own tree).
#[derive(Deserialize)]
pub struct LinkDetails {
    #[serde(rename = "LinkID")]
    pub link_id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: String,
}

#[derive(Deserialize)]
pub struct ShareResponse {
    #[serde(rename = "Volume")]
    pub volume: ShareVolume,
    #[serde(rename = "Share")]
    pub share: Share,
    #[serde(rename = "Link")]
    pub link: LinkDetails,
}

/// `GET v2/shares/my-files` — the account's "My files" root share. Not a
/// one-time login step; called fresh each time a path needs resolving,
/// matching the reference SDKs (neither caches this at session level).
pub fn fetch_my_files_share(client: &ApiClient) -> Result<ShareResponse> {
    client.get("v2/shares/my-files")
}

#[derive(Deserialize, Debug)]
pub struct ChildrenResponse {
    #[serde(rename = "LinkIDs")]
    pub link_ids: Vec<String>,
    #[serde(rename = "AnchorID")]
    pub anchor_id: Option<String>,
    #[serde(rename = "More")]
    pub more: bool,
}

/// `GET v2/volumes/{volumeId}/folders/{linkId}/children` — bare link IDs
/// only, no names/keys (those need a separate `get_link_details` call per
/// ID). `anchor` is the previous page's `AnchorID` (from `ChildrenResponse`)
/// to fetch the next page when `more` was true, matching the reference
/// SDKs' own query-parameter pagination; pass `None` for the first page.
pub fn list_folder_children(
    client: &ApiClient,
    volume_id: &str,
    folder_link_id: &str,
    anchor: Option<&str>,
) -> Result<ChildrenResponse> {
    let path = format!("v2/volumes/{volume_id}/folders/{folder_link_id}/children");
    let path = match anchor {
        Some(anchor) => format!("{path}?AnchorID={anchor}"),
        None => path,
    };
    client.get(&path)
}

#[derive(Serialize)]
struct LinkDetailsRequest<'a> {
    #[serde(rename = "LinkIDs")]
    link_ids: &'a [String],
}

#[derive(Deserialize)]
pub struct LinkDetailsResponse {
    #[serde(rename = "Links")]
    pub links: Vec<LinkDetails>,
}

/// `POST v2/volumes/{volumeId}/links` — batched details fetch (name, node
/// key, node passphrase) for a set of link IDs.
pub fn get_link_details(
    client: &ApiClient,
    volume_id: &str,
    link_ids: &[String],
) -> Result<LinkDetailsResponse> {
    let path = format!("v2/volumes/{volume_id}/links");
    let req = LinkDetailsRequest { link_ids };
    client.post(&path, &req)
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    #[test]
    fn share_response_deserializes() {
        let json = r#"{
            "Volume": {"VolumeID": "vol-1"},
            "Share": {"Key": "armored-key", "Passphrase": "armored-msg", "PassphraseSignature": "armored-sig", "AddressID": "addr-1"},
            "Link": {"LinkID": "root-link", "Name": "armored-name", "NodeKey": "armored-key-2", "NodePassphrase": "armored-msg-2"}
        }"#;
        let parsed: ShareResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.volume.id, "vol-1");
        assert_eq!(parsed.link.link_id, "root-link");
    }

    #[test]
    fn children_response_deserializes_with_pagination_fields() {
        let json = r#"{"LinkIDs": ["a", "b"], "AnchorID": "anchor-1", "More": true}"#;
        let parsed: ChildrenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.link_ids, vec!["a", "b"]);
        assert_eq!(parsed.anchor_id.as_deref(), Some("anchor-1"));
        assert!(parsed.more);
    }

    #[test]
    fn link_details_response_deserializes() {
        let json = r#"{"Links": [{"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p"}]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.links.len(), 1);
        assert_eq!(parsed.links[0].link_id, "l1");
    }
}
