use super::ApiClient;
use crate::config::APP_VERSION;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use ureq::unversioned::multipart::{Form, Part};

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
    /// The address that claims to have created this share (and signed its
    /// passphrase) — distinct from `membership_address_id`, which is
    /// whichever address's key packet decrypts the share key. For a
    /// personal "My files" share these are typically the same account's
    /// own address, but not guaranteed to be the identical one.
    #[serde(rename = "Creator")]
    pub creator: String,
}

/// A file link's currently-active revision — confirmed present on the same
/// `get_link_details`/`list_folder_children` response upload already calls,
/// per the reference C# wire type `ActiveRevisionDto`
/// (`client/cs/src/Proton.Drive.Sdk/Api/Files/ActiveRevisionDto.cs:7-30` in
/// the local SDK clone).
#[derive(Deserialize)]
pub struct ActiveRevisionDetails {
    #[serde(rename = "RevisionID")]
    pub revision_id: String,
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: Option<String>,
    #[serde(rename = "XAttr")]
    pub extended_attributes: Option<String>,
    #[serde(rename = "SignatureEmail")]
    pub signature_email: Option<String>,
}

// No `Debug` — holds a content-key packet, key material by another name.
#[derive(Deserialize)]
pub struct LinkFileDetails {
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: String,
    /// Detached signature over the decrypted content key's raw session-key
    /// bytes — absent means not signed at all (a real, legitimate case, not
    /// an error), matching `LinkDetails::node_passphrase_signature`'s own
    /// pattern.
    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_packet_signature: Option<String>,
    #[serde(rename = "ActiveRevision")]
    pub active_revision: ActiveRevisionDetails,
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
    /// The address that claims to have signed `name`'s embedded signature —
    /// can differ from `signature_email` below (a rename can be signed by
    /// a different address than the one that created the node). Absent
    /// means anonymous, verified against the parent folder's key instead.
    #[serde(rename = "NameSignatureEmail")]
    pub name_signature_email: Option<String>,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: String,
    /// Detached signature over the decrypted `node_passphrase` — absent
    /// means not signed at all (a real, legitimate case, not an error).
    #[serde(rename = "NodePassphraseSignature")]
    pub node_passphrase_signature: Option<String>,
    /// The address that claims to have signed `node_passphrase` — also
    /// covers the content-key packet's claim when `file` is present (the
    /// wire protocol has no separate claim field for that).
    #[serde(rename = "SignatureEmail")]
    pub signature_email: Option<String>,
    /// File-type links only (`Link.File.*` on the wire); absent for folders.
    #[serde(rename = "File")]
    pub file: Option<LinkFileDetails>,
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
    match anchor {
        Some(anchor) => client.get_with_query(&path, "AnchorID", anchor),
        None => client.get(&path),
    }
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

/// The wire shape shared by both "create a new node" endpoints: a brand-new
/// file (`FileCreationRequest`) and the small-file combined
/// create+upload+commit call (`SmallFileUploadMetadata`). Excludes
/// `SignatureAddress`: the two callers pair it with different siblings
/// (`FileCreationRequest`'s own field vs. `RevisionUpdateRequest`'s, flattened
/// into `SmallFileUploadMetadata`), so keeping it out here avoids a duplicate
/// `SignatureAddress` key where both get flattened into the same struct.
#[derive(Serialize)]
pub struct NewNodeMetadata<'a> {
    #[serde(rename = "Name")]
    pub name: &'a str, // armored PGP message, encrypted to the parent folder's key
    #[serde(rename = "Hash")]
    pub name_hash_digest: &'a str, // hex-encoded SHA-256 of the plaintext name — see note below
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: &'a str,
    #[serde(rename = "NodePassphrase")]
    pub node_passphrase: &'a str,
    #[serde(rename = "NodePassphraseSignature")]
    pub node_passphrase_signature: &'a str,
    #[serde(rename = "NodeKey")]
    pub node_key: &'a str,
    #[serde(rename = "MIMEType")]
    pub media_type: &'a str,
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: &'a str, // base64
    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: &'a str,
}

#[derive(Serialize)]
pub struct FileCreationRequest<'a> {
    #[serde(flatten)]
    pub node: NewNodeMetadata<'a>,
    #[serde(rename = "ClientUID")]
    pub client_uid: Option<&'a str>,
    #[serde(rename = "IntendedUploadSize")]
    pub intended_upload_size: i64,
    #[serde(rename = "SignatureAddress")]
    pub signature_email_address: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct FileCreationIdentifiers {
    #[serde(rename = "ID")]
    pub link_id: String,
    #[serde(rename = "RevisionID")]
    pub revision_id: String,
}

#[derive(Deserialize, Debug)]
struct FileCreationResponse {
    #[serde(rename = "File")]
    file: FileCreationIdentifiers,
}

/// The server's conflict payload when a create-file call collides with an
/// existing node of the same name — carries the existing node's ID so the
/// caller can retry as `create_revision` instead. Only `link_id` is used by
/// this crate; the other conflict fields exist on the wire but have no use
/// case here (unchanged "always new revision" behavior doesn't need them).
#[derive(Deserialize, Debug)]
pub struct RevisionConflict {
    #[serde(rename = "ConflictLinkID")]
    pub link_id: Option<String>,
}

pub enum CreateFileOutcome {
    Created(FileCreationIdentifiers),
    NameConflict(RevisionConflict),
}

const ALREADY_EXISTS_CODE: i64 = 2500;

/// Distinguishes a same-name conflict (`Code == 2500`, `AlreadyExists` in
/// the reference SDKs' own naming) from every other API error — shared by
/// every node-creation call site (`create_file` here, and `upload_small_file`
/// below), since a conflict isn't a failure in any of them, it's the signal
/// to retry as a new-revision call instead (this crate's "always new
/// revision" behavior, decided during brainstorming for the upload design).
/// Relies on `Error::Api` carrying the response's `Details` field.
///
/// Returns this file's `Result` (fixed to `Error` as its error type) wrapping
/// a `std::result::Result` — spelled out fully qualified because this file
/// only imports the crate's one-error-type `Result<T>` alias as bare
/// `Result`, which can't itself take `RevisionConflict` as a second type
/// argument. The inner `std::result::Result::Ok`/`Err` is a "success or
/// conflict" distinction, not a fallible operation in its own right.
fn conflict_outcome<T>(result: Result<T>) -> Result<std::result::Result<T, RevisionConflict>> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(Error::Api { code, details: Some(details), .. }) if code == ALREADY_EXISTS_CODE => {
            let conflict: RevisionConflict = serde_json::from_value(details)
                .map_err(|e| Error::Crypto(format!("unexpected conflict payload shape: {e}")))?;
            Ok(Err(conflict))
        }
        Err(e) => Err(e),
    }
}

/// `POST v2/volumes/{volumeId}/files`.
pub fn create_file(client: &ApiClient, volume_id: &str, req: &FileCreationRequest) -> Result<CreateFileOutcome> {
    let path = format!("v2/volumes/{volume_id}/files");
    match conflict_outcome(client.post::<_, FileCreationResponse>(&path, req))? {
        Ok(resp) => Ok(CreateFileOutcome::Created(resp.file)),
        Err(conflict) => Ok(CreateFileOutcome::NameConflict(conflict)),
    }
}

#[derive(Serialize)]
pub struct RevisionCreationRequest<'a> {
    #[serde(rename = "CurrentRevisionID")]
    pub current_revision_id: Option<&'a str>,
    #[serde(rename = "ClientUID")]
    pub client_uid: Option<&'a str>,
    #[serde(rename = "IntendedUploadSize")]
    pub intended_upload_size: i64,
}

#[derive(Deserialize, Debug)]
pub struct RevisionCreationIdentity {
    #[serde(rename = "ID")]
    pub revision_id: String,
}

#[derive(Deserialize, Debug)]
pub struct RevisionCreationResult {
    #[serde(rename = "Revision")]
    pub revision: RevisionCreationIdentity,
}

/// `POST v2/volumes/{volumeId}/files/{linkId}/revisions` — creates a new
/// revision on an existing node (this crate's always-taken branch when
/// `create_file` reports a name conflict).
pub fn create_revision(
    client: &ApiClient,
    volume_id: &str,
    link_id: &str,
    req: &RevisionCreationRequest,
) -> Result<RevisionCreationResult> {
    let path = format!("v2/volumes/{volume_id}/files/{link_id}/revisions");
    client.post(&path, req)
}

/// Everything `FileCreationRequest` carries, plus the commit-time fields
/// `RevisionUpdateRequest` otherwise carries separately — folded into one
/// request because the small path has no separate commit step. This struct
/// exists only because the small path sends them together as one JSON
/// `Metadata` multipart part rather than as two separate request bodies; the
/// existing-node ("new revision") small-upload call reuses
/// `RevisionUpdateRequest` directly instead of needing a variant of this
/// struct, since it has no node keypair/content-key fields to add (those
/// already exist on the target node and aren't regenerated — matching
/// `generate_content_key`'s doc comment: a content key is per-file, generated
/// once, reused across revisions).
#[derive(Serialize)]
pub struct SmallFileUploadMetadata<'a> {
    #[serde(flatten)]
    pub node: NewNodeMetadata<'a>,
    #[serde(flatten)]
    pub revision: RevisionUpdateRequest<'a>,
}

#[derive(Deserialize, Debug)]
pub struct SmallUploadResponse {
    #[serde(rename = "File")]
    pub file: FileCreationIdentifiers,
}

fn send_small_upload<M: Serialize>(
    client: &ApiClient,
    path: &str,
    metadata: &M,
    content_block: &[u8],
) -> Result<SmallUploadResponse> {
    let metadata_json = serde_json::to_vec(metadata)
        .map_err(|e| Error::Crypto(format!("failed to serialize small-upload metadata: {e}")))?;
    let form = Form::new()
        .part("Metadata", Part::bytes(&metadata_json))
        .part("ContentBlock", Part::bytes(content_block));
    client.post_multipart(path, form)
}

/// `POST v2/volumes/{volumeId}/files/small` — new file, small-upload path.
/// Reuses `CreateFileOutcome`/`conflict_outcome` (defined above, alongside
/// `create_file`) since this call can hit the exact same same-name conflict
/// `create_file` does, needing the exact same retry-as-new-revision
/// handling — just against `upload_small_revision` instead of
/// `create_revision`.
pub fn upload_small_file(
    client: &ApiClient,
    volume_id: &str,
    metadata: &SmallFileUploadMetadata,
    content_block: &[u8],
) -> Result<CreateFileOutcome> {
    let path = format!("v2/volumes/{volume_id}/files/small");
    match conflict_outcome(send_small_upload(client, &path, metadata, content_block))? {
        Ok(resp) => Ok(CreateFileOutcome::Created(resp.file)),
        Err(conflict) => Ok(CreateFileOutcome::NameConflict(conflict)),
    }
}

/// `POST v2/volumes/{volumeId}/files/{linkId}/revisions/small` — existing
/// node, small-upload path. Takes `RevisionUpdateRequest` directly (the same
/// type `commit_revision`'s general path uses) rather than a dedicated
/// struct: this call has no node keypair/content-key fields to add, so
/// there's nothing left over once the shared commit fields are covered.
pub fn upload_small_revision(
    client: &ApiClient,
    volume_id: &str,
    link_id: &str,
    metadata: &RevisionUpdateRequest,
    content_block: &[u8],
) -> Result<SmallUploadResponse> {
    let path = format!("v2/volumes/{volume_id}/files/{link_id}/revisions/small");
    send_small_upload(client, &path, metadata, content_block)
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    #[test]
    fn share_response_deserializes() {
        let json = r#"{
            "Volume": {"VolumeID": "vol-1"},
            "Share": {"Key": "armored-key", "Passphrase": "armored-msg", "PassphraseSignature": "armored-sig", "AddressID": "addr-1", "Creator": "creator@example.com"},
            "Link": {"LinkID": "root-link", "Name": "armored-name", "NodeKey": "armored-key-2", "NodePassphrase": "armored-msg-2"}
        }"#;
        let parsed: ShareResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.volume.id, "vol-1");
        assert_eq!(parsed.link.link_id, "root-link");
        assert_eq!(parsed.share.creator, "creator@example.com");
    }

    #[test]
    fn link_details_deserializes_signature_fields_when_present() {
        let json = r#"{"Links": [
            {"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p",
             "NodePassphraseSignature": "armored-sig", "SignatureEmail": "signer@example.com",
             "NameSignatureEmail": "renamer@example.com"}
        ]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        let link = &parsed.links[0];
        assert_eq!(link.node_passphrase_signature.as_deref(), Some("armored-sig"));
        assert_eq!(link.signature_email.as_deref(), Some("signer@example.com"));
        assert_eq!(link.name_signature_email.as_deref(), Some("renamer@example.com"));
    }

    #[test]
    fn link_details_signature_fields_default_to_none_when_absent() {
        let json = r#"{"Links": [{"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p"}]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        let link = &parsed.links[0];
        assert_eq!(link.node_passphrase_signature, None);
        assert_eq!(link.signature_email, None);
        assert_eq!(link.name_signature_email, None);
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
        assert!(parsed.links[0].file.is_none());
    }

    #[test]
    fn link_details_deserializes_file_content_key_fields_when_present() {
        let json = r#"{"Links": [
            {"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p",
             "File": {"ContentKeyPacket": "cpk-b64", "ContentKeyPacketSignature": "armored-sig",
                      "ActiveRevision": {"RevisionID": "rev-1"}}}
        ]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        let file = parsed.links[0].file.as_ref().expect("file field should be present");
        assert_eq!(file.content_key_packet, "cpk-b64");
    }

    #[test]
    fn link_file_details_content_key_packet_signature_defaults_to_none_when_absent() {
        let json = r#"{"Links": [
            {"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p",
             "File": {"ContentKeyPacket": "cpk-b64", "ActiveRevision": {"RevisionID": "rev-1"}}}
        ]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        let file = parsed.links[0].file.as_ref().expect("file field should be present");
        assert_eq!(file.content_key_packet_signature, None);
    }

    #[test]
    fn active_revision_deserializes_with_optional_fields_present() {
        let json = r#"{"Links": [
            {"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p",
             "File": {"ContentKeyPacket": "cpk-b64",
                      "ActiveRevision": {"RevisionID": "rev-1", "ManifestSignature": "armored-sig",
                                         "XAttr": "armored-xattr", "SignatureEmail": "signer@example.com"}}}
        ]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        let file = parsed.links[0].file.as_ref().expect("file field should be present");
        assert_eq!(file.active_revision.revision_id, "rev-1");
        assert_eq!(file.active_revision.manifest_signature.as_deref(), Some("armored-sig"));
        assert_eq!(file.active_revision.extended_attributes.as_deref(), Some("armored-xattr"));
        assert_eq!(file.active_revision.signature_email.as_deref(), Some("signer@example.com"));
    }

    #[test]
    fn active_revision_optional_fields_default_to_none_when_absent() {
        let json = r#"{"Links": [
            {"LinkID": "l1", "Name": "n", "NodeKey": "k", "NodePassphrase": "p",
             "File": {"ContentKeyPacket": "cpk-b64", "ActiveRevision": {"RevisionID": "rev-1"}}}
        ]}"#;
        let parsed: LinkDetailsResponse = serde_json::from_str(json).unwrap();
        let file = parsed.links[0].file.as_ref().expect("file field should be present");
        assert_eq!(file.active_revision.manifest_signature, None);
        assert_eq!(file.active_revision.extended_attributes, None);
        assert_eq!(file.active_revision.signature_email, None);
    }

    #[test]
    fn file_creation_response_deserializes() {
        let json = r#"{"File": {"ID": "link-1", "RevisionID": "rev-1"}}"#;
        let parsed: FileCreationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.file.link_id, "link-1");
        assert_eq!(parsed.file.revision_id, "rev-1");
    }

    #[test]
    fn revision_conflict_deserializes_with_present_or_absent_link_id() {
        let json = r#"{"ConflictLinkID": "existing-link"}"#;
        let parsed: RevisionConflict = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.link_id.as_deref(), Some("existing-link"));

        let parsed_absent: RevisionConflict = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed_absent.link_id, None);
    }

    #[test]
    fn revision_creation_result_deserializes() {
        let json = r#"{"Revision": {"ID": "rev-2"}}"#;
        let parsed: RevisionCreationResult = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.revision.revision_id, "rev-2");
    }

    #[test]
    fn small_upload_response_deserializes() {
        let json = r#"{"File": {"ID": "link-3", "RevisionID": "rev-3"}}"#;
        let parsed: SmallUploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.file.link_id, "link-3");
        assert_eq!(parsed.file.revision_id, "rev-3");
    }

    fn sample_node_metadata() -> NewNodeMetadata<'static> {
        NewNodeMetadata {
            name: "n",
            name_hash_digest: "h",
            parent_link_id: "p",
            node_passphrase: "np",
            node_passphrase_signature: "nps",
            node_key: "nk",
            media_type: "m",
            content_key_packet: "ckp",
            content_key_signature: "cks",
        }
    }

    // Regression guard for the `#[serde(flatten)]` refactor: proves the
    // nested `NewNodeMetadata` serializes to top-level keys (not a nested
    // "node" object) alongside `FileCreationRequest`'s own fields.
    #[test]
    fn file_creation_request_flattens_node_metadata_to_top_level_keys() {
        let req = FileCreationRequest {
            node: sample_node_metadata(),
            client_uid: None,
            intended_upload_size: 42,
            signature_email_address: "a@b.com",
        };
        let value = serde_json::to_value(&req).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("Name").and_then(|v| v.as_str()), Some("n"));
        assert_eq!(obj.get("IntendedUploadSize").and_then(|v| v.as_i64()), Some(42));
        assert_eq!(obj.get("SignatureAddress").and_then(|v| v.as_str()), Some("a@b.com"));
        assert!(obj.get("node").is_none(), "flatten must not nest NewNodeMetadata under its field name");
    }

    // Regression guard: `SmallFileUploadMetadata` flattens *two* structs
    // together — this proves neither their key sets nor `NewNodeMetadata`'s
    // deliberate exclusion of `SignatureAddress` (see its doc comment) drift
    // out of sync, which would otherwise silently drop or duplicate a key.
    #[test]
    fn small_file_upload_metadata_flattens_both_halves_without_key_collision() {
        let req = SmallFileUploadMetadata {
            node: sample_node_metadata(),
            revision: RevisionUpdateRequest {
                manifest_signature: "ms",
                signature_email_address: "a@b.com",
                checksum_verified: true,
                extended_attributes: "xattr",
            },
        };
        let value = serde_json::to_value(&req).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 13, "expected 9 node fields + 4 revision fields with no overlap");
        assert_eq!(obj.get("SignatureAddress").and_then(|v| v.as_str()), Some("a@b.com"));
        assert_eq!(obj.get("ManifestSignature").and_then(|v| v.as_str()), Some("ms"));
    }
}

// `conflict_outcome` is pure logic over `Result<T, Error>` values — no
// HTTP/`ApiClient` involved — so unlike `create_file`/`upload_small_file`
// themselves (which need a live server, deferred to Task 12's manual
// verification per this task's brief), it's fully unit-testable here.
#[cfg(test)]
mod conflict_outcome_tests {
    use super::*;

    #[test]
    fn passes_through_success() {
        let ok: Result<i32> = Ok(42);
        let outcome = conflict_outcome(ok).unwrap();
        assert!(matches!(outcome, std::result::Result::Ok(42)));
    }

    #[test]
    fn extracts_conflict_from_already_exists_code() {
        let err: Result<i32> = Err(Error::Api {
            code: ALREADY_EXISTS_CODE,
            message: "already exists".into(),
            details: Some(serde_json::json!({"ConflictLinkID": "existing-link"})),
        });
        let outcome = conflict_outcome(err).unwrap();
        match outcome {
            std::result::Result::Err(conflict) => {
                assert_eq!(conflict.link_id.as_deref(), Some("existing-link"))
            }
            std::result::Result::Ok(_) => panic!("expected a conflict, got success"),
        }
    }

    #[test]
    fn passes_through_unrelated_api_errors() {
        let err: Result<i32> = Err(Error::Api {
            code: 500,
            message: "server error".into(),
            details: None,
        });
        assert!(conflict_outcome(err).is_err());
    }

    // Regression guard: the match arm that extracts a conflict requires
    // *both* `code == ALREADY_EXISTS_CODE` *and* `details: Some(..)` — a
    // same-code response with no details body must fall through to the
    // catch-all `Err(e) => Err(e)` arm (propagated as a real error) rather
    // than panicking or being silently treated as a conflict.
    #[test]
    fn already_exists_code_without_details_is_not_treated_as_a_conflict() {
        let err: Result<i32> = Err(Error::Api {
            code: ALREADY_EXISTS_CODE,
            message: "already exists".into(),
            details: None,
        });
        assert!(conflict_outcome(err).is_err());
    }

    #[test]
    fn errors_clearly_on_malformed_conflict_details() {
        let err: Result<i32> = Err(Error::Api {
            code: ALREADY_EXISTS_CODE,
            message: "already exists".into(),
            details: Some(serde_json::json!("not an object")),
        });
        assert!(conflict_outcome(err).is_err());
    }
}

#[derive(Serialize)]
pub struct BlockRegistration<'a> {
    #[serde(rename = "Index")]
    pub index: i64,
    #[serde(rename = "Size")]
    pub size: i64,
    #[serde(rename = "EncSignature")]
    pub encrypted_signature: &'a str,
    #[serde(rename = "Hash")]
    pub hash_b64: &'a str,
    #[serde(rename = "Verifier")]
    pub verifier: VerifierPayload<'a>,
}

#[derive(Serialize)]
pub struct VerifierPayload<'a> {
    #[serde(rename = "Token")]
    pub token_b64: &'a str,
}

#[derive(Serialize)]
struct BlockUploadPreparationRequest<'a> {
    #[serde(rename = "AddressID")]
    address_id: &'a str,
    #[serde(rename = "VolumeID")]
    volume_id: &'a str,
    #[serde(rename = "LinkID")]
    link_id: &'a str,
    #[serde(rename = "RevisionID")]
    revision_id: &'a str,
    #[serde(rename = "BlockList")]
    blocks: &'a [BlockRegistration<'a>],
    #[serde(rename = "ThumbnailList")]
    thumbnails: &'a [EmptyThumbnail],
}

/// Never constructed — `ThumbnailList` is always empty (thumbnails are out
/// of scope for this crate), but the field still needs a concrete element
/// type to serialize an empty array.
#[derive(Serialize)]
pub enum EmptyThumbnail {}

// No `Debug` on `BlockUploadTarget` (`token` is a bearer credential for the
// block-upload PUT, the same category as `api::auth::AuthResponse`'s
// `access_token`/`refresh_token`, which also don't derive `Debug`) or on
// `BlockUploadPreparationResponse`, which contains it.
#[derive(Deserialize)]
pub struct BlockUploadTarget {
    #[serde(rename = "BareURL")]
    pub bare_url: String,
    #[serde(rename = "Token")]
    pub token: String,
}

#[derive(Deserialize)]
struct BlockUploadPreparationResponse {
    #[serde(rename = "UploadLinks")]
    upload_targets: Vec<BlockUploadTarget>,
}

/// `POST blocks` (no volume/file prefix in the path — confirmed against
/// the real reference SDK, not a typo). Registers one or more blocks and
/// returns a per-block signed upload URL + token.
pub fn prepare_block_upload(
    client: &ApiClient,
    address_id: &str,
    volume_id: &str,
    link_id: &str,
    revision_id: &str,
    blocks: &[BlockRegistration],
) -> Result<Vec<BlockUploadTarget>> {
    let req = BlockUploadPreparationRequest {
        address_id,
        volume_id,
        link_id,
        revision_id,
        blocks,
        thumbnails: &[],
    };
    let resp: BlockUploadPreparationResponse = client.post("blocks", &req)?;
    Ok(resp.upload_targets)
}

/// Uploads one block's encrypted bytes directly to its per-block `bare_url`,
/// authenticated by the distinct `pm-storage-token` header (not the crate's
/// normal session bearer token) as `multipart/form-data` with one part
/// named `Block`. Bypasses `ApiClient::post` entirely since this targets an
/// opaque runtime URL outside the API base, with different auth.
///
/// The shared `agent` has `http_status_as_error(false)` set (needed so
/// `ApiClient`'s own calls can read Proton's JSON `Code` envelope on error
/// responses — see `api::parse_response`), so a non-2xx status here comes
/// back as `Ok`, not `Err`; the storage host is a different, opaque server
/// that isn't guaranteed to return that envelope shape at all, so the
/// status is checked directly rather than routed through `parse_response`.
/// Without this check a failed upload (expired signed URL, storage-side
/// error) would be silently treated as success.
pub fn upload_block_bytes(agent: &ureq::Agent, target: &BlockUploadTarget, ciphertext: &[u8]) -> Result<()> {
    let form = Form::new().part("Block", Part::bytes(ciphertext));
    let response = agent
        .post(&target.bare_url)
        .header("x-pm-appversion", APP_VERSION)
        .header("pm-storage-token", &target.token)
        .send(form)
        .map_err(|e| Error::Network(e.to_string()))?;
    if !response.status().is_success() {
        return Err(Error::Network(format!(
            "block upload failed: storage host returned HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

#[derive(Deserialize, Debug)]
pub struct VerificationInput {
    #[serde(rename = "VerificationCode")]
    pub verification_code_b64: String,
}

/// `GET v2/volumes/{volumeId}/links/{linkId}/revisions/{revisionId}/verification` —
/// fetches the server-issued verification code for the regular (multi-block)
/// upload path. The small-file path derives its verification code locally
/// instead (the content key packet's own tail bytes) and never calls this.
pub fn get_verification_input(
    client: &ApiClient,
    volume_id: &str,
    link_id: &str,
    revision_id: &str,
) -> Result<VerificationInput> {
    let path = format!("v2/volumes/{volume_id}/links/{link_id}/revisions/{revision_id}/verification");
    client.get(&path)
}

#[derive(Deserialize)]
pub struct RevisionBlockEntry {
    #[serde(rename = "Index")]
    pub index: i64,
    #[serde(rename = "BareURL")]
    pub bare_url: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "Hash")]
    pub hash_b64: String,
}

#[derive(Deserialize)]
pub struct RevisionDetails {
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: Option<String>,
    #[serde(rename = "SignatureEmail")]
    pub signature_email: Option<String>,
    #[serde(rename = "Blocks")]
    pub blocks: Vec<RevisionBlockEntry>,
}

#[derive(Deserialize)]
struct RevisionDetailsResponse {
    #[serde(rename = "Revision")]
    revision: RevisionDetails,
}

/// `GET v2/volumes/{volumeId}/files/{linkId}/revisions/{revisionId}` —
/// paginated via `PageSize`/`FromBlockIndex` query parameters, a different
/// pagination shape than `list_folder_children`'s `AnchorID` cursor (this
/// endpoint has no cursor token — the caller just advances
/// `from_block_index` past the last block index it received). Confirmed
/// against both reference SDKs
/// (`client/js/src/internal/download/apiService.ts:25-74`'s
/// `iterateRevisionBlocks`, `client/cs/.../Nodes/Download/RevisionReader.cs:252-339`'s
/// `GetBlocksAsync`) in the local SDK clone. Call repeatedly with an
/// advancing `from_block_index` until a page returns zero blocks.
pub fn get_revision(
    client: &ApiClient,
    volume_id: &str,
    link_id: &str,
    revision_id: &str,
    from_block_index: i64,
    page_size: i64,
) -> Result<RevisionDetails> {
    let path = format!(
        "v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}?PageSize={page_size}&FromBlockIndex={from_block_index}"
    );
    let resp: RevisionDetailsResponse = client.get(&path)?;
    Ok(resp.revision)
}

#[derive(Serialize)]
pub struct RevisionUpdateRequest<'a> {
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: &'a str,
    #[serde(rename = "SignatureAddress")]
    pub signature_email_address: &'a str,
    #[serde(rename = "ChecksumVerified")]
    pub checksum_verified: bool,
    #[serde(rename = "XAttr")]
    pub extended_attributes: &'a str,
}

/// The `PUT` response body carries only the shared `Envelope` fields
/// (`Code`, already checked inside `ApiClient::put` itself) with no payload
/// this crate needs. An empty struct deserializes successfully from any JSON
/// object, ignoring all its keys — unlike `()`, which `serde_json` only
/// deserializes from a literal JSON `null`, never a JSON object, so it can't
/// stand in for "no payload" on a response that's actually an object.
#[derive(Deserialize)]
struct CommitRevisionResponse {}

/// `PUT v2/volumes/{volumeId}/files/{linkId}/revisions/{revisionId}` — the
/// final step of an upload.
pub fn commit_revision(
    client: &ApiClient,
    volume_id: &str,
    link_id: &str,
    revision_id: &str,
    req: &RevisionUpdateRequest,
) -> Result<()> {
    let path = format!("v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}");
    client.put::<_, CommitRevisionResponse>(&path, req)?;
    Ok(())
}

#[cfg(test)]
mod block_upload_shape_tests {
    use super::*;

    #[test]
    fn block_upload_preparation_response_deserializes() {
        let json = r#"{"UploadLinks": [{"BareURL": "https://example.com/blob", "Token": "tok"}]}"#;
        let parsed: BlockUploadPreparationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.upload_targets[0].bare_url, "https://example.com/blob");
    }

    #[test]
    fn verification_input_deserializes() {
        let json = r#"{"VerificationCode": "base64data"}"#;
        let parsed: VerificationInput = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.verification_code_b64, "base64data");
    }

    // Regression guard: `commit_revision` used to type its `put` call's
    // response as `()`, but `serde_json` only deserializes `()` from a
    // literal JSON `null`, never a JSON object — so it failed on every real
    // (envelope-shaped) response, success or not. `CommitRevisionResponse`
    // is an empty struct, which deserializes successfully from any object.
    #[test]
    fn commit_revision_response_deserializes_from_envelope_shaped_object() {
        let json = r#"{"Code":1000,"SomeOtherField":"whatever"}"#;
        assert!(serde_json::from_str::<CommitRevisionResponse>(json).is_ok());
        assert!(serde_json::from_str::<()>(json).is_err());
    }
}

#[cfg(test)]
mod revision_shape_tests {
    use super::*;

    #[test]
    fn revision_details_response_deserializes() {
        let json = r#"{"Revision": {
            "ManifestSignature": "armored-sig",
            "SignatureEmail": "signer@example.com",
            "Blocks": [
                {"Index": 1, "BareURL": "https://example.com/blob1", "Token": "tok1", "Hash": "aGFzaDE="},
                {"Index": 2, "BareURL": "https://example.com/blob2", "Token": "tok2", "Hash": "aGFzaDI="}
            ]
        }}"#;
        let parsed: RevisionDetailsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.revision.manifest_signature.as_deref(), Some("armored-sig"));
        assert_eq!(parsed.revision.blocks.len(), 2);
        assert_eq!(parsed.revision.blocks[0].index, 1);
        assert_eq!(parsed.revision.blocks[1].bare_url, "https://example.com/blob2");
    }

    #[test]
    fn revision_details_response_deserializes_with_empty_blocks_and_no_manifest_signature() {
        let json = r#"{"Revision": {"Blocks": []}}"#;
        let parsed: RevisionDetailsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.revision.manifest_signature, None);
        assert!(parsed.revision.blocks.is_empty());
    }
}
