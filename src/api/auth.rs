use super::{ApiClient, KeyEntry};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
struct AuthInfoRequest<'a> {
    #[serde(rename = "Intent")]
    intent: &'a str,
    #[serde(rename = "Username")]
    username: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct AuthInfoResponse {
    #[serde(rename = "Modulus")]
    pub modulus: String,
    #[serde(rename = "ServerEphemeral")]
    pub server_ephemeral: String,
    #[serde(rename = "Salt")]
    pub salt: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
    #[serde(rename = "Version")]
    pub version: i64,
}

pub fn fetch_auth_info(client: &ApiClient, username: &str) -> Result<AuthInfoResponse> {
    let req = AuthInfoRequest {
        intent: "Proton",
        username,
    };
    client.post("core/v4/auth/info", &req)
}

#[derive(Serialize)]
pub struct AuthRequest<'a> {
    #[serde(rename = "Username")]
    pub username: &'a str,
    #[serde(rename = "ClientEphemeral")]
    pub client_ephemeral: &'a str,
    #[serde(rename = "ClientProof")]
    pub client_proof: &'a str,
    #[serde(rename = "SRPSession")]
    pub srp_session: &'a str,
    #[serde(rename = "PersistentCookies")]
    pub persistent_cookies: i64,
    #[serde(rename = "Payload")]
    pub payload: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "UID")]
    pub uid: String,
    #[serde(rename = "AccessToken")]
    pub access_token: String,
    #[serde(rename = "RefreshToken")]
    pub refresh_token: String,
    #[serde(rename = "ServerProof")]
    pub server_proof: String,
    #[serde(rename = "PasswordMode")]
    pub password_mode: i64,
}

pub fn submit_auth(client: &ApiClient, req: &AuthRequest) -> Result<AuthResponse> {
    client.post("core/v4/auth", req)
}

#[derive(Deserialize, Debug)]
pub struct KeySalt {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "KeySalt")]
    pub key_salt: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct KeySaltsResponse {
    #[serde(rename = "KeySalts")]
    pub key_salts: Vec<KeySalt>,
}

pub fn fetch_key_salts(client: &ApiClient) -> Result<KeySaltsResponse> {
    client.get("core/v4/keys/salts")
}

#[derive(Deserialize)]
pub struct UserObj {
    #[serde(rename = "Keys")]
    pub keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
pub struct UsersResponse {
    #[serde(rename = "User")]
    pub user: UserObj,
}

pub fn fetch_users(client: &ApiClient) -> Result<UsersResponse> {
    client.get("core/v4/users")
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    // These confirm each struct deserializes JSON shaped the way this file's
    // #[serde(rename = ...)] attributes claim — catching a misspelled rename
    // or a wrong Option/required field. They do NOT prove this matches
    // Proton's real API response shape; that's only confirmed the first time
    // `login` runs against a real account (Task 10's manual verification).

    #[test]
    fn auth_info_response_deserializes() {
        let json = r#"{
            "Modulus": "modulus-text",
            "ServerEphemeral": "ephemeral-b64",
            "Salt": "salt-b64",
            "SRPSession": "session-id",
            "Version": 4
        }"#;
        let parsed: AuthInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.srp_session, "session-id");
    }

    #[test]
    fn auth_response_deserializes() {
        let json = r#"{
            "UID": "uid-value",
            "AccessToken": "token-value",
            "RefreshToken": "refresh-value",
            "ServerProof": "proof-b64",
            "PasswordMode": 1
        }"#;
        let parsed: AuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.uid, "uid-value");
        assert_eq!(parsed.password_mode, 1);
    }

    #[test]
    fn key_salts_response_deserializes_with_optional_salt() {
        let json = r#"{
            "KeySalts": [
                {"ID": "key-1", "KeySalt": "salt-b64"},
                {"ID": "key-2", "KeySalt": null}
            ]
        }"#;
        let parsed: KeySaltsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.key_salts.len(), 2);
        assert_eq!(parsed.key_salts[0].key_salt.as_deref(), Some("salt-b64"));
        assert_eq!(parsed.key_salts[1].key_salt, None);
    }

    #[test]
    fn users_response_deserializes() {
        let json = r#"{
            "User": {
                "Keys": [
                    {"ID": "key-1", "PrivateKey": "armored-key-text", "Primary": 1, "Active": 1}
                ]
            }
        }"#;
        let parsed: UsersResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.user.keys.len(), 1);
        assert_eq!(parsed.user.keys[0].primary, 1);
    }
}
