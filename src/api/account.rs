use super::ApiClient;
use crate::error::Result;
use serde::Deserialize;

// Holds an armored private key — never derive Debug (see api::auth::UserKey).
#[derive(Deserialize)]
pub struct AddressKey {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Primary")]
    pub primary: i64,
    #[serde(rename = "Active")]
    pub active: i64,
}

#[derive(Deserialize)]
pub struct Address {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Email")]
    pub email: String,
    #[serde(rename = "Keys")]
    pub keys: Vec<AddressKey>,
}

#[derive(Deserialize)]
pub struct AddressesResponse {
    #[serde(rename = "Addresses")]
    pub addresses: Vec<Address>,
}

/// `GET core/v4/addresses` — a distinct concept from the account's user keys
/// (which `login` already fetches via `core/v4/users`). Address keys are what
/// sign uploaded blocks and the upload manifest.
pub fn fetch_addresses(client: &ApiClient) -> Result<AddressesResponse> {
    client.get("core/v4/addresses")
}

#[derive(Deserialize, Debug)]
struct Feature {
    #[serde(rename = "Value")]
    value: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct FeatureResponse {
    #[serde(rename = "Feature")]
    feature: Feature,
}

/// `GET core/v4/features/{code}` — "Get a single feature by its code". No
/// reference client in Proton's own SDK actually calls this (feature-flag
/// fetching has no working reference implementation anywhere in that SDK —
/// see the upload design doc's Background section), so this response shape
/// is a best-effort match to the endpoint's OpenAPI type declaration, not a
/// validated one. Returns `Ok(false)` (never an error) if the flag can't be
/// confirmed `true` for ANY reason — unexpected shape, non-boolean value,
/// anything — so callers never need their own fallback logic; a missing or
/// malformed flag is indistinguishable from "disabled". Network/API errors
/// still propagate as `Err`, so a caller can log-and-continue on those too
/// per the plan's fail-safe requirement (see `commands::upload`, Task 11).
pub fn fetch_feature_flag(client: &ApiClient, code: &str) -> Result<bool> {
    let path = format!("core/v4/features/{code}");
    let resp: FeatureResponse = client.get(&path)?;
    Ok(resp.feature.value.as_bool().unwrap_or(false))
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    #[test]
    fn addresses_response_deserializes() {
        let json = r#"{
            "Addresses": [
                {"ID": "addr-1", "Email": "user@example.com", "Keys": [
                    {"ID": "key-1", "PrivateKey": "armored-key-text", "Primary": 1, "Active": 1}
                ]}
            ]
        }"#;
        let parsed: AddressesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.addresses.len(), 1);
        assert_eq!(parsed.addresses[0].keys[0].primary, 1);
    }

    #[test]
    fn feature_flag_true_when_value_is_true() {
        let json = r#"{"Feature": {"Value": true}}"#;
        let resp: FeatureResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.feature.value.as_bool(), Some(true));
    }

    #[test]
    fn feature_flag_defaults_false_for_non_bool_value() {
        let json = r#"{"Feature": {"Value": "unexpected-string"}}"#;
        let resp: FeatureResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.feature.value.as_bool().unwrap_or(false), false);
    }
}
