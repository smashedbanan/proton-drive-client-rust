use crate::config::{API_BASE_URL, APP_VERSION};
use crate::error::{Error, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ureq::unversioned::multipart::Form;

pub mod account;
pub mod auth;
pub mod drive;

/// Every Proton API response carries a top-level Code (1000 == success) and,
/// on failure, an Error message — independent of HTTP status. We disable
/// ureq's automatic status-code-as-error behavior so we always get the body
/// and can surface Proton's own error message rather than a bare HTTP code.
#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "Code")]
    code: i64,
    #[serde(rename = "Error")]
    error: Option<String>,
    #[serde(rename = "Details")]
    details: Option<serde_json::Value>,
}

const SUCCESS_CODE: i64 = 1000;

pub struct ApiClient {
    agent: ureq::Agent,
    session: Option<(String, String)>, // (uid, access_token)
}

impl ApiClient {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
            session: None,
        }
    }

    pub fn with_session(uid: String, access_token: String) -> Self {
        let mut client = Self::new();
        client.session = Some((uid, access_token));
        client
    }

    pub fn get<Resp: DeserializeOwned>(&self, path: &str) -> Result<Resp> {
        let url = format!("{API_BASE_URL}/{path}");
        let req = self.agent.get(&url).header("x-pm-appversion", APP_VERSION);
        let req = if let Some((uid, token)) = &self.session {
            req.header("x-pm-uid", uid)
                .header("Authorization", &format!("Bearer {token}"))
        } else {
            req
        };
        let response = req
            .call()
            .map_err(|e| Error::Network(e.to_string()))?;
        parse_response(response)
    }

    pub fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp> {
        let url = format!("{API_BASE_URL}/{path}");
        let req = self.agent.post(&url).header("x-pm-appversion", APP_VERSION);
        let req = if let Some((uid, token)) = &self.session {
            req.header("x-pm-uid", uid)
                .header("Authorization", &format!("Bearer {token}"))
        } else {
            req
        };
        let response = req
            .send_json(body)
            .map_err(|e| Error::Network(e.to_string()))?;
        parse_response(response)
    }

    /// Same shape as `post` above (headers, session auth), but sends a
    /// multipart body instead of JSON — used only by the small-file upload
    /// path (`api::drive::upload_small_file`/`upload_small_revision`), which
    /// is a regular authenticated API call (unlike the block-upload storage
    /// host, which uses a distinct `pm-storage-token` and no session header).
    pub fn post_multipart<Resp: DeserializeOwned>(&self, path: &str, form: Form<'_>) -> Result<Resp> {
        let url = format!("{API_BASE_URL}/{path}");
        let req = self.agent.post(&url).header("x-pm-appversion", APP_VERSION);
        let req = if let Some((uid, token)) = &self.session {
            req.header("x-pm-uid", uid)
                .header("Authorization", &format!("Bearer {token}"))
        } else {
            req
        };
        let response = req
            .send(form)
            .map_err(|e| Error::Network(e.to_string()))?;
        parse_response(response)
    }
}

fn parse_response<Resp: DeserializeOwned>(mut response: ureq::http::Response<ureq::Body>) -> Result<Resp> {
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Network(e.to_string()))?;
    let envelope: Envelope = serde_json::from_str(&text)
        .map_err(|e| Error::Network(format!("unexpected response shape: {e}")))?;
    if envelope.code != SUCCESS_CODE {
        return Err(Error::Api {
            code: envelope.code,
            message: envelope.error.unwrap_or_else(|| "unknown API error".into()),
            details: envelope.details,
        });
    }
    serde_json::from_str(&text).map_err(|e| Error::Network(format!("failed to parse response body: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_version_follows_required_pattern() {
        assert!(APP_VERSION.starts_with("external-drive-"));
        assert!(APP_VERSION.contains('@'));
    }
}
