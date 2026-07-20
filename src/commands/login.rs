use base64::Engine;
use crate::api::auth::{self, AuthRequest};
use crate::api::ApiClient;
use crate::crypto;
use crate::error::{Error, Result};
use crate::session::{self, Credentials};
use crate::srp;
use std::collections::HashMap;
use std::io::Write;

pub fn run() -> Result<()> {
    print!("Username: ");
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let username = username.trim();

    let password = rpassword::prompt_password("Password: ")
        .map_err(|e| Error::Crypto(format!("failed to read password: {e}")))?;

    let client = ApiClient::new();
    let auth_info = auth::fetch_auth_info(&client, username)?;
    if auth_info.version != 4 {
        return Err(Error::Crypto(format!(
            "unsupported auth version {} (only version 4 is implemented)",
            auth_info.version
        )));
    }

    let modulus = srp::verify_and_decode_modulus(&auth_info.modulus)?;
    let x = srp::hash_password(password.as_bytes(), &auth_info.salt, &modulus)?;
    let proofs = srp::generate_proofs(&modulus, &auth_info.server_ephemeral, &x)?;

    let auth_req = AuthRequest {
        username,
        client_ephemeral: &proofs.client_ephemeral_b64,
        client_proof: &proofs.client_proof_b64,
        srp_session: &auth_info.srp_session,
        persistent_cookies: 0,
        payload: HashMap::new(),
    };
    let auth_resp = auth::submit_auth(&client, &auth_req)?;

    let actual_server_proof = base64::engine::general_purpose::STANDARD
        .decode(&auth_resp.server_proof)
        .map_err(|e| Error::Crypto(format!("bad server proof base64: {e}")))?;
    if actual_server_proof != proofs.expected_server_proof {
        return Err(Error::Crypto(
            "server proof did not match expected value — aborting".into(),
        ));
    }

    if auth_resp.password_mode != 1 {
        return Err(Error::TwoPasswordModeUnsupported);
    }

    let authed_client = ApiClient::with_session(auth_resp.uid.clone(), auth_resp.access_token.clone());

    let salts = auth::fetch_key_salts(&authed_client)?;
    let key_salt = salts
        .key_salts
        .iter()
        .find_map(|s| s.key_salt.as_deref())
        .ok_or_else(|| Error::Crypto("no usable key salt returned".into()))?;
    let key_password = srp::compute_key_password(password.as_bytes(), key_salt)?;

    let users = auth::fetch_users(&authed_client)?;
    let primary_key = users
        .user
        .keys
        .iter()
        .find(|k| k.primary == 1 && k.active == 1)
        .ok_or_else(|| Error::Crypto("no active primary user key found".into()))?;

    crypto::unlock_private_key(&primary_key.private_key, &key_password)?;

    session::save(&Credentials {
        uid: auth_resp.uid,
        access_token: auth_resp.access_token,
        refresh_token: auth_resp.refresh_token,
        user_key_password: key_password,
    })?;

    println!("Logged in as {username}.");
    Ok(())
}
