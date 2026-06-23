use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::browser;
use crate::auth::clipboard;
use crate::cli::auth::AuthCommand;
use crate::config::credential_store::{
    KEY_ACCESS_TOKEN, KEY_REFRESH_TOKEN, KEY_TOKEN_EXPIRES_AT, default_store,
};
use crate::error::AppError;

const MDE_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default offline_access";

pub async fn handle(
    command: &AuthCommand,
    tenant_id: &str,
    client_id: &str,
) -> Result<(), AppError> {
    match command {
        AuthCommand::Login => login(tenant_id, client_id).await,
    }
}

fn compute_expires_at(expires_in: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (now + expires_in).to_string()
}

pub fn save_tokens_to_keychain(result: &browser::BrowserLoginResult) -> Result<(), AppError> {
    let Some(store) = default_store() else {
        return Ok(());
    };

    store
        .set(KEY_ACCESS_TOKEN, &result.access_token)
        .map_err(|e| AppError::Auth(format!("failed to save access token: {}", e)))?;

    let expires_at = compute_expires_at(result.expires_in);
    store
        .set(KEY_TOKEN_EXPIRES_AT, &expires_at)
        .map_err(|e| AppError::Auth(format!("failed to save token expiry: {}", e)))?;
    eprintln!(
        "Access token saved to keychain. (expires in {}s)",
        result.expires_in
    );

    if let Some(ref rt) = result.refresh_token {
        store
            .set(KEY_REFRESH_TOKEN, rt)
            .map_err(|e| AppError::Auth(format!("failed to save refresh token: {}", e)))?;
        eprintln!("Refresh token saved to keychain.");
    }

    Ok(())
}

async fn login(tenant_id: &str, client_id: &str) -> Result<(), AppError> {
    let result = browser::browser_login(tenant_id, client_id, MDE_SCOPE).await?;

    if default_store().is_some() {
        save_tokens_to_keychain(&result)?;
    } else if clipboard::is_tty() {
        clipboard::copy_and_verify(&result.access_token, result.expires_in)?;
    } else {
        clipboard::print_token(&result.access_token);
    }

    Ok(())
}
