use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::browser;
use crate::auth::clipboard;
use crate::cli::auth::AuthCommand;
use crate::config::credential_store::{KEY_TOKEN_BUNDLE, TokenBundle, default_store};
use crate::error::AppError;

pub const MDE_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default offline_access";

pub async fn handle(
    command: &AuthCommand,
    tenant_id: &str,
    client_id: &str,
) -> Result<(), AppError> {
    match command {
        AuthCommand::Login => login(tenant_id, client_id).await,
    }
}

fn compute_expires_at(expires_in: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now + expires_in
}

pub fn save_tokens_to_keychain(
    result: &browser::BrowserLoginResult,
    existing_refresh_token: Option<&str>,
) -> Result<bool, AppError> {
    let Some(store) = default_store() else {
        return Ok(false);
    };

    let bundle = TokenBundle {
        access_token: result.access_token.clone(),
        expires_at: compute_expires_at(result.expires_in),
        refresh_token: result
            .refresh_token
            .clone()
            .or_else(|| existing_refresh_token.map(|s| s.to_string())),
    };

    let json = serde_json::to_string(&bundle)
        .map_err(|e| AppError::Auth(format!("failed to serialize token bundle: {}", e)))?;

    store
        .set(KEY_TOKEN_BUNDLE, &json)
        .map_err(|e| AppError::Auth(format!("failed to save token bundle: {}", e)))?;

    eprintln!(
        "Token bundle saved to keychain. (expires in {}s)",
        result.expires_in
    );

    Ok(true)
}

async fn login(tenant_id: &str, client_id: &str) -> Result<(), AppError> {
    let result = browser::browser_login(tenant_id, client_id, MDE_SCOPE).await?;

    let saved = save_tokens_to_keychain(&result, None)?;
    if !saved {
        if clipboard::is_tty() {
            clipboard::copy_and_verify(&result.access_token, result.expires_in)?;
        } else {
            clipboard::print_token(&result.access_token);
        }
    }

    Ok(())
}
