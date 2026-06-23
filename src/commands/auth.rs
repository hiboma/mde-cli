use crate::auth::browser;
use crate::auth::clipboard;
use crate::cli::auth::AuthCommand;
use crate::config::credential_store::{KEY_ACCESS_TOKEN, KEY_REFRESH_TOKEN, default_store};
use crate::error::AppError;

const MDE_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default offline_access";

pub async fn handle(
    command: &AuthCommand,
    tenant_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<(), AppError> {
    match command {
        AuthCommand::Login => login(tenant_id, client_id).await,
        AuthCommand::Token => token(tenant_id, client_id, client_secret).await,
    }
}

async fn login(tenant_id: &str, client_id: &str) -> Result<(), AppError> {
    let result = browser::browser_login(tenant_id, client_id, MDE_SCOPE).await?;

    if let Some(store) = default_store() {
        store
            .set(KEY_ACCESS_TOKEN, &result.access_token)
            .map_err(|e| AppError::Auth(format!("failed to save access token: {}", e)))?;
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
    } else if clipboard::is_tty() {
        clipboard::copy_and_verify(&result.access_token, result.expires_in)?;
    } else {
        clipboard::print_token(&result.access_token);
    }

    Ok(())
}

async fn token(
    tenant_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<(), AppError> {
    let secret = client_secret.ok_or_else(|| {
        AppError::Auth(
            "client_secret is required for token command. Set MDE_CLIENT_SECRET.".to_string(),
        )
    })?;

    let auth = crate::auth::oauth2::OAuth2Auth::new(
        tenant_id.to_string(),
        client_id.to_string(),
        secret.to_string(),
        "https://api.securitycenter.microsoft.com/.default".to_string(),
    )?;

    let token = auth.fetch_token().await?;

    if clipboard::is_tty() {
        eprintln!("Token acquired via client_credentials flow.");
        clipboard::print_token(&token);
    } else {
        clipboard::print_token(&token);
    }

    Ok(())
}
