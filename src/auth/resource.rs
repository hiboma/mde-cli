use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

use super::{AuthProvider, StaticTokenAuth, browser, oauth2::OAuth2Auth};
use crate::client::MdeClient;
use crate::config::MdeCredentials;
use crate::config::credential_store::{
    CredentialStore, KEY_TOKEN_BUNDLE, TokenBundle, default_store,
};
use crate::error::AppError;

pub const MDE_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default offline_access";
pub const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default offline_access";

fn is_graph(scope: &str) -> bool {
    scope
        .split_whitespace()
        .any(|s| s == "https://graph.microsoft.com/.default")
}

pub(super) fn client_credentials_scope(scope: &str) -> String {
    scope
        .split_whitespace()
        .filter(|s| *s != "offline_access")
        .collect::<Vec<_>>()
        .join(" ")
}

/// Diagnose a resource mismatch only; unverified claims never establish authorization.
fn check_audience(token: &str, scope: &str) -> Result<(), AppError> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Ok(());
    }
    let Ok(payload) = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| URL_SAFE.decode(parts[1]))
    else {
        return Ok(());
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return Ok(());
    };
    let audiences: Vec<&str> = match &claims["aud"] {
        serde_json::Value::String(aud) => vec![aud],
        serde_json::Value::Array(values) => values.iter().filter_map(|v| v.as_str()).collect(),
        _ => return Ok(()),
    };
    if audiences.is_empty() {
        return Ok(());
    }
    let (target, aliases): (&str, &[&str]) = if is_graph(scope) {
        (
            "Microsoft Graph",
            &[
                "https://graph.microsoft.com",
                "00000003-0000-0000-c000-000000000000",
            ],
        )
    } else {
        (
            "Microsoft Defender for Endpoint",
            &[
                "https://api.securitycenter.microsoft.com",
                "https://api.security.microsoft.com",
                "fc780465-2017-40d4-a0c5-307022471b92",
            ],
        )
    };
    if audiences.iter().any(|aud| {
        aliases
            .iter()
            .any(|alias| aud.trim_end_matches('/').eq_ignore_ascii_case(alias))
    }) {
        return Ok(());
    }
    Err(AppError::Auth(format!(
        "this token is intended for {}; it cannot be used with {}. Run `mde-cli auth login` or provide a token for the target resource.",
        serde_json::to_string(&audiences).unwrap_or_default(),
        target
    )))
}

enum ResourceProvider {
    Static(StaticTokenAuth),
    ClientCredentials(OAuth2Auth),
}

struct ResourceAuth {
    provider: ResourceProvider,
    refresh_rotation: Option<(String, String)>,
}

async fn token_for_resource(
    credentials: &MdeCredentials,
    scope: &str,
    token_endpoint: Option<&str>,
) -> Result<ResourceAuth, AppError> {
    if is_graph(scope)
        && let Some(refresh_token) = &credentials.refresh_token
    {
        let tid = credentials.tenant_id.as_deref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".into())
        })?;
        let cid = credentials.client_id.as_deref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".into())
        })?;
        let result = match token_endpoint {
            Some(url) => browser::refresh_access_token_at_url(url, cid, refresh_token, GRAPH_SCOPE).await,
            None => browser::refresh_access_token(tid, cid, refresh_token, GRAPH_SCOPE).await,
        }.map_err(|err| AppError::Auth(format!(
            "failed to obtain a Microsoft Graph token: {}. Verify Graph delegated permissions (ThreatHunting.Read.All or SecurityIncident.ReadWrite.All) and administrator consent; run `mde-cli auth login` again if necessary.", err
        )))?;
        check_audience(&result.access_token, scope)?;
        return Ok(ResourceAuth {
            provider: ResourceProvider::Static(StaticTokenAuth(result.access_token)),
            refresh_rotation: result.refresh_token.map(|new| (refresh_token.clone(), new)),
        });
    }
    if let Some(token) = &credentials.access_token {
        check_audience(token, scope)?;
        return Ok(ResourceAuth {
            provider: ResourceProvider::Static(StaticTokenAuth(token.clone())),
            refresh_rotation: None,
        });
    }
    let tid = credentials.tenant_id.as_ref().ok_or_else(|| {
        AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".into())
    })?;
    let cid = credentials.client_id.as_ref().ok_or_else(|| {
        AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".into())
    })?;
    let secret = credentials.client_secret.as_ref().ok_or_else(|| {
        AppError::Config(
            "client_secret not set. Set MDE_CLIENT_SECRET env var or credentials.toml.".into(),
        )
    })?;
    Ok(ResourceAuth {
        provider: ResourceProvider::ClientCredentials(OAuth2Auth::new(
            tid.clone(),
            cid.clone(),
            secret.clone(),
            client_credentials_scope(scope),
        )?),
        refresh_rotation: None,
    })
}

fn persist_refresh_rotation(
    store: &dyn CredentialStore,
    previous: &str,
    next: &str,
) -> Result<(), AppError> {
    let Some(raw) = store
        .get(KEY_TOKEN_BUNDLE)
        .map_err(|e| AppError::Config(e.to_string()))?
    else {
        return Ok(());
    };
    let mut bundle: TokenBundle = serde_json::from_str(&raw)?;
    // Do not copy credentials from another source into an unrelated stored session.
    if bundle.refresh_token.as_deref() != Some(previous) {
        return Ok(());
    }
    bundle.refresh_token = Some(next.to_owned());
    store
        .set(KEY_TOKEN_BUNDLE, &serde_json::to_string(&bundle)?)
        .map_err(|e| AppError::Config(e.to_string()))
}

pub async fn build_mde_client(
    credentials: &MdeCredentials,
    base_url: &str,
    scope: &str,
) -> Result<MdeClient, AppError> {
    let auth = token_for_resource(credentials, scope, None).await?;
    if let Some((previous, next)) = auth.refresh_rotation
        && let Some(store) = default_store()
        && let Err(err) = persist_refresh_rotation(store.as_ref(), &previous, &next)
    {
        eprintln!("warning: failed to save rotated refresh token: {}", err);
    }
    let provider: Box<dyn AuthProvider> = match auth.provider {
        ResourceProvider::Static(provider) => Box::new(provider),
        ResourceProvider::ClientCredentials(provider) => Box::new(provider),
    };
    let client = MdeClient::new(base_url.to_owned(), provider)?;
    Ok(if is_graph(scope) {
        client.with_graph_permissions_hint()
    } else {
        client
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_store::test_support::MemoryStore;

    fn credentials() -> MdeCredentials {
        MdeCredentials {
            tenant_id: Some("tenant".into()),
            client_id: Some("client".into()),
            client_secret: None,
            access_token: Some("mde-access".into()),
            refresh_token: Some("old-refresh".into()),
            mde_base_url: String::new(),
            graph_base_url: String::new(),
        }
    }

    fn jwt(aud: serde_json::Value) -> String {
        format!(
            "header.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::json!({"aud": aud}).to_string())
        )
    }

    #[test]
    fn audience_checks_resource_urls_ids_and_arrays() {
        for audience in [
            "https://graph.microsoft.com",
            "https://graph.microsoft.com/",
            "00000003-0000-0000-c000-000000000000",
        ] {
            let token = jwt(audience.into());
            assert!(check_audience(&token, GRAPH_SCOPE).is_ok());
            assert!(check_audience(&token, MDE_SCOPE).is_err());
        }
        for audience in [
            "https://api.securitycenter.microsoft.com",
            "https://api.security.microsoft.com",
            "fc780465-2017-40d4-a0c5-307022471b92",
        ] {
            let token = jwt(audience.into());
            assert!(check_audience(&token, MDE_SCOPE).is_ok());
            let err = check_audience(&token, GRAPH_SCOPE).unwrap_err().to_string();
            assert!(err.contains(audience));
            assert!(err.contains("Microsoft Graph"));
        }
        assert!(
            check_audience(
                &jwt(serde_json::json!(["other", "https://graph.microsoft.com"])),
                GRAPH_SCOPE
            )
            .is_ok()
        );
        for token in ["opaque", "a.invalid-base64.c", "a.e30.c", "a.b.c.d"] {
            assert!(check_audience(token, GRAPH_SCOPE).is_ok());
        }
    }

    #[tokio::test]
    async fn mde_keeps_existing_access_token_without_refreshing() {
        let mut server = mockito::Server::new_async().await;
        let mock = server.mock("POST", "/token").expect(0).create_async().await;
        let auth = token_for_resource(
            &credentials(),
            MDE_SCOPE,
            Some(&format!("{}/token", server.url())),
        )
        .await
        .unwrap();
        let ResourceProvider::Static(provider) = auth.provider else {
            panic!("expected a static resource token");
        };
        assert_eq!(provider.token().unwrap(), "mde-access");
        assert!(auth.refresh_rotation.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn graph_refresh_uses_graph_scope_and_preserves_mde_bundle() {
        let mut server = mockito::Server::new_async().await;
        let mock = server.mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
                mockito::Matcher::UrlEncoded("client_id".into(), "client".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), "old-refresh".into()),
                mockito::Matcher::UrlEncoded("scope".into(), GRAPH_SCOPE.into()),
            ]))
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"graph-access","expires_in":3600,"refresh_token":"new-refresh"}"#)
            .create_async().await;
        let auth = token_for_resource(
            &credentials(),
            GRAPH_SCOPE,
            Some(&format!("{}/token", server.url())),
        )
        .await
        .unwrap();
        let ResourceProvider::Static(provider) = auth.provider else {
            panic!("expected a static resource token");
        };
        assert_eq!(provider.token().unwrap(), "graph-access");
        let store = MemoryStore::new();
        store
            .set(
                KEY_TOKEN_BUNDLE,
                r#"{"access_token":"mde-access","expires_at":12345,"refresh_token":"old-refresh"}"#,
            )
            .unwrap();
        let (previous, next) = auth.refresh_rotation.unwrap();
        persist_refresh_rotation(&store, &previous, &next).unwrap();
        let bundle: TokenBundle =
            serde_json::from_str(&store.get(KEY_TOKEN_BUNDLE).unwrap().unwrap()).unwrap();
        assert_eq!(bundle.access_token, "mde-access");
        assert_eq!(bundle.expires_at, 12345);
        assert_eq!(bundle.refresh_token.as_deref(), Some("new-refresh"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn graph_refresh_without_rotation_and_without_access_token() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/token")
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"graph-access","expires_in":3600}"#)
            .create_async()
            .await;
        let mut creds = credentials();
        creds.access_token = None;
        let auth = token_for_resource(
            &creds,
            GRAPH_SCOPE,
            Some(&format!("{}/token", server.url())),
        )
        .await
        .unwrap();
        let ResourceProvider::Static(provider) = auth.provider else {
            panic!("expected a static resource token");
        };
        assert_eq!(provider.token().unwrap(), "graph-access");
        assert!(auth.refresh_rotation.is_none());
        mock.assert_async().await;
    }

    #[test]
    fn rotation_does_not_create_or_replace_unrelated_session() {
        let store = MemoryStore::new();
        persist_refresh_rotation(&store, "old", "new").unwrap();
        assert!(store.get(KEY_TOKEN_BUNDLE).unwrap().is_none());
        let raw =
            r#"{"access_token":"other-access","expires_at":42,"refresh_token":"other-refresh"}"#;
        store.set(KEY_TOKEN_BUNDLE, raw).unwrap();
        persist_refresh_rotation(&store, "old", "new").unwrap();
        assert_eq!(store.get(KEY_TOKEN_BUNDLE).unwrap().as_deref(), Some(raw));
    }

    #[tokio::test]
    async fn static_graph_token_is_checked_when_refresh_is_absent() {
        let mut creds = credentials();
        creds.refresh_token = None;
        creds.access_token = Some(jwt("https://api.securitycenter.microsoft.com".into()));
        assert!(token_for_resource(&creds, GRAPH_SCOPE, None).await.is_err());
        creds.access_token = Some(jwt("https://graph.microsoft.com".into()));
        let auth = token_for_resource(&creds, GRAPH_SCOPE, None).await.unwrap();
        let ResourceProvider::Static(provider) = auth.provider else {
            panic!("expected a static resource token");
        };
        assert_eq!(provider.token().unwrap(), creds.access_token.unwrap());
    }

    #[tokio::test]
    async fn client_secret_path_preserves_resource_scope() {
        let mut creds = credentials();
        creds.access_token = None;
        creds.refresh_token = None;
        creds.client_secret = Some("secret".into());
        for (scope, expected) in [
            (
                MDE_SCOPE,
                "https://api.securitycenter.microsoft.com/.default",
            ),
            (GRAPH_SCOPE, "https://graph.microsoft.com/.default"),
        ] {
            assert_eq!(client_credentials_scope(scope), expected);
            let auth = token_for_resource(&creds, scope, None).await.unwrap();
            assert!(matches!(
                auth.provider,
                ResourceProvider::ClientCredentials(_)
            ));
            assert!(auth.refresh_rotation.is_none());
        }
    }

    #[tokio::test]
    async fn graph_refresh_error_explains_permissions_without_falling_back() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant"}"#)
            .create_async()
            .await;
        let mut creds = credentials();
        creds.client_secret = Some("secret".into());
        let result = token_for_resource(
            &creds,
            GRAPH_SCOPE,
            Some(&format!("{}/token", server.url())),
        )
        .await;
        let err = match result {
            Err(err) => err.to_string(),
            Ok(_) => panic!("refresh should fail"),
        };
        assert!(err.contains("ThreatHunting.Read.All"));
        assert!(err.contains("administrator consent"));
        assert!(err.contains("invalid_grant"));
        mock.assert_async().await;
    }
}
