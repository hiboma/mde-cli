use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auth::AuthProvider;
use crate::error::AppError;

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

pub struct OAuth2Auth {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    scope: String,
    http: reqwest::Client,
    cache: Mutex<Option<CachedToken>>,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl OAuth2Auth {
    pub fn new(
        tenant_id: String,
        client_id: String,
        client_secret: String,
        scope: String,
    ) -> Result<Self, AppError> {
        if tenant_id.is_empty() || client_id.is_empty() || client_secret.is_empty() {
            return Err(AppError::Auth(
                "tenant_id, client_id, and client_secret must not be empty.".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| AppError::Network(format!("failed to build HTTP client: {}", e)))?;
        Ok(Self {
            tenant_id,
            client_id,
            client_secret,
            scope,
            http,
            cache: Mutex::new(None),
        })
    }

    fn token_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }

    pub async fn fetch_token(&self) -> Result<String, AppError> {
        self.fetch_token_with_endpoint(
            #[cfg(test)]
            &self.token_url(),
        )
        .await
    }

    // Only unit tests can substitute a local mock endpoint. Production always
    // constructs the HTTPS Entra endpoint from the tenant ID.
    async fn fetch_token_with_endpoint(
        &self,
        #[cfg(test)] token_url: &str,
    ) -> Result<String, AppError> {
        // Check cache
        if let Ok(guard) = self.cache.lock()
            && let Some(ref cached) = *guard
            && Instant::now() < cached.expires_at
        {
            return Ok(cached.access_token.clone());
        }

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", &self.scope),
        ];

        #[cfg(not(test))]
        let request = self.http.post(self.token_url());
        #[cfg(test)]
        let request = self.http.post(token_url);

        let resp = request
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::Auth(format!("token request failed: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "failed to read response".to_string());
            return Err(AppError::Auth(format!(
                "token request returned {}: {}",
                status, body
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Auth(format!("failed to parse token response: {}", e)))?;

        let expires_at =
            Instant::now() + Duration::from_secs(token_resp.expires_in.saturating_sub(60));

        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(CachedToken {
                access_token: token_resp.access_token.clone(),
                expires_at,
            });
        }

        Ok(token_resp.access_token)
    }
}

impl AuthProvider for OAuth2Auth {
    fn token(&self) -> Result<String, AppError> {
        // Use a blocking runtime handle to call async fetch_token
        let rt = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| rt.block_on(self.fetch_token()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth2_auth_empty_params() {
        let result = OAuth2Auth::new(
            String::new(),
            "client".to_string(),
            "secret".to_string(),
            "scope".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_token_url() {
        let auth = OAuth2Auth::new(
            "tenant-123".to_string(),
            "client-456".to_string(),
            "secret-789".to_string(),
            "https://api.securitycenter.microsoft.com/.default".to_string(),
        )
        .unwrap();
        assert_eq!(
            auth.token_url(),
            "https://login.microsoftonline.com/tenant-123/oauth2/v2.0/token"
        );
    }

    #[tokio::test]
    async fn client_credentials_requests_only_the_target_default_scope() {
        use crate::auth::resource::{GRAPH_SCOPE, MDE_SCOPE, client_credentials_scope};
        let mut server = mockito::Server::new_async().await;
        for (scope, expected) in [
            (
                MDE_SCOPE,
                "https://api.securitycenter.microsoft.com/.default",
            ),
            (GRAPH_SCOPE, "https://graph.microsoft.com/.default"),
        ] {
            let mock = server
                .mock("POST", "/token")
                .match_body(mockito::Matcher::AllOf(vec![
                    mockito::Matcher::UrlEncoded("grant_type".into(), "client_credentials".into()),
                    mockito::Matcher::UrlEncoded("scope".into(), expected.into()),
                    mockito::Matcher::UrlEncoded("client_secret".into(), "secret".into()),
                ]))
                .with_header("content-type", "application/json")
                .with_body(r#"{"access_token":"app-token","expires_in":3600}"#)
                .create_async()
                .await;
            let auth = OAuth2Auth::new(
                "tenant".into(),
                "client".into(),
                "secret".into(),
                client_credentials_scope(scope),
            )
            .unwrap();
            assert_eq!(
                auth.fetch_token_with_endpoint(&format!("{}/token", server.url()))
                    .await
                    .unwrap(),
                "app-token"
            );
            mock.assert_async().await;
        }
    }
}
