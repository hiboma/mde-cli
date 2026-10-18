pub mod response;
pub mod retry;

use reqwest::Client;

use crate::auth::AuthProvider;
use crate::error::AppError;

pub struct MdeClient {
    http: Client,
    base_url: String,
    auth: Box<dyn AuthProvider>,
    graph_permissions_hint: bool,
}

impl MdeClient {
    pub fn new(base_url: String, auth: Box<dyn AuthProvider>) -> Result<Self, AppError> {
        let http = Client::builder()
            .build()
            .map_err(|e| AppError::Network(format!("failed to build HTTP client: {}", e)))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            graph_permissions_hint: false,
        })
    }

    /// Include Microsoft Graph permission guidance in authentication errors.
    pub fn with_graph_permissions_hint(mut self) -> Self {
        self.graph_permissions_hint = true;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Send a GET request to the given path.
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.token()?;
        let response = retry::with_retry(|| async {
            self.http
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
        })
        .await?;
        response::check_response_with_graph_hint(response, self.graph_permissions_hint).await
    }

    /// Send a GET request with query parameters.
    pub async fn get_with_query(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> Result<reqwest::Response, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.token()?;
        let response = retry::with_retry(|| async {
            self.http
                .get(&url)
                .query(query)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
        })
        .await?;
        response::check_response_with_graph_hint(response, self.graph_permissions_hint).await
    }

    /// Send a POST request with a JSON body.
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.token()?;
        let response = retry::with_retry(|| async {
            self.http
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .json(body)
                .send()
                .await
        })
        .await?;
        response::check_response_with_graph_hint(response, self.graph_permissions_hint).await
    }

    /// Send a PATCH request with a JSON body.
    pub async fn patch(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.token()?;
        let response = retry::with_retry(|| async {
            self.http
                .patch(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .json(body)
                .send()
                .await
        })
        .await?;
        response::check_response_with_graph_hint(response, self.graph_permissions_hint).await
    }

    /// Send a DELETE request.
    pub async fn delete(&self, path: &str) -> Result<reqwest::Response, AppError> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.auth.token()?;
        let response = retry::with_retry(|| async {
            self.http
                .delete(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
        })
        .await?;
        response::check_response_with_graph_hint(response, self.graph_permissions_hint).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;

    #[tokio::test]
    async fn graph_permission_hint_covers_all_request_methods() {
        let mut server = mockito::Server::new_async().await;
        for status in [401, 403] {
            for method in ["GET", "GET_QUERY", "POST", "PATCH", "DELETE"] {
                let mock = server
                    .mock(if method == "GET_QUERY" { "GET" } else { method }, "/test")
                    .match_query(mockito::Matcher::Any)
                    .with_status(status)
                    .with_body("permission denied")
                    .create_async()
                    .await;
                let client =
                    MdeClient::new(server.url(), Box::new(StaticTokenAuth("test-token".into())))
                        .unwrap()
                        .with_graph_permissions_hint();
                let result = match method {
                    "GET" => client.get("/test").await,
                    "GET_QUERY" => {
                        client
                            .get_with_query("/test", &[("key".into(), "value".into())])
                            .await
                    }
                    "POST" => client.post("/test", &serde_json::json!({})).await,
                    "PATCH" => client.patch("/test", &serde_json::json!({})).await,
                    "DELETE" => client.delete("/test").await,
                    _ => unreachable!(),
                };
                let error = result.unwrap_err();
                let message = error.to_string();
                assert!(message.contains("ThreatHunting.Read.All"));
                assert!(message.contains("SecurityIncident.ReadWrite.All"));
                assert!(message.contains("admin consent"));
                assert!(message.contains("may be missing"));
                assert!(message.contains("application permissions"));
                match (status, error) {
                    (401, AppError::Auth(_)) => {}
                    (
                        403,
                        AppError::Api {
                            status: 403,
                            message,
                        },
                    ) => {
                        assert!(message.contains("permission denied"));
                    }
                    (_, error) => panic!("unexpected error: {error}"),
                }
                mock.assert_async().await;
            }
        }
    }

    #[tokio::test]
    async fn mde_authentication_errors_remain_unchanged() {
        let mut server = mockito::Server::new_async().await;
        for status in [401, 403] {
            let mock = server
                .mock("GET", "/test")
                .with_status(status)
                .with_body("permission denied")
                .create_async()
                .await;
            let client =
                MdeClient::new(server.url(), Box::new(StaticTokenAuth("test-token".into())))
                    .unwrap();
            match (status, client.get("/test").await.unwrap_err()) {
                (401, AppError::Auth(message)) => {
                    assert_eq!(message, "authentication failed. Verify your credentials.");
                }
                (
                    403,
                    AppError::Api {
                        status: 403,
                        message,
                    },
                ) => {
                    assert_eq!(message, "permission denied");
                }
                (_, error) => panic!("unexpected error: {error}"),
            }
            mock.assert_async().await;
        }
    }
}
