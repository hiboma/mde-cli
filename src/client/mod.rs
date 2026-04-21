pub mod response;
pub mod retry;

use reqwest::Client;

use crate::auth::AuthProvider;
use crate::error::AppError;

pub struct MdeClient {
    http: Client,
    base_url: String,
    auth: Box<dyn AuthProvider>,
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
        })
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
        response::check_response(response).await
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
        response::check_response(response).await
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
        response::check_response(response).await
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
        response::check_response(response).await
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
        response::check_response(response).await
    }
}
