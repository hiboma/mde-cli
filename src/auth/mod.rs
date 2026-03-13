pub mod browser;
pub mod clipboard;
pub mod oauth2;

use crate::error::AppError;

pub trait AuthProvider: Send + Sync {
    fn token(&self) -> Result<String, AppError>;
}

/// Simple static token auth for pre-obtained access tokens.
pub struct StaticTokenAuth(pub String);

impl AuthProvider for StaticTokenAuth {
    fn token(&self) -> Result<String, AppError> {
        Ok(self.0.clone())
    }
}
