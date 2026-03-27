use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::AppError;

/// Resolved MDE credentials collected from CLI args, environment variables, and config.toml.
/// Once constructed, the process should unset the MDE_* environment variables so that
/// forked child processes (agent) do not inherit credentials via the environment.
#[derive(Debug, Clone, Default)]
pub struct MdeCredentials {
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub access_token: Option<String>,
}

impl MdeCredentials {
    /// Resolve credentials from CLI args, environment variables, and config.toml.
    /// Priority: CLI args > environment variables > config.toml.
    pub fn resolve(
        cli_tenant_id: Option<&str>,
        cli_client_id: Option<&str>,
        config: &Config,
    ) -> Self {
        let tenant_id = cli_tenant_id
            .map(String::from)
            .or_else(|| std::env::var("MDE_TENANT_ID").ok())
            .or_else(|| config.auth.tenant_id.clone());

        let client_id = cli_client_id
            .map(String::from)
            .or_else(|| std::env::var("MDE_CLIENT_ID").ok())
            .or_else(|| config.auth.client_id.clone());

        let client_secret = std::env::var("MDE_CLIENT_SECRET")
            .ok()
            .or_else(|| config.auth.client_secret.clone());

        let access_token = std::env::var("MDE_ACCESS_TOKEN").ok();

        Self {
            tenant_id,
            client_id,
            client_secret,
            access_token,
        }
    }

    /// Validate that required credentials are present for API access.
    /// If access_token is set, tenant_id/client_id/client_secret are not required.
    pub fn validate(&self) -> Result<(), String> {
        if self.access_token.is_some() {
            return Ok(());
        }

        let mut missing = Vec::new();
        if self.tenant_id.is_none() {
            missing.push("MDE_TENANT_ID");
        }
        if self.client_id.is_none() {
            missing.push("MDE_CLIENT_ID");
        }
        if self.client_secret.is_none() {
            missing.push("MDE_CLIENT_SECRET");
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "missing required credentials: {}. Set via environment variables or config.toml.",
                missing.join(", ")
            ))
        }
    }

    /// Remove MDE credential environment variables from the current process.
    /// Call this after resolving credentials to prevent leaking them to child processes.
    ///
    /// # Safety
    /// Must be called in a single-threaded context (before tokio runtime creation).
    pub unsafe fn clear_env() {
        for key in &[
            "MDE_TENANT_ID",
            "MDE_CLIENT_ID",
            "MDE_CLIENT_SECRET",
            "MDE_ACCESS_TOKEN",
        ] {
            // SAFETY: Caller guarantees single-threaded context.
            unsafe {
                std::env::remove_var(key);
            }
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub api: ApiConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ApiConfig {
    pub mde_base_url: Option<String>,
    pub graph_base_url: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self, AppError> {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path).map_err(|e| {
                AppError::Config(format!(
                    "failed to read config file {}: {}",
                    path.display(),
                    e
                ))
            })?;
            let config: Config = toml::from_str(&content)
                .map_err(|e| AppError::Config(format!("failed to parse config file: {}", e)))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    fn config_path() -> PathBuf {
        dirs_config_path().join("config.toml")
    }
}

fn dirs_config_path() -> PathBuf {
    if let Some(config_dir) = dirs_home().map(|h| h.join(".config").join("mde")) {
        config_dir
    } else {
        PathBuf::from(".config/mde")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Resolve a value from CLI option, environment variable, or config file (in priority order).
pub fn resolve_value(
    cli_value: Option<&str>,
    env_var: &str,
    config_value: Option<&str>,
) -> Option<String> {
    cli_value
        .map(String::from)
        .or_else(|| std::env::var(env_var).ok())
        .or_else(|| config_value.map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.auth.tenant_id.is_none());
        assert!(config.auth.client_id.is_none());
        assert!(config.auth.client_secret.is_none());
    }

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[auth]
tenant_id = "t-123"
client_id = "c-456"
client_secret = "s-789"

[api]
mde_base_url = "https://api.security.microsoft.com"
graph_base_url = "https://graph.microsoft.com"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.auth.tenant_id.as_deref(), Some("t-123"));
        assert_eq!(
            config.api.mde_base_url.as_deref(),
            Some("https://api.security.microsoft.com")
        );
    }

    #[test]
    fn test_resolve_value_priority() {
        let result = resolve_value(Some("cli"), "NONEXISTENT_VAR", Some("config"));
        assert_eq!(result.as_deref(), Some("cli"));

        let result = resolve_value(None, "NONEXISTENT_VAR_12345", Some("config"));
        assert_eq!(result.as_deref(), Some("config"));

        let result = resolve_value(None, "NONEXISTENT_VAR_12345", None);
        assert!(result.is_none());
    }

    #[test]
    fn test_mde_credentials_validate_with_access_token() {
        let creds = MdeCredentials {
            access_token: Some("token".to_string()),
            ..Default::default()
        };
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_mde_credentials_validate_with_oauth2() {
        let creds = MdeCredentials {
            tenant_id: Some("t".to_string()),
            client_id: Some("c".to_string()),
            client_secret: Some("s".to_string()),
            access_token: None,
        };
        assert!(creds.validate().is_ok());
    }

    #[test]
    fn test_mde_credentials_validate_missing() {
        let creds = MdeCredentials::default();
        let err = creds.validate().unwrap_err();
        assert!(err.contains("MDE_TENANT_ID"));
        assert!(err.contains("MDE_CLIENT_ID"));
        assert!(err.contains("MDE_CLIENT_SECRET"));
    }

    #[test]
    fn test_mde_credentials_validate_partial_missing() {
        let creds = MdeCredentials {
            tenant_id: Some("t".to_string()),
            ..Default::default()
        };
        let err = creds.validate().unwrap_err();
        assert!(!err.contains("MDE_TENANT_ID"));
        assert!(err.contains("MDE_CLIENT_ID"));
        assert!(err.contains("MDE_CLIENT_SECRET"));
    }

    /// Helper to ensure MDE_* env vars are cleared before tests that call resolve().
    /// Tests run in parallel, so env var mutations in one test can leak into another.
    unsafe fn clear_mde_env() {
        unsafe {
            std::env::remove_var("MDE_TENANT_ID");
            std::env::remove_var("MDE_CLIENT_ID");
            std::env::remove_var("MDE_CLIENT_SECRET");
            std::env::remove_var("MDE_ACCESS_TOKEN");
        }
    }

    #[test]
    fn test_mde_credentials_resolve_cli_overrides_config() {
        unsafe { clear_mde_env() };
        let config = Config {
            auth: AuthConfig {
                tenant_id: Some("config-tenant".to_string()),
                client_id: Some("config-client".to_string()),
                client_secret: Some("config-secret".to_string()),
            },
            ..Default::default()
        };
        let creds = MdeCredentials::resolve(Some("cli-tenant"), Some("cli-client"), &config);
        assert_eq!(creds.tenant_id.as_deref(), Some("cli-tenant"));
        assert_eq!(creds.client_id.as_deref(), Some("cli-client"));
        // client_secret has no CLI arg, falls through to config
        assert_eq!(creds.client_secret.as_deref(), Some("config-secret"));
    }

    #[test]
    fn test_mde_credentials_resolve_config_fallback() {
        unsafe { clear_mde_env() };
        let config = Config {
            auth: AuthConfig {
                tenant_id: Some("config-tenant".to_string()),
                client_id: Some("config-client".to_string()),
                client_secret: Some("config-secret".to_string()),
            },
            ..Default::default()
        };
        let creds = MdeCredentials::resolve(None, None, &config);
        assert_eq!(creds.tenant_id.as_deref(), Some("config-tenant"));
        assert_eq!(creds.client_id.as_deref(), Some("config-client"));
        assert_eq!(creds.client_secret.as_deref(), Some("config-secret"));
    }

    #[test]
    fn test_mde_credentials_resolve_empty() {
        unsafe { clear_mde_env() };
        let config = Config::default();
        let creds = MdeCredentials::resolve(None, None, &config);
        assert!(creds.tenant_id.is_none());
        assert!(creds.client_id.is_none());
        assert!(creds.client_secret.is_none());
        assert!(creds.access_token.is_none());
    }

    #[test]
    fn test_mde_credentials_clear_env() {
        // Set MDE env vars
        unsafe {
            std::env::set_var("MDE_TENANT_ID", "test-tenant");
            std::env::set_var("MDE_CLIENT_ID", "test-client");
            std::env::set_var("MDE_CLIENT_SECRET", "test-secret");
            std::env::set_var("MDE_ACCESS_TOKEN", "test-token");
        }

        // Clear them
        unsafe {
            MdeCredentials::clear_env();
        }

        // Verify they are removed
        assert!(std::env::var("MDE_TENANT_ID").is_err());
        assert!(std::env::var("MDE_CLIENT_ID").is_err());
        assert!(std::env::var("MDE_CLIENT_SECRET").is_err());
        assert!(std::env::var("MDE_ACCESS_TOKEN").is_err());
    }

    #[test]
    fn test_mde_credentials_resolve_then_clear_env() {
        // Set env vars
        unsafe {
            std::env::set_var("MDE_TENANT_ID", "env-tenant");
            std::env::set_var("MDE_CLIENT_SECRET", "env-secret");
        }

        // Resolve picks up env vars
        let config = Config::default();
        let creds = MdeCredentials::resolve(None, None, &config);
        assert_eq!(creds.tenant_id.as_deref(), Some("env-tenant"));
        assert_eq!(creds.client_secret.as_deref(), Some("env-secret"));

        // Clear env
        unsafe {
            MdeCredentials::clear_env();
        }

        // Credentials struct still holds the values
        assert_eq!(creds.tenant_id.as_deref(), Some("env-tenant"));
        assert_eq!(creds.client_secret.as_deref(), Some("env-secret"));

        // But env vars are gone
        assert!(std::env::var("MDE_TENANT_ID").is_err());
        assert!(std::env::var("MDE_CLIENT_SECRET").is_err());
    }
}
