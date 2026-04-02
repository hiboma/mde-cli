use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

const DEFAULT_MDE_BASE_URL: &str = "https://api.security.microsoft.com";
const DEFAULT_GRAPH_BASE_URL: &str = "https://graph.microsoft.com";

/// TOML representation of `[credentials]` in credentials.toml.
#[derive(Debug, Deserialize, Default)]
struct CredentialsFileRoot {
    #[serde(default)]
    credentials: CredentialsFile,
}

#[derive(Debug, Deserialize, Default)]
struct CredentialsFile {
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    mde_base_url: Option<String>,
    graph_base_url: Option<String>,
}

/// Filter empty strings to None so that unfilled template values
/// (e.g. `client_id = ""`) do not bypass validation.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// Search paths for credentials.toml (highest priority first).
fn credentials_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".mde-credentials.toml")];
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        paths.push(
            PathBuf::from(config_home)
                .join("mde")
                .join("credentials.toml"),
        );
    } else if let Ok(home) = std::env::var("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".config")
                .join("mde")
                .join("credentials.toml"),
        );
    }
    paths
}

/// Load credentials from the first credentials.toml found.
fn load_credentials_file() -> CredentialsFile {
    for path in credentials_search_paths() {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match toml::from_str::<CredentialsFileRoot>(&content) {
            Ok(root) => {
                let c = root.credentials;
                return CredentialsFile {
                    tenant_id: non_empty(c.tenant_id),
                    client_id: non_empty(c.client_id),
                    client_secret: non_empty(c.client_secret),
                    mde_base_url: non_empty(c.mde_base_url),
                    graph_base_url: non_empty(c.graph_base_url),
                };
            }
            Err(e) => {
                eprintln!("warning: failed to parse {}: {}", path.display(), e);
            }
        }
    }
    CredentialsFile::default()
}

/// Resolved MDE credentials collected from CLI args, environment variables,
/// and credentials.toml.
/// Once constructed, the process should unset the MDE_* environment variables so that
/// forked child processes (agent) do not inherit credentials via the environment.
#[derive(Debug, Clone)]
pub struct MdeCredentials {
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub access_token: Option<String>,
    pub mde_base_url: String,
    pub graph_base_url: String,
}

impl Default for MdeCredentials {
    fn default() -> Self {
        Self {
            tenant_id: None,
            client_id: None,
            client_secret: None,
            access_token: None,
            mde_base_url: DEFAULT_MDE_BASE_URL.to_string(),
            graph_base_url: DEFAULT_GRAPH_BASE_URL.to_string(),
        }
    }
}

impl MdeCredentials {
    /// Resolve credentials from CLI args, environment variables, and credentials.toml.
    /// Priority: CLI args > environment variables > credentials.toml > defaults.
    pub fn resolve(cli_tenant_id: Option<&str>, cli_client_id: Option<&str>) -> Self {
        let file = load_credentials_file();

        let tenant_id = cli_tenant_id
            .map(String::from)
            .or_else(|| std::env::var("MDE_TENANT_ID").ok())
            .or(file.tenant_id);

        let client_id = cli_client_id
            .map(String::from)
            .or_else(|| std::env::var("MDE_CLIENT_ID").ok())
            .or(file.client_id);

        let client_secret = std::env::var("MDE_CLIENT_SECRET")
            .ok()
            .or(file.client_secret);

        let access_token = std::env::var("MDE_ACCESS_TOKEN").ok();

        let mde_base_url = file
            .mde_base_url
            .unwrap_or_else(|| DEFAULT_MDE_BASE_URL.to_string());

        let graph_base_url = file
            .graph_base_url
            .unwrap_or_else(|| DEFAULT_GRAPH_BASE_URL.to_string());

        Self {
            tenant_id,
            client_id,
            client_secret,
            access_token,
            mde_base_url,
            graph_base_url,
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
                "missing required credentials: {}. Set via environment variables or credentials.toml.",
                missing.join(", ")
            ))
        }
    }

    /// Remove MDE credential environment variables from the current process.
    /// First overwrites the values in-place (via the C `environ` pointer) so that
    /// the kernel's process environment snapshot — visible through `ps -E` or
    /// `/proc/<pid>/environ` — no longer contains the real secrets.
    /// Then calls `remove_var` to fully unset each variable.
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
            // Overwrite the value in the C environ array before removing,
            // so the kernel snapshot no longer contains the real value.
            unsafe {
                overwrite_environ_value(key);
                std::env::remove_var(key);
            }
        }
    }
}

/// Overwrite the value portion of an environment variable in-place with `*`.
/// This mutates the C `environ` array directly so that the kernel's snapshot
/// (read by `ps -E` / `/proc/<pid>/environ`) is scrubbed.
///
/// # Safety
/// Must be called in a single-threaded context. The `environ` pointer and its
/// strings must not be concurrently accessed.
unsafe fn overwrite_environ_value(name: &str) {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }

    unsafe {
        if environ.is_null() {
            return;
        }

        let name_bytes = name.as_bytes();
        let mut ep = environ;
        while !(*ep).is_null() {
            let entry = *ep;
            // Check if entry starts with "NAME="
            let mut matches = true;
            for (i, &b) in name_bytes.iter().enumerate() {
                if *entry.add(i) as u8 != b {
                    matches = false;
                    break;
                }
            }
            if matches && *entry.add(name_bytes.len()) == b'=' as libc::c_char {
                // Overwrite the value portion with '*'
                let val_start = entry.add(name_bytes.len() + 1);
                let mut p = val_start;
                while *p != 0 {
                    *p = b'*' as libc::c_char;
                    p = p.add(1);
                }
                return;
            }
            ep = ep.add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_file_parse_full() {
        let toml_str = r#"
[credentials]
tenant_id = "toml-tenant"
client_id = "toml-id"
client_secret = "toml-secret"
mde_base_url = "https://custom.api.example.com"
graph_base_url = "https://custom.graph.example.com"
"#;
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        assert_eq!(root.credentials.tenant_id.as_deref(), Some("toml-tenant"));
        assert_eq!(root.credentials.client_id.as_deref(), Some("toml-id"));
        assert_eq!(
            root.credentials.client_secret.as_deref(),
            Some("toml-secret")
        );
        assert_eq!(
            root.credentials.mde_base_url.as_deref(),
            Some("https://custom.api.example.com")
        );
        assert_eq!(
            root.credentials.graph_base_url.as_deref(),
            Some("https://custom.graph.example.com")
        );
    }

    #[test]
    fn test_credentials_file_parse_minimal() {
        let toml_str = r#"
[credentials]
tenant_id = "toml-tenant"
client_id = "toml-id"
client_secret = "toml-secret"
"#;
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        assert_eq!(root.credentials.tenant_id.as_deref(), Some("toml-tenant"));
        assert!(root.credentials.mde_base_url.is_none());
        assert!(root.credentials.graph_base_url.is_none());
    }

    #[test]
    fn test_credentials_file_parse_empty() {
        let toml_str = "";
        let root: CredentialsFileRoot = toml::from_str(toml_str).unwrap();
        assert!(root.credentials.tenant_id.is_none());
        assert!(root.credentials.client_id.is_none());
        assert!(root.credentials.client_secret.is_none());
    }

    #[test]
    fn test_non_empty_filters_empty_strings() {
        assert_eq!(non_empty(Some("".to_string())), None);
        assert_eq!(
            non_empty(Some("value".to_string())),
            Some("value".to_string())
        );
        assert_eq!(non_empty(None), None);
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
            ..Default::default()
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

    #[test]
    fn test_mde_credentials_default_base_urls() {
        let creds = MdeCredentials::default();
        assert_eq!(creds.mde_base_url, "https://api.security.microsoft.com");
        assert_eq!(creds.graph_base_url, "https://graph.microsoft.com");
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

    /// Helper to isolate resolve() from the user's real credentials.toml.
    /// Points XDG_CONFIG_HOME to an empty temp dir so no file is found.
    /// Also sets HOME to the same temp dir to prevent fallback to ~/.config/mde/.
    fn with_isolated_credentials<F: FnOnce()>(f: F) {
        let tmp = tempfile::tempdir().unwrap();
        let orig_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
            std::env::set_var("HOME", tmp.path());
        }
        f();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            if let Some(h) = orig_home {
                std::env::set_var("HOME", h);
            }
        }
    }

    #[test]
    fn test_mde_credentials_resolve_empty() {
        unsafe { clear_mde_env() };
        with_isolated_credentials(|| {
            let creds = MdeCredentials::resolve(None, None);
            assert!(creds.tenant_id.is_none());
            assert!(creds.client_id.is_none());
            assert!(creds.client_secret.is_none());
            assert!(creds.access_token.is_none());
            assert_eq!(creds.mde_base_url, DEFAULT_MDE_BASE_URL);
            assert_eq!(creds.graph_base_url, DEFAULT_GRAPH_BASE_URL);
        });
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

    /// Helper to create an isolated credentials.toml for testing resolve().
    /// Writes the given TOML content to $XDG_CONFIG_HOME/mde/credentials.toml
    /// and calls f() with the environment isolated.
    fn with_credentials_file<F: FnOnce()>(toml_content: &str, f: F) {
        let tmp = tempfile::tempdir().unwrap();
        let creds_dir = tmp.path().join("mde");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("credentials.toml"), toml_content).unwrap();
        let orig_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
            std::env::set_var("HOME", tmp.path());
        }
        f();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            if let Some(h) = orig_home {
                std::env::set_var("HOME", h);
            }
        }
    }

    #[test]
    fn test_mde_credentials_resolve_credentials_file_fallback() {
        unsafe { clear_mde_env() };
        let toml_content = r#"
[credentials]
tenant_id = "file-tenant"
client_id = "file-client"
client_secret = "file-secret"
mde_base_url = "https://custom.api.example.com"
graph_base_url = "https://custom.graph.example.com"
"#;
        with_credentials_file(toml_content, || {
            let creds = MdeCredentials::resolve(None, None);
            assert_eq!(creds.tenant_id.as_deref(), Some("file-tenant"));
            assert_eq!(creds.client_id.as_deref(), Some("file-client"));
            assert_eq!(creds.client_secret.as_deref(), Some("file-secret"));
            assert_eq!(creds.mde_base_url, "https://custom.api.example.com");
            assert_eq!(creds.graph_base_url, "https://custom.graph.example.com");
        });
    }

    #[test]
    fn test_mde_credentials_resolve_cli_overrides_credentials_file() {
        unsafe { clear_mde_env() };
        let toml_content = r#"
[credentials]
tenant_id = "file-tenant"
client_id = "file-client"
client_secret = "file-secret"
"#;
        with_credentials_file(toml_content, || {
            let creds = MdeCredentials::resolve(Some("cli-tenant"), Some("cli-client"));
            // CLI args override credentials.toml
            assert_eq!(creds.tenant_id.as_deref(), Some("cli-tenant"));
            assert_eq!(creds.client_id.as_deref(), Some("cli-client"));
            // client_secret has no CLI arg, falls through to credentials.toml
            assert_eq!(creds.client_secret.as_deref(), Some("file-secret"));
        });
    }

    #[test]
    fn test_mde_credentials_resolve_then_clear_env() {
        with_isolated_credentials(|| {
            // Set env vars
            unsafe {
                std::env::set_var("MDE_TENANT_ID", "env-tenant");
                std::env::set_var("MDE_CLIENT_SECRET", "env-secret");
            }

            // Resolve picks up env vars
            let creds = MdeCredentials::resolve(None, None);
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
        });
    }
}
