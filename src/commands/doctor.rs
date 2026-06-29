//! `doctor` — diagnose configuration, credentials, environment, and
//! connectivity in a single screen.
//!
//! Security: this command never prints a secret value. `client_secret`,
//! `access_token`, and `refresh_token` are reported only by presence and
//! source. `client_id` is shown masked to its first few characters. The
//! point of `doctor` is to tell the user *where* each value comes from and
//! *whether* it resolved — not what it is.

use std::path::PathBuf;
use std::time::Instant;

use crate::auth::StaticTokenAuth;
use crate::auth::oauth2::OAuth2Auth;
use crate::client::MdeClient;
use crate::config::credential_store::default_store;
use crate::config::{CredentialProvenance, MdeCredentials, Resolved, Source};
use crate::error::AppError;

/// Scope used for the connectivity probe (same as alerts/machines).
const SECURITYCENTER_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default";
/// Lightweight endpoint for the connectivity probe.
const PROBE_PATH: &str = "/api/machines?$top=1";

/// Number of leading characters of `client_id` to reveal. The client ID is
/// an app identifier (not a secret), but it pins down which tenant/app this
/// install talks to, so we still avoid printing it in full to logs and
/// screenshots.
const CLIENT_ID_VISIBLE_PREFIX: usize = 4;

pub async fn handle() -> Result<(), AppError> {
    let version = env!("CARGO_PKG_VERSION");
    println!("mde-cli {}", version);
    println!();

    print_config_section();

    // Resolve with no CLI args: clap merges `--tenant-id` and the
    // `MDE_TENANT_ID` env var into one field, so forwarding it would
    // misattribute env-supplied values as CLI args. Reading env/toml here
    // gives doctor an accurate provenance.
    let store = default_store();
    let prov = MdeCredentials::resolve_with_provenance(None, None, store.as_deref());

    print_credentials_section(&prov);
    print_environment_section();
    print_connectivity_section(&prov).await;

    Ok(())
}

/// CONFIG: which credentials.toml (if any) is in effect.
fn print_config_section() {
    println!("CONFIG");
    match find_credentials_toml() {
        Some(path) => {
            let display = std::fs::canonicalize(&path).unwrap_or(path);
            println!("  path:    {}", display.display());
            println!("  status:  present");
        }
        None => {
            // Show the paths we looked at so the user knows where to put one.
            println!("  path:    (none found)");
            println!("  status:  absent");
            println!("  searched:");
            for p in credentials_search_paths() {
                println!("    {}", p.display());
            }
        }
    }
    println!();
}

/// ACTIVE CREDENTIALS: the effective value of each field and where it came
/// from. Secrets are never printed; `client_id` is masked.
fn print_credentials_section(prov: &CredentialProvenance) {
    println!("ACTIVE CREDENTIALS");

    // tenant_id is not a secret (it appears in URLs); print it in full.
    print_field(
        "tenant-id",
        &describe_plain(&prov.tenant_id),
        &prov.tenant_id.source,
    );

    // client_id: reveal only the leading prefix.
    let client_id_desc = match &prov.client_id.value {
        Some(v) => mask_prefix(v),
        None => "(not set)".to_string(),
    };
    print_field("client-id", &client_id_desc, &prov.client_id.source);

    // client_secret: presence only.
    print_field(
        "client-secret",
        &describe_secret(&prov.client_secret),
        &prov.client_secret.source,
    );

    // access_token: presence + remaining lifetime when known.
    print_field(
        "access-token",
        &describe_access_token(prov),
        &prov.access_token.source,
    );

    // refresh_token: presence only.
    print_field(
        "refresh-token",
        &describe_secret(&prov.refresh_token),
        &prov.refresh_token.source,
    );

    println!("  mde-base-url:   {}", prov.mde_base_url);
    println!("  graph-base-url: {}", prov.graph_base_url);
    println!();
}

/// Print one credential field line: `label: value (source: ...)`.
/// The source suffix is omitted when nothing resolved.
fn print_field(label: &str, value: &str, source: &Source) {
    if *source == Source::None {
        println!("  {:<15} {}", format!("{}:", label), value);
    } else {
        println!(
            "  {:<15} {:<28} (source: {})",
            format!("{}:", label),
            value,
            source.label()
        );
    }
}

/// Plain (non-secret) value description: print it, or `(not set)`.
fn describe_plain(r: &Resolved<String>) -> String {
    match &r.value {
        Some(v) => v.clone(),
        None => "(not set)".to_string(),
    }
}

/// Secret presence description: never the value.
fn describe_secret(r: &Resolved<String>) -> String {
    match &r.value {
        Some(_) => "present".to_string(),
        None => "(not set)".to_string(),
    }
}

/// access_token presence + remaining lifetime when the expiry is known
/// (i.e. it came from a Keychain TokenBundle). Env-supplied tokens have
/// unknown expiry. An expired bundle resolves to no value but we still
/// surface that it was found-but-expired.
fn describe_access_token(prov: &CredentialProvenance) -> String {
    match &prov.access_token.value {
        Some(_) => match prov.access_token_expires_at {
            Some(exp) => format!("present ({})", format_remaining(exp)),
            None => "present (expiry unknown)".to_string(),
        },
        None => match prov.access_token_expires_at {
            // We had a bundle but it was expired.
            Some(_) => "expired".to_string(),
            None => "(not set)".to_string(),
        },
    }
}

/// Mask a client ID to its leading prefix, e.g. `1234****`.
fn mask_prefix(s: &str) -> String {
    let prefix: String = s.chars().take(CLIENT_ID_VISIBLE_PREFIX).collect();
    format!("{}****", prefix)
}

/// Format the remaining lifetime of a Unix-epoch expiry as `expires in 42m`
/// or `expired`.
fn format_remaining(expires_at: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if expires_at <= now {
        return "expired".to_string();
    }
    let secs = expires_at - now;
    if secs >= 3600 {
        format!("expires in {}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("expires in {}m", secs / 60)
    } else {
        format!("expires in {}s", secs)
    }
}

/// ENVIRONMENT: which MDE_* variables are set. Values are never printed;
/// for the two secret-bearing variables we say `set (hidden)` to make clear
/// the value exists but is intentionally not shown.
fn print_environment_section() {
    println!("ENVIRONMENT");
    // (name, is_secret)
    let vars = [
        ("MDE_TENANT_ID", false),
        ("MDE_CLIENT_ID", false),
        ("MDE_CLIENT_SECRET", true),
        ("MDE_ACCESS_TOKEN", true),
        ("MDE_OUTPUT_FORMAT", false),
        ("MDE_AGENT_SOCKET", false),
        ("MDE_AGENT_TOKEN", true),
    ];
    for (name, is_secret) in vars {
        let state = match std::env::var(name) {
            Ok(_) if is_secret => "(set, hidden)",
            Ok(_) => "(set)",
            Err(_) => "(unset)",
        };
        println!("  {:<22} {}", name, state);
    }
    println!();
}

/// CONNECTIVITY: probe a lightweight API endpoint. Skipped when there are
/// no credentials to build a client with. The probe sends the bearer token
/// in the request, but the token value is never logged; only the HTTP
/// status and elapsed time are shown.
async fn print_connectivity_section(prov: &CredentialProvenance) {
    println!("CONNECTIVITY");

    let client = match build_probe_client(prov) {
        Ok(c) => c,
        Err(reason) => {
            println!("  GET {}{}", prov.mde_base_url, PROBE_PATH);
            println!("    skipped ({})", reason);
            return;
        }
    };

    let url = format!("{}{}", prov.mde_base_url, PROBE_PATH);
    let start = Instant::now();
    let result = client.get(PROBE_PATH).await;
    let elapsed = start.elapsed().as_millis();

    match result {
        Ok(resp) => {
            let status = resp.status();
            println!("  GET {}  ->  {} ({}ms)", url, status, elapsed);
        }
        Err(AppError::Api { status, .. }) => {
            // A 401/403 still proves we reached the service.
            println!("  GET {}  ->  {} ({}ms)", url, status, elapsed);
        }
        Err(e) => {
            println!(
                "  GET {}  ->  error: {} ({}ms)",
                url,
                summarize_error(&e.to_string()),
                elapsed
            );
        }
    }
}

/// Collapse a verbose error string into a single line for the diagnostic
/// view. Token-endpoint failures embed a large JSON body; we surface just
/// the leading message plus any Azure AD `AADSTS#####` code, which is the
/// part a user actually needs to act on. The full error is still available
/// by running the failing command directly.
fn summarize_error(msg: &str) -> String {
    // First non-empty line, with surrounding whitespace trimmed.
    let first_line = msg
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();

    // Pull out an AADSTS error code if present anywhere in the message.
    let aadsts = msg
        .split(|c: char| !(c.is_ascii_alphanumeric()))
        .find(|tok| tok.starts_with("AADSTS"));

    // Truncate the leading line so a JSON blob on one physical line cannot
    // blow up the output.
    const MAX: usize = 120;
    let mut head = if first_line.chars().count() > MAX {
        let truncated: String = first_line.chars().take(MAX).collect();
        format!("{}…", truncated)
    } else {
        first_line
    };

    if let Some(code) = aadsts
        && !head.contains(code)
    {
        head = format!("{} [{}]", head, code);
    }
    head
}

/// Build a client for the connectivity probe using the same auth precedence
/// as the real API path: a static access token if present, otherwise
/// OAuth2 client-credentials. Returns a short reason string when there is
/// nothing to build with, so the caller can render `skipped (reason)`.
fn build_probe_client(prov: &CredentialProvenance) -> Result<MdeClient, String> {
    if let Some(token) = &prov.access_token.value {
        let auth = StaticTokenAuth(token.clone());
        return MdeClient::new(prov.mde_base_url.clone(), Box::new(auth))
            .map_err(|e| e.to_string());
    }

    let (tid, cid, cs) = match (
        &prov.tenant_id.value,
        &prov.client_id.value,
        &prov.client_secret.value,
    ) {
        (Some(t), Some(c), Some(s)) => (t, c, s),
        _ => return Err("no credentials".to_string()),
    };

    let auth = OAuth2Auth::new(
        tid.clone(),
        cid.clone(),
        cs.clone(),
        SECURITYCENTER_SCOPE.to_string(),
    )
    .map_err(|e| e.to_string())?;
    MdeClient::new(prov.mde_base_url.clone(), Box::new(auth)).map_err(|e| e.to_string())
}

/// Search paths for credentials.toml, mirroring `config`'s own order.
/// Kept local so `doctor` can show the searched paths without exposing
/// `config`'s internal helper.
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

fn find_credentials_toml() -> Option<PathBuf> {
    credentials_search_paths().into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_prefix_reveals_only_leading_chars() {
        assert_eq!(mask_prefix("12345678-90ab"), "1234****");
        assert_eq!(mask_prefix("ab"), "ab****");
        assert_eq!(mask_prefix(""), "****");
    }

    #[test]
    fn describe_secret_never_returns_value() {
        let present = Resolved {
            value: Some("super-secret".to_string()),
            source: Source::Env("MDE_CLIENT_SECRET"),
        };
        let desc = describe_secret(&present);
        assert_eq!(desc, "present");
        assert!(!desc.contains("super-secret"));

        let absent: Resolved<String> = Resolved {
            value: None,
            source: Source::None,
        };
        assert_eq!(describe_secret(&absent), "(not set)");
    }

    #[test]
    fn format_remaining_buckets() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(format_remaining(now.saturating_sub(10)), "expired");
        assert!(format_remaining(now + 120).starts_with("expires in 2m"));
        assert!(format_remaining(now + 7200).starts_with("expires in 2h"));
    }

    #[test]
    fn summarize_error_collapses_and_extracts_aadsts() {
        let verbose = "authentication error: token request returned 400 Bad Request: {\"error\":\"invalid_request\",\"error_description\":\"AADSTS90002: Tenant 'x' not found.\"}";
        let s = summarize_error(verbose);
        // Single line.
        assert!(!s.contains('\n'));
        // AADSTS code surfaced.
        assert!(s.contains("AADSTS90002"));
        // Bounded length (120 chars + code suffix + ellipsis).
        assert!(s.chars().count() <= 120 + 20);
    }

    #[test]
    fn summarize_error_handles_plain_message() {
        let s = summarize_error("network error: connection refused");
        assert_eq!(s, "network error: connection refused");
    }

    #[test]
    fn describe_access_token_states() {
        // Present from keychain with future expiry.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let prov = CredentialProvenance {
            tenant_id: Resolved {
                value: None,
                source: Source::None,
            },
            client_id: Resolved {
                value: None,
                source: Source::None,
            },
            client_secret: Resolved {
                value: None,
                source: Source::None,
            },
            access_token: Resolved {
                value: Some("tok".to_string()),
                source: Source::Keychain("token_bundle"),
            },
            refresh_token: Resolved {
                value: None,
                source: Source::None,
            },
            access_token_expires_at: Some(now + 600),
            mde_base_url: "https://example.com".to_string(),
            graph_base_url: "https://example.com".to_string(),
        };
        let desc = describe_access_token(&prov);
        assert!(desc.starts_with("present (expires in"));
        assert!(!desc.contains("tok"));

        // Expired bundle: no value, but expiry known.
        let expired = CredentialProvenance {
            access_token: Resolved {
                value: None,
                source: Source::None,
            },
            access_token_expires_at: Some(now.saturating_sub(10)),
            ..prov.clone()
        };
        assert_eq!(describe_access_token(&expired), "expired");
    }
}
