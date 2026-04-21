use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::credentials::{CredentialField, CredentialsCommand};
use crate::config::credential_store::{CredentialStore, KEY_CLIENT_SECRET, default_store};
use crate::error::AppError;

/// File mode for any artifact that may contain plaintext credentials.
const SECRET_FILE_MODE: u32 = 0o600;

pub fn handle(cmd: &CredentialsCommand) -> Result<(), AppError> {
    let store = default_store().ok_or_else(|| {
        AppError::Config(
            "no credential store backend available on this platform (macOS Keychain required)"
                .to_string(),
        )
    })?;

    match cmd {
        CredentialsCommand::Set { field, stdin } => set_value(store.as_ref(), *field, *stdin),
        CredentialsCommand::Delete { field } => delete_value(store.as_ref(), *field),
        CredentialsCommand::Status => print_status(store.as_ref()),
        CredentialsCommand::Migrate { dry_run } => migrate(store.as_ref(), *dry_run),
    }
}

fn set_value(
    store: &dyn CredentialStore,
    field: CredentialField,
    from_stdin: bool,
) -> Result<(), AppError> {
    let value = if from_stdin {
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| AppError::Config(format!("failed to read stdin: {}", e)))?;
        // Trim full whitespace (not just CRLF) so a stray trailing space
        // pasted from a password manager does not silently corrupt the secret.
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("empty value from stdin".to_string()));
        }
        trimmed
    } else {
        let prompt = format!("Enter {} (input hidden): ", field.key());
        rpassword::prompt_password(prompt)
            .map_err(|e| AppError::Config(format!("failed to read password: {}", e)))?
    };

    if value.is_empty() {
        return Err(AppError::InvalidInput("empty value".to_string()));
    }

    store
        .set(field.key(), &value)
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("✅ Stored {} in credential store", field.key());
    Ok(())
}

fn delete_value(store: &dyn CredentialStore, field: CredentialField) -> Result<(), AppError> {
    store
        .delete(field.key())
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("✅ Deleted {} from credential store", field.key());
    Ok(())
}

fn print_status(store: &dyn CredentialStore) -> Result<(), AppError> {
    // Probe each known field. We print only the field's static key (e.g.
    // "client_secret") and a presence flag — never the credential value.
    let keys = [KEY_CLIENT_SECRET];
    println!("Credential store: macOS Keychain (service=dev.mde-cli)");
    for key in keys {
        match store.get(key) {
            Ok(Some(_)) => println!("  {} : stored", key),
            Ok(None) => println!("  {} : not stored", key),
            Err(e) => println!("  {} : error ({})", key, e),
        }
    }
    Ok(())
}

fn migrate(store: &dyn CredentialStore, dry_run: bool) -> Result<(), AppError> {
    let path = find_credentials_toml()
        .ok_or_else(|| AppError::Config("no credentials.toml found to migrate from".to_string()))?;
    // Resolve to canonical path so the user sees what we will actually
    // mutate, not a relative path that could be interpreted as something
    // surprising (e.g. `.mde-credentials.toml` in cwd).
    let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    println!("Found credentials.toml: {}", canonical.display());

    let original = fs::read_to_string(&path)
        .map_err(|e| AppError::Config(format!("failed to read {}: {}", canonical.display(), e)))?;

    let secret = match extract_client_secret(&original) {
        SecretScan::Present(s) => s,
        SecretScan::Absent => {
            println!("  client_secret: not present (nothing to migrate)");
            return Ok(());
        }
        SecretScan::Unsupported(form) => {
            return Err(AppError::Config(format!(
                "client_secret uses an unsupported quoting form ({}); refusing to rewrite. \
                 Convert it to `client_secret = \"...\"` form and retry.",
                form
            )));
        }
    };
    println!("  client_secret: present (will move to credential store)");

    if dry_run {
        println!("(dry-run) no changes made");
        return Ok(());
    }

    // Confirm before mutating. Echo the canonical path again so a hostile
    // cwd cannot smuggle in a different file between the find and the prompt.
    print!(
        "Migrate client_secret from {} to the credential store? [y/N]: ",
        canonical.display()
    );
    io::stdout()
        .flush()
        .map_err(|e| AppError::Config(format!("flush stdout: {}", e)))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|e| AppError::Config(format!("read stdin: {}", e)))?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        println!("Aborted.");
        return Ok(());
    }

    // Backup with restrictive permissions (0o600). `fs::copy` would inherit
    // the source mode, which is commonly 0o644 — leaving the plaintext
    // backup world-readable. Use create_new + 0o600 + manual byte copy.
    let backup = backup_path(&path);
    write_secret_file(&backup, original.as_bytes(), true)?;
    println!("Backup written (mode 0600): {}", backup.display());

    store
        .set(KEY_CLIENT_SECRET, &secret)
        .map_err(|e| AppError::Config(format!("credential store: {}", e)))?;
    println!("Stored client_secret in credential store");

    // Atomic rewrite: write to a sibling tempfile then rename(). If anything
    // fails, the original file is untouched and we roll back the Keychain
    // write so the user is not left in an inconsistent half-migrated state.
    let updated = blank_client_secret(&original);
    if let Err(e) = atomic_replace(&path, updated.as_bytes()) {
        // Roll back the Keychain entry we just wrote, then surface a
        // detailed error so the user knows where the secret lives now.
        let rb = store.delete(KEY_CLIENT_SECRET);
        let rb_msg = match rb {
            Ok(()) => "credential store entry rolled back".to_string(),
            Err(re) => format!(
                "WARNING: failed to roll back credential store entry: {}",
                re
            ),
        };
        return Err(AppError::Config(format!(
            "failed to update {}: {}. {}. The plaintext secret is still in {} and {}.",
            canonical.display(),
            e,
            rb_msg,
            canonical.display(),
            backup.display(),
        )));
    }
    println!("Cleared client_secret in {}", canonical.display());

    println!();
    println!(
        "The backup at {} still contains the plaintext secret.",
        backup.display()
    );
    println!("After verifying with `mde-cli credentials status`, delete it:");
    println!("    rm {}", backup.display());

    Ok(())
}

/// Write `bytes` to `path` with mode 0o600. When `exclusive` is true, fails
/// if the path already exists — used for backups so we never clobber an
/// older backup that the user might still need.
fn write_secret_file(path: &Path, bytes: &[u8], exclusive: bool) -> Result<(), AppError> {
    let mut opts = OpenOptions::new();
    opts.write(true).mode(SECRET_FILE_MODE);
    if exclusive {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut f: File = opts
        .open(path)
        .map_err(|e| AppError::Config(format!("open {}: {}", path.display(), e)))?;
    f.write_all(bytes)
        .map_err(|e| AppError::Config(format!("write {}: {}", path.display(), e)))?;
    // Belt and suspenders: explicitly set mode in case the FS ignored the
    // open-time mode (some networked filesystems do).
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(SECRET_FILE_MODE));
    Ok(())
}

/// Replace `path` with `bytes` atomically: write a sibling tempfile with
/// 0o600 then `rename` over the original. The mode of the resulting file
/// is the mode of the tempfile (0o600), which is more restrictive than the
/// previous mode and therefore safe.
fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", ts));
    let tmp = dir.join(name);

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_FILE_MODE)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(SECRET_FILE_MODE));
    fs::rename(&tmp, path).inspect_err(|_| {
        // Best-effort cleanup of the tempfile if rename fails.
        let _ = fs::remove_file(&tmp);
    })
}

fn find_credentials_toml() -> Option<PathBuf> {
    let candidates = credentials_search_paths();
    candidates.into_iter().find(|p| p.is_file())
}

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

fn backup_path(p: &Path) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bak.{}", ts));
    p.with_file_name(name)
}

/// Outcome of scanning a credentials.toml for `client_secret`.
#[derive(Debug, PartialEq, Eq)]
enum SecretScan {
    /// Field is absent or set to an empty basic string.
    Absent,
    /// Field is present and stored as `client_secret = "..."` (single-line basic).
    Present(String),
    /// Field is present but uses a quoting form we refuse to rewrite
    /// (literal strings, multi-line basic, multi-line literal). We bail out
    /// rather than risk a partial migration where extract returns None but
    /// blank_client_secret would still wipe the line.
    Unsupported(&'static str),
}

/// Scan a credentials.toml line-by-line for `client_secret`. We avoid a full
/// TOML round-trip so the user's formatting and comments survive rewrite.
fn extract_client_secret(content: &str) -> SecretScan {
    for line in content.lines() {
        let trimmed = line.trim_start();
        // Word-boundary match: rule out `client_secret_extra` etc.
        let Some(rest) = trimmed.strip_prefix("client_secret") else {
            continue;
        };
        let after_key = rest.trim_start();
        if !after_key.starts_with('=') {
            continue;
        }
        let value_part = after_key[1..].trim_start();

        if value_part.starts_with("\"\"\"") {
            return SecretScan::Unsupported("multi-line basic string (\"\"\"...\"\"\")");
        }
        if value_part.starts_with("'''") {
            return SecretScan::Unsupported("multi-line literal string ('''...''')");
        }
        if value_part.starts_with('\'') {
            return SecretScan::Unsupported("literal string ('...')");
        }
        if let Some(rest) = value_part.strip_prefix('"') {
            // Find the closing quote. Reject embedded escaped quotes for now
            // (TOML allows `\"`); they are not produced by typical templates,
            // and refusing them is safer than a half-correct parse.
            if rest.contains("\\\"") {
                return SecretScan::Unsupported("basic string with escaped quotes");
            }
            return match rest.find('"') {
                Some(0) => SecretScan::Absent,
                Some(end) => SecretScan::Present(rest[..end].to_string()),
                None => SecretScan::Unsupported("unterminated basic string"),
            };
        }
        return SecretScan::Unsupported("unrecognized value form");
    }
    SecretScan::Absent
}

/// Replace `client_secret = "..."` with `client_secret = ""` while preserving
/// the rest of the file (comments, ordering, other fields). Only a true
/// `client_secret` key is matched — `client_secret_extra` and similar are
/// left untouched.
fn blank_client_secret(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("client_secret") {
            let after = rest.trim_start();
            if after.starts_with('=') {
                let indent_len = line.len() - trimmed.len();
                out.push_str(&line[..indent_len]);
                out.push_str("client_secret = \"\"");
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_value() {
        let s = r#"
[credentials]
tenant_id = "t"
client_secret = "abc123"
client_id = "c"
"#;
        assert_eq!(
            extract_client_secret(s),
            SecretScan::Present("abc123".to_string())
        );
    }

    #[test]
    fn extract_returns_absent_when_missing() {
        let s = r#"
[credentials]
client_id = "c"
"#;
        assert_eq!(extract_client_secret(s), SecretScan::Absent);
    }

    #[test]
    fn extract_returns_absent_for_empty_basic_string() {
        let s = "client_secret = \"\"\n";
        assert_eq!(extract_client_secret(s), SecretScan::Absent);
    }

    #[test]
    fn extract_rejects_literal_string() {
        let s = "client_secret = 'abc'\n";
        assert!(matches!(
            extract_client_secret(s),
            SecretScan::Unsupported(_)
        ));
    }

    #[test]
    fn extract_rejects_multiline_basic() {
        let s = "client_secret = \"\"\"abc\"\"\"\n";
        assert!(matches!(
            extract_client_secret(s),
            SecretScan::Unsupported(_)
        ));
    }

    #[test]
    fn extract_ignores_similarly_named_keys() {
        let s = "client_secret_extra = \"x\"\n";
        assert_eq!(extract_client_secret(s), SecretScan::Absent);
    }

    #[test]
    fn blank_replaces_only_client_secret_line() {
        let s = r#"# comment
[credentials]
tenant_id = "t"
client_secret = "abc123"
client_id = "c"
"#;
        let out = blank_client_secret(s);
        assert!(out.contains("client_secret = \"\""));
        assert!(!out.contains("abc123"));
        assert!(out.contains("# comment"));
        assert!(out.contains("tenant_id = \"t\""));
        assert!(out.contains("client_id = \"c\""));
    }

    #[test]
    fn blank_preserves_indentation() {
        let s = "  client_secret = \"x\"\n";
        let out = blank_client_secret(s);
        assert_eq!(out, "  client_secret = \"\"\n");
    }

    #[test]
    fn blank_does_not_touch_similarly_named_keys() {
        let s = "client_secret_extra = \"x\"\n";
        let out = blank_client_secret(s);
        assert_eq!(out, "client_secret_extra = \"x\"\n");
    }

    #[test]
    fn atomic_replace_writes_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.toml");
        std::fs::write(&path, "old\n").unwrap();
        // Make the original world-readable to prove atomic_replace tightens it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_replace(&path, b"new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "atomic_replace must produce 0600, got {:o}",
            mode
        );
    }

    #[test]
    fn write_secret_file_creates_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup");
        write_secret_file(&path, b"secret\n", true).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_secret_file_exclusive_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup");
        std::fs::write(&path, b"existing").unwrap();
        let err = write_secret_file(&path, b"new", true).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("open"), "unexpected error: {}", msg);
    }
}
