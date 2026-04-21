use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

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
    // Wrap the secret in Zeroizing so the heap allocation is wiped on
    // drop. This narrows the window where a swap-out, core dump, or
    // panic-time backtrace could expose the value. The buffer used to
    // read stdin is also zeroized for the same reason.
    let value: Zeroizing<String> = if from_stdin {
        let mut buf: Zeroizing<String> = Zeroizing::new(String::new());
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| AppError::Config(format!("failed to read stdin: {}", e)))?;
        // Trim full whitespace (not just CRLF) so a stray trailing space
        // pasted from a password manager does not silently corrupt the secret.
        let trimmed = Zeroizing::new(buf.trim().to_string());
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("empty value from stdin".to_string()));
        }
        trimmed
    } else {
        let prompt = format!("Enter {} (input hidden): ", field.key());
        Zeroizing::new(
            rpassword::prompt_password(prompt)
                .map_err(|e| AppError::Config(format!("failed to read password: {}", e)))?,
        )
    };

    if value.is_empty() {
        return Err(AppError::InvalidInput("empty value".to_string()));
    }

    store
        .set(field.key(), &value)
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("Stored {} in credential store", field.key());
    println!("Verify with: mde-cli credentials status");
    Ok(())
}

fn delete_value(store: &dyn CredentialStore, field: CredentialField) -> Result<(), AppError> {
    store
        .delete(field.key())
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("Deleted {} from credential store", field.key());
    Ok(())
}

fn print_status(store: &dyn CredentialStore) -> Result<(), AppError> {
    // Probe each known field. We print only the field's static key (e.g.
    // "client_secret") and a presence flag — never the credential value.
    let keys = [KEY_CLIENT_SECRET];
    println!("Credential store: macOS Keychain (service=dev.mde-cli)");
    let mut saw_error = false;
    for key in keys {
        match store.get(key) {
            Ok(Some(_)) => println!("  {} : stored", key),
            Ok(None) => println!("  {} : not stored", key),
            Err(e) => {
                println!("  {} : error ({})", key, e);
                saw_error = true;
            }
        }
    }
    if saw_error {
        println!();
        println!(
            "One or more entries could not be accessed. This usually means a \
             Keychain ACL change (often triggered by a `cargo install` rebuild \
             that changed the binary's code signature). See the README section \
             \"Credential storage\" -> \"Notes on Keychain prompts\" for how to \
             re-grant access via Keychain Access.app."
        );
    }
    Ok(())
}

fn migrate(store: &dyn CredentialStore, dry_run: bool) -> Result<(), AppError> {
    let path = find_credentials_toml().ok_or_else(|| {
        AppError::Config(
            "no credentials.toml found to migrate from. \
             To store a secret directly in the Keychain, run: \
             mde-cli credentials set client-secret"
                .to_string(),
        )
    })?;
    // Resolve to canonical path so the user sees what we will actually
    // mutate, not a relative path that could be interpreted as something
    // surprising (e.g. `.mde-credentials.toml` in cwd).
    let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    println!("Found credentials.toml: {}", canonical.display());

    // Read the toml into a Zeroizing buffer: it contains the plaintext
    // secret we are about to migrate, and we want every copy of those
    // bytes wiped before this scope returns.
    let original: Zeroizing<String> =
        Zeroizing::new(fs::read_to_string(&path).map_err(|e| {
            AppError::Config(format!("failed to read {}: {}", canonical.display(), e))
        })?);

    let secret: Zeroizing<String> = match extract_client_secret(&original) {
        SecretScan::Present(s) => Zeroizing::new(s),
        SecretScan::Absent => {
            println!("  client_secret: not present (nothing to migrate)");
            println!();
            println!(
                "If you want to store a secret in the Keychain anyway, run: \
                 mde-cli credentials set client-secret"
            );
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

    // Step 1: confirm the migration itself. Echo the canonical path again
    // so a hostile cwd cannot smuggle in a different file between the find
    // and the prompt.
    if !prompt_yes_no(
        &format!(
            "Migrate client_secret from {} to the credential store?",
            canonical.display()
        ),
        false,
    )? {
        println!("Aborted.");
        return Ok(());
    }

    // Step 2: write to the credential store first. We have not touched the
    // toml yet, so any failure here leaves the user in their pre-migration
    // state with no rollback needed.
    store
        .set(KEY_CLIENT_SECRET, &secret)
        .map_err(|e| AppError::Config(format!("credential store: {}", e)))?;
    println!("Stored client_secret in credential store");

    // Step 3: ask how to dispose of the plaintext copy. The default is the
    // safest option — fully remove it. Keeping a backup leaves a 0o600
    // copy on disk that the user has to remember to delete; we surface
    // that risk loudly when they choose to keep it.
    let mode = prompt_disposal()?;
    // `updated` is derived by removing the secret line from `original`, so
    // it does not contain the secret. Plain String is fine.
    let updated = remove_client_secret_line(&original);

    match mode {
        DisposalMode::Remove => {
            if let Err(e) = atomic_replace(&path, updated.as_bytes()) {
                rollback_and_fail(store, &canonical, &e.to_string(), None)?;
            }
            println!("Removed client_secret line from {}", canonical.display());
            println!();
            println!("Done. The plaintext secret no longer exists on disk.");
        }
        DisposalMode::KeepBackup => {
            // Create the backup BEFORE rewriting the original, so a failure
            // partway through still leaves something recoverable. 0o600 +
            // create_new ensures the backup is private and never clobbers
            // an older one.
            let backup = backup_path(&path);
            if let Err(e) = write_secret_file(&backup, original.as_bytes(), true) {
                rollback_and_fail(store, &canonical, &format!("{}", e), None)?;
            }
            if let Err(e) = atomic_replace(&path, updated.as_bytes()) {
                // Try to remove the backup we just wrote, then roll back
                // Keychain. The original toml is untouched.
                let _ = fs::remove_file(&backup);
                rollback_and_fail(store, &canonical, &e.to_string(), None)?;
            }
            println!(
                "Removed client_secret line from {} (backup at {})",
                canonical.display(),
                backup.display()
            );
            println!();
            println!(
                "⚠️  WARNING: {} still contains the plaintext client_secret.",
                backup.display()
            );
            println!("⚠️  This file defeats the purpose of moving the secret to the Keychain.");
            println!("⚠️  Delete it as soon as you have confirmed the new setup works:");
            println!("       rm {}", backup.display());
        }
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DisposalMode {
    /// Remove the `client_secret` line outright; no plaintext copy remains.
    Remove,
    /// Keep a 0o600 backup of the original toml alongside the rewritten file.
    KeepBackup,
}

/// Ask the user a yes/no question and return the parsed answer.
/// `default_yes` controls what an empty (just-Enter) response means.
fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool, AppError> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{} {}: ", question, suffix);
    io::stdout()
        .flush()
        .map_err(|e| AppError::Config(format!("flush stdout: {}", e)))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|e| AppError::Config(format!("read stdin: {}", e)))?;
    Ok(match answer.trim() {
        "" => default_yes,
        s => matches!(s, "y" | "Y" | "yes" | "Yes" | "YES"),
    })
}

/// Ask the user how to dispose of the plaintext copy of `client_secret`
/// after a successful Keychain write. Default is `Remove` — the safest
/// option, since any copy left on disk re-introduces the risk we just
/// migrated away from.
fn prompt_disposal() -> Result<DisposalMode, AppError> {
    if prompt_yes_no(
        "Remove the plaintext client_secret line from credentials.toml? \
         (Recommended. Choosing 'no' keeps a 0600 backup of the original on disk.)",
        true,
    )? {
        Ok(DisposalMode::Remove)
    } else {
        Ok(DisposalMode::KeepBackup)
    }
}

/// Helper used when an atomic_replace / backup-write step fails after we
/// have already written to the credential store. Rolls the Keychain entry
/// back and returns a fully-formatted AppError so the call site can
/// short-circuit with `?`.
fn rollback_and_fail(
    store: &dyn CredentialStore,
    canonical: &Path,
    cause: &str,
    backup: Option<&Path>,
) -> Result<(), AppError> {
    let rb = store.delete(KEY_CLIENT_SECRET);
    let rb_msg = match rb {
        Ok(()) => "credential store entry rolled back".to_string(),
        Err(re) => format!(
            "WARNING: failed to roll back credential store entry: {}",
            re
        ),
    };
    let extra = match backup {
        Some(p) => format!(" Backup at {} also contains the plaintext.", p.display()),
        None => String::new(),
    };
    Err(AppError::Config(format!(
        "failed to update {}: {}. {}. The plaintext secret is still in {}.{}",
        canonical.display(),
        cause,
        rb_msg,
        canonical.display(),
        extra,
    )))
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
///
/// Uses `tempfile::NamedTempFile::new_in` so the tempfile name is
/// random rather than predictable (a unix-nanos suffix could be raced
/// in shared dirs), and so the tempfile is dropped automatically if the
/// rename step fails — no manual cleanup path to forget about.
fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".mde-cred-")
        .suffix(".tmp")
        .permissions(fs::Permissions::from_mode(SECRET_FILE_MODE))
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all().ok();
    // persist() consumes the NamedTempFile; on success the file lives at
    // `path`. On failure the NamedTempFile is returned inside the error
    // and dropped, which unlinks it.
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
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

/// Remove the `client_secret = "..."` line entirely while preserving the
/// rest of the file (comments, ordering, other fields). Only a true
/// `client_secret` key is matched — `client_secret_extra` and similar are
/// left untouched.
///
/// We delete the line rather than blanking the value because a blanked
/// `client_secret = ""` is itself a footgun: a future reader might think
/// the empty string is an intentional override and wonder where the real
/// value lives. A missing key makes the toml's role as "non-secret config"
/// unambiguous.
fn remove_client_secret_line(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("client_secret") {
            let after = rest.trim_start();
            if after.starts_with('=') {
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
    fn remove_drops_only_client_secret_line() {
        let s = r#"# comment
[credentials]
tenant_id = "t"
client_secret = "abc123"
client_id = "c"
"#;
        let out = remove_client_secret_line(s);
        // Don't include `out` in the assert message: CodeQL flags
        // formatting a function-of-secret-shaped-input into a diagnostic
        // string, even though this is a test fixture.
        assert!(!out.contains("client_secret"));
        assert!(!out.contains("abc123"));
        assert!(out.contains("# comment"));
        assert!(out.contains("tenant_id = \"t\""));
        assert!(out.contains("client_id = \"c\""));
    }

    #[test]
    fn remove_works_with_indented_key() {
        let s = "  client_secret = \"x\"\nother = 1\n";
        let out = remove_client_secret_line(s);
        assert_eq!(out, "other = 1\n");
    }

    #[test]
    fn remove_does_not_touch_similarly_named_keys() {
        let s = "client_secret_extra = \"x\"\n";
        let out = remove_client_secret_line(s);
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
