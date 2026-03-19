pub mod client;
pub mod handler;
pub mod peer_verify;
pub mod protocol;
pub mod security;
pub mod server;
pub mod session;

use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

/// Default socket directory under the user's runtime directory.
fn resolve_socket_dir() -> PathBuf {
    dirs::runtime_dir()
        .or_else(|| std::env::var("TMPDIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("mde-agent")
}

/// Ensure the socket directory exists with mode 0700.
pub fn ensure_socket_dir() -> std::io::Result<PathBuf> {
    let dir = resolve_socket_dir();
    fs::create_dir_all(&dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }

    Ok(dir)
}

/// Resolve the socket path with 3-stage fallback:
/// 1. MDE_AGENT_SOCKET environment variable
/// 2. Auto-discover: if exactly one socket exists in the directory, use it
/// 3. Fallback to default name
pub fn resolve_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("MDE_AGENT_SOCKET") {
        return PathBuf::from(path);
    }

    let sockets = list_agent_sockets();
    if sockets.len() == 1 {
        return sockets.into_iter().next().unwrap();
    }

    // Multiple or no sockets: fall back to default name.
    resolve_socket_dir().join("mde.sock")
}

/// Generate a PID-based socket path for a new agent instance.
pub fn pid_socket_path(pid: u32) -> PathBuf {
    resolve_socket_dir().join(format!("mde-{}.sock", pid))
}

/// List all agent socket files in the socket directory.
pub fn list_agent_sockets() -> Vec<PathBuf> {
    let dir = resolve_socket_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return vec![];
    };

    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("mde-") && name.ends_with(".sock"))
        })
        .map(|e| e.path())
        .collect()
}

/// Generate a session token (two UUIDv4 concatenated).
pub fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// PID file path for a given socket path.
pub fn pid_file_path(socket_path: &std::path::Path) -> PathBuf {
    socket_path.with_extension("pid")
}

/// Write a PID file with O_EXCL to prevent overwrites.
/// If the file already exists, it is removed first (stale PID file).
pub fn write_pid_file(path: &std::path::Path, pid: u32) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    // Remove stale PID file if it exists.
    if path.exists() {
        fs::remove_file(path)?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_EXCL: fail if file already exists
    #[cfg(unix)]
    opts.mode(0o600);
    let file = opts.open(path)?;

    let mut writer = std::io::BufWriter::new(file);
    write!(writer, "{}", pid)?;
    Ok(())
}

/// Read a PID from a PID file.
pub fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Clean up socket and PID files.
pub fn cleanup_files(socket_path: &std::path::Path) {
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_file(pid_file_path(socket_path));
}

/// Environment variables allowed to survive sanitization.
/// See ADR-0003 for rationale.
const ENV_WHITELIST: &[&str] = &[
    // Path resolution
    "HOME",
    "PATH",
    "USER",
    "TMPDIR",
    // XDG
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    // Proxy
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    // TLS
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    // Locale
    "LANG",
    // Debug
    "RUST_LOG",
    "RUST_BACKTRACE",
];

/// Environment variable prefixes allowed to survive sanitization.
const ENV_WHITELIST_PREFIXES: &[&str] = &["LC_"];

/// Check whether an environment variable name is whitelisted.
fn is_env_whitelisted(name: &str) -> bool {
    if ENV_WHITELIST.contains(&name) {
        return true;
    }
    ENV_WHITELIST_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Returns true if `RUST_LOG` is set (debug/trace logging requested).
fn is_debug() -> bool {
    std::env::var("RUST_LOG").is_ok()
}

/// Remove all environment variables that are not whitelisted.
/// Called in single-threaded context (before tokio runtime) so the
/// unsafe `remove_var` is safe. See ADR-0003.
pub fn sanitize_env() {
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let mut removed = 0u32;

    for (key, _value) in &vars {
        if !is_env_whitelisted(key) {
            // SAFETY: Called in single-threaded context before tokio runtime
            // creation (fork mode) or at startup (foreground mode).
            // See ADR-0003.
            unsafe {
                std::env::remove_var(key);
            }
            removed += 1;
        }
    }

    if is_debug() {
        eprintln!("agent: sanitize_env removed {} variables", removed);
    }
}

/// Apply OS-level process hardening.
/// Errors are logged but not fatal — the agent continues regardless.
/// See ADR-0003.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // Disable ptrace attachment.
        // SAFETY: prctl with PR_SET_DUMPABLE is always safe.
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if ret != 0 {
            eprintln!(
                "agent: prctl(PR_SET_DUMPABLE, 0) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Deny debugger attachment.
        // SAFETY: ptrace with PT_DENY_ATTACH is safe for self-hardening.
        let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if ret != 0 {
            eprintln!(
                "agent: ptrace(PT_DENY_ATTACH) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        eprintln!("agent: harden_process not implemented for this OS");
    }

    // Disable core dumps on all Unix platforms.
    #[cfg(unix)]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with RLIMIT_CORE is always safe.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret != 0 {
            eprintln!(
                "agent: setrlimit(RLIMIT_CORE, 0) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    #[test]
    fn test_is_env_whitelisted_exact_match() {
        assert!(is_env_whitelisted("HOME"));
        assert!(is_env_whitelisted("PATH"));
        assert!(is_env_whitelisted("RUST_LOG"));
        assert!(is_env_whitelisted("SSL_CERT_FILE"));
        assert!(is_env_whitelisted("http_proxy"));
    }

    #[test]
    fn test_is_env_whitelisted_prefix_match() {
        assert!(is_env_whitelisted("LC_ALL"));
        assert!(is_env_whitelisted("LC_CTYPE"));
        assert!(is_env_whitelisted("LC_MESSAGES"));
    }

    #[test]
    fn test_is_env_whitelisted_rejects_secrets() {
        assert!(!is_env_whitelisted("MDE_CLIENT_ID"));
        assert!(!is_env_whitelisted("MDE_CLIENT_SECRET"));
        assert!(!is_env_whitelisted("GITHUB_TOKEN"));
        assert!(!is_env_whitelisted("SLACK_BOT_TOKEN"));
        assert!(!is_env_whitelisted("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_env_whitelisted("DATABASE_URL"));
    }

    #[test]
    fn test_sanitize_env_removes_non_whitelisted() {
        let key = "MDE_TEST_SANITIZE_SECRET_12345";
        unsafe {
            std::env::set_var(key, "secret_value");
        }
        assert!(std::env::var(key).is_ok());

        sanitize_env();

        assert!(
            std::env::var(key).is_err(),
            "non-whitelisted variable should have been removed"
        );
    }

    #[test]
    fn test_sanitize_env_keeps_whitelisted() {
        // HOME is whitelisted and typically always set.
        let home_before = std::env::var("HOME").ok();

        sanitize_env();

        let home_after = std::env::var("HOME").ok();
        assert_eq!(home_before, home_after, "HOME should survive sanitization");
    }
}
