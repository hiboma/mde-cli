pub mod client;
pub mod handler;
pub mod peer_verify;
pub mod protocol;
pub mod security;
pub mod server;

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
