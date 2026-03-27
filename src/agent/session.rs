use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Session information persisted to disk for cross-terminal auto-detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub socket_path: String,
    pub token: String,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
}

/// Session file name varies by build profile to avoid debug/release conflicts.
fn session_file_name() -> &'static str {
    if cfg!(debug_assertions) {
        "session.debug.json"
    } else {
        "session.json"
    }
}

/// Resolve the session file path.
/// Uses `$XDG_DATA_HOME/mde-cli/<session-file>` (default: `~/.local/share/mde-cli/<session-file>`).
/// Debug builds use `session.debug.json`; release builds use `session.json`.
pub fn session_file_path() -> PathBuf {
    let filename = session_file_name();
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(data_home).join("mde-cli").join(filename);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("mde-cli")
            .join(filename);
    }
    PathBuf::from(format!("/tmp/mde-cli-{filename}"))
}

/// Write session info to disk with restricted permissions (0600).
pub fn write_session(info: &SessionInfo) -> std::io::Result<()> {
    let path = session_file_path();

    // Ensure parent directory exists with 0700 permissions.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    let json = serde_json::to_string_pretty(info).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Read session info from disk. Returns None if the file does not exist or is invalid.
pub fn read_session() -> Option<SessionInfo> {
    let path = session_file_path();
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Remove the session file from disk.
pub fn remove_session() {
    let path = session_file_path();
    let _ = std::fs::remove_file(&path);
}

/// Check if the agent referenced by session info is still reachable (socket exists).
pub fn is_session_alive(info: &SessionInfo) -> bool {
    Path::new(&info.socket_path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_roundtrip() {
        let info = SessionInfo {
            socket_path: "/tmp/mde-agent/mde-12345.sock".to_string(),
            token: "abcdef0123456789".to_string(),
            pid: 12345,
            started_at: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&info).unwrap();
        let loaded: SessionInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.socket_path, info.socket_path);
        assert_eq!(loaded.token, info.token);
        assert_eq!(loaded.pid, info.pid);
    }

    #[test]
    fn test_session_file_path_default() {
        let path = session_file_path();
        // Tests run as debug builds, so expect session.debug.json
        assert_eq!(path.file_name().unwrap(), "session.debug.json");
        assert!(path.to_string_lossy().contains("mde-cli"));
    }

    #[test]
    fn test_is_session_alive_nonexistent() {
        let info = SessionInfo {
            socket_path: "/tmp/mde-cli-nonexistent-test.sock".to_string(),
            token: "test".to_string(),
            pid: 99999,
            started_at: Utc::now(),
        };
        assert!(!is_session_alive(&info));
    }
}
