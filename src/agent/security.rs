use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

use chrono::Utc;
use serde::Deserialize;

/// Command whitelist configuration.
#[derive(Debug, Clone)]
pub struct CommandWhitelist {
    allowed: HashSet<String>,
}

impl CommandWhitelist {
    /// Create a whitelist from a set of allowed command names.
    pub fn new(allowed: HashSet<String>) -> Self {
        Self { allowed }
    }

    /// Create a default whitelist allowing all mde resource commands.
    pub fn default_mde() -> Self {
        let allowed = ["alerts", "incidents", "hunting", "machines"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        Self { allowed }
    }

    /// Check if a command is allowed.
    pub fn is_allowed(&self, command: &str) -> bool {
        self.allowed.contains(command)
    }
}

/// Validate a command name: only alphanumeric, hyphen, underscore.
pub fn validate_command_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Token bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<RateLimiterState>,
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given requests per minute.
    pub fn new(requests_per_minute: u32) -> Self {
        let max_tokens = requests_per_minute as f64;
        Self {
            state: Mutex::new(RateLimiterState {
                tokens: max_tokens,
                max_tokens,
                refill_rate: max_tokens / 60.0,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    pub fn try_acquire(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();

        // Refill tokens
        state.tokens = (state.tokens + elapsed * state.refill_rate).min(state.max_tokens);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Constant-time token comparison to prevent timing attacks.
/// Uses subtle crate for proper constant-time operations including
/// length comparison.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Audit log entry.
#[derive(Debug)]
pub struct AuditEntry {
    pub timestamp: String,
    pub request_id: String,
    pub command: String,
    pub action: String,
    pub peer_uid: Option<u32>,
    pub result: AuditResult,
}

/// Result of an audited action.
#[derive(Debug)]
pub enum AuditResult {
    Allowed,
    Denied(String),
    Error(String),
}

/// Maximum number of audit entries to keep in memory (ring buffer).
const MAX_AUDIT_ENTRIES: usize = 1024;

/// Audit logger with bounded ring buffer.
#[derive(Debug)]
pub struct AuditLog {
    entries: Mutex<std::collections::VecDeque<AuditEntry>>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(std::collections::VecDeque::with_capacity(MAX_AUDIT_ENTRIES)),
        }
    }

    /// Log an audit entry and print to stderr.
    /// Old entries are evicted when the ring buffer is full.
    ///
    /// Note: peer_uid is intentionally logged for security auditing purposes.
    /// It represents a Unix UID (not a secret) and is essential for detecting
    /// unauthorized access attempts.
    pub fn log(&self, entry: AuditEntry) {
        // Format UID separately to clarify intent for static analysis.
        // peer_uid is a Unix UID (numeric process owner ID), not a secret.
        let uid_str = format!("{:?}", entry.peer_uid);
        let msg = match &entry.result {
            AuditResult::Allowed => format!(
                "audit: {} {} {} ALLOWED (uid={})",
                entry.timestamp, entry.command, entry.action, uid_str
            ),
            AuditResult::Denied(reason) => format!(
                "audit: {} {} {} DENIED: {} (uid={})",
                entry.timestamp, entry.command, entry.action, reason, uid_str
            ),
            AuditResult::Error(err) => format!(
                "audit: {} {} {} ERROR: {} (uid={})",
                entry.timestamp, entry.command, entry.action, err, uid_str
            ),
        };
        eprintln!("{}", msg);

        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_AUDIT_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Create an audit entry with the current timestamp.
    pub fn entry(
        request_id: String,
        command: String,
        action: String,
        peer_uid: Option<u32>,
        result: AuditResult,
    ) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            request_id,
            command,
            action,
            peer_uid,
            result,
        }
    }
}

/// Verify that the peer process has the same UID as the current process.
#[cfg(unix)]
pub fn verify_peer_uid(peer_uid: u32) -> bool {
    // SAFETY: getuid() is always safe.
    let my_uid = unsafe { libc::getuid() };
    peer_uid == my_uid
}

/// Agent configuration loaded from agent.toml.
#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub whitelist: WhitelistConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub watchdog: WatchdogConfig,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default = "default_allowed_commands")]
    pub allowed_commands: Vec<String>,
}

impl Default for WhitelistConfig {
    fn default() -> Self {
        Self {
            allowed_commands: default_allowed_commands(),
        }
    }
}

fn default_allowed_commands() -> Vec<String> {
    vec![
        "alerts".to_string(),
        "incidents".to_string(),
        "hunting".to_string(),
        "machines".to_string(),
    ]
}

#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: default_requests_per_minute(),
        }
    }
}

fn default_requests_per_minute() -> u32 {
    60
}

#[derive(Debug, Deserialize)]
pub struct WatchdogConfig {
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_check_interval_secs(),
        }
    }
}

fn default_check_interval_secs() -> u64 {
    30
}

impl AgentConfig {
    /// Load config from a TOML file, or return defaults.
    pub fn load(path: Option<&std::path::Path>) -> Self {
        if let Some(path) = path
            && let Ok(content) = std::fs::read_to_string(path)
        {
            if let Ok(config) = toml::from_str(&content) {
                return config;
            }
            eprintln!("agent: warning: failed to parse config, using defaults");
        }
        Self {
            whitelist: WhitelistConfig::default(),
            rate_limit: RateLimitConfig::default(),
            watchdog: WatchdogConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist() {
        let wl = CommandWhitelist::default_mde();
        assert!(wl.is_allowed("alerts"));
        assert!(wl.is_allowed("incidents"));
        assert!(wl.is_allowed("hunting"));
        assert!(wl.is_allowed("machines"));
        assert!(!wl.is_allowed("unknown"));
        assert!(!wl.is_allowed(""));
    }

    #[test]
    fn test_validate_command_name() {
        assert!(validate_command_name("alerts"));
        assert!(validate_command_name("data-enrichment"));
        assert!(validate_command_name("my_command"));
        assert!(!validate_command_name(""));
        assert!(!validate_command_name("cmd;evil"));
        assert!(!validate_command_name("cmd && evil"));
        assert!(!validate_command_name("../etc/passwd"));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(2); // 2 per minute
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // exhausted
    }

    #[test]
    fn test_config_defaults() {
        let config = AgentConfig::load(None);
        assert_eq!(config.rate_limit.requests_per_minute, 60);
        assert_eq!(config.watchdog.check_interval_secs, 30);
        assert_eq!(config.whitelist.allowed_commands.len(), 4);
    }
}
