use std::fmt;

/// Service identifier used as the Keychain "service" attribute.
/// Acts as a namespace so credentials do not collide with other apps.
pub const SERVICE: &str = "dev.mde-cli";

/// Account names (Keychain "account" attribute) for each credential field.
pub const ACCOUNT_CLIENT_SECRET: &str = "client_secret";

#[derive(Debug)]
pub enum StoreError {
    /// The backend (e.g. Keychain) is not available on this platform.
    Unavailable(String),
    /// An I/O or backend error occurred while accessing the store.
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable(s) => write!(f, "credential store unavailable: {}", s),
            StoreError::Backend(s) => write!(f, "credential store error: {}", s),
        }
    }
}

impl std::error::Error for StoreError {}

/// Abstract storage backend for sensitive credentials.
///
/// `get` returns `Ok(None)` when the entry simply does not exist (a normal
/// state during fallback to the next source). Backend-level failures must
/// be surfaced as `Err` so callers can distinguish "not stored" from
/// "store unreachable".
pub trait CredentialStore {
    fn get(&self, account: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, account: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, account: &str) -> Result<(), StoreError>;
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::{CredentialStore, SERVICE, StoreError};
    use keyring::Entry;

    pub struct KeychainStore;

    impl KeychainStore {
        pub fn new() -> Self {
            Self
        }

        fn entry(account: &str) -> Result<Entry, StoreError> {
            Entry::new(SERVICE, account).map_err(|e| StoreError::Backend(e.to_string()))
        }
    }

    impl Default for KeychainStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for KeychainStore {
        fn get(&self, account: &str) -> Result<Option<String>, StoreError> {
            let entry = Self::entry(account)?;
            match entry.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }

        fn set(&self, account: &str, value: &str) -> Result<(), StoreError> {
            let entry = Self::entry(account)?;
            entry.set_password(value).map_err(classify_keyring_err)
        }

        fn delete(&self, account: &str) -> Result<(), StoreError> {
            let entry = Self::entry(account)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }
    }

    /// Classify a `keyring::Error` into `Unavailable` (the store as a whole
    /// is not present, e.g. CI sandbox without a default keychain) vs
    /// `Backend` (an actual access failure that the user should investigate
    /// — denied prompt, daemon down, ACL mismatch).
    ///
    /// "default keychain could not be found" comes from
    /// `Security.framework`'s `errSecNoDefaultKeychain` and means there is
    /// nothing to read from at all; treating it as `Backend` would block
    /// the toml fallback for users who never opted into the Keychain.
    fn classify_keyring_err(e: keyring::Error) -> StoreError {
        let msg = e.to_string();
        let lower = msg.to_lowercase();
        let unavailable = lower.contains("no default keychain")
            || lower.contains("default keychain could not be found")
            || lower.contains("no platform credential store");
        if unavailable {
            StoreError::Unavailable(msg)
        } else {
            StoreError::Backend(msg)
        }
    }
}

#[cfg(target_os = "macos")]
pub use keychain::KeychainStore;

/// Returns the platform's default credential store, or `None` if no
/// secure store backend is available on this build target.
pub fn default_store() -> Option<Box<dyn CredentialStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(KeychainStore::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(test)]
pub mod test_support {
    use super::{CredentialStore, StoreError};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `CredentialStore` used by tests.
    pub struct MemoryStore {
        inner: Mutex<HashMap<String, String>>,
    }

    impl MemoryStore {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    impl Default for MemoryStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for MemoryStore {
        fn get(&self, account: &str) -> Result<Option<String>, StoreError> {
            Ok(self.inner.lock().unwrap().get(account).cloned())
        }

        fn set(&self, account: &str, value: &str) -> Result<(), StoreError> {
            self.inner
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), StoreError> {
            self.inner.lock().unwrap().remove(account);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemoryStore;
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.get("k").unwrap().is_none());
        s.set("k", "v").unwrap();
        assert_eq!(s.get("k").unwrap().as_deref(), Some("v"));
        s.delete("k").unwrap();
        assert!(s.get("k").unwrap().is_none());
    }

    #[test]
    fn memory_store_delete_missing_is_ok() {
        let s = MemoryStore::new();
        s.delete("missing").unwrap();
    }
}
