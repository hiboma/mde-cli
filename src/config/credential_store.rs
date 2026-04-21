use std::fmt;

/// Service identifier used as the Keychain "service" attribute.
/// Acts as a namespace so credentials do not collide with other apps.
pub const SERVICE: &str = "dev.mde-cli";

/// Logical identifier for the OAuth2 client_secret entry. This is the
/// label / key used to look the entry up in the store; it is NOT the
/// secret value itself.
pub const KEY_CLIENT_SECRET: &str = "client_secret";

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
/// `key` is the entry's identifier (e.g. "client_secret"), not the
/// credential value. `get` returns `Ok(None)` when the entry simply does
/// not exist (a normal state during fallback to the next source).
/// Backend-level failures must be surfaced as `Err` so callers can
/// distinguish "not stored" from "store unreachable".
pub trait CredentialStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
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

        fn entry(key: &str) -> Result<Entry, StoreError> {
            // The Keychain API names the second slot "account"; we use our
            // logical key as the account string.
            Entry::new(SERVICE, key).map_err(|e| StoreError::Backend(e.to_string()))
        }
    }

    impl Default for KeychainStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CredentialStore for KeychainStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            let entry = Self::entry(key)?;
            match entry.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }

        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            let entry = Self::entry(key)?;
            entry.set_password(value).map_err(classify_keyring_err)
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            let entry = Self::entry(key)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }
    }

    /// `errSecNoDefaultKeychain` from `Security.framework`.
    /// See <https://developer.apple.com/documentation/security/errsecnodefaultkeychain>.
    /// Locale-independent: the OSStatus is the same on every macOS install.
    pub(super) const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;
    pub(super) const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;

    /// Classify a `keyring::Error` into `Unavailable` (the store as a whole
    /// is not present, e.g. CI sandbox without a default keychain) vs
    /// `Backend` (an actual access failure that the user should investigate
    /// — denied prompt, daemon down, ACL mismatch).
    ///
    /// We prefer to inspect the underlying `security_framework::base::Error`
    /// OSStatus when available: the codes are locale-independent, whereas
    /// the human-readable message text on `keyring::Error` is translated
    /// (e.g. Japanese macOS reports the same condition with different
    /// wording, which would slip past a string-match allowlist and force
    /// the user into the `Backend` branch on a clean machine).
    ///
    /// We keep the previous string-match heuristic as a fallback for the
    /// `NoStorageAccess` variant and for unexpected error shapes.
    pub(super) fn classify_keyring_err(e: keyring::Error) -> StoreError {
        // First try to extract a `security_framework::base::Error` from
        // the boxed source. `keyring`'s apple-native backend always wraps
        // a security_framework error inside `PlatformFailure`, so the
        // downcast succeeds in practice.
        if let keyring::Error::PlatformFailure(ref boxed) = e
            && let Some(sf_err) = boxed.downcast_ref::<security_framework::base::Error>()
        {
            let code = sf_err.code();
            let msg = e.to_string();
            if code == ERR_SEC_NO_DEFAULT_KEYCHAIN || code == ERR_SEC_INVALID_KEYCHAIN {
                return StoreError::Unavailable(msg);
            }
            return StoreError::Backend(msg);
        }

        // Fallback for non-PlatformFailure errors (Invalid, NoStorageAccess)
        // or for unrecognized boxed source types: keep the locale-fragile
        // string match as a last line of defense, but err on the side of
        // Backend (the cautious choice — refuses to fall through to the
        // toml).
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
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            Ok(self.inner.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            self.inner
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.lock().unwrap().remove(key);
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

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_keyring_err_recognizes_no_default_keychain_by_osstatus() {
        // Build a security_framework error directly from the OSStatus,
        // box it through keyring::Error::PlatformFailure, and confirm
        // the classifier maps it to Unavailable regardless of the
        // localized message text.
        let sf = security_framework::base::Error::from_code(
            super::keychain::ERR_SEC_NO_DEFAULT_KEYCHAIN,
        );
        let kr = keyring::Error::PlatformFailure(Box::new(sf));
        match super::keychain::classify_keyring_err(kr) {
            StoreError::Unavailable(_) => {}
            other => panic!("expected Unavailable, got {:?}", other),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_keyring_err_treats_other_osstatus_as_backend() {
        // errSecAuthFailed = -25293 — a real access denial, NOT an
        // "unavailable backend". Must surface as Backend so resolve()
        // refuses the toml fallback.
        let sf = security_framework::base::Error::from_code(-25293);
        let kr = keyring::Error::PlatformFailure(Box::new(sf));
        match super::keychain::classify_keyring_err(kr) {
            StoreError::Backend(_) => {}
            other => panic!("expected Backend, got {:?}", other),
        }
    }
}
