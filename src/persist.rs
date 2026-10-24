//! Pluggable persistence.
//!
//! The persistence is a simple key-value store. The intention is to make it simple to implement
//! other persistence mechanisms than the provided ones, such as against a databases.

use std::collections::hash_map::{DefaultHasher, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Error, Result};

/// Kinds of [persistence keys](struct.PersistKey.html).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum PersistKind {
    /// Persisted account private key.
    AccountPrivateKey,
    /// Persisted private key.
    PrivateKey,
    /// Persisted certificate.
    Certificate,
}

impl PersistKind {
    fn name(self) -> &'static str {
        match self {
            PersistKind::Certificate => "crt",
            PersistKind::PrivateKey => "key",
            PersistKind::AccountPrivateKey => "key",
        }
    }
}

/// Key for a value in the persistence.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct PersistKey<'a> {
    pub realm: u64,
    pub kind: PersistKind,
    pub key: &'a str,
    /// The realm as 0.9 and before hashed it (std's `DefaultHasher`, which isn't stable
    /// across Rust versions)
    legacy_realm: u64,
}

impl<'a> PersistKey<'a> {
    /// Create a new key under a "realm", kind and key. The realm is an opaque hash
    /// of the given realm string: the first 8 bytes of its SHA-256.
    ///
    /// The realm is in normally defined as the account contact email, however it depends
    /// on how the `Account` object is accessed, see [`account_with_realm`].
    ///
    /// [`account_with_realm`]: ../struct.Directory.html#method.account_with_realm
    pub fn new(realm: &str, kind: PersistKind, key: &'a str) -> Self {
        let digest = openssl::sha::sha256(realm.as_bytes());
        let mut first = [0; 8];
        first.copy_from_slice(&digest[..8]);

        let mut h = DefaultHasher::new();
        realm.hash(&mut h);
        PersistKey {
            realm: u64::from_be_bytes(first),
            kind,
            key,
            legacy_realm: h.finish(),
        }
    }

    /// The same key, as 0.9 and before named it
    pub(crate) fn legacy(&self) -> Self {
        PersistKey {
            realm: self.legacy_realm,
            ..*self
        }
    }
}

/// The value of `key`, or the one saved under its name in 0.9 and before (copied under the
/// new name, and kept under the old one for older versions)
pub(crate) fn read<P: Persist>(persist: &P, key: &PersistKey) -> Result<Option<Vec<u8>>> {
    if let Some(value) = persist.get(key)? {
        return Ok(Some(value));
    }
    let Some(value) = persist.get(&key.legacy())? else {
        return Ok(None);
    };
    persist.put(key, &value)?;
    Ok(Some(value))
}

impl<'a> std::fmt::Display for PersistKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}_{}_{}",
            self.realm,
            self.kind.name(),
            self.key.replace('.', "_").replace('*', "STAR")
        )
    }
}

/// Trait for a persistence implementation.
///
/// Implementation must be clonable and thread safe (Send). This can easily be done by
/// wrapping the implemetation an `Arc<Mutex<P>>`.
pub trait Persist: Clone + Send {
    /// Store the given bytes under the given key.
    fn put(&self, key: &PersistKey, value: &[u8]) -> Result<()>;
    /// Read the bytes stored under the given key.
    ///
    /// `None` if the value doesn't exist.
    fn get(&self, key: &PersistKey) -> Result<Option<Vec<u8>>>;
}

/// Memory implementation for dev/testing.
///
/// The entries in memory are never saved to disk and are gone when the process dies.
///
/// Since the API is [rate limited] it's not a good idea to use this in production code.
///
/// [rate limited]: ../index.html#rate-limits
#[derive(Clone, Default)]
pub struct MemoryPersist {
    inner: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryPersist {
    /// Create a memory persistence for testing.
    pub fn new() -> Self {
        MemoryPersist {
            ..Default::default()
        }
    }
}

impl Persist for MemoryPersist {
    fn put(&self, key: &PersistKey, value: &[u8]) -> Result<()> {
        let mut lock = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        lock.insert(key.to_string(), value.to_owned());
        Ok(())
    }
    fn get(&self, key: &PersistKey) -> Result<Option<Vec<u8>>> {
        let lock = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(lock.get(&key.to_string()).cloned())
    }
}

/// Simple file persistence.
///
/// Each key is saved under a unique filename.
#[derive(Clone)]
pub struct FilePersist {
    dir: PathBuf,
}

impl FilePersist {
    /// Create a file persistence in the directory pointed out by the `dir` given.
    ///
    /// The directory must be writable.
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        FilePersist {
            dir: dir.as_ref().to_path_buf(),
        }
    }
}

impl Persist for FilePersist {
    #[cfg(not(unix))]
    fn put(&self, key: &PersistKey, value: &[u8]) -> Result<()> {
        let f_name = file_name_of(&self.dir, &key);
        fs::write(f_name, value).map_err(Error::from)
    }

    #[cfg(unix)]
    fn put(&self, key: &PersistKey, value: &[u8]) -> Result<()> {
        let f_name = file_name_of(&self.dir, key);
        match key.kind {
            PersistKind::AccountPrivateKey | PersistKind::PrivateKey => fs::OpenOptions::new()
                .mode(0o600)
                .write(true)
                .truncate(true)
                .create(true)
                .open(f_name)?
                .write_all(value)
                .map_err(Error::from),
            PersistKind::Certificate => fs::write(f_name, value).map_err(Error::from),
        }
    }

    fn get(&self, key: &PersistKey) -> Result<Option<Vec<u8>>> {
        let f_name = file_name_of(&self.dir, key);
        let ret = match fs::File::open(f_name) {
            Ok(mut file) => {
                let mut v = vec![];
                file.read_to_end(&mut v)?;
                Some(v)
            }
            _ => None,
        };
        Ok(ret)
    }
}

fn file_name_of(dir: &Path, key: &PersistKey) -> PathBuf {
    let mut f_name = dir.join(key.to_string());
    f_name.set_extension(key.kind.name());
    f_name
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_names_are_stable() {
        // The first 8 bytes of the SHA-256 of the realm
        let key = PersistKey::new("me@example.com", PersistKind::Certificate, "*.a.test");
        assert_eq!(key.to_string(), "10099964089078436617_crt_STAR_a_test");
        // As 0.9 named it, with std's `DefaultHasher`
        assert_eq!(
            key.legacy().to_string(),
            "7001910076126598734_crt_STAR_a_test"
        );
    }

    #[test]
    fn test_values_saved_under_older_names_are_found_and_copied() {
        let persist = MemoryPersist::new();
        let key = PersistKey::new("me@example.com", PersistKind::Certificate, "a.test");
        persist.put(&key.legacy(), b"cert").unwrap();

        assert_eq!(read(&persist, &key).unwrap(), Some(b"cert".to_vec()));
        // Copied under the new name, and kept under the old one (for older versions)
        assert_eq!(persist.get(&key).unwrap(), Some(b"cert".to_vec()));
        assert_eq!(persist.get(&key.legacy()).unwrap(), Some(b"cert".to_vec()));

        let missing = PersistKey::new("me@example.com", PersistKind::Certificate, "b.test");
        assert_eq!(read(&persist, &missing).unwrap(), None);
    }
}
