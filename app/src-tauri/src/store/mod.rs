pub mod atomic;
pub mod crypto;
pub mod format;
pub mod paths;

use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::{x25519, Identity, Recipient};

pub use format::{Algorithm, Entry, EntryKind, StoreFile, STORE_FORMAT_VERSION};
pub use paths::StorePaths;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("atomic write: {0}")]
    Atomic(#[from] atomic::AtomicWriteError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml serialize: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml parse: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("master.age does not contain a valid age identity: {0}")]
    InvalidMaster(&'static str),
    #[error("paths: {0}")]
    Paths(#[from] paths::PathError),
}

/// In-memory unlocked view of the seed store, plus enough state to
/// re-encrypt back to disk.
pub struct Store {
    paths: StorePaths,
    file: StoreFile,
    master: x25519::Identity,
    extra_recipients: Vec<x25519::Recipient>,
}

impl Store {
    /// Create a fresh store on disk. Generates a new master X25519
    /// identity, writes `master.age` (passphrase-encrypted) and
    /// `store.age` (encrypted to master pubkey + `extra_recipients`).
    pub fn create(
        paths: StorePaths,
        passphrase: SecretString,
        extra_recipients: Vec<x25519::Recipient>,
    ) -> Result<Self, StoreError> {
        paths.ensure_dirs()?;
        let master = x25519::Identity::generate();
        let store = Self {
            paths,
            file: StoreFile::new(),
            master,
            extra_recipients,
        };
        store.write_master(&passphrase)?;
        store.write_store()?;
        Ok(store)
    }

    /// Open an existing store using the recovery passphrase.
    /// Decrypts `master.age` to recover the master identity, then
    /// uses it to decrypt `store.age`.
    pub fn open_with_passphrase(
        paths: StorePaths,
        passphrase: SecretString,
    ) -> Result<Self, StoreError> {
        let master_ciphertext = std::fs::read(&paths.master)?;
        let master_plaintext =
            crypto::decrypt_with_passphrase(&master_ciphertext, passphrase)?;
        let master = parse_master(&master_plaintext)?;

        let store_ciphertext = std::fs::read(&paths.store)?;
        let plaintext =
            crypto::decrypt_with_identity(&store_ciphertext, &master as &dyn Identity)?;
        let text = std::str::from_utf8(&plaintext)
            .map_err(|_| StoreError::InvalidMaster("store payload is not valid UTF-8"))?;
        let file = format::deserialize(text)?;

        Ok(Self {
            paths,
            file,
            master,
            extra_recipients: Vec::new(),
        })
    }

    /// Re-encrypt and atomic-write `store.age` using the current
    /// recipient set (master pubkey + `extra_recipients`).
    pub fn save(&self) -> Result<(), StoreError> {
        self.write_store()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.file.entries
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.file.entries.push(entry);
    }

    pub fn remove_entry(&mut self, id: &str) -> bool {
        let before = self.file.entries.len();
        self.file.entries.retain(|e| e.id != id);
        self.file.entries.len() != before
    }

    pub fn paths(&self) -> &StorePaths {
        &self.paths
    }

    fn write_master(&self, passphrase: &SecretString) -> Result<(), StoreError> {
        let identity_string = self.master.to_string();
        let ciphertext = crypto::encrypt_with_passphrase(
            identity_string.expose_secret().as_bytes(),
            passphrase.clone(),
        )?;
        atomic::write(&self.paths.master, &ciphertext)?;
        Ok(())
    }

    fn write_store(&self) -> Result<(), StoreError> {
        let text = format::serialize(&self.file)?;
        let master_pub = self.master.to_public();
        let mut refs: Vec<&dyn Recipient> = Vec::with_capacity(1 + self.extra_recipients.len());
        refs.push(&master_pub as &dyn Recipient);
        for r in &self.extra_recipients {
            refs.push(r as &dyn Recipient);
        }
        let ciphertext = crypto::encrypt_to_recipients(text.as_bytes(), &refs)?;
        atomic::write(&self.paths.store, &ciphertext)?;
        Ok(())
    }
}

fn parse_master(bytes: &[u8]) -> Result<x25519::Identity, StoreError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| StoreError::InvalidMaster("master.age plaintext is not UTF-8"))?;
    x25519::Identity::from_str(s.trim())
        .map_err(|_| StoreError::InvalidMaster("could not parse master identity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_paths() -> (tempfile::TempDir, StorePaths) {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let config = tmp.path().join("config");
        let paths = StorePaths::from_dirs(data, config);
        (tmp, paths)
    }

    #[test]
    fn create_then_open_with_passphrase_round_trips_empty_store() {
        let (_tmp, paths) = tmp_paths();
        let passphrase = SecretString::from("recovery");
        let _ = Store::create(paths.clone(), passphrase.clone(), Vec::new()).unwrap();

        let opened = Store::open_with_passphrase(paths, passphrase).unwrap();
        assert!(opened.entries().is_empty());
    }

    #[test]
    fn add_save_reopen_preserves_entry() {
        use ::secrecy::ExposeSecret;
        let (_tmp, paths) = tmp_paths();
        let passphrase = SecretString::from("recovery");
        let mut store =
            Store::create(paths.clone(), passphrase.clone(), Vec::new()).unwrap();
        store.add_entry(Entry {
            id: "01h9z0e3mq6kngd5gp7w4tnsx2".into(),
            issuer: "Google".into(),
            account: "user@example.com".into(),
            secret: SecretString::from("JBSWY3DPEHPK3PXP"),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            kind: EntryKind::Totp,
            created_at: "2026-04-29T10:00:00Z".into(),
        });
        store.save().unwrap();

        let reopened = Store::open_with_passphrase(paths, passphrase).unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].issuer, "Google");
        assert_eq!(
            reopened.entries()[0].secret.expose_secret(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn extra_recipient_can_decrypt_store_directly() {
        let (_tmp, paths) = tmp_paths();
        let passphrase = SecretString::from("recovery");
        let backup = x25519::Identity::generate();
        let _ = Store::create(
            paths.clone(),
            passphrase,
            vec![backup.to_public()],
        )
        .unwrap();

        let ciphertext = std::fs::read(&paths.store).unwrap();
        let plaintext =
            crypto::decrypt_with_identity(&ciphertext, &backup as &dyn Identity).unwrap();
        let text = std::str::from_utf8(&plaintext).unwrap();
        let parsed = format::deserialize(text).unwrap();
        assert_eq!(parsed.version, STORE_FORMAT_VERSION);
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let (_tmp, paths) = tmp_paths();
        let _ = Store::create(
            paths.clone(),
            SecretString::from("right"),
            Vec::new(),
        )
        .unwrap();
        let result = Store::open_with_passphrase(paths, SecretString::from("wrong"));
        assert!(result.is_err());
    }
}
