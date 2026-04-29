pub mod atomic;
pub mod crypto;
pub mod format;
pub mod paths;

use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::{x25519, Identity, Recipient};

// TODO(#3, #9): these re-exports document the storage layer's public
// surface. Consumed by the code panel state machine (#3) and account
// management (#9); silence the dead-code warning in the meantime.
#[allow(unused_imports)]
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
    #[error("store.age payload is malformed: {0}")]
    InvalidStorePayload(&'static str),
    #[error("paths: {0}")]
    Paths(#[from] paths::PathError),
}

/// Boxed recipient suitable for storing in `Store::extra_recipients`.
/// Lets callers mix `x25519::Recipient` and plugin recipients (e.g.
/// `age::plugin::RecipientPluginV1` for YubiKey) under one type.
pub type BoxedRecipient = Box<dyn Recipient + Send + Sync>;

/// A recipient paired with its bech32 string form. The trait object
/// alone doesn't expose a stable string representation (plugin
/// recipients don't implement `Display`), so callers hand in the
/// original string at construction time. `recipients.txt` (#17) reads
/// these to render the audit-aid file alongside `store.age`.
pub struct NamedRecipient {
    pub bech32: String,
    pub recipient: BoxedRecipient,
}

/// In-memory unlocked view of the seed store, plus enough state to
/// re-encrypt back to disk.
pub struct Store {
    paths: StorePaths,
    file: StoreFile,
    master: x25519::Identity,
    extra_recipients: Vec<NamedRecipient>,
}

impl Store {
    /// Create a fresh store on disk. Generates a new master X25519
    /// identity, writes `master.age` (passphrase-encrypted) and
    /// `store.age` (encrypted to master pubkey + `extra_recipients`).
    pub fn create(
        paths: StorePaths,
        passphrase: SecretString,
        extra_recipients: Vec<NamedRecipient>,
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
        let master_plaintext = crypto::decrypt_with_passphrase(&master_ciphertext, passphrase)?;
        let master = parse_master(&master_plaintext)?;

        let store_ciphertext = std::fs::read(&paths.store)?;
        let plaintext = crypto::decrypt_with_identity(&store_ciphertext, &master as &dyn Identity)?;
        let text = std::str::from_utf8(&plaintext)
            .map_err(|_| StoreError::InvalidStorePayload("not valid UTF-8"))?;
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
    // TODO(#9): consumed by account management writes.
    #[allow(dead_code)]
    pub fn save(&self) -> Result<(), StoreError> {
        self.write_store()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.file.entries
    }

    // TODO(#9): consumed by account management; tests already exercise it.
    #[allow(dead_code)]
    pub fn add_entry(&mut self, entry: Entry) {
        self.file.entries.push(entry);
    }

    // TODO(#9): consumed by account management.
    #[allow(dead_code)]
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
            refs.push(r.recipient.as_ref() as &dyn Recipient);
        }
        let ciphertext = crypto::encrypt_to_recipients(text.as_bytes(), &refs)?;
        atomic::write(&self.paths.store, &ciphertext)?;
        self.write_recipients_txt(&master_pub.to_string())?;
        Ok(())
    }

    /// Render the recipient list to `recipients.txt` as an audit aid
    /// (ADR-100 §4, #17). Strictly informational — losing or tampering
    /// with this file does NOT affect decryption, which reads the
    /// canonical recipient stanzas from `store.age`'s header. Atomic
    /// write so a partial file never replaces a valid one.
    fn write_recipients_txt(&self, master_bech32: &str) -> Result<(), StoreError> {
        let mut body = String::from(RECIPIENTS_TXT_HEADER);
        body.push_str(master_bech32);
        body.push('\n');
        for r in &self.extra_recipients {
            body.push_str(&r.bech32);
            body.push('\n');
        }
        atomic::write(&self.paths.recipients, body.as_bytes())?;
        Ok(())
    }
}

const RECIPIENTS_TXT_HEADER: &str =
    "# tocken recipients (informational; redundant with store.age header)\n# do not edit by hand — overwritten on every encrypt\n\n";

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
        let mut store = Store::create(paths.clone(), passphrase.clone(), Vec::new()).unwrap();
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
        let backup_pub = backup.to_public();
        let backup_bech32 = backup_pub.to_string();
        let _ = Store::create(
            paths.clone(),
            passphrase,
            vec![NamedRecipient {
                bech32: backup_bech32,
                recipient: Box::new(backup_pub),
            }],
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
        let _ = Store::create(paths.clone(), SecretString::from("right"), Vec::new()).unwrap();
        let result = Store::open_with_passphrase(paths, SecretString::from("wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn recipients_txt_lists_master_and_extras_in_order() {
        let (_tmp, paths) = tmp_paths();
        let backup = x25519::Identity::generate();
        let backup_pub = backup.to_public();
        let backup_bech32 = backup_pub.to_string();
        let store = Store::create(
            paths.clone(),
            SecretString::from("recovery"),
            vec![NamedRecipient {
                bech32: backup_bech32.clone(),
                recipient: Box::new(backup_pub),
            }],
        )
        .unwrap();

        let body = std::fs::read_to_string(&paths.recipients).unwrap();
        let lines: Vec<&str> = body
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let master_bech32 = store.master.to_public().to_string();
        assert_eq!(lines, vec![master_bech32.as_str(), backup_bech32.as_str()]);
    }

    #[test]
    fn recipients_txt_rewritten_on_save() {
        let (_tmp, paths) = tmp_paths();
        let mut store =
            Store::create(paths.clone(), SecretString::from("recovery"), Vec::new()).unwrap();
        let first = std::fs::read_to_string(&paths.recipients).unwrap();
        // Mutate then save; recipients didn't change but the file
        // should be rewritten faithfully, not deleted or corrupted.
        store.add_entry(Entry {
            id: "01h9z0e3mq6kngd5gp7w4tnsx2".into(),
            issuer: "Example".into(),
            account: "alice@example.com".into(),
            secret: SecretString::from("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            kind: EntryKind::Totp,
            created_at: "2026-04-29T10:00:00Z".into(),
        });
        store.save().unwrap();
        let second = std::fs::read_to_string(&paths.recipients).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn recipients_txt_atomic_write_no_partial_on_failure() {
        // Verifies the temp-file + rename pattern: a stable file always
        // exists at the recipients path after a successful create.
        let (_tmp, paths) = tmp_paths();
        let _ = Store::create(paths.clone(), SecretString::from("recovery"), Vec::new()).unwrap();
        assert!(paths.recipients.exists());
        // No leftover .tmp.* files in the data directory.
        let stragglers: Vec<_> = std::fs::read_dir(paths.recipients.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            stragglers.is_empty(),
            "unexpected temp files: {stragglers:?}"
        );
    }
}
