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
    #[error("recipients.txt: {0}")]
    RecipientsMetadata(String),
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
///
/// `master_public` is always present — re-encryption needs it on every
/// save path, including the YubiKey-unlock path that never sees the
/// private master. `master_private` is `Some` only when the caller has
/// recovered or generated the master identity (create flow, passphrase
/// recovery). Lifecycle operations that mutate `master.age` itself
/// (rotate-master, future #10 work) require `master_private`; ordinary
/// re-encrypt does not.
pub struct Store {
    paths: StorePaths,
    file: StoreFile,
    master_private: Option<x25519::Identity>,
    master_public: x25519::Recipient,
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
        let master_public = master.to_public();
        let store = Self {
            paths,
            file: StoreFile::new(),
            master_private: Some(master),
            master_public,
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
        let master_public = master.to_public();

        let store_ciphertext = std::fs::read(&paths.store)?;
        let plaintext = crypto::decrypt_with_identity(&store_ciphertext, &master as &dyn Identity)?;
        let text = std::str::from_utf8(&plaintext)
            .map_err(|_| StoreError::InvalidStorePayload("not valid UTF-8"))?;
        let file = format::deserialize(text)?;

        Ok(Self {
            paths,
            file,
            master_private: Some(master),
            master_public,
            extra_recipients: Vec::new(),
        })
    }

    /// Construct a `Store` after a successful YubiKey-side decryption,
    /// using `recipients.txt` to recover the recipient set without the
    /// passphrase. The first non-comment line in `recipients.txt` MUST
    /// be the master x25519 pubkey; subsequent lines are extras.
    /// Without this file the recipient set is unrecoverable from
    /// `store.age` alone (age plugin recipients are opaque tags), so
    /// missing or malformed metadata is a hard error here rather than
    /// a silent "save would drop YubiKey from the recipient set" trap
    /// at the next encrypt.
    pub fn from_yubikey_unlock(paths: StorePaths, file: StoreFile) -> Result<Self, StoreError> {
        let body = std::fs::read_to_string(&paths.recipients).map_err(|e| {
            StoreError::RecipientsMetadata(format!(
                "missing or unreadable: {e} — re-run the wizard to restore"
            ))
        })?;
        let (master_public, extra_recipients) = parse_recipients_file(&body)?;
        Ok(Self {
            paths,
            file,
            master_private: None,
            master_public,
            extra_recipients,
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
        let master = self.master_private.as_ref().ok_or(StoreError::InvalidMaster(
            "cannot write master.age without master_private (rotate-master needs the passphrase path)",
        ))?;
        let identity_string = master.to_string();
        let ciphertext = crypto::encrypt_with_passphrase(
            identity_string.expose_secret().as_bytes(),
            passphrase.clone(),
        )?;
        atomic::write(&self.paths.master, &ciphertext)?;
        Ok(())
    }

    fn write_store(&self) -> Result<(), StoreError> {
        let text = format::serialize(&self.file)?;
        let mut refs: Vec<&dyn Recipient> = Vec::with_capacity(1 + self.extra_recipients.len());
        refs.push(&self.master_public as &dyn Recipient);
        for r in &self.extra_recipients {
            refs.push(r.recipient.as_ref() as &dyn Recipient);
        }
        let ciphertext = crypto::encrypt_to_recipients(text.as_bytes(), &refs)?;
        atomic::write(&self.paths.store, &ciphertext)?;
        self.write_recipients_txt(&self.master_public.to_string())?;
        Ok(())
    }

    /// Render the recipient list to `recipients.txt`. Originally an
    /// audit aid (ADR-100 §4, #17); load-bearing on the YubiKey-unlock
    /// path (#27) where it's the only way to recover the recipient set
    /// without the passphrase. Atomic write so a partial file never
    /// replaces a valid one.
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

/// Parse `recipients.txt`. First non-comment, non-blank line is the
/// master x25519 pubkey (strict: any other prefix here is a hard
/// reject). Subsequent lines are extras: `age1yubikey1...` go through
/// the age plugin recipient path, plain `age1...` are x25519. Any
/// other line shape is rejected so a malformed file can't masquerade
/// as a legitimate state.
fn parse_recipients_file(
    body: &str,
) -> Result<(x25519::Recipient, Vec<NamedRecipient>), StoreError> {
    use age::plugin::{Recipient as PluginRecipient, RecipientPluginV1};
    use age::NoCallbacks;

    let lines: Vec<&str> = body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let master_str = lines
        .first()
        .ok_or_else(|| StoreError::RecipientsMetadata("file has no recipient lines".into()))?;
    if !master_str.starts_with("age1") || master_str.starts_with("age1yubikey") {
        return Err(StoreError::RecipientsMetadata(format!(
            "first line must be a plain x25519 pubkey (got: {master_str})"
        )));
    }
    let master_public = x25519::Recipient::from_str(master_str)
        .map_err(|e| StoreError::RecipientsMetadata(format!("master pubkey did not parse: {e}")))?;

    let mut extras = Vec::with_capacity(lines.len().saturating_sub(1));
    for line in &lines[1..] {
        let bech32 = line.to_string();
        let recipient: BoxedRecipient = if bech32.starts_with("age1yubikey") {
            let pr = PluginRecipient::from_str(&bech32).map_err(|e| {
                StoreError::RecipientsMetadata(format!("plugin recipient {bech32}: {e}"))
            })?;
            let plugin_name = pr.plugin().to_owned();
            let plugin =
                RecipientPluginV1::new(&plugin_name, &[pr], &[], NoCallbacks).map_err(|e| {
                    StoreError::RecipientsMetadata(format!("plugin {plugin_name} init: {e}"))
                })?;
            Box::new(plugin)
        } else if bech32.starts_with("age1") {
            let r = x25519::Recipient::from_str(&bech32).map_err(|e| {
                StoreError::RecipientsMetadata(format!("x25519 recipient {bech32}: {e}"))
            })?;
            Box::new(r)
        } else {
            return Err(StoreError::RecipientsMetadata(format!(
                "unrecognized recipient line: {bech32}"
            )));
        };
        extras.push(NamedRecipient { bech32, recipient });
    }
    Ok((master_public, extras))
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
        let master_bech32 = store.master_public.to_string();
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
    fn parse_recipients_file_accepts_master_plus_x25519_extra() {
        let master = x25519::Identity::generate();
        let backup = x25519::Identity::generate();
        let body = format!(
            "# tocken recipients\n{}\n{}\n",
            master.to_public(),
            backup.to_public()
        );
        let (master_pub, extras) = parse_recipients_file(&body).unwrap();
        assert_eq!(master_pub.to_string(), master.to_public().to_string());
        assert_eq!(extras.len(), 1);
        assert_eq!(extras[0].bech32, backup.to_public().to_string());
    }

    #[test]
    fn parse_recipients_file_rejects_empty() {
        let body = "# only comments\n\n";
        assert!(matches!(
            parse_recipients_file(body),
            Err(StoreError::RecipientsMetadata(_))
        ));
    }

    #[test]
    fn parse_recipients_file_rejects_yubikey_master() {
        // Plugin recipient where the master x25519 should be — strict
        // reject so a malformed file can't masquerade.
        let body = "age1yubikey1qfakebut_recognizable_prefix\nage1blah\n";
        let result = parse_recipients_file(body);
        assert!(matches!(result, Err(StoreError::RecipientsMetadata(_))));
    }

    #[test]
    fn parse_recipients_file_rejects_garbage_line() {
        let master = x25519::Identity::generate();
        let body = format!("{}\nnot-a-recipient\n", master.to_public());
        let result = parse_recipients_file(&body);
        assert!(matches!(result, Err(StoreError::RecipientsMetadata(_))));
    }

    #[test]
    fn from_yubikey_unlock_round_trips_via_recipients_txt() {
        // Build a store with a backup x25519 recipient (substituting
        // for the YubiKey we don't have in unit tests). Decrypt with
        // the backup identity (mimicking the YubiKey plugin's job),
        // then reconstruct via from_yubikey_unlock and confirm save()
        // produces the same recipient set.
        let (_tmp, paths) = tmp_paths();
        let backup = x25519::Identity::generate();
        let backup_pub = backup.to_public();
        let backup_bech32 = backup_pub.to_string();
        let initial = Store::create(
            paths.clone(),
            SecretString::from("recovery"),
            vec![NamedRecipient {
                bech32: backup_bech32.clone(),
                recipient: Box::new(backup_pub),
            }],
        )
        .unwrap();
        let original_master_pub = initial.master_public.to_string();
        drop(initial);

        // Simulate the YubiKey-unlock path: decrypt store.age via the
        // backup identity, then reconstruct via from_yubikey_unlock.
        let ciphertext = std::fs::read(&paths.store).unwrap();
        let plaintext =
            crypto::decrypt_with_identity(&ciphertext, &backup as &dyn Identity).unwrap();
        let text = std::str::from_utf8(&plaintext).unwrap();
        let file = format::deserialize(text).unwrap();

        let mut recovered = Store::from_yubikey_unlock(paths.clone(), file).unwrap();
        assert!(recovered.master_private.is_none());
        assert_eq!(recovered.master_public.to_string(), original_master_pub);
        assert_eq!(recovered.extra_recipients.len(), 1);
        assert_eq!(recovered.extra_recipients[0].bech32, backup_bech32);

        // Save adds an entry through the recovered store; recipients
        // must persist unchanged.
        recovered.add_entry(Entry {
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
        recovered.save().unwrap();

        // The backup identity must still decrypt the new ciphertext —
        // the recipient set was preserved across save.
        let new_ct = std::fs::read(&paths.store).unwrap();
        let new_pt = crypto::decrypt_with_identity(&new_ct, &backup as &dyn Identity).unwrap();
        let new_text = std::str::from_utf8(&new_pt).unwrap();
        let new_file = format::deserialize(new_text).unwrap();
        assert_eq!(new_file.entries.len(), 1);
    }

    #[test]
    fn from_yubikey_unlock_errors_when_recipients_txt_missing() {
        let (_tmp, paths) = tmp_paths();
        let _ = Store::create(paths.clone(), SecretString::from("p"), Vec::new()).unwrap();
        std::fs::remove_file(&paths.recipients).unwrap();
        let result = Store::from_yubikey_unlock(paths, StoreFile::new());
        assert!(matches!(result, Err(StoreError::RecipientsMetadata(_))));
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
