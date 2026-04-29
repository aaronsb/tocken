use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const STORE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    #[serde(serialize_with = "serialize_secret", deserialize_with = "deserialize_secret")]
    pub secret: SecretString,
    pub digits: u8,
    pub period: u32,
    pub algorithm: Algorithm,
    #[serde(rename = "type")]
    pub kind: EntryKind,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Totp,
    Hotp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreFile {
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl StoreFile {
    pub fn new() -> Self {
        Self {
            version: STORE_FORMAT_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Default for StoreFile {
    fn default() -> Self {
        Self::new()
    }
}

const HEADER_COMMENT: &str =
    "# tocken store v1 — do not edit by hand unless you know what you're doing\n\n";

pub fn serialize(store: &StoreFile) -> Result<String, toml::ser::Error> {
    let body = toml::to_string_pretty(store)?;
    Ok(format!("{HEADER_COMMENT}{body}"))
}

pub fn deserialize(text: &str) -> Result<StoreFile, toml::de::Error> {
    let store: StoreFile = toml::from_str(text)?;
    if store.version != STORE_FORMAT_VERSION {
        // Future-proof point: dispatch on version. Today only v1 exists.
        return Err(serde::de::Error::custom(format!(
            "unsupported store version {}; this build understands version {}",
            store.version, STORE_FORMAT_VERSION
        )));
    }
    Ok(store)
}

fn serialize_secret<S: serde::Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use secrecy::ExposeSecret;
    serializer.serialize_str(secret.expose_secret())
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty_store() {
        let store = StoreFile::new();
        let text = serialize(&store).unwrap();
        let parsed = deserialize(&text).unwrap();
        assert_eq!(parsed.version, STORE_FORMAT_VERSION);
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn roundtrip_with_entry() {
        use secrecy::ExposeSecret;
        let mut store = StoreFile::new();
        store.entries.push(Entry {
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
        let text = serialize(&store).unwrap();
        let parsed = deserialize(&text).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].issuer, "Google");
        assert_eq!(
            parsed.entries[0].secret.expose_secret(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn rejects_future_version() {
        let bad = "version = 999\nentries = []\n";
        assert!(deserialize(bad).is_err());
    }
}
