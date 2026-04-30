//! Minimal config.toml read/write. The schema landed by this issue
//! is *minimal* — just the YubiKey recipient string — and #8 will
//! reformat it into a proper UX/behavior config later. Keeping the
//! footprint small means #8 has freedom to redesign without us
//! shipping a v1 schema we'd then have to migrate.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bech32-encoded YubiKey recipient (`age1yubikey1...`). Public
    /// key material — safe to persist in plaintext config.
    #[serde(default)]
    pub yubikey_recipient: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml serialize: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml parse: {0}")]
    TomlDe(#[from] toml::de::Error),
}

impl Config {
    // TODO(#3, #8): consumed by the code-panel state machine and the
    // settings UI; the wizard only writes config, doesn't read it.
    #[allow(dead_code)]
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.yubikey_recipient.is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config {
            yubikey_recipient: Some("age1yubikey1abc".into()),
        };
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.yubikey_recipient.as_deref(), Some("age1yubikey1abc"));
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/config.toml");
        let cfg = Config {
            yubikey_recipient: Some("age1yubikey1xyz".into()),
        };
        cfg.save(&path).unwrap();
        assert!(path.exists());
    }
}
