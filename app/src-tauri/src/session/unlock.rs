//! Daily-unlock via `age::plugin::IdentityPluginV1`. Decrypts
//! `store.age` using the YubiKey identity stub from
//! `age-plugin-yubikey --identity`. The plugin only blinks while we're
//! mid-decrypt; the touch prompt UX is rendered statically by the
//! frontend (`AWAITING_TOUCH` state) per the spike #23 finding.

use std::io::Read;
use std::process::Command;
use std::str::FromStr;

use age::plugin::{Identity as PluginIdentity, IdentityPluginV1};
use age::{Decryptor, NoCallbacks};
use serde::Serialize;

use crate::store::{format, paths::StorePaths, format::StoreFile};

const PLUGIN_BINARY: &str = "age-plugin-yubikey";

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("{PLUGIN_BINARY} is not installed or not on PATH")]
    PluginMissing,
    #[error("no YubiKey identity available — run the first-run wizard")]
    NoIdentity,
    #[error("touch not registered (timed out or wrong key); plug the YubiKey in and try again")]
    TouchTimeoutOrMismatch,
    #[error("store data is missing or unreadable: {0}")]
    StoreUnreadable(String),
    #[error("store contents are corrupted")]
    StoreCorrupted,
    #[error("unexpected: {0}")]
    Other(String),
}

/// Tagged shape for IPC. The JS state machine routes on `kind` —
/// TouchTimeout → TOUCH_TIMEOUT pane, PluginMissing or NoIdentity →
/// installer-help pane (#5 should have prevented these), other →
/// generic error.
#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum UnlockErrorIpc {
    PluginMissing,
    NoIdentity,
    TouchTimeout,
    StoreCorrupted,
    Other { detail: String },
}

impl From<&UnlockError> for UnlockErrorIpc {
    fn from(err: &UnlockError) -> Self {
        match err {
            UnlockError::PluginMissing => Self::PluginMissing,
            UnlockError::NoIdentity => Self::NoIdentity,
            UnlockError::TouchTimeoutOrMismatch => Self::TouchTimeout,
            UnlockError::StoreCorrupted => Self::StoreCorrupted,
            UnlockError::StoreUnreadable(detail) | UnlockError::Other(detail) => {
                Self::Other { detail: detail.clone() }
            }
        }
    }
}

/// Decrypt `store.age` using the active YubiKey identity. Blocks
/// until the user touches the key (typically ~15s timeout enforced by
/// the plugin). On success, returns the parsed `StoreFile` ready to
/// hand to `Session::new`.
pub fn decrypt_store_with_yubikey(paths: &StorePaths) -> Result<StoreFile, UnlockError> {
    let identity_stub = read_identity_stub()?;
    let identity = PluginIdentity::from_str(&identity_stub)
        .map_err(|e| UnlockError::Other(format!("identity stub did not parse: {e}")))?;
    let plugin_name = identity.plugin().to_owned();
    let plugin = IdentityPluginV1::new(&plugin_name, &[identity], NoCallbacks).map_err(|e| {
        // age::DecryptError::MissingPlugin is the explicit case
        if format!("{e}").to_lowercase().contains("missing") {
            UnlockError::PluginMissing
        } else {
            UnlockError::Other(format!("plugin init: {e}"))
        }
    })?;

    let ciphertext = std::fs::read(&paths.store)
        .map_err(|e| UnlockError::StoreUnreadable(e.to_string()))?;

    let decryptor = Decryptor::new_buffered(ciphertext.as_slice())
        .map_err(|e| UnlockError::Other(format!("decryptor init: {e}")))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&plugin as &dyn age::Identity))
        .map_err(|e| classify_decrypt_error(&e))?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| UnlockError::Other(format!("read decrypted: {e}")))?;

    let text = std::str::from_utf8(&plaintext).map_err(|_| UnlockError::StoreCorrupted)?;
    format::deserialize(text).map_err(|_| UnlockError::StoreCorrupted)
}

/// Probe `age-plugin-yubikey --identity` and pull out the identity
/// stub line (begins with `AGE-PLUGIN-YUBIKEY-`). PluginMissing if
/// the binary isn't there; NoIdentity if there's no slot configured.
fn read_identity_stub() -> Result<String, UnlockError> {
    let output = Command::new(PLUGIN_BINARY).arg("--identity").output();
    let output = match output {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(UnlockError::PluginMissing);
        }
        Err(e) => return Err(UnlockError::Other(format!("spawn {PLUGIN_BINARY}: {e}"))),
    };
    if !output.status.success() {
        return Err(UnlockError::NoIdentity);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.starts_with("AGE-PLUGIN-YUBIKEY-"))
        .map(|s| s.trim().to_string())
        .ok_or(UnlockError::NoIdentity)
}

fn classify_decrypt_error(err: &age::DecryptError) -> UnlockError {
    let msg = format!("{err}").to_lowercase();
    if msg.contains("plugin") && msg.contains("missing") {
        UnlockError::PluginMissing
    } else if msg.contains("no matching")
        || msg.contains("could not unwrap")
        || msg.contains("failed to decrypt")
        || msg.contains("stanza")
    {
        // Hardware-path failure modes that all surface as the same UX:
        // "touch not registered, or this YubiKey doesn't match the one
        // that encrypted the store." User retries (or runs the wizard
        // again if the slot was reprovisioned).
        UnlockError::TouchTimeoutOrMismatch
    } else {
        UnlockError::Other(format!("decrypt: {err}"))
    }
}
