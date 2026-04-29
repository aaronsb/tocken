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

use crate::store::{format, format::StoreFile, paths::StorePaths};

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
            UnlockError::StoreUnreadable(detail) | UnlockError::Other(detail) => Self::Other {
                detail: detail.clone(),
            },
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

    let ciphertext =
        std::fs::read(&paths.store).map_err(|e| UnlockError::StoreUnreadable(e.to_string()))?;

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

/// Substrings that identify an age::DecryptError as a missing-plugin
/// failure (binary not on PATH, plugin protocol can't initialize).
const PLUGIN_MISSING_HINTS: &[&str] = &["plugin", "missing"];

/// Substrings that identify a hardware-path decrypt failure where the
/// right UX is "retouch or re-run wizard" — covers genuine touch
/// timeouts, slot/identity mismatches, and the recipient-stanza
/// unwrap failures the plugin returns when no key works.
const TOUCH_OR_MISMATCH_HINTS: &[&str] = &[
    "no matching",
    "could not unwrap",
    "failed to decrypt",
    "stanza",
];

fn classify_decrypt_error(err: &age::DecryptError) -> UnlockError {
    classify_decrypt_message(&format!("{err}"))
}

/// Pure string-matching half of `classify_decrypt_error`, factored out
/// so the heuristic is unit-testable without having to construct
/// `age::DecryptError` variants (most of which aren't `pub`).
fn classify_decrypt_message(msg: &str) -> UnlockError {
    let lower = msg.to_lowercase();
    if PLUGIN_MISSING_HINTS.iter().all(|h| lower.contains(h)) {
        UnlockError::PluginMissing
    } else if TOUCH_OR_MISMATCH_HINTS.iter().any(|h| lower.contains(h)) {
        UnlockError::TouchTimeoutOrMismatch
    } else {
        UnlockError::Other(format!("decrypt: {msg}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard: if `age` ever changes its `Display` wording,
    /// these tests catch the silent UX break before users do. New
    /// patterns get added here when we observe them in the wild
    /// (the "stanza" / "Failed to decrypt YubiKey stanza" mapping
    /// was added after smoke-test feedback in #3).
    #[test]
    fn plugin_missing_message_classifies_correctly() {
        let cases = [
            "plugin 'age-plugin-yubikey' missing",
            "Plugin Missing",
            "the age-plugin-yubikey plugin is missing from PATH",
        ];
        for case in cases {
            assert!(
                matches!(classify_decrypt_message(case), UnlockError::PluginMissing),
                "expected PluginMissing for: {case:?}"
            );
        }
    }

    #[test]
    fn touch_timeout_or_mismatch_messages_classify_correctly() {
        let cases = [
            "no matching identity",
            "could not unwrap file key",
            "(stanza 0 0) Failed to decrypt YubiKey stanza", // observed during smoke
            "Failed to decrypt: bad payload",
            "got bad stanza body",
        ];
        for case in cases {
            assert!(
                matches!(
                    classify_decrypt_message(case),
                    UnlockError::TouchTimeoutOrMismatch
                ),
                "expected TouchTimeoutOrMismatch for: {case:?}"
            );
        }
    }

    #[test]
    fn unrecognized_messages_fall_through_to_other() {
        let result = classify_decrypt_message("some weird future error");
        assert!(matches!(result, UnlockError::Other(_)));
    }
}
