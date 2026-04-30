//! Typed errors for the enrollment surface. Crosses the Tauri command
//! boundary, so variants carry only `serde`-friendly data and carefully
//! avoid `Display` strings the frontend can't act on. The `WeakSecret`
//! variant exists specifically to let the frontend render the ADR-101
//! confirmation dialog without round-tripping a stringly-typed error.

use serde::Serialize;

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnrollError {
    /// Base32 decoder rejected the secret. Typically a typo in manual
    /// entry or a corrupted QR.
    #[error("invalid base32 secret")]
    InvalidSecret,

    /// Decoded secret is shorter than RFC 4226's 128-bit minimum.
    /// Per ADR-101, this is a confirmation prompt, not a hard reject.
    /// `bits` is the actual length so the dialog can name it.
    #[error("secret is {bits} bits, less than the 128-bit RFC 4226 minimum")]
    WeakSecret { bits: u32 },

    /// `digits` outside RFC 4226's 6..=8 range.
    #[error("digits must be 6, 7, or 8 (got {digits})")]
    InvalidDigits { digits: u8 },

    /// `period` zero or impossibly large.
    #[error("period must be between 1 and 86400 seconds (got {period})")]
    InvalidPeriod { period: u32 },

    /// Account is empty or whitespace-only.
    #[error("account name is required")]
    MissingAccount,

    /// URI didn't parse as `otpauth://`.
    /// Struct variant (not tuple) so the internally-tagged
    /// `#[serde(tag = "kind")]` representation works.
    #[error("could not parse otpauth URI: {detail}")]
    InvalidUri { detail: String },

    /// `otpauth-migration://` URI handed to a single-entry path.
    /// Tracked separately under #7.
    #[error("otpauth-migration:// URIs are not yet supported (tracked in #7)")]
    MigrationUriNotSupported,

    /// `otpauth://` URI specified a `type` other than `totp`. HOTP is
    /// schema-supported but enrollment surfaces don't accept it yet.
    #[error("HOTP enrollment is not yet supported")]
    HotpNotSupported,

    /// Tried to enroll while the session is locked. Frontend should
    /// route to the unlock pane.
    #[error("session is locked")]
    Locked,

    /// Re-encrypt or atomic-write failed at commit time. Wraps the
    /// `StoreError` variant for log visibility but only surfaces a
    /// generic message to the user; the entry was NOT added.
    #[error("could not save: {detail}")]
    SaveFailed { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against serde's internally-tagged-enum constraint:
    /// `#[serde(tag = "kind")]` can't combine with tuple variants
    /// carrying primitive payloads. If any variant fails to serialize
    /// here, the Tauri command surface that returns these errors will
    /// fail at runtime rather than at compile time.
    #[test]
    fn every_variant_serializes() {
        let cases = [
            EnrollError::InvalidSecret,
            EnrollError::WeakSecret { bits: 80 },
            EnrollError::InvalidDigits { digits: 5 },
            EnrollError::InvalidPeriod { period: 0 },
            EnrollError::MissingAccount,
            EnrollError::InvalidUri {
                detail: "bad".into(),
            },
            EnrollError::MigrationUriNotSupported,
            EnrollError::HotpNotSupported,
            EnrollError::Locked,
            EnrollError::SaveFailed {
                detail: "io".into(),
            },
        ];
        for c in &cases {
            let json =
                serde_json::to_string(c).unwrap_or_else(|e| panic!("variant {c:?} failed: {e}"));
            assert!(json.contains("\"kind\""), "missing tag: {json}");
        }
    }
}
