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
    #[error("digits must be 6, 7, or 8 (got {0})")]
    InvalidDigits(u8),

    /// `period` zero or impossibly large.
    #[error("period must be between 1 and 86400 seconds (got {0})")]
    InvalidPeriod(u32),

    /// Account is empty or whitespace-only.
    #[error("account name is required")]
    MissingAccount,

    /// URI didn't parse as `otpauth://`.
    #[error("could not parse otpauth URI: {0}")]
    InvalidUri(String),

    /// `otpauth-migration://` URI handed to a single-entry path.
    /// Tracked separately under #7.
    #[error("otpauth-migration:// URIs are not yet supported (tracked in #7)")]
    MigrationUriNotSupported,

    /// `otpauth://` URI specified a `type` other than `totp`. HOTP is
    /// schema-supported but enrollment surfaces don't accept it yet.
    #[error("HOTP enrollment is not yet supported")]
    HotpNotSupported,
}
