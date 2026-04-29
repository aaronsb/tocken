//! Pre-store validation. Splits into two phases so the Tauri command
//! layer can implement ADR-101's "weak secret? prompt to confirm" flow:
//!
//! 1. `validate_form` checks everything *except* secret length. Errors
//!    here are unconditional rejections (typo'd base32, bad digit
//!    count, missing account).
//! 2. `check_weak_secret` runs after step 1 succeeds. Returns
//!    `Some(bits)` for sub-128-bit secrets so the Tauri command can
//!    decide whether to surface `EnrollError::WeakSecret { bits }` or
//!    let it through (when the user confirmed past the prompt).
//!
//! Splitting the check this way keeps a single source of truth for
//! "what's a weak secret" and avoids a boolean parameter that would
//! otherwise change validation semantics.

use secrecy::{ExposeSecret, SecretString};
use totp_rs::Secret;

use super::error::EnrollError;
use super::EnrollForm;

/// Per-field validation, except for secret length. Idempotent and
/// side-effect-free — pure check on the form's contents.
pub fn validate_form(form: &EnrollForm) -> Result<(), EnrollError> {
    if form.account.trim().is_empty() {
        return Err(EnrollError::MissingAccount);
    }

    if !(6..=8).contains(&form.digits) {
        return Err(EnrollError::InvalidDigits(form.digits));
    }

    if form.period == 0 || form.period > 86_400 {
        return Err(EnrollError::InvalidPeriod(form.period));
    }

    decode_secret(&form.secret)?;

    Ok(())
}

/// Returns the decoded secret length in bits if it falls below ADR-101's
/// 128-bit threshold, otherwise `None`. Assumes `validate_form` has
/// already confirmed the secret is base32-valid; calling this on an
/// invalid secret returns `None` (the validation phase will have
/// surfaced `InvalidSecret`).
pub fn check_weak_secret(secret: &SecretString) -> Option<u32> {
    let bytes = decode_secret(secret).ok()?;
    let bits = (bytes.len() * 8) as u32;
    (bits < 128).then_some(bits)
}

fn decode_secret(secret: &SecretString) -> Result<Vec<u8>, EnrollError> {
    Secret::Encoded(secret.expose_secret().to_string())
        .to_bytes()
        .map_err(|_| EnrollError::InvalidSecret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::EnrollForm;
    use crate::store::format::{Algorithm, EntryKind};

    fn form(secret: &str) -> EnrollForm {
        EnrollForm {
            issuer: "Example".into(),
            account: "alice@example.com".into(),
            secret: SecretString::from(secret),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            kind: EntryKind::Totp,
        }
    }

    #[test]
    fn accepts_well_formed_strong_secret() {
        // 32 chars of base32 = 160 bits.
        let f = form("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        assert!(validate_form(&f).is_ok());
        assert_eq!(check_weak_secret(&f.secret), None);
    }

    #[test]
    fn flags_short_secret_as_weak_after_validation_passes() {
        // 16 chars of base32 = 80 bits.
        let f = form("JBSWY3DPEHPK3PXP");
        assert!(validate_form(&f).is_ok());
        assert_eq!(check_weak_secret(&f.secret), Some(80));
    }

    #[test]
    fn boundary_at_128_bits_is_not_weak() {
        // Exactly 16 bytes = 128 bits. RFC MUST is 128, so 128 itself
        // is compliant.
        let bytes = [0x55u8; 16];
        let b32 = data_encoding_like_base32(&bytes);
        let f = form(&b32);
        assert!(validate_form(&f).is_ok());
        assert_eq!(check_weak_secret(&f.secret), None);
    }

    #[test]
    fn rejects_non_base32_secret() {
        let f = form("not-base32!");
        assert!(matches!(validate_form(&f), Err(EnrollError::InvalidSecret)));
    }

    #[test]
    fn rejects_empty_account() {
        let mut f = form("JBSWY3DPEHPK3PXP");
        f.account = "   ".into();
        assert!(matches!(
            validate_form(&f),
            Err(EnrollError::MissingAccount)
        ));
    }

    #[test]
    fn rejects_invalid_digits() {
        let mut f = form("JBSWY3DPEHPK3PXP");
        f.digits = 5;
        assert!(matches!(
            validate_form(&f),
            Err(EnrollError::InvalidDigits(5))
        ));
        f.digits = 9;
        assert!(matches!(
            validate_form(&f),
            Err(EnrollError::InvalidDigits(9))
        ));
    }

    #[test]
    fn rejects_invalid_period() {
        let mut f = form("JBSWY3DPEHPK3PXP");
        f.period = 0;
        assert!(matches!(
            validate_form(&f),
            Err(EnrollError::InvalidPeriod(0))
        ));
        f.period = 100_000;
        assert!(matches!(
            validate_form(&f),
            Err(EnrollError::InvalidPeriod(100_000))
        ));
    }

    /// Round-trip helper: encode raw bytes as base32 the same way the
    /// `totp-rs` `Secret` decoder expects. `totp-rs` uses RFC 4648
    /// base32 with no padding for `Secret::Encoded::to_bytes`.
    fn data_encoding_like_base32(bytes: &[u8]) -> String {
        // Manual implementation to avoid pulling in another base32 dep
        // for one test helper.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let mut buffer: u32 = 0;
        let mut bits = 0;
        for &b in bytes {
            buffer = (buffer << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let idx = ((buffer >> bits) & 0x1F) as usize;
                out.push(ALPHABET[idx] as char);
            }
        }
        if bits > 0 {
            let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
        out
    }
}
