//! Enrollment surface (#6). Adds a TOTP/HOTP entry to the encrypted
//! store. Sub-modules:
//!
//! - `qr` — decode QR-bearing images (file picker, clipboard,
//!   webcam frame). All three sources normalize to bytes before
//!   reaching `qr::decode_image_bytes`.
//! - `parse` — `otpauth://` URI → `EnrollForm`. Same DTO as manual
//!   entry, so all sources land at one validation surface (ADR-101 §1).
//! - `validate` — base32, digits/period bounds, weak-secret detection.
//!   Two-phase split (`validate_form` / `check_weak_secret`) so the
//!   ADR-101 confirmation prompt is a typed flow, not a boolean kludge.
//! - `error` — `EnrollError` carrying `WeakSecret { bits }` across the
//!   Tauri command boundary.

pub mod error;
pub mod parse;
pub mod qr;
pub mod validate;

use secrecy::SecretString;
use serde::Deserialize;
use ulid::Ulid;

use crate::store::format::{Algorithm, Entry, EntryKind};

/// User-supplied (or URI-derived) enrollment input. The pre-store DTO:
/// no ULID, no created_at, no commitment that the secret has been
/// vetted. `finalize_entry` mints those fields and produces a
/// store-shaped `Entry`.
#[derive(Debug, Deserialize)]
pub struct EnrollForm {
    #[serde(default)]
    pub issuer: String,
    pub account: String,
    #[serde(deserialize_with = "deserialize_secret")]
    pub secret: SecretString,
    pub digits: u8,
    pub period: u32,
    pub algorithm: Algorithm,
    pub kind: EntryKind,
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}

/// Mint ULID + timestamp and produce the store-shaped entry. Caller is
/// expected to have run `validate::validate_form` and resolved any
/// weak-secret prompt before reaching this point.
pub fn finalize_entry(form: EnrollForm) -> Entry {
    Entry {
        id: Ulid::new().to_string(),
        issuer: form.issuer,
        account: form.account,
        secret: form.secret,
        digits: form.digits,
        period: form.period,
        algorithm: form.algorithm,
        kind: form.kind,
        created_at: now_rfc3339(),
    }
}

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    // `OffsetDateTime::now_utc()` returns a value the `Rfc3339`
    // formatter can always render. If this ever errors it indicates a
    // logic bug, not a runtime condition we can recover from — fail
    // loudly rather than write a Unix epoch into a real entry.
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC 3339 formatting of now_utc() is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn finalize_mints_ulid_and_timestamp() {
        let form = EnrollForm {
            issuer: "Example".into(),
            account: "alice@example.com".into(),
            secret: SecretString::from("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            kind: EntryKind::Totp,
        };
        let entry = finalize_entry(form);
        assert_eq!(entry.id.len(), 26, "ULID is 26 chars in canonical form");
        assert!(entry.created_at.contains('T'));
        assert!(entry.created_at.ends_with('Z') || entry.created_at.contains('+'));
        assert_eq!(entry.issuer, "Example");
        assert_eq!(
            entry.secret.expose_secret(),
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        );
    }
}
