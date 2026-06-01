//! `otpauth-migration://` parser (Google Authenticator export QRs, #7).
//!
//! Format observed in the wild:
//!
//! ```text
//! otpauth-migration://offline?data=<urlsafe-base64 of MigrationPayload protobuf>
//! ```
//!
//! The protobuf carries one or more `OtpParameters` so a single QR can
//! represent N TOTP entries (Google's batch export). We expand each
//! batch into N synthesized `otpauth://` URIs that re-flow through the
//! existing `parse::parse_otpauth_uri` → `validate::*` → `payload_to_row`
//! pipeline. Reusing that path means weak-secret detection, validation,
//! and the per-row preview UI all behave identically to file / clipboard
//! imports — no parallel commit code path to maintain.
//!
//! HOTP entries inside a migration payload aren't surfaced (yet) since
//! the rest of enrollment doesn't accept HOTP. They expand to error
//! rows pointing at #15-style HOTP support work; the user can still
//! commit the TOTP siblings.
//!
//! Multi-QR batches (`batch_size > 1`, where Google split a large
//! export across several QRs) parse independently for v1 — each QR
//! contributes its share. Stitching them is a future enhancement; not
//! a blocker for typical small exports (1-10 entries).

use data_encoding::BASE32_NOPAD;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use prost::Message;

use super::error::EnrollError;

/// Generated from `proto/migration.proto` by `prost-build` (see
/// `build.rs`). `_.rs` is prost's default name when the proto has no
/// `package` declaration. `pub(crate)` so cross-module tests (e.g.
/// `enroll::file::tests`) can build payloads without round-tripping
/// through a real GA QR.
pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

/// Path/query encoding set for synthesized `otpauth://` URIs.
/// Conservative — we percent-encode anything that isn't pchar or
/// query-safe. The standard library `percent_encoding` crate's
/// `NON_ALPHANUMERIC` would over-encode (would percent-encode `:`
/// in the label, which legacy parsers might mishandle), so this is
/// a tighter set that still covers reserved and unsafe characters.
const URI_RESERVED: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Parse an `otpauth-migration://` URI into one synthesized
/// `otpauth://` URI per OtpParameters entry the payload contains.
///
/// Returns synthesized URI strings rather than `EnrollForm` directly
/// so the caller (`decode_payloads`) can flow them through the same
/// validate + weak-check + preview pipeline that file/clipboard/camera
/// imports use. The trade-off is one extra parse per entry — cheap
/// at batch sizes we expect (single-digit entries per QR).
///
/// HOTP entries are surfaced as `EnrollError::HotpNotSupported` rows
/// rather than dropped silently — the user sees "this entry was
/// skipped" instead of a missing entry.
pub fn parse_otpauth_migration_uri(
    input: &str,
) -> Result<Vec<Result<String, EnrollError>>, EnrollError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let url = url::Url::parse(&cleaned).map_err(|e| EnrollError::MigrationDecodeFailed {
        detail: format!("not a URL: {e}"),
    })?;
    if url.scheme() != "otpauth-migration" {
        return Err(EnrollError::MigrationDecodeFailed {
            detail: format!("expected otpauth-migration scheme, got {}", url.scheme()),
        });
    }

    let data = url
        .query_pairs()
        .find(|(k, _)| k == "data")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| EnrollError::MigrationDecodeFailed {
            detail: "missing data param".into(),
        })?;

    // GA emits URL-safe base64; some QR generators round-trip through
    // standard base64. Try URL-safe first, then standard. Both with
    // optional padding tolerance (GA includes padding; some normalizers
    // strip it).
    let bytes =
        decode_base64_tolerant(&data).ok_or_else(|| EnrollError::MigrationDecodeFailed {
            detail: "data param is not valid base64".into(),
        })?;

    let payload = proto::MigrationPayload::decode(bytes.as_slice()).map_err(|e| {
        EnrollError::MigrationDecodeFailed {
            detail: format!("malformed protobuf: {e}"),
        }
    })?;

    if payload.otp_parameters.is_empty() {
        return Err(EnrollError::MigrationDecodeFailed {
            detail: "payload contains no entries".into(),
        });
    }

    let entries: Vec<Result<String, EnrollError>> = payload
        .otp_parameters
        .into_iter()
        .map(otp_to_synthesized_uri)
        .collect();
    Ok(entries)
}

fn decode_base64_tolerant(input: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    // Try URL-safe with padding (GA's canonical shape).
    if let Ok(bytes) = general_purpose::URL_SAFE.decode(input) {
        return Some(bytes);
    }
    // No padding (some normalizers strip it).
    if let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD.decode(input) {
        return Some(bytes);
    }
    // Standard base64 (some QR generators emit this instead).
    if let Ok(bytes) = general_purpose::STANDARD.decode(input) {
        return Some(bytes);
    }
    if let Ok(bytes) = general_purpose::STANDARD_NO_PAD.decode(input) {
        return Some(bytes);
    }
    None
}

fn otp_to_synthesized_uri(otp: proto::OtpParameters) -> Result<String, EnrollError> {
    let kind = proto::OtpType::try_from(otp.r#type).unwrap_or(proto::OtpType::Unspecified);
    match kind {
        proto::OtpType::Totp => {}
        proto::OtpType::Hotp => return Err(EnrollError::HotpNotSupported),
        proto::OtpType::Unspecified => {
            return Err(EnrollError::MigrationDecodeFailed {
                detail: "OTP type unspecified".into(),
            });
        }
    }

    if otp.secret.is_empty() {
        return Err(EnrollError::InvalidSecret);
    }
    // GA stores the secret as RAW bytes; otpauth:// URIs carry it as
    // RFC 4648 base32 (uppercase, no padding). Encode at the boundary.
    let secret_b32 = BASE32_NOPAD.encode(&otp.secret);

    let digits =
        match proto::DigitCount::try_from(otp.digits).unwrap_or(proto::DigitCount::Unspecified) {
            proto::DigitCount::Six => 6u8,
            proto::DigitCount::Eight => 8u8,
            proto::DigitCount::Unspecified => 6u8, // RFC 4226 default.
        };

    let algorithm =
        match proto::Algorithm::try_from(otp.algorithm).unwrap_or(proto::Algorithm::Unspecified) {
            proto::Algorithm::Sha1 | proto::Algorithm::Unspecified => "SHA1",
            proto::Algorithm::Sha256 => "SHA256",
            proto::Algorithm::Sha512 => "SHA512",
            proto::Algorithm::Md5 => {
                // Our store schema doesn't model MD5. Reject rather than
                // silently downgrade to SHA1 — codes would be wrong.
                return Err(EnrollError::MigrationDecodeFailed {
                    detail: "MD5 algorithm not supported".into(),
                });
            }
        };

    let issuer = otp.issuer;
    let account = otp.name;
    if account.trim().is_empty() {
        return Err(EnrollError::MissingAccount);
    }

    // Build label: "Issuer:Account" if issuer present, else "Account".
    let label = if issuer.is_empty() {
        utf8_percent_encode(&account, URI_RESERVED).to_string()
    } else {
        format!(
            "{}:{}",
            utf8_percent_encode(&issuer, URI_RESERVED),
            utf8_percent_encode(&account, URI_RESERVED)
        )
    };

    let mut uri = format!("otpauth://totp/{label}?secret={secret_b32}");
    if !issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&utf8_percent_encode(&issuer, URI_RESERVED).to_string());
    }
    if digits != 6 {
        uri.push_str(&format!("&digits={digits}"));
    }
    // GA's TOTP migration entries always imply 30s period — the proto
    // has no period field. The synthesized URI omits it (parser falls
    // back to the RFC default of 30s).
    if algorithm != "SHA1" {
        uri.push_str(&format!("&algorithm={algorithm}"));
    }

    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    /// Build a migration URI from raw OtpParameters. Round-trip helper
    /// so tests don't need to capture a real GA QR.
    fn build_migration_uri(entries: Vec<proto::OtpParameters>) -> String {
        let payload = proto::MigrationPayload {
            otp_parameters: entries,
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 42,
        };
        let bytes = payload.encode_to_vec();
        let b64 = general_purpose::URL_SAFE.encode(&bytes);
        format!("otpauth-migration://offline?data={b64}")
    }

    fn sample_entry(name: &str, issuer: &str) -> proto::OtpParameters {
        // 20-byte secret = 160 bits = strong, fits SHA1's block.
        let secret = b"01234567890123456789".to_vec();
        proto::OtpParameters {
            secret,
            name: name.to_string(),
            issuer: issuer.to_string(),
            algorithm: proto::Algorithm::Sha1 as i32,
            digits: proto::DigitCount::Six as i32,
            r#type: proto::OtpType::Totp as i32,
            counter: 0,
        }
    }

    #[test]
    fn round_trip_single_entry() {
        let uri = build_migration_uri(vec![sample_entry("alice@example.com", "Example")]);
        let entries = parse_otpauth_migration_uri(&uri).expect("parse");
        assert_eq!(entries.len(), 1);
        let synth = entries[0].as_ref().expect("entry ok");
        assert!(synth.starts_with("otpauth://totp/"));
        assert!(
            synth.contains("Example:alice%40example.com")
                || synth.contains("Example:alice@example.com")
        );
        assert!(synth.contains("secret="));
        assert!(synth.contains("issuer=Example"));
        // SHA1 + 6 digits = canonical defaults; should NOT appear.
        assert!(!synth.contains("algorithm="));
        assert!(!synth.contains("digits="));
    }

    #[test]
    fn round_trip_through_otpauth_parser() {
        // The synthesized URI must parse cleanly back through
        // parse_otpauth_uri so the file-row pipeline accepts it.
        let uri = build_migration_uri(vec![sample_entry("bob@example.com", "Acme")]);
        let entries = parse_otpauth_migration_uri(&uri).expect("parse");
        let synth = entries[0].as_ref().expect("entry ok");
        let form = super::super::parse::parse_otpauth_uri(synth).expect("re-parse");
        assert_eq!(form.issuer, "Acme");
        assert_eq!(form.account, "bob@example.com");
    }

    #[test]
    fn multi_entry_batch_expands() {
        let entries = vec![
            sample_entry("alice", "A"),
            sample_entry("bob", "B"),
            sample_entry("charlie", "C"),
        ];
        let uri = build_migration_uri(entries);
        let parsed = parse_otpauth_migration_uri(&uri).expect("parse");
        assert_eq!(parsed.len(), 3);
        for (i, want) in ["alice", "bob", "charlie"].iter().enumerate() {
            let synth = parsed[i].as_ref().expect("entry ok");
            assert!(synth.contains(want), "synth[{i}] missing {want}: {synth}");
        }
    }

    #[test]
    fn hotp_entry_yields_per_row_error() {
        let mut hotp = sample_entry("alice", "X");
        hotp.r#type = proto::OtpType::Hotp as i32;
        let uri = build_migration_uri(vec![hotp]);
        let parsed = parse_otpauth_migration_uri(&uri).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert!(matches!(parsed[0], Err(EnrollError::HotpNotSupported)));
    }

    #[test]
    fn sha256_synthesizes_with_algorithm_param() {
        let mut entry = sample_entry("alice", "X");
        entry.algorithm = proto::Algorithm::Sha256 as i32;
        let uri = build_migration_uri(vec![entry]);
        let parsed = parse_otpauth_migration_uri(&uri).expect("parse");
        let synth = parsed[0].as_ref().expect("entry ok");
        assert!(synth.contains("algorithm=SHA256"), "want SHA256: {synth}");
    }

    #[test]
    fn eight_digit_synthesizes_with_digits_param() {
        let mut entry = sample_entry("alice", "X");
        entry.digits = proto::DigitCount::Eight as i32;
        let uri = build_migration_uri(vec![entry]);
        let parsed = parse_otpauth_migration_uri(&uri).expect("parse");
        let synth = parsed[0].as_ref().expect("entry ok");
        assert!(synth.contains("digits=8"), "want digits=8: {synth}");
    }

    #[test]
    fn empty_secret_is_per_row_error() {
        let mut entry = sample_entry("alice", "X");
        entry.secret = vec![];
        let uri = build_migration_uri(vec![entry]);
        let parsed = parse_otpauth_migration_uri(&uri).expect("parse");
        assert!(matches!(parsed[0], Err(EnrollError::InvalidSecret)));
    }

    #[test]
    fn empty_account_is_per_row_error() {
        let mut entry = sample_entry("", "X");
        entry.name = "   ".into();
        let uri = build_migration_uri(vec![entry]);
        let parsed = parse_otpauth_migration_uri(&uri).expect("parse");
        assert!(matches!(parsed[0], Err(EnrollError::MissingAccount)));
    }

    #[test]
    fn malformed_base64_errors() {
        let uri = "otpauth-migration://offline?data=!!!not-base64!!!";
        assert!(matches!(
            parse_otpauth_migration_uri(uri),
            Err(EnrollError::MigrationDecodeFailed { .. })
        ));
    }

    #[test]
    fn missing_data_param_errors() {
        let uri = "otpauth-migration://offline";
        assert!(matches!(
            parse_otpauth_migration_uri(uri),
            Err(EnrollError::MigrationDecodeFailed { .. })
        ));
    }

    #[test]
    fn empty_payload_errors() {
        let uri = build_migration_uri(vec![]);
        assert!(matches!(
            parse_otpauth_migration_uri(&uri),
            Err(EnrollError::MigrationDecodeFailed { .. })
        ));
    }

    #[test]
    fn truncated_protobuf_errors() {
        // Valid base64, but the bytes don't decode to a MigrationPayload.
        let bad = general_purpose::URL_SAFE.encode(b"this-is-not-protobuf");
        let uri = format!("otpauth-migration://offline?data={bad}");
        assert!(matches!(
            parse_otpauth_migration_uri(&uri),
            Err(EnrollError::MigrationDecodeFailed { .. })
        ));
    }

    #[test]
    fn wrong_scheme_errors() {
        let uri = build_migration_uri(vec![sample_entry("a", "B")])
            .replace("otpauth-migration", "otpauth");
        assert!(matches!(
            parse_otpauth_migration_uri(&uri),
            Err(EnrollError::MigrationDecodeFailed { .. })
        ));
    }
}
