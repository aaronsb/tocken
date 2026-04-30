//! `otpauth://` URI parser. Produces an `EnrollForm` from a URI string,
//! the same DTO manual-entry submits. Feeding both paths through one
//! validation surface (`validate::validate_form` + `check_weak_secret`)
//! is the contract that prevents per-source UX divergence (ADR-101 §1).
//!
//! Supports `otpauth://totp/...`. `otpauth-migration://` (Google
//! Authenticator export shape) returns a distinct error pointing at #7.
//! HOTP URIs are recognized and rejected with their own error variant
//! since `EntryKind::Hotp` is schema-supported but enrollment doesn't
//! cover HOTP yet.

use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use url::Url;

use super::error::EnrollError;
use super::EnrollForm;
use crate::store::format::{Algorithm, EntryKind};

const DEFAULT_DIGITS: u8 = 6;
const DEFAULT_PERIOD: u32 = 30;
const DEFAULT_ALG: Algorithm = Algorithm::Sha1;

/// Parse an `otpauth://` URI into an `EnrollForm`. Does not run
/// `validate::*` — call sites combine the two so a single error path
/// surfaces both URI-shape problems and field-level validation.
pub fn parse_otpauth_uri(input: &str) -> Result<EnrollForm, EnrollError> {
    let trimmed = input.trim();

    if trimmed.starts_with("otpauth-migration://") {
        return Err(EnrollError::MigrationUriNotSupported);
    }

    let url = Url::parse(trimmed).map_err(|e| EnrollError::InvalidUri {
        detail: format!("not a URL: {e}"),
    })?;

    if url.scheme() != "otpauth" {
        return Err(EnrollError::InvalidUri {
            detail: format!("expected otpauth scheme, got {}", url.scheme()),
        });
    }

    let kind = match url.host_str() {
        Some("totp") => EntryKind::Totp,
        Some("hotp") => return Err(EnrollError::HotpNotSupported),
        Some(other) => {
            return Err(EnrollError::InvalidUri {
                detail: format!("expected totp or hotp, got {other}"),
            })
        }
        None => {
            return Err(EnrollError::InvalidUri {
                detail: "missing type".into(),
            })
        }
    };

    let label = parse_label(&url)?;

    let mut secret: Option<String> = None;
    let mut issuer_param: Option<String> = None;
    let mut digits = DEFAULT_DIGITS;
    let mut period = DEFAULT_PERIOD;
    let mut algorithm = DEFAULT_ALG;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.into_owned()),
            "issuer" => issuer_param = Some(value.into_owned()),
            "digits" => {
                digits = value.parse().map_err(|_| EnrollError::InvalidUri {
                    detail: format!("digits not a number: {value}"),
                })?
            }
            "period" => {
                period = value.parse().map_err(|_| EnrollError::InvalidUri {
                    detail: format!("period not a number: {value}"),
                })?
            }
            "algorithm" => {
                algorithm = parse_algorithm(&value)?;
            }
            _ => {} // Ignore unknown params; future-compatible.
        }
    }

    let secret = secret.ok_or_else(|| EnrollError::InvalidUri {
        detail: "missing secret parameter".into(),
    })?;

    // Issuer precedence: `issuer=` query param wins over the label's
    // "Issuer:" prefix. RFC ambiguity (Google's QR docs prefer the
    // param; some other apps use the prefix). When both exist and
    // disagree, the param is canonical.
    let issuer = issuer_param.unwrap_or(label.issuer);

    Ok(EnrollForm {
        issuer,
        account: label.account,
        secret: SecretString::from(secret),
        digits,
        period,
        algorithm,
        kind,
    })
}

struct Label {
    issuer: String,
    account: String,
}

fn parse_label(url: &Url) -> Result<Label, EnrollError> {
    let path = url.path().trim_start_matches('/');
    if path.is_empty() {
        return Err(EnrollError::InvalidUri {
            detail: "missing label".into(),
        });
    }
    // `url::Url::path()` returns the percent-encoded path; decode here
    // so non-ASCII issuers (Cyrillic, CJK) survive the round-trip.
    // Lossy on invalid UTF-8 — enrollment shouldn't fail on a quirky
    // label encoding when the secret itself is recoverable.
    let decoded = percent_decode_str(path).decode_utf8_lossy();
    if let Some((issuer, account)) = decoded.split_once(':') {
        Ok(Label {
            issuer: issuer.trim().to_string(),
            account: account.trim().to_string(),
        })
    } else {
        Ok(Label {
            issuer: String::new(),
            account: decoded.trim().to_string(),
        })
    }
}

fn parse_algorithm(value: &str) -> Result<Algorithm, EnrollError> {
    match value.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(Algorithm::Sha1),
        "SHA256" => Ok(Algorithm::Sha256),
        "SHA512" => Ok(Algorithm::Sha512),
        other => Err(EnrollError::InvalidUri {
            detail: format!("unknown algorithm: {other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn parses_canonical_uri() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30&algorithm=SHA1";
        let form = parse_otpauth_uri(uri).unwrap();
        assert_eq!(form.issuer, "Example");
        assert_eq!(form.account, "alice@example.com");
        assert_eq!(
            form.secret.expose_secret(),
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        );
        assert_eq!(form.digits, 6);
        assert_eq!(form.period, 30);
        assert!(matches!(form.algorithm, Algorithm::Sha1));
        assert!(matches!(form.kind, EntryKind::Totp));
    }

    #[test]
    fn defaults_when_params_omitted() {
        let uri = "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let form = parse_otpauth_uri(uri).unwrap();
        assert_eq!(form.issuer, "");
        assert_eq!(form.account, "alice@example.com");
        assert_eq!(form.digits, DEFAULT_DIGITS);
        assert_eq!(form.period, DEFAULT_PERIOD);
        assert!(matches!(form.algorithm, Algorithm::Sha1));
    }

    #[test]
    fn issuer_param_overrides_label_prefix() {
        let uri = "otpauth://totp/Stale:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Fresh";
        let form = parse_otpauth_uri(uri).unwrap();
        assert_eq!(form.issuer, "Fresh");
    }

    #[test]
    fn percent_encoded_label_decodes() {
        let uri =
            "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let form = parse_otpauth_uri(uri).unwrap();
        assert_eq!(form.issuer, "Example");
        assert_eq!(form.account, "alice@example.com");
    }

    #[test]
    fn non_ascii_label_decodes() {
        // Cyrillic "Привет" UTF-8-then-percent-encoded.
        let uri = "otpauth://totp/%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82:bob?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let form = parse_otpauth_uri(uri).unwrap();
        assert_eq!(form.issuer, "Привет");
        assert_eq!(form.account, "bob");
    }

    #[test]
    fn migration_uri_returns_distinct_error() {
        let uri = "otpauth-migration://offline?data=ABCDEFG";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(EnrollError::MigrationUriNotSupported)
        ));
    }

    #[test]
    fn hotp_returns_distinct_error() {
        let uri =
            "otpauth://hotp/alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&counter=0";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(EnrollError::HotpNotSupported)
        ));
    }

    #[test]
    fn missing_secret_errors() {
        let uri = "otpauth://totp/alice@example.com?issuer=Example";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(EnrollError::InvalidUri { .. })
        ));
    }

    #[test]
    fn weak_secret_passes_parser_lands_at_validation() {
        // Parser doesn't enforce length — that's enrollment's job per
        // ADR-101. This test asserts the parser hands off the short
        // secret intact for the validation/weak-check phase.
        let uri = "otpauth://totp/Demo:bob?secret=JBSWY3DPEHPK3PXP";
        let form = parse_otpauth_uri(uri).unwrap();
        assert_eq!(form.secret.expose_secret(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn unknown_scheme_errors() {
        let uri = "https://example.com/totp/?secret=ABCD";
        assert!(matches!(
            parse_otpauth_uri(uri),
            Err(EnrollError::InvalidUri { .. })
        ));
    }
}
