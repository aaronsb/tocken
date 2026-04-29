//! TOTP code generation per RFC 6238. Thin wrapper over `totp-rs`
//! that maps from our `store::format::Algorithm` enum and shapes the
//! API around the call site (which has a unix timestamp and a base32
//! secret string in hand).

use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};

use crate::store::format::Algorithm;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid base32 secret")]
    InvalidSecret,
    #[error("totp library: {0}")]
    Totp(String),
}

/// Generate the TOTP code for `time_unix` (seconds since epoch).
///
/// Unlike `totp.generate_current()`, this takes the time explicitly so
/// the caller can render countdown UIs with consistent rollover and
/// tests can pin specific instants.
pub fn generate(
    secret_b32: &str,
    digits: u8,
    period: u32,
    algorithm: Algorithm,
    time_unix: u64,
) -> Result<String, TotpError> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|_| TotpError::InvalidSecret)?;
    let alg = match algorithm {
        Algorithm::Sha1 => TotpAlgorithm::SHA1,
        Algorithm::Sha256 => TotpAlgorithm::SHA256,
        Algorithm::Sha512 => TotpAlgorithm::SHA512,
    };
    // skew=0: no clock-skew tolerance window; we want the exact
    // current-step code for display.
    let totp = TOTP::new(alg, digits as usize, 0, period as u64, bytes)
        .map_err(|e| TotpError::Totp(e.to_string()))?;
    Ok(totp.generate(time_unix))
}

/// Seconds remaining in the current TOTP step. Useful for rendering
/// countdown indicators and deciding when to re-fetch codes.
pub fn time_remaining(period: u32, time_unix: u64) -> u32 {
    let p = period as u64;
    (p - (time_unix % p)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B test vectors (SHA1, 8-digit, 30s step).
    /// Secret: ASCII "12345678901234567890" → base32:
    ///         GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const RFC6238_SECRET_SHA1_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_8digit_vectors() {
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (t, expected) in cases {
            let got =
                generate(RFC6238_SECRET_SHA1_B32, 8, 30, Algorithm::Sha1, t).unwrap();
            assert_eq!(got, expected, "RFC 6238 SHA1 t={t}");
        }
    }

    /// A realistic-length 160-bit base32 secret. `totp-rs` enforces
    /// RFC 4226's 128-bit minimum, which short demo secrets like
    /// `JBSWY3DPEHPK3PXP` (80-bit) don't meet.
    const REALISTIC_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    #[test]
    fn six_digit_default_period() {
        let code = generate(REALISTIC_SECRET, 6, 30, Algorithm::Sha1, 1_700_000_000).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        let again = generate(REALISTIC_SECRET, 6, 30, Algorithm::Sha1, 1_700_000_000).unwrap();
        assert_eq!(code, again, "same time + secret should give same code");
    }

    #[test]
    fn time_remaining_within_period() {
        assert_eq!(time_remaining(30, 0), 30);
        assert_eq!(time_remaining(30, 29), 1);
        assert_eq!(time_remaining(30, 30), 30);
        assert_eq!(time_remaining(30, 45), 15);
        // 1_700_000_007 % 60 = 27, so 60 - 27 = 33 remaining.
        assert_eq!(time_remaining(60, 1_700_000_007), 33);
    }

    #[test]
    fn invalid_base32_rejected() {
        let result = generate("not-base32!", 6, 30, Algorithm::Sha1, 0);
        assert!(matches!(result, Err(TotpError::InvalidSecret)));
    }

    #[test]
    fn code_changes_at_period_boundary() {
        let a = generate(REALISTIC_SECRET, 6, 30, Algorithm::Sha1, 30).unwrap();
        let b = generate(REALISTIC_SECRET, 6, 30, Algorithm::Sha1, 60).unwrap();
        assert_ne!(a, b, "consecutive 30s windows must produce different codes");
    }
}
