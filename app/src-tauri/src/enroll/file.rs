//! File-source enrollment (#6 file picker). Reads a path the user
//! picked, decides image vs plaintext, decodes every payload, and
//! produces per-row preview metadata.
//!
//! Plaintext: one `otpauth://...` URI per line (matches the legacy
//! bash CLI's `secrets.txt`). Empty lines and lines with leading `#`
//! are skipped. Migration URIs (`otpauth-migration://`) parse as
//! `MigrationUriNotSupported` per-row errors — when #7 lands the row
//! state model is unchanged, only the UI's handling of that error.
//!
//! The preview returns the raw payload alongside the decoded fields
//! so the frontend can echo selected payloads back to the commit
//! command without the backend caching session state. Secrets do
//! cross the IPC boundary, but they already do for the paste-URI and
//! manual-entry surfaces — same trust posture.

use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

use secrecy::ExposeSecret;
use serde::Serialize;

use super::error::EnrollError;
use super::parse::parse_otpauth_uri;
use super::qr::{decode_image_bytes, QrError};
use super::{normalize_secret, validate};

/// Per-row preview returned from `enroll_file_preview`. The frontend
/// renders these as a list with checkboxes; `error.is_some()` rows are
/// disabled, `weak_bits.is_some()` rows get a per-row "Use anyway"
/// affordance per ADR-101. `payload` carries the raw URI/QR text the
/// frontend echoes back on commit.
#[derive(Debug, Serialize)]
pub struct FileRowPreview {
    /// Display string. Truncated for very long payloads.
    pub source: String,
    /// Raw URI/QR text. Present when `error.is_none()` so the frontend
    /// can hand it back on commit. The backend re-parses + re-vets
    /// rather than trusting JS to forward an `EnrollForm` shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Display fields. Present iff parse succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u32>,
    /// Parse / validate failure. Mutually exclusive with the metadata
    /// fields above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<EnrollError>,
    /// Independent of `error`: secret is below RFC-4226's 128-bit
    /// minimum but otherwise valid. UI surfaces a "Use anyway"
    /// per-row checkbox; commit honors `force_weak` per row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weak_bits: Option<u32>,
}

/// Top-level errors from the preview command. Per-payload errors land
/// inside `FileRowPreview::error`; this enum covers conditions that
/// kill the whole pass (file missing, no QR in image, etc.).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileError {
    #[error("could not read file: {detail}")]
    Io { detail: String },
    #[error("file is empty")]
    Empty,
    #[error("could not decode image: {detail}")]
    Image { detail: String },
    #[error("no QR codes found in image")]
    NoCodesFound,
    /// Clipboard didn't carry an image at all (text, empty, etc.).
    /// Distinct from `Image` — that's "tried to decode and failed",
    /// which is a different user-facing message.
    #[error("no image on clipboard")]
    ClipboardEmpty,
}

impl From<io::Error> for FileError {
    fn from(e: io::Error) -> Self {
        FileError::Io {
            detail: e.to_string(),
        }
    }
}

impl From<QrError> for FileError {
    fn from(e: QrError) -> Self {
        match e {
            QrError::NoCodesFound => FileError::NoCodesFound,
            QrError::Image(err) => FileError::Image {
                detail: err.to_string(),
            },
            QrError::Decode(detail) => FileError::Image { detail },
        }
    }
}

/// Decode every payload from a file, yielding one row per payload.
pub fn decode_file(path: &Path) -> Result<Vec<FileRowPreview>, FileError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Err(FileError::Empty);
    }

    let payloads = if looks_like_image(path, &bytes) {
        decode_image_bytes(&bytes)?
    } else {
        let text = String::from_utf8_lossy(&bytes);
        text.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    };

    Ok(decode_payloads(payloads))
}

/// Wrap raw decoded payloads into `FileRowPreview`s. Shared by the
/// file-picker path (after `decode_file`) and the clipboard-image
/// path (after `qr::decode_image_bytes`) — same row state machine,
/// different upstreams.
pub fn decode_payloads(payloads: Vec<String>) -> Vec<FileRowPreview> {
    payloads.into_iter().map(payload_to_row).collect()
}

/// Securely overwrite `path` with zeros, fsync, then unlink. Best-
/// effort under modern filesystem realities — see issue #6 caveat
/// (CoW, journals, SSD wear leveling). The user-facing prompt
/// surfaces that limitation; this function does its part.
///
/// Rejects symlinks and non-regular files outright. The UI promises
/// "overwrite and delete the source file"; following a symlink would
/// zero the target while only unlinking the link, breaking that
/// promise and turning the command into a write-anywhere primitive
/// bounded only by user-writable files.
pub fn destroy_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let ft = metadata.file_type();
    if ft.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destroy refused: source is a symlink",
        ));
    }
    if !ft.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destroy refused: source is not a regular file",
        ));
    }
    let size = metadata.len();

    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(0))?;
    let zeros = vec![0u8; 64 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    f.sync_all()?;
    drop(f);

    fs::remove_file(path)
}

fn looks_like_image(path: &Path, bytes: &[u8]) -> bool {
    // Image formats here must stay aligned with the `image` crate's
    // enabled features in Cargo.toml (currently png + jpeg) and the
    // dialog filter in enroll.js. Adding a format means turning on
    // its `image` feature, otherwise a pass through this gate fails
    // at decode.
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let lower = ext.to_ascii_lowercase();
        if matches!(lower.as_str(), "png" | "jpg" | "jpeg") {
            return true;
        }
        if matches!(lower.as_str(), "txt" | "uri" | "list") {
            return false;
        }
    }
    bytes.starts_with(&[0x89, 0x50, 0x4e, 0x47]) // PNG
        || bytes.starts_with(&[0xff, 0xd8, 0xff]) // JPEG
}

fn payload_to_row(payload: String) -> FileRowPreview {
    let display_source = truncate_for_display(&payload, 80);
    match parse_otpauth_uri(&payload) {
        Ok(mut form) => {
            // Normalize the secret so weak-secret detection sees the
            // same canonical form the commit path will. Mutating in
            // place avoids exposing plaintext twice.
            let normalized = normalize_secret(form.secret.expose_secret());
            form.secret = secrecy::SecretString::from(normalized);

            // Run validate before exposing the row as committable.
            // invalid_secret / invalid_digits / etc. become row errors;
            // weak_bits is independent and gates commit via force_weak.
            if let Err(err) = validate::validate_form(&form) {
                return FileRowPreview {
                    source: display_source,
                    payload: None,
                    issuer: None,
                    account: None,
                    digits: None,
                    period: None,
                    error: Some(err),
                    weak_bits: None,
                };
            }
            let weak_bits = validate::check_weak_secret(&form.secret);
            FileRowPreview {
                source: display_source,
                payload: Some(payload),
                issuer: Some(form.issuer),
                account: Some(form.account),
                digits: Some(form.digits),
                period: Some(form.period),
                error: None,
                weak_bits,
            }
        }
        Err(err) => FileRowPreview {
            source: display_source,
            payload: None,
            issuer: None,
            account: None,
            digits: None,
            period: None,
            error: Some(err),
            weak_bits: None,
        },
    }
}

pub fn truncate_for_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn decodes_plaintext_with_mixed_rows() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example"
        )
        .unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, "# a comment").unwrap();
        writeln!(
            tmp,
            "otpauth://totp/Demo:bob@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo"
        )
        .unwrap();
        writeln!(tmp, "not-a-uri").unwrap();
        writeln!(tmp, "otpauth-migration://offline?data=somebase64payload").unwrap();
        tmp.as_file_mut().sync_all().unwrap();

        let rows = decode_file(tmp.path()).expect("decode");
        assert_eq!(rows.len(), 4, "blank + comment lines skipped");

        // Strong, valid.
        assert!(rows[0].error.is_none());
        assert_eq!(rows[0].weak_bits, None);
        assert_eq!(rows[0].issuer.as_deref(), Some("Example"));

        // Weak (80 bits) but valid.
        assert!(rows[1].error.is_none());
        assert_eq!(rows[1].weak_bits, Some(80));

        // Garbage row.
        assert!(matches!(
            rows[2].error,
            Some(EnrollError::InvalidUri { .. })
        ));

        // Migration URI surfaces as a per-row error pointing at #7.
        assert!(matches!(
            rows[3].error,
            Some(EnrollError::MigrationUriNotSupported)
        ));
    }

    #[test]
    fn empty_file_errors() {
        let tmp = NamedTempFile::new().unwrap();
        assert!(matches!(decode_file(tmp.path()), Err(FileError::Empty)));
    }

    #[test]
    fn missing_file_io_errors() {
        let path = std::path::Path::new("/nonexistent/path/tocken-test");
        assert!(matches!(decode_file(path), Err(FileError::Io { .. })));
    }

    #[test]
    fn destroy_file_zeros_and_unlinks() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "secret data").unwrap();
        tmp.as_file_mut().sync_all().unwrap();
        let path = tmp.path().to_path_buf();
        // tempfile would unlink on drop, but we want the file to exist
        // until destroy_file runs. Persist takes ownership.
        let _ = tmp.persist(&path).unwrap();

        destroy_file(&path).expect("destroy");
        assert!(!path.exists(), "file removed after destroy");
    }

    #[cfg(unix)]
    #[test]
    fn destroy_file_refuses_symlink() {
        // Regression: a symlink-followed destroy would zero the target
        // and only unlink the link, breaking the UI's "delete the
        // source file" promise and giving a write-anywhere primitive
        // bounded only by user-writable files.
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");

        fs::write(&target, b"do not zero me").unwrap();
        symlink(&target, &link).unwrap();

        let err = destroy_file(&link).expect_err("must reject symlink");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // The link is still there, the target is intact.
        assert!(link.exists());
        let preserved = fs::read(&target).unwrap();
        assert_eq!(preserved, b"do not zero me");
    }
}
