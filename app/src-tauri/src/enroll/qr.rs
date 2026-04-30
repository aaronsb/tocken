//! QR decode surface for enrollment. Wraps `rqrr` so the rest of
//! `enroll/` only sees `Vec<String>` (one decoded payload per QR).
//!
//! Image bytes come in three shapes during enrollment: a PNG/JPG read
//! from a file picker (#6 file source), a clipboard image (#6
//! clipboard source), and a frame captured from the webcam (#6 camera
//! source). All three normalize to "decode bytes containing an image"
//! before reaching this module.

use image::ImageReader;
use std::io::Cursor;

#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error("could not decode image: {0}")]
    Image(#[from] image::ImageError),
    #[error("no QR codes found in image")]
    NoCodesFound,
    #[error("rqrr decode failed: {0}")]
    Decode(String),
}

/// Decode every QR code present in `image_bytes`. Returns the textual
/// payloads in the order `rqrr` finds them (typically top-left to
/// bottom-right). A successful decode returns at least one payload;
/// `Err(NoCodesFound)` means the image was readable but contained no
/// recognizable QR.
pub fn decode_image_bytes(image_bytes: &[u8]) -> Result<Vec<String>, QrError> {
    let img = ImageReader::new(Cursor::new(image_bytes))
        .with_guessed_format()
        .map_err(image::ImageError::IoError)?
        .decode()?;
    decode_grids(img.into_luma8())
}

/// Decode every QR present in raw RGBA pixel data (row-major, top to
/// bottom — matches `tauri::image::Image::rgba()`). Used by the
/// clipboard-image source: arboard/clipboard-manager hands us decoded
/// pixels rather than encoded image bytes.
///
/// The `to_vec()` is unavoidable at this boundary: `Image::rgba()`
/// returns `&[u8]` and exposes no method to move the underlying Vec
/// out. One copy per click is fine — image decode itself dwarfs it.
pub fn decode_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>, QrError> {
    let buf = image::RgbaImage::from_raw(width, height, rgba.to_vec()).ok_or_else(|| {
        QrError::Decode(format!(
            "rgba buffer size {} doesn't match {}x{}",
            rgba.len(),
            width,
            height
        ))
    })?;
    let luma = image::DynamicImage::ImageRgba8(buf).into_luma8();
    decode_grids(luma)
}

fn decode_grids(luma: image::GrayImage) -> Result<Vec<String>, QrError> {
    let mut prep = rqrr::PreparedImage::prepare(luma);
    let grids = prep.detect_grids();
    if grids.is_empty() {
        return Err(QrError::NoCodesFound);
    }
    let mut payloads = Vec::with_capacity(grids.len());
    for grid in grids {
        let (_meta, content) = grid.decode().map_err(|e| QrError::Decode(e.to_string()))?;
        payloads.push(content);
    }
    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, Luma};
    use qrcode::QrCode;

    /// Render `payload` as a QR code and return PNG bytes. Uses the
    /// `qrcode` crate's matrix output and writes pixels manually so we
    /// don't pull in `qrcode`'s `image` integration (which would need
    /// matching feature flags between this dep and our prod `image`).
    fn encode_to_png(payload: &str, scale: u32) -> Vec<u8> {
        let code = QrCode::new(payload).expect("encode QR");
        let modules = code.to_colors();
        let width = code.width() as u32;
        let quiet = 4u32; // standard 4-module quiet zone
        let img_size = (width + 2 * quiet) * scale;
        let mut img = GrayImage::from_pixel(img_size, img_size, Luma([255u8]));

        for y in 0..width {
            for x in 0..width {
                let dark = matches!(modules[(y * width + x) as usize], qrcode::Color::Dark);
                if !dark {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        let px = (quiet + x) * scale + dx;
                        let py = (quiet + y) * scale + dy;
                        img.put_pixel(px, py, Luma([0u8]));
                    }
                }
            }
        }

        let mut buf = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .expect("png encode");
        buf
    }

    #[test]
    fn round_trip_otpauth_uri() {
        let payload = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30&algorithm=SHA1";
        let png = encode_to_png(payload, 6);
        let decoded = decode_image_bytes(&png).expect("decode");
        assert_eq!(decoded, vec![payload.to_string()]);
    }

    #[test]
    fn round_trip_short_secret_otpauth_uri() {
        // Sub-128-bit demo secret. Decoder doesn't validate length —
        // ADR-101 places that check at enrollment time, after decode.
        let payload = "otpauth://totp/Demo:bob@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo";
        let png = encode_to_png(payload, 6);
        let decoded = decode_image_bytes(&png).expect("decode");
        assert_eq!(decoded, vec![payload.to_string()]);
    }

    #[test]
    fn no_qr_in_blank_image_errors() {
        let blank = GrayImage::from_pixel(200, 200, Luma([255u8]));
        let mut buf = Vec::new();
        image::DynamicImage::ImageLuma8(blank)
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        assert!(matches!(
            decode_image_bytes(&buf),
            Err(QrError::NoCodesFound)
        ));
    }

    #[test]
    fn malformed_image_bytes_errors() {
        let result = decode_image_bytes(b"not an image");
        assert!(matches!(result, Err(QrError::Image(_))));
    }

    #[test]
    fn decode_rgba_round_trips_otpauth_uri() {
        // Build a PNG, decode it back to RGBA via the same `image`
        // crate clipboard-manager uses internally, then run it
        // through the in-memory RGBA path. Verifies the row-major
        // layout assumption and the RGBA → luma → rqrr pipeline.
        let payload =
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example";
        let png = encode_to_png(payload, 6);
        let img = image::ImageReader::new(Cursor::new(&png))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        let decoded = decode_rgba(w, h, rgba.as_raw()).expect("decode");
        assert_eq!(decoded, vec![payload.to_string()]);
    }

    #[test]
    fn decode_rgba_size_mismatch_errors() {
        // Buffer too small for the claimed dimensions — RgbaImage::
        // from_raw returns None, and decode_rgba surfaces it as
        // QrError::Decode rather than panicking.
        let result = decode_rgba(100, 100, &[0u8; 16]);
        assert!(matches!(result, Err(QrError::Decode(_))));
    }
}
