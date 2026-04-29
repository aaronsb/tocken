//! Enrollment surface (#6). Adds a TOTP/HOTP entry to the encrypted
//! store. Sub-modules:
//!
//! - `qr` — decode QR-bearing images (file picker, clipboard,
//!   webcam frame). All three sources normalize to bytes before
//!   reaching `qr::decode_image_bytes`.
//!
//! Future siblings (next tasks): `parse` (otpauth:// URI shape),
//! `validate` (base32 decode + ADR-101 weak-secret check), `error`
//! (typed boundary for the Tauri command surface).

pub mod qr;
