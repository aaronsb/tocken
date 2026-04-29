//! Daily-unlock session state (issue #3).
//!
//! Holds decrypted TOTP entries in memory between unlock and re-lock.
//! Re-lock is rotation-count driven (memory zeroed when min(rotations
//! since unlock) crosses LOCK_AFTER_ROTATIONS).

pub mod totp;
