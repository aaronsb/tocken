//! First-run wizard (issue #5).
//!
//! Drives the onboarding flow: Diceware passphrase generation, YubiKey
//! detection / provisioning, initial empty store creation.

pub mod config;
pub mod passphrase;
pub mod yubikey;
