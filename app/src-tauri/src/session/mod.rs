//! Daily-unlock session state (issue #3).
//!
//! Holds decrypted TOTP entries in memory between unlock and re-lock.
//! Re-lock is rotation-count driven (memory zeroed when min(rotations
//! since unlock) crosses LOCK_AFTER_ROTATIONS).

pub mod totp;
pub mod unlock;

#[cfg(test)]
mod spike;

use age::secrecy::ExposeSecret;
use serde::Serialize;

use crate::store::format::{Entry, EntryKind};
use totp::TotpError;

/// After this many rotations of the slowest visible entry, the session
/// re-locks (memory zeroed; user must touch again). At the default
/// 30s period that's ~5 minutes; at 60s it's ~10 minutes. #8 makes
/// this configurable; #3 lands the constant.
pub const LOCK_AFTER_ROTATIONS: u32 = 10;

/// In-memory unlocked view. `Entry` already wraps the secret in
/// `SecretString` (zeroizes on drop), so dropping this struct clears
/// the seed material — see #13 for the broader hygiene work.
pub struct Session {
    entries: Vec<Entry>,
    unlocked_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryCode {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub code: String,
    pub digits: u8,
    pub period: u32,
    pub time_remaining: u32,
}

impl Session {
    pub fn new(entries: Vec<Entry>, now_unix: u64) -> Self {
        Self {
            entries,
            unlocked_at_unix: now_unix,
        }
    }

    /// Number of period boundaries crossed for entry `idx` since unlock.
    /// Counts crossings of `period`-aligned boundaries between
    /// `unlocked_at_unix` and `now_unix`.
    pub fn rotations_for_entry(&self, idx: usize, now_unix: u64) -> u32 {
        let Some(entry) = self.entries.get(idx) else {
            return 0;
        };
        let period = entry.period as u64;
        if period == 0 {
            return u32::MAX;
        }
        let unlock_step = self.unlocked_at_unix / period;
        let now_step = now_unix / period;
        now_step.saturating_sub(unlock_step) as u32
    }

    /// Minimum rotation count across all TOTP entries. Re-lock fires
    /// once this exceeds `LOCK_AFTER_ROTATIONS`. HOTP entries don't
    /// rotate on a timer and are excluded.
    ///
    /// **Empty-session policy:** with zero TOTP entries we return 0,
    /// so empty sessions never auto-relock on time alone. ADR-100's
    /// threat model: an empty session has no exfiltratable secrets,
    /// so indefinite hold is safe. This branch becomes effectively
    /// dead code once #6 (enrollment) lands and every session has
    /// at least one entry — flag for cleanup at that point.
    pub fn min_rotations(&self, now_unix: u64) -> u32 {
        let counts: Vec<u32> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.kind, EntryKind::Totp))
            .map(|(i, _)| self.rotations_for_entry(i, now_unix))
            .collect();
        if counts.is_empty() {
            return 0;
        }
        *counts.iter().min().unwrap()
    }

    pub fn should_relock(&self, now_unix: u64) -> bool {
        self.min_rotations(now_unix) >= LOCK_AFTER_ROTATIONS
    }

    /// Compute codes for every TOTP entry at `now_unix`. HOTP entries
    /// are skipped (they need counter management, separate concern).
    pub fn codes(&self, now_unix: u64) -> Result<Vec<EntryCode>, TotpError> {
        self.entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::Totp))
            .map(|e| {
                let code = totp::generate(
                    e.secret.expose_secret(),
                    e.digits,
                    e.period,
                    e.algorithm,
                    now_unix,
                )?;
                Ok(EntryCode {
                    id: e.id.clone(),
                    issuer: e.issuer.clone(),
                    account: e.account.clone(),
                    code,
                    digits: e.digits,
                    period: e.period,
                    time_remaining: totp::time_remaining(e.period, now_unix),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::format::Algorithm;
    use age::secrecy::SecretString;

    fn make_entry(id: &str, period: u32) -> Entry {
        Entry {
            id: id.into(),
            issuer: "Issuer".into(),
            account: "user@example.com".into(),
            secret: SecretString::from("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
            digits: 6,
            period,
            algorithm: Algorithm::Sha1,
            kind: EntryKind::Totp,
            created_at: "2026-04-29T10:00:00Z".into(),
        }
    }

    #[test]
    fn rotations_counts_period_boundaries() {
        let entries = vec![make_entry("a", 30)];
        let session = Session::new(entries, 1_700_000_000);
        // Unlock at 1_700_000_000 (step = 56666666). At t+30 we've
        // crossed exactly one boundary if we landed on a boundary on
        // unlock; otherwise the first crossing is at the next
        // multiple-of-30 boundary.
        assert_eq!(session.rotations_for_entry(0, 1_700_000_000), 0);
        assert_eq!(session.rotations_for_entry(0, 1_700_000_030), 1);
        assert_eq!(session.rotations_for_entry(0, 1_700_000_300), 10);
    }

    #[test]
    fn should_relock_after_threshold() {
        let entries = vec![make_entry("a", 30)];
        let session = Session::new(entries, 1_700_000_000);
        assert!(!session.should_relock(1_700_000_000));
        assert!(!session.should_relock(1_700_000_270)); // 9 rotations
        assert!(session.should_relock(1_700_000_300)); // 10 rotations
    }

    #[test]
    fn min_rotations_uses_slowest_period() {
        // 30s and 60s entries; after 10 minutes the 60s entry has
        // rotated 10 times and the 30s entry 20 times. min = 10.
        let entries = vec![make_entry("a", 30), make_entry("b", 60)];
        let session = Session::new(entries, 1_700_000_000);
        assert_eq!(session.min_rotations(1_700_000_600), 10);
        // After 9 rotations of the 60s entry (540s), min = 9.
        assert_eq!(session.min_rotations(1_700_000_540), 9);
    }

    #[test]
    fn codes_returns_one_per_totp_entry() {
        let entries = vec![make_entry("a", 30), make_entry("b", 30)];
        let session = Session::new(entries, 1_700_000_000);
        let codes = session.codes(1_700_000_000).unwrap();
        assert_eq!(codes.len(), 2);
        assert_eq!(codes[0].id, "a");
        assert_eq!(codes[1].id, "b");
        assert_eq!(codes[0].code.len(), 6);
        assert!(codes[0].code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn hotp_entries_skipped() {
        let mut hotp = make_entry("hotp", 30);
        hotp.kind = EntryKind::Hotp;
        let entries = vec![make_entry("totp", 30), hotp];
        let session = Session::new(entries, 1_700_000_000);
        assert_eq!(session.codes(1_700_000_000).unwrap().len(), 1);
    }

    #[test]
    fn empty_session_does_not_relock_on_time() {
        let session = Session::new(vec![], 1_700_000_000);
        assert!(!session.should_relock(1_800_000_000));
    }
}
