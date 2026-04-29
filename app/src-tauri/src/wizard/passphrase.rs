//! Diceware passphrase generation for the first-run wizard.
//!
//! Uses the EFF large wordlist (7,776 words). Six words give ~77 bits
//! of entropy: log2(7776^6) ≈ 77.55. The wordlist is bundled at build
//! time via `include_str!` and parsed once on first use.
//!
//! Source: <https://www.eff.org/dice>
//! License: CC-BY-3.0-US — see `wordlists/LICENSE-EFF-WORDLIST.md`.

// SPDX-License-Identifier: CC-BY-3.0-US (for the bundled wordlist text)

use std::sync::LazyLock;

use secrecy::SecretString;

const WORDLIST_RAW: &str = include_str!("../../wordlists/eff_large_wordlist.txt");

/// Parsed view of the bundled wordlist: 7,776 entries, just the words
/// (the leading dice numbers are stripped).
static WORDLIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    WORDLIST_RAW
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .collect()
});

/// Default Diceware word count. Six words ≈ 77 bits of entropy.
pub const DEFAULT_WORDS: usize = 6;

/// Generate a Diceware-style passphrase by uniformly sampling `words`
/// entries from the wordlist with the thread CSPRNG. Words are joined
/// by single ASCII spaces.
pub fn generate(words: usize) -> SecretString {
    let list: &[&'static str] = &WORDLIST;
    let chosen: Vec<&str> = (0..words)
        .map(|_| list[rand::random_range(..list.len())])
        .collect();
    SecretString::from(chosen.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn wordlist_has_7776_entries() {
        assert_eq!(WORDLIST.len(), 7776);
    }

    #[test]
    fn wordlist_entries_are_safe_to_display() {
        // EFF canonical list is lowercase ASCII; four entries contain
        // a hyphen (drop-down, felt-tip, t-shirt, yo-yo). Anything
        // beyond [a-z\-] would be a parse bug.
        for word in WORDLIST.iter() {
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "unexpected character in word: {word:?}"
            );
        }
    }

    #[test]
    fn generates_default_six_words() {
        let phrase = generate(DEFAULT_WORDS);
        let parts: Vec<&str> = phrase.expose_secret().split(' ').collect();
        assert_eq!(parts.len(), DEFAULT_WORDS);
    }

    #[test]
    fn every_word_is_from_wordlist() {
        let phrase = generate(DEFAULT_WORDS);
        for word in phrase.expose_secret().split(' ') {
            assert!(
                WORDLIST.contains(&word),
                "generated word {word:?} not in wordlist"
            );
        }
    }

    #[test]
    fn distinct_invocations_differ() {
        // Collision probability: 1 / 7776^6 ≈ 4e-24. If this ever
        // fails legitimately, buy a lottery ticket.
        let a = generate(DEFAULT_WORDS);
        let b = generate(DEFAULT_WORDS);
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn supports_other_word_counts() {
        for n in [4, 5, 7, 8, 10] {
            let phrase = generate(n);
            assert_eq!(phrase.expose_secret().split(' ').count(), n);
        }
    }
}
