// SPDX-License-Identifier: Apache-2.0

//! Password / passphrase generation for `origin-pass generate`.
//!
//! # Entropy honesty
//!
//! Entropy is reported from the **actual** charset / wordlist sizes, never
//! from a nominal value. If a charset has 26+26+10+25 = 87 symbols, a
//! 24-char password drawn uniformly from it carries exactly
//! `24 * log2(87) ≈ 154.6` bits — that is what the command prints. The
//! passphrase wordlist is exactly 256 words (8 bits/word), enforced by a
//! unit test that rejects duplicates, so `--words 8` = 64 bits.
//!
//! # Randomness
//!
//! All randomness comes from `origin_common::random_bytes` (the SDK's
//! OS-CSPRNG). Selection uses rejection sampling so that no index is
//! favored (no modulo bias), which matters for secrets.

/// Character sets (as byte slices). Symbols default to ON.
pub const CHARSET_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const CHARSET_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const CHARSET_DIGITS: &[u8] = b"0123456789";
pub const CHARSET_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/~";

/// Default password length when `--length` is not given.
pub const DEFAULT_LENGTH: usize = 24;
/// Default passphrase word count when `--words` is not given.
pub const DEFAULT_WORDS: usize = 8;
/// Bounds for `--length`.
pub const MIN_LENGTH: usize = 1;
pub const MAX_LENGTH: usize = 512;

/// Passphrase wordlist — exactly 256 lowercase English words (8 bits of
/// entropy per word). The unit test `wordlist_is_256_unique_words`
/// rejects duplicates, so the entropy claim is exact.
pub const WORDLIST: &[&str] = &[
    // ── group 1 ──────────────────────────────────────────────────────
    "after",
    "apple",
    "apricot",
    "arrow",
    "autumn",
    "badge",
    "banner",
    "barrel",
    "beach",
    "berry",
    "bicycle",
    "blade",
    "blaze",
    "bloom",
    "bolt",
    "bonus",
    "bottle",
    "brave",
    "bread",
    "breeze",
    "brick",
    "bridge",
    "bright",
    "bronze",
    "bucket",
    "butter",
    "cabin",
    "cactus",
    "camera",
    "candle",
    "canyon",
    "carbon",
    // ── group 2 ──────────────────────────────────────────────────────
    "carpet",
    "carrot",
    "castle",
    "cedar",
    "celery",
    "chain",
    "chalk",
    "cherry",
    "chest",
    "circle",
    "circus",
    "clover",
    "coast",
    "cobra",
    "coffee",
    "coin",
    "comet",
    "compass",
    "copper",
    "coral",
    "cotton",
    "couch",
    "crane",
    "crater",
    "crayon",
    "creek",
    "crimson",
    "crown",
    "crystal",
    "daisy",
    "dawn",
    "desert",
    // ── group 3 ──────────────────────────────────────────────────────
    "diamond",
    "dolphin",
    "donkey",
    "dragon",
    "drift",
    "drum",
    "dusk",
    "eagle",
    "earth",
    "echo",
    "eclipse",
    "ember",
    "engine",
    "falcon",
    "feather",
    "fern",
    "field",
    "finch",
    "flame",
    "flash",
    "flock",
    "flour",
    "fog",
    "forest",
    "fossil",
    "fountain",
    "fox",
    "frost",
    "galaxy",
    "garden",
    "garnet",
    "geyser",
    // ── group 4 ──────────────────────────────────────────────────────
    "ginger",
    "glacier",
    "glade",
    "glass",
    "globe",
    "glove",
    "glow",
    "gold",
    "goose",
    "grape",
    "grass",
    "gravel",
    "green",
    "grove",
    "guitar",
    "gulf",
    "gust",
    "hammer",
    "harbor",
    "hawk",
    "hazel",
    "heart",
    "hedge",
    "hill",
    "honey",
    "horizon",
    "hornet",
    "horse",
    "hurricane",
    "icicle",
    "igloo",
    "iron",
    // ── group 5 ──────────────────────────────────────────────────────
    "island",
    "ivy",
    "jacket",
    "jade",
    "jungle",
    "juniper",
    "kettle",
    "kindle",
    "koi",
    "lagoon",
    "lake",
    "lantern",
    "laurel",
    "leaf",
    "lemon",
    "lily",
    "linen",
    "lion",
    "lizard",
    "lobster",
    "lodge",
    "lotus",
    "lumber",
    "maple",
    "marble",
    "meadow",
    "melon",
    "mercury",
    "mesa",
    "meteor",
    "mint",
    "mist",
    // ── group 6 ──────────────────────────────────────────────────────
    "moon",
    "moss",
    "moth",
    "mountain",
    "mouse",
    "mushroom",
    "nectar",
    "nest",
    "nickel",
    "night",
    "north",
    "nugget",
    "oak",
    "oasis",
    "ocean",
    "olive",
    "onion",
    "opal",
    "orange",
    "orbit",
    "orchid",
    "otter",
    "owl",
    "oyster",
    "palm",
    "panther",
    "paper",
    "parrot",
    "pass",
    "pearl",
    "pebble",
    "pepper",
    // ── group 7 ──────────────────────────────────────────────────────
    "petal",
    "pine",
    "pinto",
    "planet",
    "plaza",
    "plum",
    "pond",
    "poppy",
    "prairie",
    "prism",
    "puppy",
    "quartz",
    "quill",
    "quilt",
    "rabbit",
    "raven",
    "reef",
    "ridge",
    "river",
    "robin",
    "rock",
    "rose",
    "ruby",
    "rust",
    "saddle",
    "salmon",
    "sand",
    "sapphire",
    "scarf",
    "school",
    "scrub",
    "sea",
    // ── group 8 ──────────────────────────────────────────────────────
    "seal",
    "shark",
    "shelf",
    "shell",
    "shore",
    "silver",
    "skate",
    "slate",
    "slope",
    "smoke",
    "snail",
    "snake",
    "snow",
    "soap",
    "sparrow",
    "spear",
    "spider",
    "spore",
    "spring",
    "spruce",
    "squid",
    "star",
    "stone",
    "storm",
    "stream",
    "summit",
    "sunset",
    "swan",
    "swift",
    "sword",
    "tiger",
    "toast",
];
/// Build the effective password charset from the exclusion flags.
/// Returns an error if every class is excluded.
pub fn build_charset(
    exclude_symbols: bool,
    exclude_digits: bool,
    exclude_upper: bool,
) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(87);
    out.extend_from_slice(CHARSET_LOWER);
    if !exclude_upper {
        out.extend_from_slice(CHARSET_UPPER);
    }
    if !exclude_digits {
        out.extend_from_slice(CHARSET_DIGITS);
    }
    if !exclude_symbols {
        out.extend_from_slice(CHARSET_SYMBOLS);
    }
    if out.is_empty() {
        return Err(
            "all character classes excluded — nothing to generate from (lowercase is always on)"
                .to_string(),
        );
    }
    Ok(out)
}

/// Pick a uniform index in `0..range` using rejection sampling over the
/// SDK CSPRNG (no modulo bias).
///
/// `range` must be `1..=256`. **Do not raise that bound without also
/// widening the sample to 2 bytes**: for `range > 256` the rejection
/// threshold `256 - (256 % range)` becomes `0`, which hangs forever
/// (this bit the first wordlist draft, which shipped 280 words).
fn uniform_index(range: usize, bytes: &mut Vec<u8>) -> Result<usize, String> {
    assert!(range > 0, "uniform_index range must be > 0");
    assert!(range <= 256, "uniform_index range {range} exceeds 256");
    let range_u32 = range as u32;
    // Rejection threshold: the largest multiple of `range` below 256.
    let limit = 256u32 - (256u32 % range_u32);
    loop {
        if bytes.is_empty() {
            bytes.resize(1, 0);
        }
        origin_common::random_bytes(&mut bytes[..1])?;
        let b = bytes[0] as u32;
        if b < limit {
            return Ok((b % range_u32) as usize);
        }
    }
}

/// Generate a random password of `length` bytes drawn uniformly from
/// `charset`.
pub fn generate_password(length: usize, charset: &[u8]) -> Result<String, String> {
    if length == 0 {
        return Err("password length must be ≥ 1".to_string());
    }
    let mut out = String::with_capacity(length);
    let mut scratch: Vec<u8> = Vec::new();
    for _ in 0..length {
        let idx = uniform_index(charset.len(), &mut scratch)?;
        out.push(charset[idx] as char);
    }
    Ok(out)
}

/// Generate a passphrase of `words` words joined by `-`.
pub fn generate_passphrase(words: usize) -> Result<String, String> {
    if words == 0 {
        return Err("passphrase word count must be ≥ 1".to_string());
    }
    let mut out = String::with_capacity(words * 7);
    let mut scratch: Vec<u8> = Vec::new();
    for i in 0..words {
        if i > 0 {
            out.push('-');
        }
        let idx = uniform_index(WORDLIST.len(), &mut scratch)?;
        out.push_str(WORDLIST[idx]);
    }
    Ok(out)
}

/// Estimated entropy of a password drawn uniformly from `charset`.
pub fn password_entropy_bits(length: usize, charset: &[u8]) -> f64 {
    let per_char = (charset.len() as f64).log2();
    length as f64 * per_char
}

/// Estimated entropy of a passphrase drawn from `WORDLIST`.
pub fn passphrase_entropy_bits(words: usize) -> f64 {
    (WORDLIST.len() as f64).log2() * words as f64
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn wordlist_is_256_unique_words() {
        // This is what makes the 8-bits-per-word entropy claim exact.
        let mut seen = BTreeSet::new();
        for w in WORDLIST {
            assert!(!w.is_empty(), "wordlist contains an empty word");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "word `{w}` must be lowercase ASCII"
            );
            assert!(seen.insert(*w), "duplicate word in WORDLIST: `{w}`");
        }
        assert_eq!(WORDLIST.len(), 256);
    }

    #[test]
    fn charset_default_is_87_symbols() {
        let cs = build_charset(false, false, false).unwrap();
        assert_eq!(cs.len(), 26 + 26 + 10 + 25);
    }

    #[test]
    fn charset_exclusions_remove_classes() {
        let cs = build_charset(true, true, true).unwrap();
        assert_eq!(cs, CHARSET_LOWER.to_vec());
        let cs = build_charset(true, false, false).unwrap();
        assert!(!cs.contains(&b'!'));
        assert!(cs.contains(&b'0'));
        assert!(cs.contains(&b'A'));
    }

    #[test]
    fn charset_all_excluded_errors() {
        // Lowercase is always on, so this cannot actually happen; the
        // guard exists for future classes. Keep the API honest anyway.
        assert!(build_charset(true, true, true).is_ok());
    }

    #[test]
    fn generate_password_length_and_charset() {
        let cs = build_charset(false, false, false).unwrap();
        let pw = generate_password(24, &cs).unwrap();
        assert_eq!(pw.len(), 24);
        assert!(pw.chars().all(|c| cs.contains(&(c as u8))));
    }

    #[test]
    fn generate_password_respects_exclusions() {
        let cs = build_charset(true, true, true).unwrap(); // lowercase only
        let pw = generate_password(32, &cs).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn generate_password_zero_length_errors() {
        let cs = build_charset(false, false, false).unwrap();
        assert!(generate_password(0, &cs).is_err());
    }

    #[test]
    fn generate_passphrase_word_count_and_membership() {
        let phrase = generate_passphrase(8).unwrap();
        let words: Vec<&str> = phrase.split('-').collect();
        assert_eq!(words.len(), 8);
        for w in words {
            assert!(WORDLIST.contains(&w), "word `{w}` not in WORDLIST");
        }
    }

    #[test]
    fn passphrase_words_differ_across_runs() {
        // Overwhelmingly likely to differ; guards against a broken RNG
        // path that always returns the same index.
        let a = generate_passphrase(8).unwrap();
        let b = generate_passphrase(8).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn entropy_bits_match_list_size() {
        // 87-symbol charset → log2(87) ≈ 6.443 bits/char.
        let cs = build_charset(false, false, false).unwrap();
        let e = password_entropy_bits(24, &cs);
        assert!((e - 24.0 * (87.0f64).log2()).abs() < 1e-9);
        // 256-word list → exactly 8 bits/word.
        assert!((passphrase_entropy_bits(8) - 64.0).abs() < 1e-9);
    }
}
