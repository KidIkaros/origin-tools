//! Symbol packs: the alphabet a Recovery Phrase is written under.
//!
//! A pack is a blob of symbols — an emoji set, a script's block, a rune row —
//! separated by whitespace, newlines, or commas. The SDK owns the recovery
//! format; this module is the suite adapter that turns a downloaded pack into
//! the format a tool encodes and decodes with, so every Origin tool reads a
//! pack the same way.
//!
//! Without a pack a phrase uses the built-in symbol set (format v1). With one
//! it uses the pack (format v2), and the pack file becomes part of the backup:
//! the phrase cannot decode without it.

use origin_crypto_sdk::recovery::{RecoveryAlphabet, RecoveryFormat};

use crate::io::read_input;

/// A pack loaded into the format a phrase is written under.
#[derive(Debug)]
pub struct PhrasePack {
    /// The format to encode and decode with.
    pub format: RecoveryFormat,
    /// Symbols the SDK's policy rejected, or that repeated an earlier symbol.
    ///
    /// A downloaded pack can legitimately contain these — a Unicode block has
    /// gaps — so they are reported rather than treated as an error.
    pub skipped: Vec<char>,
}

/// Build the phrase format from pack text.
///
/// `seed_bytes` is the entropy width the tool's seed uses (32 for every Origin
/// tool today), which is what fixes the phrase length. A pack too small to
/// encode that width within the SDK's phrase limit is refused here, naming the
/// smallest usable alphabet.
pub fn phrase_pack_from_text(text: &str, seed_bytes: usize) -> Result<PhrasePack, String> {
    let (alphabet, skipped) =
        RecoveryAlphabet::from_pack(text).map_err(|e| format!("not a usable symbol pack: {e}"))?;
    let format = RecoveryFormat::new(alphabet, seed_bytes)
        .map_err(|e| format!("cannot encode a Recovery Phrase: {e}"))?;
    Ok(PhrasePack { format, skipped })
}

/// Load a pack file into the phrase format.
pub fn phrase_pack_from_file(path: &str, seed_bytes: usize) -> Result<PhrasePack, String> {
    let bytes = read_input(Some(path))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{path} is not valid UTF-8"))?;
    phrase_pack_from_text(&text, seed_bytes).map_err(|e| format!("alphabet pack {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Twenty-four runes — the smallest pack that comfortably fits 256 bits.
    fn rune_pack() -> String {
        (0x16A0u32..0x16B8).filter_map(char::from_u32).collect()
    }

    #[test]
    fn a_rune_pack_builds_a_format_with_no_skips() {
        let pack = phrase_pack_from_text(&rune_pack(), 32).unwrap();
        assert!(pack.skipped.is_empty());
        assert_eq!(pack.format.alphabet().len(), 24);
        assert_eq!(pack.format.symbol_count(), 63);
    }

    #[test]
    fn unusable_symbols_are_reported_not_fatal() {
        // U+0300 is a combining mark; the second rune repeats.
        let pack = phrase_pack_from_text(&format!("{}\u{0300}\u{16A0}", rune_pack()), 32).unwrap();
        assert_eq!(pack.skipped.len(), 2);
        assert_eq!(pack.format.alphabet().len(), 24);
    }

    #[test]
    fn a_pack_too_small_for_the_seed_is_refused_with_the_minimum() {
        let err = phrase_pack_from_text("\u{2660}\u{2665}\u{2666}\u{2663}", 32).unwrap_err();
        assert!(err.contains("at least 23 symbols"), "got: {err}");
    }

    #[test]
    fn a_pack_file_loads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pack.txt");
        std::fs::write(&path, rune_pack()).unwrap();

        let pack = phrase_pack_from_file(path.to_str().unwrap(), 32).unwrap();
        assert_eq!(pack.format.symbol_count(), 63);

        let missing = phrase_pack_from_file(dir.path().join("absent.txt").to_str().unwrap(), 32);
        assert!(missing.is_err());
    }
}
