// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-provenance` as a foundational dependency.
//!
//! File integrity provenance through the typed library API: single-file
//! `Stamp`s (SHA3-256 + timestamp + optional signature), recursive
//! directory `Manifest`s with tamper detection, and invisible
//! `Watermark` markers for content identity.
//!
//! Run with: `cargo run -p origin-provenance --example dogfood`

use origin_provenance::manifest::{FileStatus, Manifest};
use origin_provenance::stamp::Stamp;
use origin_provenance::watermark::Watermark;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "origin-dogfood-provenance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(dir.join("tree/src"))?;

    // ── Stamp: content hash + timestamp, JSON round-trip ─────────────
    let content = b"release artifact v1.2.3";
    let stamp = Stamp::new(content, 1_700_000_000);
    assert!(stamp.verify_content(content), "stamp must match content");
    assert!(
        !stamp.verify_content(b"tampered"),
        "stamp must reject changed content"
    );

    let json = stamp.to_json()?;
    let parsed = Stamp::from_json(&json)?;
    assert_eq!(parsed.content_hash, stamp.content_hash);
    assert_eq!(parsed.size, stamp.size);
    println!("✓ Stamp (SHA3-256 + size + timestamp) JSON round-trip");

    // ── Manifest: scan a tree, tamper, re-verify ─────────────────────
    std::fs::write(dir.join("tree/src/main.rs"), b"fn main() {}\n")?;
    std::fs::write(dir.join("tree/src/lib.rs"), b"pub fn lib() {}\n")?;
    std::fs::write(dir.join("tree/Cargo.toml"), b"[package]\nname = \"demo\"\n")?;

    let manifest = Manifest::scan(&dir.join("tree"))?;
    assert_eq!(manifest.entries.len(), 3, "manifest covers all 3 files");
    let mjson = manifest.to_json()?;
    let restored = Manifest::from_json(&mjson)?;
    assert_eq!(restored.entries.len(), 3);

    // Verify pristine tree: everything OK.
    let results = manifest.verify(&dir.join("tree"))?;
    assert!(
        results.values().all(|s| *s == FileStatus::Ok),
        "pristine tree must verify clean"
    );

    // Tamper with one file + add one: Modified + Added.
    std::fs::write(
        dir.join("tree/src/main.rs"),
        b"fn main() { println!(\"x\"); }\n",
    )?;
    std::fs::write(dir.join("tree/NOTES.md"), b"untracked note\n")?;
    let results = manifest.verify(&dir.join("tree"))?;
    assert_eq!(results["src/main.rs"], FileStatus::Modified);
    assert_eq!(results["NOTES.md"], FileStatus::Added);
    assert_eq!(results["src/lib.rs"], FileStatus::Ok);
    println!("✓ Manifest scan → verify (clean, then Modified + Added detected)");

    // Deletion detection.
    std::fs::remove_file(dir.join("tree/Cargo.toml"))?;
    let results = manifest.verify(&dir.join("tree"))?;
    assert_eq!(results["Cargo.toml"], FileStatus::Missing);
    println!("✓ Missing-file detection");

    // ── Watermark: invisible marker embedded in content ──────────────
    let wm = Watermark::new(b"Acme Corp", Some("internal".to_string()));
    let original = b"plaintext document body".repeat(8);
    let watermarked = wm.embed(&original)?;
    assert!(Watermark::has_watermark(&watermarked), "marker present");
    let (extracted, restored_content) = Watermark::extract(&watermarked)?;
    assert_eq!(extracted.label.as_deref(), Some("internal"));
    assert_eq!(&restored_content, &original, "content restored byte-exact");
    println!("✓ Watermark embed → extract (label + byte-exact restore)");

    println!("\norigin-provenance dogfood OK — usable as a foundational dependency");
    Ok(())
}
