// SPDX-License-Identifier: Apache-2.0

//! R5 decision bench: zstd vs deflate for at-rest body compression.
//!
//! Background: memory nodes are markdown bodies (frontmatter + prose). If we
//! ever compress them at rest (SQLite `body`/`body_encrypted` columns or the
//! on-disk `.md` files), we want to know the ratio/speed trade BEFORE paying
//! the dependency cost. This bench runs both codecs over a realistic corpus
//! and asserts the ordering we expect; the printed numbers drive the decision.
//!
//! Run with: cargo test -p origin-memory --test compression_bench -- --nocapture

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;
use std::time::Instant;

fn corpus() -> Vec<String> {
    // Realistic mix: short titles in frontmatter, prose bodies of varying
    // length, some repeated structure (frontmatter keys, wikilinks), some
    // unique prose. 200 nodes ≈ a year of daily-ish note-taking.
    let mut out = Vec::new();
    for i in 0..200 {
        let day = 1 + (i % 28);
        let month = 1 + ((i / 28) % 12);
        let body = format!(
            "---\ntitle: Observation {i}\ntime: 2004-{month:02}-{day:02}\ntopic: [field-notes, series-{ser}]\nevidence: documented\n---\nField note {i}: the signal held through the transition window. Cross-reference [[obs-{prev}]] and [[obs-{next}]]. Noise floor stable at {n} dB; see the calibration run for context. Follow-up scheduled once the upstream feed stabilises.\n",
            i = i,
            month = month,
            day = day,
            ser = i % 7,
            prev = (i + 199) % 200,
            next = (i + 1) % 200,
            n = 34 + (i % 11),
        );
        out.push(body);
    }
    out
}

#[test]
fn zstd_vs_deflate_on_markdown_corpus() {
    let docs = corpus();
    let total: usize = docs.iter().map(|d| d.len()).sum();

    // --- deflate (zlib, level 6 = default) ---
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    let t0 = Instant::now();
    for d in &docs {
        enc.write_all(d.as_bytes()).unwrap();
    }
    let deflate_bytes = enc.finish().unwrap();
    let deflate_time = t0.elapsed();

    // --- zstd (level 3 = default) ---
    let mut blob = Vec::new();
    let t0 = Instant::now();
    {
        let mut zw = zstd::Encoder::new(&mut blob, 3).unwrap();
        for d in &docs {
            zw.write_all(d.as_bytes()).unwrap();
        }
        zw.finish().unwrap();
    }
    let zstd_time = t0.elapsed();

    let deflate_ratio = deflate_bytes.len() as f64 / total as f64;
    let zstd_ratio = blob.len() as f64 / total as f64;

    println!("corpus: {} nodes, {} bytes", docs.len(), total);
    println!(
        "deflate: {} bytes (ratio {:.3}), {:?}",
        deflate_bytes.len(),
        deflate_ratio,
        deflate_time
    );
    println!(
        "zstd:    {} bytes (ratio {:.3}), {:?}",
        blob.len(),
        zstd_ratio,
        zstd_time
    );

    // zstd should never be meaningfully worse on this corpus; if it is, the
    // dependency isn't worth it and deflate (already in the tree) wins.
    assert!(
        blob.len() <= deflate_bytes.len() + 64,
        "zstd regressed vs deflate: {} vs {}",
        blob.len(),
        deflate_bytes.len()
    );

    // Round-trip sanity: both must decompress to the exact corpus.
    let mut concat: Vec<u8> = Vec::new();
    for d in &docs {
        concat.extend_from_slice(d.as_bytes());
    }
    let zstd_back = zstd::decode_all(&blob[..]).unwrap();
    assert_eq!(zstd_back, concat, "zstd round-trip");

    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut deflate_back = Vec::new();
    ZlibDecoder::new(&deflate_bytes[..])
        .read_to_end(&mut deflate_back)
        .unwrap();
    assert_eq!(deflate_back, concat, "deflate round-trip");
}
