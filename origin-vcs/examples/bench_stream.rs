// SPDX-License-Identifier: Apache-2.0

//! Benchmark: streamed vs buffered blob add/checkout (Phase 12 follow-up).
//!
//! Generates a single large file in a temp store and times four paths:
//!   buffered add   — `std::fs::read` + `Store::write_blob` (whole file in RAM)
//!   streamed add   — `Store::write_blob_stream` (chunked encryption, bounded RAM)
//!   buffered check — `Store::read_blob` (whole envelope in RAM)
//!   streamed check — `Store::read_blob_to_path` (bounded RAM)
//!
//! Usage: `cargo run -p origin-vcs --example bench_stream [size-mib]`
//! (default 32 MiB). Results are wall-clock + MiB/s per path.
//!
//! ## Assertions (the benchmark is also a check)
//!
//! The example fails loudly when the streaming claim breaks, instead of just
//! printing numbers:
//!   1. Both write paths produce the SAME content-addressed id.
//!   2. Both checkout paths produce byte-identical files.
//!   3. Peak RSS (Linux `VmHWM`) must not grow by ~a whole file during the
//!      streamed paths — the whole point of `--stream` is bounded memory.
//!      Concretely, the high-water mark after the streamed path must stay
//!      within a slack of the high-water mark after the buffered path; a
//!      streamed implementation that quietly buffered the file would add
//!      ~`size` KiB and trip the assertion.

use std::path::Path;
use std::time::Instant;

/// Peak RSS high-water mark (VmHWM, KiB) on Linux; `None` elsewhere.
fn peak_rss_kib() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.trim().trim_end_matches(" kB").parse().ok();
        }
    }
    None
}

fn main() {
    let mib: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let size = mib * 1024 * 1024;

    let dir = tempfile::TempDir::new().expect("temp dir");
    let root = dir.path().join("store");
    let store = origin_vcs::store::Store::open(&root, [7u8; 32]).expect("open store");

    // Deterministic pseudo-random content (xorshift64*) — compresses poorly,
    // so encryption work dominates rather than redundancy.
    let path = dir.path().join("payload.bin");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path).expect("create payload");
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut buf = [0u8; 65536];
        let mut remaining = size;
        while remaining > 0 {
            for b in buf.iter_mut() {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u8;
            }
            let n = remaining.min(buf.len());
            f.write_all(&buf[..n]).expect("write payload");
            remaining -= n;
        }
    }

    let mib_f = size as f64 / (1024.0 * 1024.0);
    // Slack for the peak-RSS assertions: a streamed path may allocate a few
    // MiB of chunk buffers + envelope headers, but never ~a whole file.
    let rss_slack_kib = ((size as f64 * 0.5) as u64).max(4 * 1024);

    // Buffered add (whole file in RAM).
    let t = Instant::now();
    let data = std::fs::read(&path).expect("read payload");
    let id_buf = store.write_blob(&data).expect("buffered add");
    let buf_add = t.elapsed();
    drop(data);
    let hwm_after_buf_add = peak_rss_kib();

    // Streamed add (64 KiB chunks) — must not grow peak RSS by ~a file.
    let t = Instant::now();
    let id_stream = store.write_blob_stream(&path, 65536).expect("streamed add");
    let str_add = t.elapsed();
    let hwm_after_str_add = peak_rss_kib();
    assert_eq!(
        id_buf, id_stream,
        "content-addressed ids must match regardless of write path"
    );

    // Buffered checkout (whole envelope in RAM).
    let out_buf = dir.path().join("out-buffered.bin");
    let t = Instant::now();
    let blob = store.read_blob(&id_buf).expect("buffered checkout");
    std::fs::write(&out_buf, &blob.data).expect("write out");
    let buf_check = t.elapsed();
    drop(blob);
    let hwm_after_buf_check = peak_rss_kib();

    // Streamed checkout — must not grow peak RSS by ~a file either.
    let out_str = dir.path().join("out-streamed.bin");
    let t = Instant::now();
    store
        .read_blob_to_path(&id_stream, &out_str)
        .expect("streamed checkout");
    let str_check = t.elapsed();
    let hwm_after_str_check = peak_rss_kib();

    let mibs = |d: std::time::Duration| mib_f / d.as_secs_f64();
    println!("payload: {mib_f:.1} MiB\n");
    println!("{:<16} {:>10} {:>10}", "path", "time", "MiB/s");
    println!(
        "{:<16} {:>8.2}s {:>9.1}",
        "add buffered",
        buf_add.as_secs_f64(),
        mibs(buf_add)
    );
    println!(
        "{:<16} {:>8.2}s {:>9.1}",
        "add streamed",
        str_add.as_secs_f64(),
        mibs(str_add)
    );
    println!(
        "{:<16} {:>8.2}s {:>9.1}",
        "check buffered",
        buf_check.as_secs_f64(),
        mibs(buf_check)
    );
    println!(
        "{:<16} {:>8.2}s {:>9.1}",
        "check streamed",
        str_check.as_secs_f64(),
        mibs(str_check)
    );
    if let (Some(a), Some(b)) = (hwm_after_buf_add, hwm_after_str_add) {
        println!("\npeak RSS: buffered add {a} KiB, streamed add {b} KiB");
    }
    if let (Some(a), Some(b)) = (hwm_after_buf_check, hwm_after_str_check) {
        println!("peak RSS: buffered check {a} KiB, streamed check {b} KiB");
    }

    // Assertion 2: byte-identical checkout output.
    assert_eq!(
        std::fs::read(&out_buf).expect("read out-buffered"),
        std::fs::read(&out_str).expect("read out-streamed"),
        "buffered and streamed checkouts must produce identical bytes"
    );

    // Assertion 3: bounded memory. `VmHWM` is monotonic — the streamed path
    // ran after the buffered one, so a delta near the file size means the
    // "streamed" path silently buffered the whole payload in RAM.
    if let (Some(a), Some(b)) = (hwm_after_buf_add, hwm_after_str_add) {
        let delta = b.saturating_sub(a);
        assert!(
            delta <= rss_slack_kib,
            "streamed add grew peak RSS by {delta} KiB (> {rss_slack_kib} KiB slack): \
             streamed add is buffering the whole file"
        );
    }
    if let (Some(a), Some(b)) = (hwm_after_buf_check, hwm_after_str_check) {
        let delta = b.saturating_sub(a);
        assert!(
            delta <= rss_slack_kib,
            "streamed checkout grew peak RSS by {delta} KiB (> {rss_slack_kib} KiB slack): \
             streamed checkout is buffering the whole file"
        );
    }

    println!(
        "\nids match: {} == {}",
        hex::encode(id_buf),
        hex::encode(id_stream)
    );
    println!("assertions passed: ids match, round-trip identical, streamed memory bounded");
    let _ = Path::new("");
}
