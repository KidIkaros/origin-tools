// SPDX-License-Identifier: Apache-2.0

//! Streaming blob encryption (Phase 12).
//!
//! Large blobs are written/read in bounded-memory chunks instead of being
//! buffered whole. The wire format mirrors origin-seal's streamed envelope:
//!
//! ```text
//! magic "OVCS" (4) ‖ version (1) ‖ tier (1) ‖ reserved (1)
//!   ‖ base_nonce (24) ‖ [4-byte BE chunk_len ‖ ct+tag]*
//!   ‖ 4-byte 0 sentinel
//! ```
//!
//! Each chunk is XChaCha20-Poly1305 under `nonce = base_nonce XOR counter`
//! (big-endian counter XORed into the low 8 bytes), so every chunk has a unique
//! nonce — avoiding the SDK's `aead::streaming` nonce-reuse weakness. The
//! zero-length sentinel distinguishes a clean end-of-stream from truncation.
//!
//! The blob **address** is still the plaintext content hash (`blob:<len>\n`
//! header + bytes), computed by streaming the file through SHA3-256 in one
//! bounded pass, so streamed blobs dedupe and verify exactly like buffered
//! ones. Reads auto-detect the `OVCS` magic and decode chunk-by-chunk.

use std::io::{Read, Write};
use std::path::Path;

use origin_crypto_sdk::aead::XChaCha20Poly1305;

use crate::object::{blob_address, Blob};

/// Streamed-envelope magic (distinct from ORGN so the store never mistakes a
/// streamed blob for a regular envelope).
pub const STREAM_MAGIC: &[u8; 4] = b"OVCS";
pub const STREAM_VERSION: u8 = 1;
/// Header: magic(4) + version(1) + tier(1) + reserved(1) + base_nonce(24).
pub const STREAM_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 24;

/// Default chunk size for `--stream` (64 KiB — matches origin-seal).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Derive a unique per-chunk nonce from a random base and a counter
/// (XOR the BE counter into the low 8 bytes of the 24-byte nonce).
fn chunk_nonce(base: &[u8; 24], counter: u64) -> [u8; 24] {
    let mut n = *base;
    let cb = counter.to_be_bytes();
    for i in 0..8 {
        n[16 + i] ^= cb[i];
    }
    n
}

/// Read up to `buf.len()` bytes, retrying on partial reads.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(filled)
}

/// Compute the blob content address by streaming the file (constant memory).
///
/// The address is `SHA3_256("blob:<len>\n" ‖ file_bytes)` — the exact same
/// bytes the buffered path hashes — so streamed blobs dedupe and verify
/// identically to buffered ones. Uses the SDK's incremental `Sha3_256` to
/// avoid buffering the file.
pub fn stream_blob_id(path: &Path) -> Result<[u8; 32], String> {
    // Pass 1: compute the byte length (needed for the `blob:<len>\n` header).
    let len = {
        let file =
            std::fs::File::open(path).map_err(|e| format!("open {:?}: {e}", path.display()))?;
        let mut reader = std::io::BufReader::new(file);
        let mut buf = vec![0u8; 64 * 1024];
        let mut n: u64 = 0;
        loop {
            let got = read_full(&mut reader, &mut buf)?;
            if got == 0 {
                break;
            }
            n += got as u64;
        }
        n
    };

    // Pass 2: hash `blob:<len>\n` then the file bytes (same bytes as the
    // buffered `address_of("blob:<len>", data)` path), streaming. We use the
    // external `sha3` crate's incremental hasher here rather than the SDK's
    // `internal::sha3` one, which is byte-order correct but its incremental
    // `update` does not reproduce one-shot digests; `sha3` is already a
    // transitive dependency of the SDK.
    use sha3::{Digest, Sha3_256};
    let file = std::fs::File::open(path).map_err(|e| format!("open {:?}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha3_256::new();
    hasher.update(format!("blob:{len}\n").as_bytes());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let out: [u8; 32] = hasher.finalize().into();
    Ok(out)
}

/// Stream-encrypt `path` (raw file bytes) into a chunked envelope written to
/// `dest`. Returns the blob content address. Bounded memory: one chunk buffer.
pub fn stream_encrypt_file(
    key: &[u8; 32],
    path: &Path,
    dest: &Path,
    chunk_size: usize,
) -> Result<[u8; 32], String> {
    if !(1024..=(1 << 30)).contains(&chunk_size) {
        return Err(format!(
            "chunk size {chunk_size} out of range (1024..={})",
            1 << 30
        ));
    }

    let id = stream_blob_id(path)?;

    let mut base_nonce = [0u8; 24];
    origin_crypto_sdk::fill_random(&mut base_nonce)
        .map_err(|e| format!("nonce generation failed: {e}"))?;

    let tmp = dest.with_extension("tmp");
    let mut writer = std::io::BufWriter::new(
        std::fs::File::create(&tmp).map_err(|e| format!("create {:?}: {e}", tmp.display()))?,
    );

    let mut header = Vec::with_capacity(STREAM_HEADER_LEN);
    header.extend_from_slice(STREAM_MAGIC);
    header.push(STREAM_VERSION);
    header.push(0); // tier byte (unused in vcs stream format)
    header.push(0); // reserved
    header.extend_from_slice(&base_nonce);
    writer
        .write_all(&header)
        .map_err(|e| format!("write header: {e}"))?;

    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("open {:?}: {e}", path.display()))?,
    );
    let mut buf = vec![0u8; chunk_size];
    let mut counter: u64 = 0;
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        let nonce = chunk_nonce(&base_nonce, counter);
        let ct = XChaCha20Poly1305::encrypt(key, &nonce, &buf[..n])
            .map_err(|e| format!("chunk {counter} encrypt: {e:?}"))?;
        writer
            .write_all(&(ct.len() as u32).to_be_bytes())
            .map_err(|e| format!("write chunk len: {e}"))?;
        writer
            .write_all(&ct)
            .map_err(|e| format!("write chunk data: {e}"))?;
        counter += 1;
    }
    // Sentinel: zero-length chunk = clean end-of-stream.
    writer
        .write_all(&0u32.to_be_bytes())
        .map_err(|e| format!("write sentinel: {e}"))?;
    writer.flush().map_err(|e| format!("flush: {e}"))?;
    drop(writer);

    std::fs::rename(&tmp, dest).map_err(|e| format!("finalize {:?}: {e}", dest.display()))?;
    Ok(id)
}

/// Stream-decrypt a chunked envelope at `src` (magic `OVCS`) into `dest`.
/// Bounded memory: one chunk buffer. Returns the plaintext length.
pub fn stream_decrypt_to_file(key: &[u8; 32], src: &Path, dest: &Path) -> Result<u64, String> {
    let bytes = std::fs::read(src).map_err(|e| format!("read {:?}: {e}", src.display()))?;
    if bytes.len() < STREAM_HEADER_LEN + 4 {
        return Err("streamed blob too short".to_string());
    }
    if &bytes[..4] != STREAM_MAGIC {
        return Err("not a streamed (OVCS) blob".to_string());
    }
    if bytes[4] != STREAM_VERSION {
        return Err(format!("unsupported streamed blob version {}", bytes[4]));
    }
    let mut base_nonce = [0u8; 24];
    base_nonce.copy_from_slice(&bytes[7..31]);

    let tmp = dest.with_extension("tmp");
    let mut writer = std::io::BufWriter::new(
        std::fs::File::create(&tmp).map_err(|e| format!("create {:?}: {e}", tmp.display()))?,
    );

    let mut cursor = &bytes[STREAM_HEADER_LEN..];
    let mut counter: u64 = 0;
    let mut total: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        let n = read_full(&mut cursor, &mut len_buf)?;
        if n < 4 {
            return Err(format!(
                "truncated stream: expected 4-byte chunk length, got {n} bytes (no sentinel)"
            ));
        }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            break; // sentinel
        }
        if cursor.len() < chunk_len {
            return Err(format!(
                "truncated stream: chunk {counter} expected {chunk_len} bytes, got {}",
                cursor.len()
            ));
        }
        let nonce = chunk_nonce(&base_nonce, counter);
        let pt = XChaCha20Poly1305::decrypt(key, &nonce, &cursor[..chunk_len])
            .map_err(|_| format!("chunk {counter} decryption failed (corrupt or wrong key)"))?;
        writer
            .write_all(&pt)
            .map_err(|e| format!("write chunk {counter}: {e}"))?;
        total += pt.len() as u64;
        cursor = &cursor[chunk_len..];
        counter += 1;
    }
    writer.flush().map_err(|e| format!("flush: {e}"))?;
    drop(writer);
    std::fs::rename(&tmp, dest).map_err(|e| format!("finalize {:?}: {e}", dest.display()))?;
    Ok(total)
}

/// Decode a streamed blob fully into memory (used when a command needs the
/// bytes, e.g. verify/status on a streamed object). Returns the plaintext.
pub fn stream_decrypt_to_vec(key: &[u8; 32], src: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(src).map_err(|e| format!("read {:?}: {e}", src.display()))?;
    if bytes.len() < STREAM_HEADER_LEN + 4 || &bytes[..4] != STREAM_MAGIC {
        return Err("not a streamed (OVCS) blob".to_string());
    }
    let mut base_nonce = [0u8; 24];
    base_nonce.copy_from_slice(&bytes[7..31]);
    let mut out = Vec::new();
    let mut cursor = &bytes[STREAM_HEADER_LEN..];
    let mut counter: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        if read_full(&mut cursor, &mut len_buf)? < 4 {
            return Err("truncated stream (no sentinel)".to_string());
        }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            break;
        }
        if cursor.len() < chunk_len {
            return Err("truncated stream (short chunk)".to_string());
        }
        let nonce = chunk_nonce(&base_nonce, counter);
        let pt = XChaCha20Poly1305::decrypt(key, &nonce, &cursor[..chunk_len])
            .map_err(|_| format!("chunk {counter} decryption failed"))?;
        out.extend_from_slice(&pt);
        cursor = &cursor[chunk_len..];
        counter += 1;
    }
    Ok(out)
}

/// Whether a blob envelope on disk is a streamed (OVCS) blob.
pub fn is_streamed(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == STREAM_MAGIC
}

/// Blob address for raw bytes (used by callers that already hold data).
pub fn blob_id_of(data: &[u8]) -> [u8; 32] {
    blob_address(&Blob::new(data.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_nonce_unique_per_counter() {
        let base = [7u8; 24];
        let a = chunk_nonce(&base, 0);
        let b = chunk_nonce(&base, 1);
        assert_ne!(a, b);
        // Deterministic.
        assert_eq!(chunk_nonce(&base, 5), chunk_nonce(&base, 5));
    }

    #[test]
    fn stream_roundtrip_matches_address() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("big.bin");
        let enc = dir.path().join("big.ovcs");
        let dec = dir.path().join("big.out");

        // 300 KB (5 chunks at 64 KiB) of patterned data.
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let key = [42u8; 32];
        let id = stream_encrypt_file(&key, &src, &enc, DEFAULT_CHUNK_SIZE).unwrap();
        let expect = blob_address(&Blob::new(data.clone()));
        assert_eq!(id, expect, "streamed address must equal buffered address");

        let bytes = std::fs::read(&enc).unwrap();
        assert!(is_streamed(&bytes));

        let n = stream_decrypt_to_file(&key, &enc, &dec).unwrap();
        assert_eq!(n as usize, data.len());
        let recovered = std::fs::read(&dec).unwrap();
        assert_eq!(recovered, data);

        // Wrong key fails.
        let bad = [1u8; 32];
        assert!(stream_decrypt_to_file(&bad, &enc, &dir.path().join("bad.out")).is_err());
    }

    #[test]
    fn truncation_detected() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("t.bin");
        let enc = dir.path().join("t.ovcs");
        std::fs::write(&src, vec![9u8; 100_000]).unwrap();
        let key = [3u8; 32];
        stream_encrypt_file(&key, &src, &enc, 4096).unwrap();

        let bytes = std::fs::read(&enc).unwrap();
        // Chop off the sentinel + part of a chunk.
        let truncated = &bytes[..bytes.len() - 8];
        let tpath = dir.path().join("t.trunc");
        std::fs::write(&tpath, truncated).unwrap();
        assert!(stream_decrypt_to_file(&key, &tpath, &dir.path().join("o")).is_err());
    }
}
