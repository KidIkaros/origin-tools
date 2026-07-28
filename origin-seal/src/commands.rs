// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-seal.
//!
//! Every command reads from stdin or a file, writes to stdout or a file,
//! and returns `Result<(), String>`. Errors go to stderr via main().

use std::io::{Read, Write};
use std::path::Path;

use origin_common::{
    read_input, resolve_passphrase, tier_from_byte as tier_from_byte_fn, tier_from_str,
    tier_to_byte, write_output, MemoryTier,
};
use origin_crypto_sdk::{
    aead::XChaCha20Poly1305,
    blake3,
    blob::{create_blob, recover_seed},
    compression, hmac_sha3_256,
    kdf::Argon2idBuilder,
    pqc::falcon1024,
    sha3_256, sha3_512,
    signing::{classical::Ed25519Signer, hybrid::HybridSigningKeyBundle},
};

use crate::cli::{
    DecryptArgs, EncryptArgs, HashAlgo, HashArgs, KdfArgs, MacArgs, OutputFormat, SignArgs,
    VerifyArgs,
};

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Parse a memory tier string.
fn parse_tier(s: &str) -> Result<MemoryTier, String> {
    tier_from_str(s)
}

/// Build an Argon2id KDF configured for the given tier.
/// Uses the SDK's canonical tier parameters.
fn tier_argon2(tier: MemoryTier) -> Argon2idBuilder {
    let params = tier.argon2_params(32);
    Argon2idBuilder::new()
        .memory_kib(params.m_cost())
        .iterations(params.t_cost())
        .parallelism(params.p_cost())
}

/// Read a hex key from --key or --key-file.
fn resolve_key(key: &Option<String>, key_file: &Option<String>) -> Result<Vec<u8>, String> {
    match (key, key_file) {
        (Some(h), None) => hex::decode(h.trim()).map_err(|e| format!("invalid hex key: {e}")),
        (None, Some(p)) => {
            let s = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read key file '{}': {e}", p))?;
            hex::decode(s.trim()).map_err(|e| format!("invalid hex in key file: {e}"))
        }
        (Some(_), Some(_)) => Err("specify --key or --key-file, not both".to_string()),
        (None, None) => Err("a key is required (--key or --key-file)".to_string()),
    }
}

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

pub fn cmd_hash(args: HashArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;

    let digest: Vec<u8> = match args.algo {
        HashAlgo::Sha3_256 => sha3_256(&data).to_vec(),
        HashAlgo::Sha3_512 => sha3_512(&data).to_vec(),
        HashAlgo::Blake3 => blake3::hash(&data).as_bytes().to_vec(),
        HashAlgo::HmacSha3_256 => {
            let key = resolve_key(&args.key, &args.key_file)?;
            hmac_sha3_256(&key, &data)
                .map_err(|e| format!("HMAC failed: {e:?}"))?
                .to_vec()
        }
    };

    if args.raw {
        write_output(None, &digest)
    } else {
        println!("{}", hex::encode(&digest));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// encrypt / decrypt
// ---------------------------------------------------------------------------

/// On-disk envelope:
///   magic(4) ‖ version(1) ‖ flags(1) ‖ tier(1) ‖ reserved(1)
///   ‖ salt(16) ‖ nonce(24) ‖ ciphertext+tag(...)
///
/// flags bit 0 = compressed.
const MAGIC: &[u8; 4] = b"SEAL";
const VERSION: u8 = 1;
const FLAG_COMPRESSED: u8 = 0x01;
const FLAG_STREAMED: u8 = 0x02;
const HEADER_LEN: usize = 8 + 16 + 24; // magic+ver+flags+tier+rsvd + salt + nonce

/// Streaming chunk bounds. Framing stores explicit lengths, so power-of-2 is
/// not required — only a sane min/max to avoid pathological buffers.
const CHUNK_MIN: usize = 1024; // 1 KiB
const CHUNK_MAX: usize = 1 << 30; // 1 GiB

/// Derive a unique per-chunk nonce from a random base nonce and a counter.
///
/// XORs the big-endian counter into the low 8 bytes of the 24-byte nonce.
/// With a random base and a strictly increasing counter, every chunk gets a
/// distinct nonce (safe for XChaCha20-Poly1305 up to 2^64 chunks). This is
/// the critical fix over the SDK's `aead::streaming`, which reuses one nonce
/// across all chunks (a catastrophic nonce-reuse vulnerability).
fn chunk_nonce(base: &[u8; 24], counter: u64) -> [u8; 24] {
    let mut n = *base;
    let cb = counter.to_be_bytes();
    for i in 0..8 {
        n[16 + i] ^= cb[i];
    }
    n
}

fn validate_chunk_size(cs: usize) -> Result<usize, String> {
    if !(CHUNK_MIN..=CHUNK_MAX).contains(&cs) {
        return Err(format!(
            "chunk size {cs} out of range ({CHUNK_MIN}..={CHUNK_MAX})"
        ));
    }
    Ok(cs)
}

pub fn cmd_encrypt(args: EncryptArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    if args.stream {
        return cmd_encrypt_stream(&args, tier, &passphrase);
    }

    let plaintext = read_input(args.input.as_deref())?;

    // Optional compression.
    let (payload, compressed) = if args.compress {
        let c = compression::compress_with_level(&plaintext, args.compress_level)
            .map_err(|e| format!("compression failed: {e:?}"))?;
        (c, true)
    } else {
        (plaintext, false)
    };

    // Random salt + nonce.
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive key via Argon2id.
    let key = tier_argon2(tier)
        .derive(passphrase.as_bytes(), &salt)
        .map_err(|e| format!("Argon2id failed: {e:?}"))?;
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key[..32]);

    let ct = XChaCha20Poly1305::encrypt(&key_arr, &nonce, &payload)
        .map_err(|e| format!("encryption failed: {e:?}"))?;

    // Build envelope.
    let flags = if compressed { FLAG_COMPRESSED } else { 0 };
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.push(tier_to_byte(tier));
    out.push(0); // reserved
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    write_output(args.output.as_deref(), &out)?;

    // Report to stderr so stdout stays clean for piping.
    if args.output.is_none() {
        eprintln!(
            "sealed {} bytes -> {} bytes ({}compressed, tier={:?})",
            payload.len(),
            out.len(),
            if compressed { "" } else { "un" },
            tier
        );
    }
    Ok(())
}

/// Streaming encrypt: chunked I/O with unique per-chunk nonces.
///
/// Envelope layout (streamed):
///   header(48) ‖ [len(4) ‖ ct+tag(len)]* ‖ len(4)=0 (sentinel)
///
/// Each chunk's nonce = base_nonce XOR counter (see `chunk_nonce`).
fn cmd_encrypt_stream(
    args: &EncryptArgs,
    tier: MemoryTier,
    passphrase: &str,
) -> Result<(), String> {
    if args.compress {
        return Err("--stream and --compress are mutually exclusive".to_string());
    }
    let chunk_size = validate_chunk_size(args.chunk_size)?;

    // Random salt + base nonce.
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut base_nonce);

    let key = tier_argon2(tier)
        .derive(passphrase.as_bytes(), &salt)
        .map_err(|e| format!("Argon2id failed: {e:?}"))?;
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key[..32]);

    // Open input.
    let mut reader: Box<dyn Read> = match &args.input {
        Some(p) => Box::new(
            std::fs::File::open(p).map_err(|e| format!("cannot open '{}': {e}", p))?,
        ),
        None => Box::new(std::io::stdin()),
    };

    // Open output.
    let mut writer: Box<dyn Write> = match &args.output {
        Some(p) => Box::new(
            std::fs::File::create(p).map_err(|e| format!("cannot create '{}': {e}", p))?,
        ),
        None => Box::new(std::io::stdout()),
    };

    // Write header with FLAG_STREAMED.
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(FLAG_STREAMED);
    header.push(tier_to_byte(tier));
    header.push(0);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);
    writer
        .write_all(&header)
        .map_err(|e| format!("write header: {e}"))?;

    // Stream chunks.
    let mut buf = vec![0u8; chunk_size];
    let mut counter: u64 = 0;
    let mut total_plain: u64 = 0;
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        let nonce = chunk_nonce(&base_nonce, counter);
        let ct = XChaCha20Poly1305::encrypt(&key_arr, &nonce, &buf[..n])
            .map_err(|e| format!("chunk {counter} encrypt: {e:?}"))?;
        // Frame: 4-byte big-endian ciphertext length, then ciphertext+tag.
        writer
            .write_all(&(ct.len() as u32).to_be_bytes())
            .map_err(|e| format!("write chunk len: {e}"))?;
        writer
            .write_all(&ct)
            .map_err(|e| format!("write chunk data: {e}"))?;
        total_plain += n as u64;
        counter += 1;
    }

    // Sentinel: zero-length chunk marks clean end-of-stream.
    writer
        .write_all(&0u32.to_be_bytes())
        .map_err(|e| format!("write sentinel: {e}"))?;
    writer.flush().map_err(|e| format!("flush: {e}"))?;

    if args.output.is_none() {
        eprintln!(
            "sealed {} bytes in {counter} chunks (streamed, tier={:?})",
            total_plain, tier
        );
    }
    Ok(())
}

/// Read up to `buf.len()` bytes, retrying on partial reads (handles pipes).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break, // EOF
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(filled)
}

pub fn cmd_decrypt(args: DecryptArgs) -> Result<(), String> {
    let envelope = read_input(args.input.as_deref())?;
    if envelope.len() < HEADER_LEN + 16 {
        return Err(format!(
            "input too short ({} bytes) to be a sealed envelope",
            envelope.len()
        ));
    }
    if &envelope[..4] != MAGIC {
        return Err("not an origin-seal envelope (bad magic)".to_string());
    }
    if envelope[4] != VERSION {
        return Err(format!("unsupported envelope version {}", envelope[4]));
    }

    let flags = envelope[5];
    let env_tier = tier_from_byte_fn(envelope[6])?;
    let cli_tier = parse_tier(&args.tier)?;
    if env_tier != cli_tier {
        return Err(format!(
            "tier mismatch: envelope was sealed with {env_tier:?} but --tier={cli_tier:?}"
        ));
    }

    let salt: [u8; 16] = envelope[8..24].try_into().unwrap();
    let base_nonce: [u8; 24] = envelope[24..48].try_into().unwrap();

    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    let key = tier_argon2(env_tier)
        .derive(passphrase.as_bytes(), &salt)
        .map_err(|e| format!("Argon2id failed: {e:?}"))?;
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key[..32]);

    if flags & FLAG_STREAMED != 0 {
        return cmd_decrypt_stream(&args, &key_arr, &base_nonce, &envelope[HEADER_LEN..]);
    }

    let ct = &envelope[HEADER_LEN..];
    let payload = XChaCha20Poly1305::decrypt(&key_arr, &base_nonce, ct)
        .map_err(|_| "decryption failed (wrong passphrase or corrupt data)".to_string())?;

    let plaintext = if flags & FLAG_COMPRESSED != 0 {
        compression::decompress(&payload).map_err(|e| format!("decompression failed: {e:?}"))?
    } else {
        payload
    };

    write_output(args.output.as_deref(), &plaintext)
}

/// Streaming decrypt: read length-framed chunks, decrypt each with its
/// counter-derived nonce, and detect truncation via the zero-length sentinel.
fn cmd_decrypt_stream(
    args: &DecryptArgs,
    key: &[u8; 32],
    base_nonce: &[u8; 24],
    body: &[u8],
) -> Result<(), String> {
    let mut writer: Box<dyn Write> = match &args.output {
        Some(p) => {
            Box::new(std::fs::File::create(p).map_err(|e| format!("cannot create '{}': {e}", p))?)
        }
        None => Box::new(std::io::stdout()),
    };

    let mut cursor: &mut &[u8] = &mut &body[..];
    let mut counter: u64 = 0;
    let mut total_plain: u64 = 0;

    loop {
        // Read 4-byte big-endian chunk length.
        let mut len_buf = [0u8; 4];
        match read_full(&mut cursor, &mut len_buf) {
            Ok(4) => {}
            Ok(n) => {
                return Err(format!(
                    "truncated stream: expected 4-byte chunk length, got {n} bytes (no sentinel)"
                ));
            }
            Err(e) => return Err(e),
        }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;

        // Zero-length sentinel = clean end-of-stream.
        if chunk_len == 0 {
            break;
        }

        // Read ciphertext chunk.
        let mut ct = vec![0u8; chunk_len];
        match read_full(&mut cursor, &mut ct) {
            Ok(n) if n == chunk_len => {}
            Ok(n) => {
                return Err(format!(
                    "truncated stream: chunk {counter} expected {chunk_len} bytes, got {n}"
                ));
            }
            Err(e) => return Err(e),
        }

        let nonce = chunk_nonce(base_nonce, counter);
        let pt = XChaCha20Poly1305::decrypt(key, &nonce, &ct)
            .map_err(|_| format!("chunk {counter} decryption failed (corrupt or wrong key)"))?;
        writer
            .write_all(&pt)
            .map_err(|e| format!("write chunk {counter}: {e}"))?;
        total_plain += pt.len() as u64;
        counter += 1;
    }

    writer.flush().map_err(|e| format!("flush: {e}"))?;

    if args.output.is_none() {
        eprintln!(
            "unsealed {total_plain} bytes from {counter} chunks (streamed)"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sign / verify
// ---------------------------------------------------------------------------

/// Resolve a 32-byte seed from --seed (hex) or --blob (encrypted).
fn resolve_seed(
    seed_hex: &Option<String>,
    blob_path: &Option<String>,
    passphrase_file: &Option<String>,
    tier: MemoryTier,
) -> Result<[u8; 32], String> {
    match (seed_hex, blob_path) {
        (Some(h), None) => {
            let bytes =
                hex::decode(h.trim()).map_err(|e| format!("invalid hex seed: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        (None, Some(p)) => {
            let blob =
                std::fs::read(p).map_err(|e| format!("cannot read blob '{}': {e}", p))?;
            let passphrase = resolve_passphrase(passphrase_file.as_deref())?;
            recover_seed(&blob, passphrase.as_bytes(), tier)
                .map_err(|_| "blob decryption failed (wrong passphrase or corrupt)".to_string())
        }
        (Some(_), Some(_)) => Err("specify --seed or --blob, not both".to_string()),
        (None, None) => Err("a seed source is required (--seed or --blob)".to_string()),
    }
}

pub fn cmd_sign(args: SignArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let data = read_input(args.input.as_deref())?;
    let seed = if args.identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        *store.seed_bytes()
    } else {
        resolve_seed(&args.seed, &args.blob, &args.passphrase_file, tier)?
    };

    let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
        .map_err(|e| format!("key derivation failed: {e:?}"))?;
    let sig = bundle.sign_hybrid(&data);

    match args.format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
                "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
                "domain": args.domain,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        OutputFormat::Hex => {
            let wire = combined_to_wire(&sig);
            println!("{}", hex::encode(&wire));
        }
    }
    Ok(())
}

pub fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;

    // Load signature (JSON or hex wire).
    let sig_bytes = std::fs::read(&args.signature)
        .map_err(|e| format!("cannot read signature '{}': {e}", args.signature))?;
    let (ed_bytes, falcon_bytes) = parse_signature(&sig_bytes)?;

    if ed_bytes.len() != 64 {
        return Err(format!("ed25519 signature must be 64 bytes, got {}", ed_bytes.len()));
    }
    let mut ed_sig = [0u8; 64];
    ed_sig.copy_from_slice(&ed_bytes);

    let falcon_sig = falcon1024::FalconSignature::from_bytes(&falcon_bytes)
        .map_err(|e| format!("invalid falcon signature: {e:?}"))?;

    // Resolve public keys: from seed/blob, or from explicit pubkey args.
    let (ed_pk, falcon_pk) = resolve_verify_pubkeys(&args)?;

    // Verify each component using the SDK's raw-byte APIs — no external
    // crypto deps needed here, everything goes through origin-crypto-sdk.
    let ed_ok = Ed25519Signer::verify_with_pubkey(&ed_pk, &data, &ed_sig);
    let falcon_ok = falcon1024::verify(&data, &falcon_sig, &falcon_pk).is_ok();

    if ed_ok && falcon_ok {
        println!("OK");
        Ok(())
    } else {
        Err(format!(
            "signature verification FAILED (ed25519={}, falcon1024={})",
            if ed_ok { "ok" } else { "bad" },
            if falcon_ok { "ok" } else { "bad" }
        ))
    }
}

/// Resolve the verifying keys for a verify command.
///
/// Returns the Ed25519 public key as raw `[u8; 32]` and the Falcon public key
/// as an SDK `FalconPublicKey`, so verification can use the SDK's raw-byte
/// APIs without any direct dalek dependency.
fn resolve_verify_pubkeys(
    args: &VerifyArgs,
) -> Result<([u8; 32], falcon1024::FalconPublicKey), String> {
    // Path A: derive from seed/blob (has both keys).
    if args.seed.is_some() || args.blob.is_some() {
        let tier = parse_tier(&args.tier)?;
        let seed = resolve_seed(&args.seed, &args.blob, &args.passphrase_file, tier)?;
        let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
            .map_err(|e| format!("key derivation failed: {e:?}"))?;
        let ed_pk = bundle.ed25519_pk().to_bytes();
        let falcon_pk = bundle.falcon1024_pk().clone();
        return Ok((ed_pk, falcon_pk));
    }

    // Path B: explicit public keys.
    let ed_hex = args
        .ed25519_pubkey
        .as_ref()
        .ok_or("verification needs --seed/--blob, or --ed25519-pubkey + --falcon-pubkey")?;
    let ed_bytes =
        hex::decode(ed_hex.trim()).map_err(|e| format!("invalid ed25519 pubkey hex: {e}"))?;
    if ed_bytes.len() != 32 {
        return Err(format!("ed25519 pubkey must be 32 bytes, got {}", ed_bytes.len()));
    }
    let mut ed_pk = [0u8; 32];
    ed_pk.copy_from_slice(&ed_bytes);

    let falcon_path = args
        .falcon_pubkey
        .as_ref()
        .ok_or("verification with --ed25519-pubkey also needs --falcon-pubkey")?;
    let falcon_bytes = std::fs::read(falcon_path)
        .map_err(|e| format!("cannot read falcon pubkey '{}': {e}", falcon_path))?;
    let falcon_pk = falcon1024::FalconPublicKey::from_bytes(&falcon_bytes)
        .map_err(|e| format!("invalid falcon pubkey: {e:?}"))?;

    Ok((ed_pk, falcon_pk))
}

/// Serialize a hybrid signature to length-prefixed wire format.
fn combined_to_wire(sig: &origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024) -> Vec<u8> {
    let falcon = sig.falcon_sig.as_bytes();
    let mut out = Vec::with_capacity(4 + 64 + falcon.len());
    out.extend_from_slice(&(falcon.len() as u32).to_be_bytes());
    out.extend_from_slice(sig.ed25519_sig.to_bytes().as_ref());
    out.extend_from_slice(falcon);
    out
}

/// Parse a signature from JSON or hex wire format.
fn parse_signature(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Try JSON first.
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim();
        if trimmed.starts_with('{') {
            let v: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| format!("invalid signature JSON: {e}"))?;
            let ed = hex::decode(
                v["ed25519"]
                    .as_str()
                    .ok_or("missing ed25519 field in signature JSON")?,
            )
            .map_err(|e| format!("ed25519 hex: {e}"))?;
            let falcon = hex::decode(
                v["falcon1024"]
                    .as_str()
                    .ok_or("missing falcon1024 field in signature JSON")?,
            )
            .map_err(|e| format!("falcon hex: {e}"))?;
            return Ok((ed, falcon));
        }
        // Otherwise treat as hex wire.
        let raw = hex::decode(trimmed).map_err(|e| format!("invalid signature hex: {e}"))?;
        return parse_wire(&raw);
    }
    // Raw binary wire.
    parse_wire(bytes)
}

/// Parse length-prefixed wire: len(4 BE) ‖ ed25519(64) ‖ falcon(len).
fn parse_wire(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if raw.len() < 4 + 64 {
        return Err(format!(
            "signature wire too short ({} bytes); need >= 68",
            raw.len()
        ));
    }
    let falcon_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let ed = raw[4..68].to_vec();
    if raw.len() != 68 + falcon_len {
        return Err(format!(
            "signature wire length mismatch: header says falcon={} but total={}",
            falcon_len,
            raw.len()
        ));
    }
    let falcon = raw[68..68 + falcon_len].to_vec();
    Ok((ed, falcon))
}

// ---------------------------------------------------------------------------
// kdf
// ---------------------------------------------------------------------------

pub fn cmd_kdf(args: KdfArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    let salt: [u8; 16] = match &args.salt {
        Some(h) => {
            let b = hex::decode(h.trim()).map_err(|e| format!("invalid salt hex: {e}"))?;
            if b.len() != 16 {
                return Err(format!("salt must be 16 bytes, got {}", b.len()));
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&b);
            a
        }
        None => {
            let mut a = [0u8; 16];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut a);
            a
        }
    };

    let key = tier_argon2(tier)
        .output_len(args.len)
        .derive(passphrase.as_bytes(), &salt)
        .map_err(|e| format!("Argon2id failed: {e:?}"))?;

    if args.raw {
        write_output(None, &key)?;
    } else {
        println!("salt: {}", hex::encode(salt));
        println!("key:  {}", hex::encode(&key));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// mac
// ---------------------------------------------------------------------------

pub fn cmd_mac(args: MacArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;
    let key = resolve_key(&args.key, &args.key_file)?;
    let mac = hmac_sha3_256(&key, &data).map_err(|e| format!("HMAC failed: {e:?}"))?;

    if args.raw {
        write_output(None, &mac)?;
    } else {
        println!("{}", hex::encode(mac));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// blob helper (used by tests / future `seal keygen`)
// ---------------------------------------------------------------------------

/// Create an encrypted seed blob (thin wrapper over SDK).
#[allow(dead_code)]
pub fn make_blob(passphrase: &str, tier: MemoryTier, seed: Option<&[u8; 32]>) -> Vec<u8> {
    create_blob(passphrase.as_bytes(), tier, seed).expect("blob creation")
}

/// Validate that a path's parent is creatable (used before writes).
#[allow(dead_code)]
pub fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create dir {}: {e}", parent.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tier_accepts_all_variants() {
        assert_eq!(parse_tier("nano").unwrap(), MemoryTier::Nano);
        assert_eq!(parse_tier("STANDARD").unwrap(), MemoryTier::Standard);
        assert_eq!(parse_tier("Sovereign").unwrap(), MemoryTier::Sovereign);
        assert!(parse_tier("bogus").is_err());
    }

    #[test]
    fn tier_byte_roundtrip() {
        for t in [MemoryTier::Nano, MemoryTier::Standard, MemoryTier::Sovereign] {
            assert_eq!(tier_from_byte_fn(tier_to_byte(t)).unwrap(), t);
        }
        assert!(tier_from_byte_fn(9).is_err());
    }

    #[test]
    fn wire_signature_roundtrip() {
        let ed = vec![0xABu8; 64];
        let falcon = vec![0xCDu8; 200];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(falcon.len() as u32).to_be_bytes());
        wire.extend_from_slice(&ed);
        wire.extend_from_slice(&falcon);

        let (ed_out, falcon_out) = parse_wire(&wire).unwrap();
        assert_eq!(ed_out, ed);
        assert_eq!(falcon_out, falcon);
    }

    #[test]
    fn wire_too_short_rejected() {
        assert!(parse_wire(&[0u8; 10]).is_err());
    }

    #[test]
    fn wire_length_mismatch_rejected() {
        // Header claims falcon=100 but total is only 68+5.
        let mut wire = Vec::new();
        wire.extend_from_slice(&100u32.to_be_bytes());
        wire.extend_from_slice(&[0u8; 64]);
        wire.extend_from_slice(&[0u8; 5]);
        assert!(parse_wire(&wire).is_err());
    }

    #[test]
    fn parse_signature_json() {
        let json = r#"{"ed25519":"aabb","falcon1024":"ccdd","domain":"x"}"#;
        let (ed, falcon) = parse_signature(json.as_bytes()).unwrap();
        assert_eq!(ed, vec![0xaa, 0xbb]);
        assert_eq!(falcon, vec![0xcc, 0xdd]);
    }

    #[test]
    fn parse_signature_hex_wire() {
        let ed = vec![0x11u8; 64];
        let falcon = vec![0x22u8; 32];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(falcon.len() as u32).to_be_bytes());
        wire.extend_from_slice(&ed);
        wire.extend_from_slice(&falcon);
        let hex_str = hex::encode(&wire);

        let (ed_out, falcon_out) = parse_signature(hex_str.as_bytes()).unwrap();
        assert_eq!(ed_out, ed);
        assert_eq!(falcon_out, falcon);
    }

    #[test]
    fn envelope_constants_consistent() {
        // magic(4) + ver(1) + flags(1) + tier(1) + rsvd(1) + salt(16) + nonce(24)
        assert_eq!(HEADER_LEN, 48);
        assert_eq!(MAGIC, b"SEAL");
    }
}
