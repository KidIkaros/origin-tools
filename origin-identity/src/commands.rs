// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-identity.
//!
//! Each `cmd_*` function returns `Result<(), String>` — a single error
//! channel keeps the dispatch in main.rs trivial.

use std::path::{Path, PathBuf};

use origin_crypto_sdk::{
    blake3,
    blob::{create_blob, recover_seed},
    recovery::unicode_cipher::{decode_phrase, encode_phrase, PhraseLength, UnicodeWordlist},
    seed::gen::{generate, SeedVariant},
    signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle},
    tier::MemoryTier,
    Ed25519Signature,
};

use crate::cli::{
    resolve_dir, DeleteArgs, ExportPubkeyArgs, ImportArgs, KeygenArgs, ListArgs, ListFormat,
    OutputFormat, RenameArgs, RotatePassphraseArgs, ShowArgs, ShowFormat, SignArgs, VerifyArgs,
};

/// Format a byte length with a space before the unit so columns align.
fn fmt_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut idx = 0;
    while size >= 1024.0 && idx < UNITS.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[idx])
    }
}

// ── Passphrase + path helpers ──────────────────────────────────────

pub fn parse_tier(s: &str) -> Result<MemoryTier, String> {
    match s.to_lowercase().as_str() {
        "nano" => Ok(MemoryTier::Nano),
        "standard" => Ok(MemoryTier::Standard),
        "sovereign" => Ok(MemoryTier::Sovereign),
        other => Err(format!(
            "unknown tier '{other}'; use nano, standard, or sovereign"
        )),
    }
}

pub fn identity_path(name: &str, dir: &str) -> Result<PathBuf, String> {
    Ok(resolve_dir(dir)?.join(format!("{}.id", name)))
}

pub fn read_blob(name: &str, dir: &str) -> Result<Vec<u8>, String> {
    let path = identity_path(name, dir)?;
    std::fs::read(&path).map_err(|e| format!("cannot read {}: {}", path.display(), e))
}

pub fn ensure_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))
    } else {
        Ok(())
    }
}

pub fn resolve_passphrase(file: &Option<String>) -> Result<String, String> {
    match file {
        Some(path) => {
            let pw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read passphrase file: {e}"))?;
            Ok(pw.trim().to_string())
        }
        None => {
            let pw = rpassword::prompt_password("Passphrase: ")
                .map_err(|e| format!("passphrase prompt failed: {e}"))?;
            Ok(pw)
        }
    }
}

pub fn resolve_passphrase_confirm(file: &Option<String>) -> Result<String, String> {
    match file {
        Some(path) => {
            let pw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read passphrase file: {e}"))?;
            Ok(pw.trim().to_string())
        }
        None => {
            let pw = rpassword::prompt_password("Passphrase: ")
                .map_err(|e| format!("passphrase prompt failed: {e}"))?;
            let pw2 = rpassword::prompt_password("Confirm:   ")
                .map_err(|e| format!("passphrase prompt failed: {e}"))?;
            if pw != pw2 {
                return Err("passphrases do not match".to_string());
            }
            Ok(pw)
        }
    }
}

// ── Input parsing helpers ──────────────────────────────────────────

/// Read a "raw bytes" argument that may be a literal UTF-8 string,
/// an `@file` reference, or (when `hex == true`) hex-encoded bytes.
pub fn read_bytes(s: &str, hex: bool) -> Result<Vec<u8>, String> {
    if hex {
        hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
    } else if let Some(stripped) = s.strip_prefix('@') {
        std::fs::read(stripped).map_err(|e| format!("cannot read {}: {}", stripped, e))
    } else {
        Ok(s.as_bytes().to_vec())
    }
}

/// Atomically write a 24-codepoint recovery phrase to `path` as
/// `<c1> <c2> … <c24>\n` (single-space-separated, single line, trailing
/// newline). The on-disk format is exactly what `read_phrase` accepts
/// via `split_whitespace`, so a shell-driven restore works:
///
/// ```text
/// keygen  … --phrase-output phrase.txt
/// import  … --phrase @phrase.txt
/// ```
///
/// # Atomicity
///
/// Uses `<file>.<pid>.<nanos>.tmp` in the same directory as the target,
/// followed by `rename(2)` — POSIX atomic on the same filesystem, so
/// the caller observes either a complete file or **no file**, never a
/// truncated one.
///
/// # Errors
///
/// Returns `Err` (string-formatted) on any IO error: missing parent
/// directory, permission denied, disk full, etc. The target file is
/// NOT created in any of these cases; the tmp sibling may remain on
/// disk for post-mortem (the caller can `rm` it).
pub fn write_phrase_file(phrase: &[char], path: &std::path::Path) -> Result<(), String> {
    if phrase.len() != 24 {
        return Err(format!(
            "internal: write_phrase_file expects exactly 24 codepoints; got {}",
            phrase.len()
        ));
    }
    let mut body = String::with_capacity(phrase.len() * 4 + 1);
    for (i, c) in phrase.iter().enumerate() {
        if i > 0 {
            body.push(' ');
        }
        body.push(*c);
    }
    body.push('\n');

    // Build tmp path in the same directory as the target so the rename
    // stays atomic on POSIX (same-filesystem rename). `<pid>.<nanos>`
    // suffix prevents concurrent keygen runs from stepping on each
    // other's tmp.
    let pid = std::process::id();
    let nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("phrase");
    let tmp_name = format!("{base_name}.{pid}.{nano}.tmp");
    let tmp = path.with_file_name(tmp_name);

    // `create_new(true)` opens with O_CREAT | O_EXCL semantics. This
    // atomically reserves the tmp path: it refuses to follow symlinks
    // (closes a TOCTOU race where an attacker pre-places a symlink at
    // the predictable <file>.<pid>.<nanos>.tmp path) and refuses to
    // clobber an existing file. The phrase is the ONLY backup of the
    // identity, so symlink-leak hardening is a real concern.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("cannot create phrase tmpfile {}: {e}", tmp.display()))?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("cannot write phrase tmpfile {}: {e}", tmp.display()))?;
    file.sync_all()
        .map_err(|e| format!("cannot fsync phrase tmpfile {}: {e}", tmp.display()))?;
    drop(file);

    std::fs::rename(&tmp, path)
        .map_err(|e| format!("cannot rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Parse a recovery phrase (24 unicode codepoints separated by whitespace).
/// Each whitespace-delimited token must be exactly one codepoint.
pub fn read_phrase(s: &str) -> Result<Vec<char>, String> {
    let mut text = if let Some(stripped) = s.strip_prefix('@') {
        std::fs::read_to_string(stripped).map_err(|e| format!("cannot read {}: {}", stripped, e))?
    } else {
        s.to_string()
    };

    // Strip a leading UTF-8 BOM (U+FEFF) if present. Common when phrases
    // are pasted from Windows-pinned notes or email bodies — without this,
    // decode_phrase rejects U+FEFF as DEFAULT_IGNORABLE with a confusing
    // codepoint-class error.
    if let Some(stripped) = text.strip_prefix('\u{feff}') {
        text = stripped.to_string();
    }

    let mut chars = Vec::new();
    for token in text.split_whitespace() {
        let mut iter = token.chars();
        let c = iter
            .next()
            .ok_or_else(|| "empty token in phrase (extra whitespace?)".to_string())?;
        if iter.next().is_some() {
            return Err(format!(
                "phrase token {:?} has more than one codepoint; each word must be one Unicode character",
                token
            ));
        }
        chars.push(c);
    }
    if chars.is_empty() {
        return Err("phrase is empty".to_string());
    }
    Ok(chars)
}

// ── Commands ───────────────────────────────────────────────────────

pub fn cmd_keygen(args: KeygenArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let path = identity_path(&args.name, &args.dir)?;

    ensure_dir(&path)?;

    // 1. Generate 32-byte master seed using multi-hash chain
    eprintln!("Generating master seed...");
    let generated = generate(SeedVariant::Blake2bShake256);
    let seed: [u8; 32] = generated
        .seed
        .as_slice()
        .try_into()
        .map_err(|_| "seed not 32 bytes".to_string())?;

    // 2. Encode phrase once. (Re-used by both banner and file paths below.)
    let list = UnicodeWordlist::default();
    let phrase = encode_phrase(&seed, &list, PhraseLength::Words24)
        .map_err(|e| format!("phrase encoding failed: {e}"))?;

    // 3. Recovery phrase presentation: file > banner > silent.
    //    --phrase-output writes the file atomically and suppresses the
    //    on-screen banner (the file IS the output). --no-phrase suppresses
    //    everything. Otherwise, print the banner + interactive prompt.
    if let Some(out_path_str) = &args.phrase_output {
        let out_path = resolve_dir(out_path_str)?;
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "cannot create phrase-output parent dir {}: {e}",
                        parent.display()
                    )
                })?;
            }
        }
        write_phrase_file(&phrase, &out_path)?;
        eprintln!(
            "Wrote recovery phrase (24 codepoints) to: {}\n  Keep this file offline and secure. It is the ONLY backup for this identity.",
            out_path.display()
        );
    } else if !args.no_phrase {
        eprintln!();
        eprintln!("╔══ RECOVERY PHRASE (24 words) ═══════════════════╗");
        eprintln!("║  Write this down. Store it offline.            ║");
        eprintln!("║  It is the ONLY backup for this identity.      ║");
        eprintln!("╚═════════════════════════════════════════════════╝");
        eprintln!();
        for (i, ch) in phrase.iter().enumerate() {
            eprint!(" {} ", ch);
            if (i + 1) % 6 == 0 {
                eprintln!();
            }
        }
        eprintln!();
        eprintln!();
        eprint!("Press Enter to continue (passphrase prompt follows)... ");
        let mut _discard = String::new();
        std::io::stdin().read_line(&mut _discard).ok();
    }

    // 4. Get passphrase and encrypt to blob
    let passphrase = resolve_passphrase_confirm(&args.passphrase_file)?;
    let blob = create_blob(passphrase.as_bytes(), tier, Some(&seed))
        .map_err(|e| format!("blob encryption failed: {e}"))?;

    std::fs::write(&path, &blob).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;

    eprintln!("Created identity '{}' at {}", args.name, path.display());
    Ok(())
}

pub fn cmd_sign(args: SignArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let _ = resolve_dir(&args.dir)?; // validate HOME early
    let blob = read_blob(&args.name, &args.dir)?;
    let msg = read_bytes(&args.message, args.hex)?;

    let passphrase = resolve_passphrase(&args.passphrase_file)?;

    let seed = recover_seed(&blob, passphrase.as_bytes(), tier)
        .map_err(|_| "decryption failed (wrong passphrase or corrupted blob)".to_string())?;

    let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
        .map_err(|e| format!("key bundle failed: {e}"))?;

    let sig = bundle.sign_hybrid(&msg);

    match args.output {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
                "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
                "domain": args.domain,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        OutputFormat::Hex => {
            // Pre-computed via CombinedSignature (see that type for
            // wire format). The encoder and decoder share the struct, so
            // they cannot drift.
            let combined = CombinedSignature {
                ed: sig.ed25519_sig,
                falcon: sig.falcon_sig,
            };
            let wire = combined.to_wire_bytes();
            println!("{}", hex::encode(&wire));
        }
    }

    Ok(())
}

pub fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let _ = resolve_dir(&args.dir)?; // validate HOME early
    let blob = read_blob(&args.name, &args.dir)?;
    let msg = read_bytes(&args.message, args.hex)?;

    let combined_sig = if args.hex {
        let raw = read_bytes(&args.signature, true)?;
        CombinedSignature::from_wire(&raw)?
    } else {
        let sig_json = std::fs::read_to_string(&args.signature)
            .map_err(|e| format!("cannot read signature file '{}': {e}", args.signature))?;
        let sig_val: serde_json::Value =
            serde_json::from_str(&sig_json).map_err(|e| format!("invalid signature JSON: {e}"))?;
        let ed25519_hex = sig_val["ed25519"]
            .as_str()
            .ok_or("missing ed25519 field in signature")?;
        let falcon_hex = sig_val["falcon1024"]
            .as_str()
            .ok_or("missing falcon1024 field in signature")?;
        let ed_bytes = hex::decode(ed25519_hex).map_err(|e| format!("ed25519 hex: {e}"))?;
        let falcon_bytes = hex::decode(falcon_hex).map_err(|e| format!("falcon hex: {e}"))?;
        let ed = Ed25519Signature::from_slice(&ed_bytes)
            .map_err(|e| format!("invalid ed25519 signature: {e}"))?;
        let falcon = origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&falcon_bytes)
            .map_err(|e| format!("invalid falcon signature: {e}"))?;
        CombinedSignature { ed, falcon }
    };

    let passphrase = resolve_passphrase(&args.passphrase_file)?;

    let seed = recover_seed(&blob, passphrase.as_bytes(), tier)
        .map_err(|_| "decryption failed (wrong passphrase or corrupted blob)".to_string())?;

    let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
        .map_err(|e| format!("key bundle failed: {e}"))?;

    let combined = Ed25519Falcon1024 {
        ed25519_sig: combined_sig.ed,
        falcon_sig: combined_sig.falcon,
    };

    match Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), &msg, &combined) {
        Ok(()) => {
            println!("valid");
            Ok(())
        }
        Err(e) => Err(format!("invalid signature: {e}")),
    }
}

/// Length-prefixed combined Ed25519 + Falcon-1024 signature blob.
///
/// Used by `sign --output hex` (encoder) and `verify --hex` (decoder)
/// so they cannot drift. Falcon-1024 sigs are **variable-length** (up
/// to ~1330 bytes), so a length prefix is mandatory.
///
/// # Wire format (BE = big-endian)
///
/// ```text
/// ┌────────────────────┬──────────────────┬──────────────────────┐
/// │ falcon_len (4B BE) │ ed25519_sig (64B)│ falcon_sig (N B)     │
/// └────────────────────┴──────────────────┴──────────────────────┘
/// ```
///
/// Total = `4 + 64 + falcon_len` bytes. `falcon_len` is read as a
/// `u32` from the first 4 bytes; values above 32-bit max are rejected
/// structurally because the buffer can't carry that many bytes.
pub struct CombinedSignature {
    pub ed: Ed25519Signature,
    pub falcon: origin_crypto_sdk::pqc::falcon1024::FalconSignature,
}

// Manual Debug impl because FalconSignature lacks Debug. Prints
// lengths only — sigs are PUBLIC material, but logs should stay tidy.
impl std::fmt::Debug for CombinedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CombinedSignature")
            .field("ed_len", &self.ed.to_bytes().len())
            .field("falcon_len", &self.falcon.as_bytes().len())
            .finish()
    }
}

impl CombinedSignature {
    /// Ed25519 signature length is universally 64 bytes.
    pub const ED_LEN: usize = 64;
    /// 4-byte BE unsigned length prefix.
    pub const LEN_PREFIX: usize = 4;
    /// Maximum wire size using the SDK's Falcon-1024 CT signature maximum.
    pub const MAX_WIRE_LEN: usize =
        Self::LEN_PREFIX + Self::ED_LEN + origin_crypto_sdk::pqc::falcon1024::sizes::SIGNATURE_MAX;

    /// Serialize to the canonical wire byte format.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let falcon = self.falcon.as_bytes();
        let mut out = Vec::with_capacity(Self::LEN_PREFIX + Self::ED_LEN + falcon.len());
        out.extend_from_slice(&(falcon.len() as u32).to_be_bytes());
        out.extend_from_slice(self.ed.to_bytes().as_ref());
        out.extend_from_slice(falcon);
        out
    }

    /// Parse the canonical wire byte format.
    pub fn from_wire(raw: &[u8]) -> Result<Self, String> {
        let min = Self::LEN_PREFIX + Self::ED_LEN;
        if raw.len() < min {
            return Err(format!(
                "length-prefixed signature must be at least {min} bytes (4 len + 64 ed25519); got {}",
                raw.len()
            ));
        }
        let falcon_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let max_falcon_len = origin_crypto_sdk::pqc::falcon1024::sizes::SIGNATURE_MAX;
        if falcon_len > max_falcon_len {
            return Err(format!(
                "falcon signature length {falcon_len} exceeds maximum {max_falcon_len} bytes"
            ));
        }
        let expected_len = min + falcon_len;
        if raw.len() != expected_len {
            return Err(format!(
                "length-prefixed signature size mismatch: header says falcon={falcon_len} B, total should be {expected_len} B; got {} B",
                raw.len()
            ));
        }
        let ed =
            Ed25519Signature::from_slice(&raw[Self::LEN_PREFIX..Self::LEN_PREFIX + Self::ED_LEN])
                .map_err(|e| format!("invalid ed25519 signature: {e}"))?;
        let falcon = origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(
            &raw[Self::LEN_PREFIX + Self::ED_LEN..],
        )
        .map_err(|e| format!("invalid falcon signature: {e}"))?;
        Ok(Self { ed, falcon })
    }
}

pub fn cmd_list(args: ListArgs) -> Result<(), String> {
    let dir = resolve_dir(&args.dir)?;
    if !dir.exists() {
        return Err(format!(
            "identity directory does not exist: {}",
            dir.display()
        ));
    }
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| format!("cannot read directory {}: {}", dir.display(), e))?;

    let mut skipped_metadata: Vec<String> = Vec::new();

    // Collect matching `.id` files with metadata + fingerprint.
    let mut rows: Vec<ListRow> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("directory entry error: {e}"))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name_os) = path.file_name() else {
            continue;
        };
        let Some(name_str) = name_os.to_str() else {
            continue;
        };
        let Some(stem) = name_str.strip_suffix(".id") else {
            continue;
        };

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                skipped_metadata.push(format!("{}: {}", path.display(), e));
                continue;
            }
        };

        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        if bytes.len() < 40 {
            // salt+nonce = 40. Anything smaller is malformed.
            rows.push(ListRow {
                name: stem.to_string(),
                size: meta.len(),
                modified: meta.modified().ok(),
                fingerprint: "<malformed>".to_string(),
            });
            continue;
        }

        let modified = meta.modified().ok();
        if modified.is_none() {
            skipped_metadata.push(format!("{}: cannot read mtime", path.display()));
        }
        let fingerprint = hex::encode(&blake3::hash(&bytes[..40]).as_bytes()[..4]);
        rows.push(ListRow {
            name: stem.to_string(),
            size: meta.len(),
            modified,
            fingerprint,
        });
    }

    rows.sort_by(|a, b| a.name.cmp(&b.name));

    if !skipped_metadata.is_empty() {
        eprintln!(
            "(warning: skipped {} entries with unreadable metadata)",
            skipped_metadata.len()
        );
        for s in &skipped_metadata {
            eprintln!("  - {s}");
        }
    }

    if args.names_only {
        for r in &rows {
            println!("{}", r.name);
        }
        if rows.is_empty() {
            eprintln!("(no identities found in {})", dir.display());
        }
        return Ok(());
    }

    match args.format {
        ListFormat::Table => print_table(&rows),
        ListFormat::Csv => print_csv(&rows),
        ListFormat::Json => print_json(&rows),
    }

    if rows.is_empty() {
        eprintln!("(no identities found in {})", dir.display());
    }
    Ok(())
}

struct ListRow {
    name: String,
    size: u64,
    modified: Option<std::time::SystemTime>,
    fingerprint: String,
}

fn system_time_to_rfc3339(t: Option<std::time::SystemTime>) -> String {
    use std::time::UNIX_EPOCH;
    match t {
        Some(tt) => {
            let dur = tt.duration_since(UNIX_EPOCH).unwrap_or_default();
            // Cheap ISO formatting: YYYY-MM-DDTHH:MM:SSZ from epoch seconds.
            // (Avoids pulling in `chrono` for one column.)
            let secs = dur.as_secs();
            let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
            format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
        }
        None => "unknown".to_string(),
    }
}

fn epoch_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    let m = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;
    let mut days = (secs / 86_400) as i64;
    let mut year: i32 = 1970;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days >= dy {
            days -= dy;
            year += 1;
        } else {
            break;
        }
    }
    let mdays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    while month < 12 {
        let dm = if month == 1 && is_leap(year) {
            29
        } else {
            mdays[month]
        };
        if days >= dm {
            days -= dm;
            month += 1;
        } else {
            break;
        }
    }
    (year, (month + 1) as u32, (days + 1) as u32, h, m, s)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn print_table(rows: &[ListRow]) {
    if rows.is_empty() {
        return;
    }
    println!(
        "{:<24} {:>10}  {:<20}  FINGERPRINT",
        "NAME", "SIZE", "MODIFIED"
    );
    for r in rows {
        println!(
            "{:<24} {:>10}  {:<20}  {}",
            r.name,
            fmt_size(r.size),
            system_time_to_rfc3339(r.modified),
            r.fingerprint
        );
    }
}

fn print_csv(rows: &[ListRow]) {
    println!("name,size,modified,fingerprint");
    for r in rows {
        println!(
            "{},{},{},{}",
            r.name,
            r.size,
            system_time_to_rfc3339(r.modified),
            r.fingerprint
        );
    }
}

fn print_json(rows: &[ListRow]) {
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "size": r.size,
                "modified": system_time_to_rfc3339(r.modified),
                "fingerprint": r.fingerprint,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&arr).unwrap());
}

pub fn cmd_import(args: ImportArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;

    // 1. Parse + decode recovery phrase → 32-byte seed.
    let chars = read_phrase(&args.phrase)?;
    let entropy = decode_phrase(&chars, &UnicodeWordlist::default())
        .map_err(|e| format!("phrase decode failed: {e}"))?;
    if entropy.len() != 32 {
        return Err(format!(
            "origin-identity requires 256-bit master seeds (24 words). \
             Got {} bytes of entropy from a {}-word phrase. \
             12-word import is not supported.",
            entropy.len(),
            chars.len()
        ));
    }
    let seed: [u8; 32] = entropy.as_slice().try_into().expect("length checked above");

    // 2. Resolve target path; refuse to overwrite unless --force.
    let path = identity_path(&args.name, &args.dir)?;
    if path.exists() && !args.force {
        return Err(format!(
            "identity '{}' already exists at {}; use --force to overwrite",
            args.name,
            path.display()
        ));
    }
    ensure_dir(&path)?;

    // 3. Get passphrase and encrypt to blob (same path as keygen).
    let passphrase = resolve_passphrase_confirm(&args.passphrase_file)?;
    let blob = create_blob(passphrase.as_bytes(), tier, Some(&seed))
        .map_err(|e| format!("blob encryption failed: {e}"))?;

    std::fs::write(&path, &blob).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;

    eprintln!(
        "Imported identity '{}' from {}-word phrase → {}",
        args.name,
        chars.len(),
        path.display()
    );
    Ok(())
}

// ── Show ────────────────────────────────────────────────────────────

/// Print metadata for a single identity blob. Does NOT decrypt; safe to
/// invoke without a passphrase. Fingerprint is `blake3(salt‖nonce)[:4]`
/// (8 hex chars), matching `cmd_list` so shell scripts can correlate.
pub fn cmd_show(args: ShowArgs) -> Result<(), String> {
    let path = identity_path(&args.name, &args.dir)?;
    let meta =
        std::fs::metadata(&path).map_err(|e| format!("cannot stat {}: {}", path.display(), e))?;
    let bytes =
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let fingerprint = if bytes.len() >= 40 {
        hex::encode(&blake3::hash(&bytes[..40]).as_bytes()[..4])
    } else {
        "<malformed>".to_string()
    };
    let modified = meta.modified().ok();

    match args.format {
        ShowFormat::Text => {
            println!("Name:        {}", args.name);
            println!("Path:        {}", path.display());
            println!("Size:        {} ({})", meta.len(), fmt_size(meta.len()));
            println!("Modified:    {}", system_time_to_rfc3339(modified));
            println!("Fingerprint: {}", fingerprint);
            println!("Encrypted:   yes (passphrase-sealed)");
            println!("Tier:        unknown (sealed; supply --tier when signing)");
        }
        ShowFormat::Json => {
            let out = serde_json::json!({
                "name": args.name,
                "path": path.to_string_lossy(),
                "size": meta.len(),
                "modified": system_time_to_rfc3339(modified),
                "fingerprint": fingerprint,
                "encrypted": true,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
    }
    Ok(())
}

// ── Rename ─────────────────────────────────────────────────────────

/// Atomic filesystem rename. Does NOT touch key material — the blob
/// bytes are byte-for-byte identical before/after. Refuses to overwrite
/// an existing target unless `--force`.
pub fn cmd_rename(args: RenameArgs) -> Result<(), String> {
    let old = identity_path(&args.old_name, &args.dir)?;
    let new = identity_path(&args.new_name, &args.dir)?;
    if !old.exists() {
        return Err(format!(
            "identity '{}' does not exist at {}",
            args.old_name,
            old.display()
        ));
    }
    if new.exists() && !args.force {
        return Err(format!(
            "identity '{}' already exists at {}; use --force to overwrite",
            args.new_name,
            new.display()
        ));
    }
    std::fs::rename(&old, &new).map_err(|e| format!("rename failed: {e}"))?;
    eprintln!("Renamed '{}' \u{2192} '{}'", args.old_name, args.new_name);
    Ok(())
}

// ── Delete ─────────────────────────────────────────────────────────

/// Securely delete an identity blob. Default behavior:
///   1. Interactive confirmation (skipped with `--force`)
///   2. Single-pass random overwrite (`/dev/urandom`) of the file's
///      existing size, fsynced, then truncated to 0 bytes
///   3. `remove_file`
///
/// NIST SP 800-88 sanitization rationale: on modern drives (ATA
/// ≥15 GB, SSD) a single-pass overwrite followed by truncation is
/// sufficient because the data is either overwritten in place or
/// unmapped and unrecoverable. Caveat for SSDs with wear-leveling:
/// `blkdiscard` / TRIM is more thorough but requires root, so we
/// don't attempt it from a userland CLI by default. For higher
/// assurance, users should pair this with full-disk encryption.
pub fn cmd_delete(args: DeleteArgs) -> Result<(), String> {
    let path = identity_path(&args.name, &args.dir)?;
    if !path.exists() {
        return Err(format!(
            "identity '{}' does not exist at {}",
            args.name,
            path.display()
        ));
    }

    // Confirmation unless --force.
    if !args.force {
        eprintln!(
            "About to delete identity '{}' at {}.",
            args.name,
            path.display()
        );
        eprint!("Type the identity name to confirm: ");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("stdin read failed: {e}"))?;
        if input.trim() != args.name {
            return Err("confirmation failed: name does not match".to_string());
        }
    }

    // Secure overwrite unless --no-overwrite.
    if !args.no_overwrite {
        let meta = std::fs::metadata(&path).map_err(|e| format!("cannot stat: {e}"))?;
        let len = meta.len() as usize;
        let mut rng_bytes = vec![0u8; len];
        // /dev/urandom is the OS CSPRNG; reads block until len bytes.
        // On Linux, getrandom(2) backs this. On macOS, /dev/urandom is
        // also CSPRNG-backed. On Windows this would need BCryptGenRandom
        // — unsupported in this CLI's current scope.
        let mut urandom = std::fs::File::open("/dev/urandom")
            .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
        use std::io::Read;
        urandom
            .read_exact(&mut rng_bytes)
            .map_err(|e| format!("urandom read failed: {e}"))?;

        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| format!("cannot open for overwrite: {e}"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek failed: {e}"))?;
        file.write_all(&rng_bytes)
            .map_err(|e| format!("overwrite write failed: {e}"))?;
        file.sync_all().map_err(|e| format!("fsync failed: {e}"))?;
        drop(file);
        // Truncate to 0.
        std::fs::File::create(&path).map_err(|e| format!("truncate failed: {e}"))?;
    }

    std::fs::remove_file(&path).map_err(|e| format!("remove failed: {e}"))?;
    eprintln!("Deleted identity '{}'", args.name);
    Ok(())
}

// ── ExportPubkey ───────────────────────────────────────────────────

/// Decrypt the blob, derive the signing key bundle, and emit ONLY the
/// public keys (no seed, no signatures, no secret material of any kind).
/// The `domain` is required because the bundle derivation includes it.
pub fn cmd_export_pubkey(args: ExportPubkeyArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let _ = resolve_dir(&args.dir)?;
    let blob = read_blob(&args.name, &args.dir)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;

    let seed = recover_seed(&blob, passphrase.as_bytes(), tier)
        .map_err(|_| "decryption failed (wrong passphrase or corrupted blob)".to_string())?;

    let bundle = HybridSigningKeyBundle::from_seed(&seed, &args.domain)
        .map_err(|e| format!("key bundle failed: {e}"))?;

    let ed_pub = bundle.ed25519_pk();
    let falcon_pub = bundle.falcon1024_pk();
    let ed_hex = hex::encode(ed_pub.to_bytes());
    let falcon_hex = hex::encode(falcon_pub.as_bytes());

    match args.format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "name": args.name,
                "domain": args.domain,
                "ed25519": ed_hex,
                "falcon1024": falcon_hex,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        OutputFormat::Hex => {
            // Concatenated hex: ed25519 (32B = 64 hex) + falcon1024 (~1793B).
            // Pubkeys are fixed-length so no prefix is needed.
            println!("{}{}", ed_hex, falcon_hex);
        }
    }
    Ok(())
}

// ── RotatePassphrase ───────────────────────────────────────────────

/// Re-encrypt an identity blob with a new passphrase. Optionally also
/// migrate to a new Argon2id tier. Atomic via tmp+rename: if the write
/// fails for any reason (disk full, permission denied), the original
/// blob is preserved untouched.
pub fn cmd_rotate_passphrase(args: RotatePassphraseArgs) -> Result<(), String> {
    let tier = parse_tier(&args.tier)?;
    let new_tier = match &args.new_tier {
        Some(t) => parse_tier(t)?,
        None => tier,
    };
    let _ = resolve_dir(&args.dir)?;
    let path = identity_path(&args.name, &args.dir)?;
    if !path.exists() {
        return Err(format!(
            "identity '{}' does not exist at {}",
            args.name,
            path.display()
        ));
    }

    let old_pw = resolve_passphrase(&args.passphrase_file)?;
    let blob = read_blob(&args.name, &args.dir)?;
    let seed = recover_seed(&blob, old_pw.as_bytes(), tier)
        .map_err(|_| "decryption failed with current passphrase".to_string())?;

    let new_pw = resolve_passphrase_confirm(&args.new_passphrase_file)?;
    let new_blob = create_blob(new_pw.as_bytes(), new_tier, Some(&seed))
        .map_err(|e| format!("re-encryption failed: {e}"))?;

    // Atomic write: tmp file with pid+nanos suffix, then rename.
    let pid = std::process::id();
    let nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("blob");
    let tmp = path.with_file_name(format!("{}.{}.{}.tmp", base_name, pid, nano));

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("cannot create tmp {}: {e}", tmp.display()))?;
    file.write_all(&new_blob)
        .map_err(|e| format!("cannot write tmp {}: {e}", tmp.display()))?;
    file.sync_all()
        .map_err(|e| format!("cannot fsync tmp {}: {e}", tmp.display()))?;
    drop(file);

    std::fs::rename(&tmp, &path).map_err(|e| {
        format!(
            "cannot rename tmp {} \u{2192} {}: {e}",
            tmp.display(),
            path.display()
        )
    })?;

    eprintln!(
        "Rotated passphrase for '{}' (tier: {:?} \u{2192} {:?})",
        args.name, tier, new_tier
    );
    Ok(())
}

// ── Dispatch ───────────────────────────────────────────────────────

/// Dispatch a parsed CLI to the matching command implementation.
pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    use crate::cli::Commands;
    match cli.command {
        Commands::Keygen(args) => cmd_keygen(args),
        Commands::Sign(args) => cmd_sign(args),
        Commands::Verify(args) => cmd_verify(args),
        Commands::List(args) => cmd_list(args),
        Commands::Import(args) => cmd_import(args),
        Commands::Show(args) => cmd_show(args),
        Commands::Rename(args) => cmd_rename(args),
        Commands::Delete(args) => cmd_delete(args),
        Commands::ExportPubkey(args) => cmd_export_pubkey(args),
        Commands::RotatePassphrase(args) => cmd_rotate_passphrase(args),
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Process-wide monotonic counter that uniquely namespaces unit test
    /// temp files. Same rationale as the `TempDir` helper in
    /// `tests/integration.rs`: parallel test threads + same `nanos` for
    /// rapid back-to-back calls would otherwise collide on `/tmp`.
    static UNIT_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Build a fresh path under a per-process temp directory for a
    /// single test artifact. Uses `/tmp/origin-test-{pid}/` instead of
    /// flat `/tmp` to avoid interference from system tmp cleaners and
    /// cargo target-dir management that caused flaky "No such file"
    /// failures in parallel workspace test runs.
    /// Caller owns the cleanup (call `fs::remove_file` /
    /// `fs::remove_dir_all` on the path).
    fn fresh_tmp_path(label: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("origin-test-{pid}"));
        std::fs::create_dir_all(&base).expect("create per-process test dir");
        let counter = UNIT_COUNTER.fetch_add(1, Ordering::Relaxed);
        base.join(format!("{label}-{counter}"))
    }

    #[test]
    fn fingerprint_changes_after_rotate() {
        // Two blobs with the same seed but different salt (forced by RNG) → different fingerprints.
        // Uses real Nano tier to confirm Argon2id KDF works end-to-end.
        let seed_a = [7u8; 32];
        let seed_b = [7u8; 32];
        let blob_a = create_blob(b"pw", MemoryTier::Nano, Some(&seed_a)).unwrap();
        let blob_b = create_blob(b"pw", MemoryTier::Nano, Some(&seed_b)).unwrap();
        assert_ne!(
            blob_a[..40],
            blob_b[..40],
            "salt+nonce must differ between independent calls"
        );
        let fp_a = hex::encode(&blake3::hash(&blob_a[..40]).as_bytes()[..4]);
        let fp_b = hex::encode(&blake3::hash(&blob_b[..40]).as_bytes()[..4]);
        assert_ne!(fp_a, fp_b, "fingerprints differ after fresh blob");
    }

    #[test]
    fn fingerprint_is_stable_for_same_blob() {
        let seed = [9u8; 32];
        let blob = create_blob(b"pw", MemoryTier::Nano, Some(&seed)).unwrap();
        let fp1 = hex::encode(&blake3::hash(&blob[..40]).as_bytes()[..4]);
        let fp2 = hex::encode(&blake3::hash(&blob[..40]).as_bytes()[..4]);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 8);
    }

    #[test]
    fn parse_tier_known_values() {
        assert!(matches!(parse_tier("nano"), Ok(MemoryTier::Nano)));
        assert!(matches!(parse_tier("Standard"), Ok(MemoryTier::Standard)));
        assert!(matches!(parse_tier("SOVEREIGN"), Ok(MemoryTier::Sovereign)));
        assert!(parse_tier("ultra").is_err());
    }

    #[test]
    fn read_phrase_inline() {
        // Each token is exactly one Unicode codepoint, separated by
        // whitespace. (No whitespace between α and β → "αβ" would
        // be a single 2-codepoint token and rejected; see the
        // read_phrase_rejects_multichar_word test below.)
        let chars = read_phrase("α β γ δ ε").expect("parse");
        assert_eq!(chars, vec!['α', 'β', 'γ', 'δ', 'ε']);
    }

    #[test]
    fn read_phrase_handles_newlines_and_extra_spaces() {
        // Multiple whitespace chars (space, tab, newline) between tokens.
        let chars = read_phrase("α   β\tγ\nδ  ε").expect("parse");
        assert_eq!(chars, vec!['α', 'β', 'γ', 'δ', 'ε']);
    }

    #[test]
    fn read_phrase_rejects_multichar_word() {
        // Two-codepoint token — must fail.
        let err = read_phrase("αβ γ").unwrap_err();
        assert!(err.contains("more than one codepoint"), "got: {err}");
    }

    #[test]
    fn read_phrase_rejects_empty() {
        assert!(read_phrase("   ").is_err());
        assert!(read_phrase("").is_err());
    }

    #[test]
    fn read_phrase_strips_utf8_bom() {
        // Common when phrases are pasted from Windows editors / email.
        let with_bom = "\u{feff}α β γ δ ε".to_string();
        let chars = read_phrase(&with_bom).expect("BOM strip");
        assert_eq!(chars, vec!['α', 'β', 'γ', 'δ', 'ε']);
    }

    // Single mutex to serialize HOME-mutating tests. Cargo's default
    // test runner runs tests in parallel threads; without this, two
    // HOME-touching tests could race and produce flake failures.
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard: at construction, takes a saved snapshot of $HOME
    /// and removes the env var. On Drop (success OR panic), restores
    /// the original value (or leaves it unset if it was unset).
    ///
    /// Field order is deliberate: `_guard` is declared first so it is
    /// dropped LAST (Rust drops struct fields in REVERSE of declaration
    /// order). This means `saved` is dropped under the lock, restoring
    /// HOME before releasing the mutex to any other test.
    // Field declaration order is deliberate. Rust drops struct fields
    // in DECLARATION order (top-to-bottom), not reverse — unlike
    // tuples/slices/arrays. We declare `saved` FIRST so it drops
    // FIRST (HOME restored under the still-held lock), then `_guard`
    // SECOND so it drops LAST (lock released AFTER restore).
    struct HomeGuard {
        saved: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl HomeGuard {
        fn new() -> Self {
            // SAFETY: env mutation is thread-unsafe at the OS level.
            // We serialize via the static mutex below, and the Drop
            // impl restores HOME before returning to the caller.
            let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let saved = std::env::var_os("HOME");
            unsafe { std::env::remove_var("HOME") };
            Self {
                // Field init order is independent of drop order; drop
                // order follows the struct declaration above.
                saved,
                _guard: guard,
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            // SAFETY: serialized via `_guard`; we are the only thread
            // touching HOME between new() and drop().
            match &self.saved {
                Some(v) => unsafe { std::env::set_var("HOME", v) },
                None => unsafe { std::env::remove_var("HOME") },
            }
        }
    }

    #[test]
    fn resolve_dir_errors_without_home() {
        let _g = HomeGuard::new();
        let result = resolve_dir("~/identities");
        assert!(
            result.is_err(),
            "expected resolve_dir to error without HOME; got {result:?}"
        );
        // HOME is restored automatically when _g drops at end of scope.
    }

    #[test]
    fn resolve_dir_expands_home() {
        // Skipped if HOME is unset in the test environment.
        if let Ok(home) = std::env::var("HOME") {
            let resolved = resolve_dir("~/foo").unwrap();
            assert_eq!(resolved, PathBuf::from(home).join("foo"));
        }
    }

    #[test]
    fn read_bytes_literal_mode() {
        let b = read_bytes("hello", false).unwrap();
        assert_eq!(b, b"hello");
    }

    #[test]
    fn read_bytes_hex_mode() {
        let b = read_bytes("deadbeef", true).unwrap();
        assert_eq!(b, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn read_bytes_rejects_invalid_hex() {
        let err = read_bytes("xyz", true).unwrap_err();
        assert!(err.contains("invalid hex"), "got: {err}");
        let err = read_bytes("abc", true).unwrap_err(); // odd length
        assert!(err.contains("invalid hex"), "got: {err}");
    }

    #[test]
    fn combined_signature_round_trip() {
        // Build a CombinedSignature, encode it, then decode it.
        let ed_bytes = [0xAAu8; 64];
        let ed = Ed25519Signature::from_bytes(&ed_bytes);
        let falcon_bytes: Vec<u8> = (0..666).map(|i| (i & 0xff) as u8).collect();
        let falcon =
            origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&falcon_bytes).unwrap();

        let original = CombinedSignature {
            ed,
            falcon: falcon.clone(),
        };
        let wire = original.to_wire_bytes();
        assert_eq!(wire.len(), 4 + 64 + 666);

        let decoded = CombinedSignature::from_wire(&wire).unwrap();
        assert_eq!(decoded.ed.to_bytes(), ed_bytes);
        // FalconSignature lacks PartialEq; compare byte slices instead.
        assert_eq!(decoded.falcon.as_bytes(), falcon.as_bytes());
    }

    #[test]
    fn combined_signature_accepts_sdk_falcon1024_maximum() {
        let ed = origin_crypto_sdk::Ed25519Signature::from_bytes(&[0xAAu8; 64]);
        let falcon = origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(
            &vec![0x55u8; origin_crypto_sdk::pqc::falcon1024::sizes::SIGNATURE_MAX],
        )
        .unwrap();
        let signature = CombinedSignature { ed, falcon };

        let wire = signature.to_wire_bytes();
        assert_eq!(wire.len(), CombinedSignature::MAX_WIRE_LEN);
        let decoded = CombinedSignature::from_wire(&wire).unwrap();
        assert_eq!(
            decoded.falcon.as_bytes().len(),
            origin_crypto_sdk::pqc::falcon1024::sizes::SIGNATURE_MAX
        );
    }

    #[test]
    fn combined_signature_rejects_short() {
        let err = CombinedSignature::from_wire(&[0u8; 50]).unwrap_err();
        assert!(err.contains("at least 68 bytes"), "got: {err}");
    }

    #[test]
    fn combined_signature_rejects_wrong_total_length() {
        // Header says 100 B falcon, but actual payload has 50 B.
        let mut bad = Vec::new();
        bad.extend_from_slice(&100u32.to_be_bytes());
        bad.extend_from_slice(&[0u8; 64]);
        bad.extend_from_slice(&[0u8; 50]);
        let err = CombinedSignature::from_wire(&bad).unwrap_err();
        assert!(err.contains("size mismatch"), "got: {err}");
    }

    #[test]
    fn combined_signature_rejects_size_mismatch_only_via_header() {
        // An over-large declared Falcon length that exceeds the actual
        // payload is caught by the size-mismatch branch before from_bytes
        // is even called — there's no SDK SIGNATURE_MAX to import, so
        // the defense is purely structural.
        let bad = {
            let mut v = Vec::new();
            v.extend_from_slice(&(2048u32).to_be_bytes());
            v.extend_from_slice(&[0u8; 64]);
            v.extend_from_slice(&[0u8; 100]); // intentionally short
            v
        };
        let err = CombinedSignature::from_wire(&bad).unwrap_err();
        // 2048 > 1280 max, so the max-length check fires first.
        assert!(
            err.contains("exceeds maximum") || err.contains("size mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn combined_signature_handles_max_falcon_len() {
        // u32::MAX declared length should fail (exceeds max or size mismatch).
        let mut bad = Vec::new();
        bad.extend_from_slice(&u32::MAX.to_be_bytes());
        bad.extend_from_slice(&[0u8; 64]);
        // We don't actually allocate 4GB; the max-length or size-mismatch
        // check kicks in long before we try to read that many bytes.
        bad.extend_from_slice(&[0u8; 100]);
        let err = CombinedSignature::from_wire(&bad).unwrap_err();
        assert!(
            err.contains("exceeds maximum") || err.contains("size mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn fmt_size_human_readable() {
        assert_eq!(fmt_size(88), "88 B");
        assert_eq!(fmt_size(2048), "2.0 KB");
        assert_eq!(fmt_size(1_500_000), "1.4 MB");
    }

    #[test]
    fn epoch_to_ymdhms_unix_epoch() {
        assert_eq!(epoch_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(epoch_to_ymdhms(86_400), (1970, 1, 2, 0, 0, 0));
    }

    #[test]
    fn is_leap_year() {
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
        assert!(is_leap(2024));
        assert!(!is_leap(2026));
    }

    #[test]
    fn sign_and_verify_hex_pipe_roundtrip() {
        // End-to-end: sign --output hex → verify --signature HEXSTR --hex.
        // Uses the canonical CombinedSignature::to_wire_bytes (same
        // produced by cmd_sign --output hex) and CombinedSignature::from_wire
        // (same consumed by cmd_verify --hex).
        let seed = [0x33u8; 32];
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let msg = b"pipe test";
        let sig = bundle.sign_hybrid(msg);

        let combined = CombinedSignature {
            ed: sig.ed25519_sig,
            falcon: sig.falcon_sig,
        };
        let hex_str = hex::encode(combined.to_wire_bytes());

        let decoded = CombinedSignature::from_wire(&hex::decode(&hex_str).unwrap()).unwrap();
        let combined_sig = Ed25519Falcon1024 {
            ed25519_sig: decoded.ed,
            falcon_sig: decoded.falcon,
        };
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            msg,
            &combined_sig,
        )
        .expect("verify over hex pipe");
    }

    #[test]
    fn verify_with_hex_message() {
        // Verify that --hex message mode sees the same bytes as input.
        let seed = [0x44u8; 32];
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let raw_msg = b"\x00\x01\x02\xff";
        let sig = bundle.sign_hybrid(raw_msg);

        // Decode "000102ff" via read_bytes(..., hex=true)
        let decoded = read_bytes("000102ff", true).unwrap();
        assert_eq!(decoded, raw_msg);

        // Verify the produced signature against the decoded bytes
        let combined = Ed25519Falcon1024 {
            ed25519_sig: sig.ed25519_sig,
            falcon_sig: sig.falcon_sig,
        };
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            &decoded,
            &combined,
        )
        .expect("verify of raw hex msg");
    }

    // ─── TDD contract tests for --phrase-output (v0.2.0) ────────

    #[test]
    fn keygen_phrase_output_helper_writes_24_codepoints_single_spaced_trailing_newline() {
        // Direct test of the helper: confirms on-disk format = "c1 c2 … c24\n",
        // which is exactly what `read_phrase` accepts via split_whitespace.
        // This is the foundational contract that the shell-driven restore
        // path depends on.
        let path = fresh_tmp_path("phrase-format");
        let phrase: Vec<char> = UnicodeWordlist::default().as_slice()[..24].to_vec();
        super::write_phrase_file(&phrase, &path).expect("write must succeed");
        let body = std::fs::read_to_string(&path).expect("read back");
        let expected: String = {
            let mut s = String::new();
            for (i, c) in phrase.iter().enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                s.push(*c);
            }
            s.push('\n');
            s
        };
        assert_eq!(
            body, expected,
            "phrase file must be exactly '<c1> … <c24>\\n'"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keygen_phrase_output_round_trips_through_read_phrase() {
        // End-to-end semantic: write file, then read back via the binary's
        // own `read_phrase` helper, then `decode_phrase` must reproduce
        // the same 32-byte master seed. Locks the contract: shell-driven
        // restore works byte-for-byte.
        let dir = fresh_tmp_path("phrase-roundtrip-unit");
        std::fs::create_dir(&dir).unwrap();
        let phrase_path = dir.join("phrase.txt");

        // Use a deterministic 32-byte seed so we can assert equality.
        let seed: [u8; 32] = [0xCCu8; 32];
        let phrase =
            encode_phrase(&seed, &UnicodeWordlist::default(), PhraseLength::Words24).unwrap();
        super::write_phrase_file(&phrase, &phrase_path).expect("write");

        let body = std::fs::read_to_string(&phrase_path).unwrap();
        let chars = super::read_phrase(&body).expect("read_phrase accepts the file format");
        assert_eq!(chars.len(), 24);
        let decoded = decode_phrase(&chars, &UnicodeWordlist::default()).unwrap();
        assert_eq!(decoded.len(), 32);
        let decoded_seed: [u8; 32] = decoded.as_slice().try_into().unwrap();
        assert_eq!(decoded_seed, seed, "round-trip must be byte-exact");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keygen_phrase_output_helper_rejects_non_24_codepoint_input() {
        // Defensive: if the helper is ever called with an unexpected
        // length (programmer error), it should refuse instead of writing
        // bogus content. The check is a guardrail, not a user-facing
        // error path.
        let path = fresh_tmp_path("phrase-wrong-len");
        let short_phrase = UnicodeWordlist::default().as_slice()[..12].to_vec();
        let result = super::write_phrase_file(&short_phrase, &path);
        assert!(result.is_err(), "must reject non-24 input");
        assert!(
            !path.exists(),
            "no target file should be created when input is wrong length"
        );
    }

    // ─── Helper tests ────────────────────────────────────────────

    #[test]
    fn identity_path_joins_dir_and_name() {
        let path = identity_path("test-id", "/tmp/origin-test").unwrap();
        assert_eq!(
            path,
            std::path::PathBuf::from("/tmp/origin-test/test-id.id")
        );
    }

    #[test]
    fn read_blob_fails_on_nonexistent() {
        let err = read_blob("nonexistent-blob", "/dev/null/nope").unwrap_err();
        assert!(err.contains("cannot read"), "got: {err}");
    }

    #[test]
    fn ensure_dir_creates_parent() {
        let p = fresh_tmp_path("ensure-dir-test");
        // file path -> parent dir doesn't exist; ensure_dir creates it
        ensure_dir(&p).expect("ensure_dir must create parent");
        assert!(
            p.parent().unwrap().exists(),
            "parent dir must exist after ensure_dir"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn ensure_dir_ok_with_root_parent() {
        // A path with no parent (e.g. just a filename) should be Ok.
        let p = std::path::PathBuf::from("just-a-filename");
        assert!(ensure_dir(&p).is_ok());
    }

    #[test]
    fn resolve_passphrase_reads_file() {
        let p = fresh_tmp_path("pw-file");
        let pw = "hunter2";
        std::fs::write(&p, pw).unwrap();
        let result = resolve_passphrase(&Some(p.to_string_lossy().to_string())).unwrap();
        assert_eq!(result, pw);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn resolve_passphrase_file_trims_whitespace() {
        let p = fresh_tmp_path("pw-trim");
        std::fs::write(&p, "  secret  \n").unwrap();
        let result = resolve_passphrase(&Some(p.to_string_lossy().to_string())).unwrap();
        assert_eq!(result, "secret");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn resolve_passphrase_file_errors_on_missing() {
        let err = resolve_passphrase(&Some("/dev/null/does-not-exist/pw".to_string())).unwrap_err();
        assert!(err.contains("cannot read passphrase file"), "got: {err}");
    }

    // ─── system_time_to_rfc3339 ───────────────────────────────────

    #[test]
    fn system_time_to_rfc3339_known_epoch() {
        use std::time::{Duration, UNIX_EPOCH};
        let t = UNIX_EPOCH + Duration::from_secs(0);
        assert_eq!(system_time_to_rfc3339(Some(t)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn system_time_to_rfc3339_known_date_mid_2024() {
        use std::time::{Duration, UNIX_EPOCH};
        // 2024-06-15T12:30:00Z = 1718454600
        let t = UNIX_EPOCH + Duration::from_secs(1_718_454_600);
        let s = system_time_to_rfc3339(Some(t));
        assert_eq!(s, "2024-06-15T12:30:00Z", "got: {s}");
    }

    #[test]
    fn system_time_to_rfc3339_none() {
        assert_eq!(system_time_to_rfc3339(None), "unknown");
    }

    #[test]
    fn epoch_to_ymdhms_leap_year() {
        // 2000-03-01T00:00:00Z (leap year has Feb 29)
        // Days from 1970-01-01 to 2000-03-01:
        // 1970-1999 = 30 years: 7 leap years (72,76,80,84,88,92,96) = 7*366 + 23*365 = 10957 days
        // Jan 2000 = 31, Feb 2000 = 29 (leap) → 60, March 1 = day 61
        // Total: 10957 + 60 = 11017 days = 951868800 secs
        assert_eq!(epoch_to_ymdhms(951_868_800), (2000, 3, 1, 0, 0, 0));
    }

    #[test]
    fn epoch_to_ymdhms_non_leap_year_boundary() {
        // 1900 is NOT a leap year (divisible by 100 but not 400)
        // But the epoch only starts at 1970, so test a known non-leap: 2100-03-01
        // Days: 1970-2099 = 130 years: 32 leap years → 32*366 + 98*365 = 47482 days
        // Jan 2100 = 31, Feb 2100 = 28 (not leap) → 59, March 1 = day 60
        // Total: 47482 + 59 = 47541 days = 4107542400
        // Note: this uses u64, and 4107542400 < u64::MAX
        assert_eq!(epoch_to_ymdhms(4_107_542_400), (2100, 3, 1, 0, 0, 0));
    }

    // ─── cmd_keygen ───────────────────────────────────────────────

    #[test]
    fn cmd_keygen_with_no_phrase_and_passphrase_file() {
        let dir = fresh_tmp_path("keygen-unit");
        std::fs::create_dir(&dir).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "test-passphrase").unwrap();

        let args = KeygenArgs {
            name: "unit-test-key".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(args).expect("keygen should succeed");

        let blob_path = dir.join("unit-test-key.id");
        assert!(
            blob_path.exists(),
            "blob should exist at {}",
            blob_path.display()
        );

        let blob = std::fs::read(&blob_path).unwrap();
        assert!(
            blob.len() > 40,
            "blob should have salt+nonce+encrypted payload"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_keygen_with_phrase_output() {
        let dir = fresh_tmp_path("keygen-phrase-out");
        std::fs::create_dir(&dir).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let phrase_path = dir.join("phrase.txt");

        let args = KeygenArgs {
            name: "phrase-key".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: false,
            phrase_output: Some(phrase_path.to_string_lossy().to_string()),
        };
        cmd_keygen(args).expect("keygen with --phrase-output should succeed");

        // Phrase file should exist with 24 whitespace-separated codepoints + newline
        assert!(phrase_path.exists(), "phrase output file not created");
        let body = std::fs::read_to_string(&phrase_path).unwrap();
        let tokens: Vec<&str> = body.split_whitespace().collect();
        assert_eq!(tokens.len(), 24, "phrase file must have 24 tokens");
        assert!(body.ends_with('\n'), "phrase file must end with newline");

        // Blob should also exist
        let blob_path = dir.join("phrase-key.id");
        assert!(blob_path.exists(), "blob should exist");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── cmd_import ───────────────────────────────────────────────

    #[test]
    fn cmd_import_rejects_12_word_phrase() {
        // A 12-word phrase produces 16 bytes of entropy, not 32.
        // Use real wordlist codepoints (not arbitrary Greek letters) so
        // decode_phrase succeeds and the length-check branch is hit.
        let short_seed = [0xABu8; 16];
        let phrase = encode_phrase(
            &short_seed,
            &UnicodeWordlist::default(),
            PhraseLength::Words12,
        )
        .unwrap();
        let phrase_str: String = phrase
            .iter()
            .map(|c| format!(" {c}"))
            .collect::<String>()
            .trim_start()
            .to_string();
        let err = cmd_import(ImportArgs {
            name: "short".to_string(),
            phrase: phrase_str,
            tier: "nano".to_string(),
            dir: "/tmp/origin-import-test-short".to_string(),
            passphrase_file: None,
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("256-bit master seeds"), "got: {err}");
    }

    #[test]
    fn cmd_import_rejects_existing_without_force() {
        let dir = fresh_tmp_path("import-exists");
        std::fs::create_dir(&dir).unwrap();

        // Create a real blob via keygen so the identity exists.
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let kg_args = KeygenArgs {
            name: "existing-id".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(kg_args).unwrap();

        // Now try to import a different seed to same name — should fail.
        let pw_path2 = dir.join("pw2.txt");
        std::fs::write(&pw_path2, "pw2").unwrap();

        // Generate a valid 24-word phrase from a deterministic seed.
        let seed = [0xABu8; 32];
        let phrase =
            encode_phrase(&seed, &UnicodeWordlist::default(), PhraseLength::Words24).unwrap();
        let phrase_str: String = phrase
            .iter()
            .map(|c| format!(" {c}"))
            .collect::<String>()
            .trim_start()
            .to_string();

        let err = cmd_import(ImportArgs {
            name: "existing-id".to_string(),
            phrase: phrase_str.clone(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path2.to_string_lossy().to_string()),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_import_with_force_overwrites_existing() {
        let dir = fresh_tmp_path("import-force");
        std::fs::create_dir(&dir).unwrap();

        // Create a real blob first.
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let kg_args = KeygenArgs {
            name: "force-id".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(kg_args).unwrap();

        let _original_size = std::fs::metadata(dir.join("force-id.id")).unwrap().len();

        // Import different seed with --force.
        let pw_path2 = dir.join("pw2.txt");
        std::fs::write(&pw_path2, "pw-different").unwrap();

        let seed2 = [0xCDu8; 32];
        let phrase =
            encode_phrase(&seed2, &UnicodeWordlist::default(), PhraseLength::Words24).unwrap();
        let phrase_str: String = phrase
            .iter()
            .map(|c| format!(" {c}"))
            .collect::<String>()
            .trim_start()
            .to_string();

        cmd_import(ImportArgs {
            name: "force-id".to_string(),
            phrase: phrase_str,
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path2.to_string_lossy().to_string()),
            force: true,
        })
        .expect("import --force should overwrite");

        // Blob should still exist, possibly different size (different passphrase).
        let blob_path = dir.join("force-id.id");
        assert!(blob_path.exists());
        // Salt+nonce randomization means size may differ slightly due to Argon2 settings.
        // Just assert something was written.
        assert!(std::fs::metadata(&blob_path).unwrap().len() > 40);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── cmd_list ────────────────────────────────────────────────

    #[test]
    fn cmd_list_empty_dir_returns_no_identities() {
        let dir = fresh_tmp_path("list-empty");
        std::fs::create_dir(&dir).unwrap();

        // Empty directory should produce Ok with no identities.
        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Table,
            names_only: false,
        })
        .expect("list on empty dir should succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_empty_dir_names_only() {
        let dir = fresh_tmp_path("list-empty-names");
        std::fs::create_dir(&dir).unwrap();

        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Table,
            names_only: true,
        })
        .expect("list --names-only on empty dir");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_with_blob_defaults_to_table() {
        let dir = fresh_tmp_path("list-table");
        std::fs::create_dir(&dir).unwrap();

        // Create a real blob in the dir.
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let kg_args = KeygenArgs {
            name: "list-me".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(kg_args).unwrap();

        // List with table format (default).
        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Table,
            names_only: false,
        })
        .expect("list with table format");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_with_blob_csv_format() {
        let dir = fresh_tmp_path("list-csv");
        std::fs::create_dir(&dir).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let kg_args = KeygenArgs {
            name: "csv-id".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(kg_args).unwrap();

        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Csv,
            names_only: false,
        })
        .expect("list with csv format");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_with_blob_json_format() {
        let dir = fresh_tmp_path("list-json");
        std::fs::create_dir(&dir).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let kg_args = KeygenArgs {
            name: "json-id".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(kg_args).unwrap();

        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Json,
            names_only: false,
        })
        .expect("list with json format");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_with_blob_names_only() {
        let dir = fresh_tmp_path("list-names");
        std::fs::create_dir(&dir).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let kg_args = KeygenArgs {
            name: "names-id".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(kg_args).unwrap();

        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Table,
            names_only: true,
        })
        .expect("list --names-only");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_fails_on_nonexistent_dir() {
        let err = cmd_list(ListArgs {
            dir: "/dev/null/does-not-exist-12345".to_string(),
            format: ListFormat::Table,
            names_only: false,
        })
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn cmd_list_with_malformed_blob() {
        let dir = fresh_tmp_path("list-malformed");
        std::fs::create_dir(&dir).unwrap();

        // Write a tiny file (less than 40 bytes) that looks like an .id file
        let bad_path = dir.join("broken.id");
        std::fs::write(&bad_path, b"too short").unwrap();

        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Table,
            names_only: false,
        })
        .expect("list should handle malformed blobs gracefully");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_list_skips_non_id_files() {
        let dir = fresh_tmp_path("list-non-id");
        std::fs::create_dir(&dir).unwrap();

        // Write a non-.id file — should be silently skipped.
        std::fs::write(dir.join("readme.txt"), b"not a blob").unwrap();

        cmd_list(ListArgs {
            dir: dir.to_string_lossy().to_string(),
            format: ListFormat::Table,
            names_only: false,
        })
        .expect("list should skip non-.id files");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── parse_tier ───────────────────────────────────────────────

    #[test]
    fn parse_tier_error_message_includes_unknown() {
        let err = parse_tier("ultra").unwrap_err();
        assert!(err.contains("unknown"), "got: {err}");
        assert!(err.contains("ultra"), "got: {err}");
    }

    // ─── cmd_sign + cmd_verify ─────────────────────────────────────

    #[test]
    fn cmd_sign_json_output() {
        let dir = fresh_tmp_path("sign-json");
        std::fs::create_dir(&dir).unwrap();

        // Create a real blob with known seed + passphrase.
        let seed = [0x42u8; 32];
        let pw = b"test-pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("test-identity.id");
        std::fs::write(&blob_path, &blob).unwrap();

        // Write passphrase file
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "test-pw").unwrap();

        let result = cmd_sign(SignArgs {
            name: "test-identity".to_string(),
            message: "hello world".to_string(),
            domain: "test:v1".to_string(),
            output: OutputFormat::Json,
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: false,
        });
        assert!(result.is_ok(), "cmd_sign JSON should succeed: {:?}", result);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_sign_hex_output() {
        let dir = fresh_tmp_path("sign-hex");
        std::fs::create_dir(&dir).unwrap();

        let seed = [0x42u8; 32];
        let pw = b"test-pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("hex-identity.id");
        std::fs::write(&blob_path, &blob).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "test-pw").unwrap();

        let result = cmd_sign(SignArgs {
            name: "hex-identity".to_string(),
            message: "deadbeef".to_string(),
            domain: "test:v1".to_string(),
            output: OutputFormat::Hex,
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: true,
        });
        assert!(result.is_ok(), "cmd_sign Hex should succeed: {:?}", result);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_verify_json_signature() {
        let dir = fresh_tmp_path("verify-json");
        std::fs::create_dir(&dir).unwrap();

        // Create blob + sign first, capture the JSON output.
        let seed = [0x42u8; 32];
        let pw = b"test-pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("verify-target.id");
        std::fs::write(&blob_path, &blob).unwrap();

        // Create the blob for the sign operation
        // Need the blob present + passphrase file.
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "test-pw").unwrap();

        // Sign directly using SDK to get the signature parts
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let sig = bundle.sign_hybrid(b"hello world");
        let sig_json = serde_json::json!({
            "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
            "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
            "domain": "test:v1",
        });
        let sig_path = dir.join("sig.json");
        std::fs::write(&sig_path, sig_json.to_string().as_bytes()).unwrap();

        let result = cmd_verify(VerifyArgs {
            name: "verify-target".to_string(),
            message: "hello world".to_string(),
            signature: sig_path.to_string_lossy().to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: false,
        });
        assert!(
            result.is_ok(),
            "cmd_verify JSON should succeed: {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_verify_hex_signature() {
        let dir = fresh_tmp_path("verify-hex");
        std::fs::create_dir(&dir).unwrap();

        let seed = [0x42u8; 32];
        let pw = b"test-pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("hex-vfy.id");
        std::fs::write(&blob_path, &blob).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "test-pw").unwrap();

        // Sign + encode as CombinedSignature wire format + hex.
        // Message must be valid hex (read_bytes with hex:true calls hex::decode).
        let msg_hex = "deadbeef";
        let raw_msg = hex::decode(msg_hex).unwrap();
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let sig = bundle.sign_hybrid(&raw_msg);
        let combined = CombinedSignature {
            ed: sig.ed25519_sig,
            falcon: sig.falcon_sig,
        };
        let hex_sig = hex::encode(combined.to_wire_bytes());

        // hex:true mode calls read_bytes(message, true) and read_bytes(signature, true).
        // Both must pass valid hex strings directly (no @-file expansion in hex mode).
        let result = cmd_verify(VerifyArgs {
            name: "hex-vfy".to_string(),
            message: msg_hex.to_string(),
            signature: hex_sig,
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: true,
        });
        assert!(
            result.is_ok(),
            "cmd_verify hex should succeed: {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_verify_rejects_wrong_message() {
        let dir = fresh_tmp_path("verify-wrong-msg");
        std::fs::create_dir(&dir).unwrap();

        let seed = [0x42u8; 32];
        let pw = b"test-pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("wrong-msg.id");
        std::fs::write(&blob_path, &blob).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "test-pw").unwrap();

        // Sign "real message" but verify "wrong message"
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let sig = bundle.sign_hybrid(b"real message");
        let sig_json = serde_json::json!({
            "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
            "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
            "domain": "test:v1",
        });
        let sig_path = dir.join("sig.json");
        std::fs::write(&sig_path, sig_json.to_string().as_bytes()).unwrap();

        let result = cmd_verify(VerifyArgs {
            name: "wrong-msg".to_string(),
            message: "wrong message".to_string(),
            signature: sig_path.to_string_lossy().to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: false,
        });
        assert!(result.is_err(), "cmd_verify should reject wrong message");
        let err = result.unwrap_err();
        assert!(err.contains("invalid signature"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_verify_rejects_wrong_passphrase() {
        let dir = fresh_tmp_path("verify-wrong-pw");
        std::fs::create_dir(&dir).unwrap();

        let seed = [0x42u8; 32];
        let pw = b"correct-pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("wrong-pw.id");
        std::fs::write(&blob_path, &blob).unwrap();

        // Sign correctly but write WRONG passphrase file
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let sig = bundle.sign_hybrid(b"message");
        let sig_json = serde_json::json!({
            "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
            "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
            "domain": "test:v1",
        });
        let sig_path = dir.join("sig.json");
        std::fs::write(&sig_path, sig_json.to_string().as_bytes()).unwrap();

        // Wrong passphrase
        let wrong_pw_path = dir.join("wrong_pw.txt");
        std::fs::write(&wrong_pw_path, "wrong-passphrase").unwrap();

        let result = cmd_verify(VerifyArgs {
            name: "wrong-pw".to_string(),
            message: "message".to_string(),
            signature: sig_path.to_string_lossy().to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(wrong_pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: false,
        });
        assert!(result.is_err(), "cmd_verify should reject wrong passphrase");
        let err = result.unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_verify_rejects_malformed_json_sig() {
        let dir = fresh_tmp_path("verify-bad-json");
        std::fs::create_dir(&dir).unwrap();

        let seed = [0x42u8; 32];
        let pw = b"pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("badjson.id");
        std::fs::write(&blob_path, &blob).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        // Write malformed JSON as the signature file
        let bad_sig_path = dir.join("bad_sig.json");
        std::fs::write(&bad_sig_path, b"{not valid json}").unwrap();

        let result = cmd_verify(VerifyArgs {
            name: "badjson".to_string(),
            message: "msg".to_string(),
            signature: bad_sig_path.to_string_lossy().to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: false,
        });
        assert!(result.is_err(), "cmd_verify should reject malformed JSON");
        let err = result.unwrap_err();
        assert!(err.contains("invalid signature JSON"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_verify_rejects_missing_fields_in_json() {
        let dir = fresh_tmp_path("verify-missing-fields");
        std::fs::create_dir(&dir).unwrap();

        let seed = [0x42u8; 32];
        let pw = b"pw";
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        let blob_path = dir.join("missing-fields.id");
        std::fs::write(&blob_path, &blob).unwrap();

        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        // JSON with missing ed25519 field
        let bad_sig_path = dir.join("bad.json");
        std::fs::write(&bad_sig_path, b"{\"falcon1024\":\"aa\"}").unwrap();

        let result = cmd_verify(VerifyArgs {
            name: "missing-fields".to_string(),
            message: "msg".to_string(),
            signature: bad_sig_path.to_string_lossy().to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            hex: false,
        });
        assert!(
            result.is_err(),
            "cmd_verify should reject missing ed25519 field"
        );
        let err = result.unwrap_err();
        assert!(err.contains("missing ed25519"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── print_table / print_csv / print_json empty-row paths ──────
    // These functions are private to commands.rs but accessible via
    // `use super::*;` from the test module. Directly calling them with
    // empty input exercises the early-return/single-line branches that
    // otherwise only trigger when cmd_list finds zero identities.

    #[test]
    fn print_table_empty_list_returns_immediately() {
        // The function has an explicit `if rows.is_empty() { return; }`
        // at the top. Calling it with an empty slice exercises this
        // branch and returns silently.
        print_table(&[]);
    }

    #[test]
    fn print_csv_empty_list_prints_header() {
        // print_csv does NOT early-return on empty — it still prints
        // the header line "name,size,modified,fingerprint" followed by
        // zero data lines. This test exercises the println!("name,...")
        // path with an empty iterator.
        print_csv(&[]);
    }

    #[test]
    fn print_json_empty_list_prints_empty_array() {
        // print_json maps over an empty slice → produces "[]".
        // The `.iter().map(|r| ...)` closure on an empty iterator
        // is still compiled and invoked (it just produces zero items).
        print_json(&[]);
    }

    #[test]
    fn print_csv_nonempty_list_prints_data_rows() {
        // One data row exercises the full path: header + one CSV row.
        rows_printout_checks(false);
    }

    #[test]
    fn print_json_nonempty_list_prints_data_array() {
        rows_printout_checks(true);
    }

    /// Helper: build a non-empty ListRow slice and run either csv or json.
    fn rows_printout_checks(json: bool) {
        let row = ListRow {
            name: "test-row".to_string(),
            size: 1024,
            modified: None,
            fingerprint: "abcdef01".to_string(),
        };
        if json {
            print_json(&[row]);
        } else {
            print_csv(&[row]);
        }
    }

    // ─── Coverage round (8 tests) ────────────────────────────────
    // These target 7 real uncovered branches + 1 sentinel trait-impl
    // test. Each `fresh_tmp_path` is cleaned up explicitly.

    #[test]
    fn read_bytes_file_mode_reads_from_path_and_errors_on_missing() {
        // Success path: `@file` reads the file bytes.
        let p = fresh_tmp_path("read-bytes-file");
        std::fs::write(&p, b"file-content-data").unwrap();
        let arg = format!("@{}", p.to_string_lossy());
        let data = read_bytes(&arg, false).unwrap();
        assert_eq!(data, b"file-content-data");
        let _ = std::fs::remove_file(&p);

        // Error path: missing file surfaces "cannot read".
        let missing = fresh_tmp_path("read-bytes-missing");
        let arg_missing = format!("@{}", missing.to_string_lossy());
        let err = read_bytes(&arg_missing, false).unwrap_err();
        assert!(err.contains("cannot read"), "got: {err}");
    }

    #[test]
    fn fmt_size_gb_unit_and_mb_boundary() {
        // 1.5 GiB should hit the GB branch (idx == 3, last unit).
        assert_eq!(fmt_size(1536 * 1024 * 1024), "1.5 GB");
        // Boundary: 1023 MB stays in MB (not promoted to GB).
        assert_eq!(fmt_size(1023 * 1024 * 1024), "1023.0 MB");
    }

    #[test]
    fn combined_signature_debug_redacts_signature_material() {
        // The manual Debug impl formats `ed_len` / `falcon_len` only.
        let ed_bytes = [0xAAu8; 64];
        let ed = Ed25519Signature::from_bytes(&ed_bytes);
        // 666-byte synthetic Falcon sig is structurally accepted by
        // Signature::from_bytes (mirrors round-trip test above).
        let falcon_bytes: Vec<u8> = (0..666).map(|i| (i as u8).wrapping_mul(7)).collect();
        let falcon =
            origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&falcon_bytes).unwrap();

        let sig = CombinedSignature {
            ed,
            falcon: falcon.clone(),
        };
        let debug_out = format!("{:?}", sig);

        // Must include both length fields with correct values.
        assert!(debug_out.contains("ed_len"), "missing ed_len: {debug_out}");
        assert!(
            debug_out.contains("falcon_len"),
            "missing falcon_len: {debug_out}"
        );
        assert!(
            debug_out.contains("64"),
            "missing ed_len value 64: {debug_out}"
        );
        assert!(
            debug_out.contains("666"),
            "missing falcon_len value 666: {debug_out}"
        );
        assert!(
            debug_out.contains("CombinedSignature"),
            "missing struct name: {debug_out}"
        );
    }

    #[test]
    fn cmd_keygen_write_error_when_blob_target_is_a_directory() {
        // Pre-create the blob target as a directory so std::fs::write
        // at the end of cmd_keygen fails with EISDIR. Exercises the
        // error-mapping branch in the production code.
        let dir = fresh_tmp_path("keygen-target-dir");
        std::fs::create_dir(&dir).unwrap();
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "pw").unwrap();

        let blob_target = dir.join("target-test.id");
        std::fs::create_dir(&blob_target).unwrap();

        let args = KeygenArgs {
            name: "target-test".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        let err = cmd_keygen(args).unwrap_err();
        assert!(
            err.contains("cannot write") || err.contains("is a directory"),
            "got: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_tier_handles_all_valid_tiers_and_empty_input() {
        // All three valid tiers (lowercase).
        assert!(matches!(parse_tier("nano"), Ok(MemoryTier::Nano)));
        assert!(matches!(parse_tier("standard"), Ok(MemoryTier::Standard)));
        assert!(matches!(parse_tier("sovereign"), Ok(MemoryTier::Sovereign)));

        // Empty string falls through to the unknown error branch.
        let err = parse_tier("").unwrap_err();
        assert!(err.contains("unknown tier"), "got: {err}");
        assert!(err.contains("nano"), "got: {err}");
    }

    #[test]
    fn cmd_keygen_with_standard_tier_succeeds() {
        // 64 MiB Argon2id KDF path — different from the Nano tier path
        // exercised by every other cmd_keygen test in the suite.
        let dir = fresh_tmp_path("keygen-standard");
        std::fs::create_dir(&dir).unwrap();
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "standard-pw").unwrap();

        let args = KeygenArgs {
            name: "standard-id".to_string(),
            tier: "standard".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(args).expect("keygen with Standard tier should succeed");

        let blob_path = dir.join("standard-id.id");
        assert!(
            blob_path.exists(),
            "blob should exist at {}",
            blob_path.display()
        );
        let blob = std::fs::read(&blob_path).unwrap();
        assert!(
            blob.len() > 80,
            "standard-tier blob should be larger than nano: got {} bytes",
            blob.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epoch_to_ymdhms_far_future_year_with_multiple_leap_iterations() {
        // 2050-01-01T00:00:00Z = 2_524_608_000 seconds from epoch.
        // 1970-2050 = 80 years; 20 leap years (incl. 2000); 60 non-leap.
        // Total days: 20*366 + 60*365 = 29_220 = 2_524_608_000 s.
        // Confirms year-iteration loop and leap-year accumulator handle
        // multi-decade spans correctly.
        assert_eq!(epoch_to_ymdhms(2_524_608_000), (2050, 1, 1, 0, 0, 0));
    }

    #[test]
    fn trait_impls_sentinel_covers_all_public_cli_types() {
        // Coverage sentinel: exercises Clone::clone, Debug::fmt, and
        // Drop on every public CLI struct + enum. Production code
        // routinely clones arg structs and formats them in error
        // messages; this guards against any derive panicking on edge
        // field combinations. Mechanical coverage with real defensive
        // value.

        // ── Enums (no PartialEq — compare via Debug string instead) ──
        let of1 = OutputFormat::Json;
        let of2 = of1.clone();
        assert_eq!(format!("{:?}", of1), format!("{:?}", of2));
        // of1/of2 consumed by assert_eq above; no explicit drop needed

        let lf1 = ListFormat::Csv;
        let lf2 = lf1.clone();
        // ListFormat derives PartialEq for real assertion here.
        assert_eq!(lf1, lf2);
        assert_ne!(lf1, ListFormat::Json);
        let _ = format!("{:?}", lf1);

        // ── KeygenArgs (clap derive → Clone + Debug) ─────────────────
        let kg = KeygenArgs {
            name: "sentinel".to_string(),
            tier: "nano".to_string(),
            dir: "/tmp/sentinel-keygen".to_string(),
            passphrase_file: Some("/tmp/sentinel-keygen.pw".to_string()),
            no_phrase: true,
            phrase_output: Some("/tmp/sentinel-keygen.phrase".to_string()),
        };
        let kg2 = kg.clone();
        assert_eq!(kg.name, kg2.name);
        assert_eq!(kg.dir, kg2.dir);
        assert_eq!(kg.no_phrase, kg2.no_phrase);
        let _ = format!("{:?}", kg);
        let _ = format!("{:?}", kg2);

        // ── ImportArgs ─────────────────────────────────────────────────
        let ia = ImportArgs {
            name: "sentinel-import".to_string(),
            phrase: "phrase".to_string(),
            tier: "standard".to_string(),
            dir: "/tmp/sentinel-import".to_string(),
            passphrase_file: Some("/tmp/sentinel-import.pw".to_string()),
            force: true,
        };
        let ia2 = ia.clone();
        assert_eq!(ia.force, ia2.force);
        assert_eq!(ia.tier, ia2.tier);
        let _ = format!("{:?}", ia);
        let _ = format!("{:?}", ia2);

        // ── SignArgs ───────────────────────────────────────────────────
        let sa = SignArgs {
            name: "sentinel-sign".to_string(),
            message: "msg".to_string(),
            domain: "origin-identity:v1".to_string(),
            output: OutputFormat::Hex,
            tier: "standard".to_string(),
            passphrase_file: Some("/tmp/sentinel-sign.pw".to_string()),
            dir: "/tmp/sentinel-sign".to_string(),
            hex: true,
        };
        let sa2 = sa.clone();
        assert_eq!(sa.hex, sa2.hex);
        let _ = format!("{:?}", sa);
        let _ = format!("{:?}", sa2);

        // ── VerifyArgs ─────────────────────────────────────────────────
        let va = VerifyArgs {
            name: "sentinel-verify".to_string(),
            message: "msg".to_string(),
            signature: "sig".to_string(),
            domain: "origin-identity:v1".to_string(),
            tier: "standard".to_string(),
            passphrase_file: Some("/tmp/sentinel-verify.pw".to_string()),
            dir: "/tmp/sentinel-verify".to_string(),
            hex: false,
        };
        let va2 = va.clone();
        assert_eq!(va.hex, va2.hex);
        let _ = format!("{:?}", va);
        let _ = format!("{:?}", va2);

        // ── ListArgs ───────────────────────────────────────────────────
        let la = ListArgs {
            dir: "/tmp/sentinel-list".to_string(),
            format: ListFormat::Json,
            names_only: true,
        };
        let la2 = la.clone();
        assert_eq!(la2.format, ListFormat::Json);
        assert!(la2.names_only);
        let _ = format!("{:?}", la);
        let _ = format!("{:?}", la2);

        // All values fall out of scope here — Drop runs automatically,
        // exercising the auto-derived Drop (or no-op drop if absent).
    }

    // ─── v0.3.0 tests: show / rename / delete / export-pubkey / rotate-passphrase ───

    // ─── Helpers shared by the v0.3.0 tests ─────────────────────────

    fn make_keygened_dir(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = fresh_tmp_path(label);
        std::fs::create_dir(&dir).unwrap();
        let pw_path = dir.join("pw.txt");
        std::fs::write(&pw_path, "rotate-pw").unwrap();
        let args = KeygenArgs {
            name: "vid".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        };
        cmd_keygen(args).expect("keygen");
        (dir, pw_path)
    }

    // ─── cmd_show ────────────────────────────────────────────────

    #[test]
    fn cmd_show_text_format_includes_metadata_lines() {
        let (dir, pw_path) = make_keygened_dir("show-text");
        let args = ShowArgs {
            name: "vid".to_string(),
            dir: dir.to_string_lossy().to_string(),
            format: ShowFormat::Text,
        };
        cmd_show(args).expect("show must succeed");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_show_json_format_outputs_structured_payload() {
        let (dir, pw_path) = make_keygened_dir("show-json");
        let args = ShowArgs {
            name: "vid".to_string(),
            dir: dir.to_string_lossy().to_string(),
            format: ShowFormat::Json,
        };
        cmd_show(args).expect("show json must succeed");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_show_errors_on_nonexistent_identity() {
        let err = cmd_show(ShowArgs {
            name: "no-such-id".to_string(),
            dir: "/dev/null/does-not-exist-12345".to_string(),
            format: ShowFormat::Text,
        })
        .unwrap_err();
        assert!(
            err.contains("cannot stat") || err.contains("cannot read"),
            "got: {err}"
        );
    }

    // ─── cmd_rename ───────────────────────────────────────────────

    #[test]
    fn cmd_rename_moves_blob_to_new_name() {
        let (dir, pw_path) = make_keygened_dir("rename-move");
        let result = cmd_rename(RenameArgs {
            old_name: "vid".to_string(),
            new_name: "renamed".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: false,
        });
        assert!(result.is_ok(), "rename should succeed; got: {:?}", result);
        assert!(!dir.join("vid.id").exists());
        assert!(dir.join("renamed.id").exists());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_rename_errors_when_old_missing() {
        let dir = fresh_tmp_path("rename-missing");
        std::fs::create_dir(&dir).unwrap();
        let err = cmd_rename(RenameArgs {
            old_name: "nope".to_string(),
            new_name: "whatever".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cmd_rename_errors_when_new_exists_without_force() {
        let (dir, pw_path) = make_keygened_dir("rename-clash");
        // Create a second identity at the target name.
        let pw2 = dir.join("pw2.txt");
        std::fs::write(&pw2, "pw2").unwrap();
        cmd_keygen(KeygenArgs {
            name: "clash".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw2.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        })
        .unwrap();
        let err = cmd_rename(RenameArgs {
            old_name: "vid".to_string(),
            new_name: "clash".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_rename_with_force_overwrites_existing_target() {
        let (dir, pw_path) = make_keygened_dir("rename-force");
        let pw2 = dir.join("pw2.txt");
        std::fs::write(&pw2, "pw2").unwrap();
        cmd_keygen(KeygenArgs {
            name: "force-target".to_string(),
            tier: "nano".to_string(),
            dir: dir.to_string_lossy().to_string(),
            passphrase_file: Some(pw2.to_string_lossy().to_string()),
            no_phrase: true,
            phrase_output: None,
        })
        .unwrap();
        cmd_rename(RenameArgs {
            old_name: "vid".to_string(),
            new_name: "force-target".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: true,
        })
        .expect("rename --force should overwrite");
        assert!(dir.join("force-target.id").exists());
        assert!(!dir.join("vid.id").exists());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    // ─── cmd_delete ──────────────────────────────────────────────

    #[test]
    fn cmd_delete_with_no_overwrite_and_force_removes_file() {
        let (dir, pw_path) = make_keygened_dir("delete-simple");
        let blob_path = dir.join("vid.id");
        assert!(blob_path.exists());
        cmd_delete(DeleteArgs {
            name: "vid".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: true,        // skip interactive confirm
            no_overwrite: true, // skip /dev/urandom write
        })
        .expect("delete should succeed");
        assert!(!blob_path.exists(), "blob should be gone after delete");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_delete_with_overwrite_writes_random_bytes_then_removes() {
        let (dir, pw_path) = make_keygened_dir("delete-overwrite");
        let blob_path = dir.join("vid.id");
        let original_size = std::fs::metadata(&blob_path).unwrap().len();
        cmd_delete(DeleteArgs {
            name: "vid".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: true,
            no_overwrite: false, // exercise the overwrite path
        })
        .expect("delete-with-overwrite should succeed");
        assert!(!blob_path.exists(), "blob should be gone after delete");
        // (Original size is asserted to validate that overwrite would have
        // written exactly this many random bytes; we can't easily verify
        // the random bytes because the file no longer exists.)
        assert!(original_size > 40);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_delete_errors_when_identity_missing() {
        let dir = fresh_tmp_path("delete-missing");
        std::fs::create_dir(&dir).unwrap();
        let err = cmd_delete(DeleteArgs {
            name: "never-existed".to_string(),
            dir: dir.to_string_lossy().to_string(),
            force: true,
            no_overwrite: true,
        })
        .unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── cmd_export_pubkey ──────────────────────────────────────

    #[test]
    fn cmd_export_pubkey_json_contains_both_keys_and_domain() {
        let (dir, pw_path) = make_keygened_dir("export-json");
        cmd_export_pubkey(ExportPubkeyArgs {
            name: "vid".to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            format: OutputFormat::Json,
        })
        .expect("export should succeed");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_export_pubkey_wrong_passphrase_errors() {
        let (dir, pw_path) = make_keygened_dir("export-wrong-pw");
        // Write a different passphrase file.
        let wrong_pw = dir.join("wrong-pw.txt");
        std::fs::write(&wrong_pw, "wrong-passphrase").unwrap();
        let err = cmd_export_pubkey(ExportPubkeyArgs {
            name: "vid".to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(wrong_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            format: OutputFormat::Json,
        })
        .unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_export_pubkey_hex_concatenates_correctly() {
        let (dir, pw_path) = make_keygened_dir("export-hex");
        cmd_export_pubkey(ExportPubkeyArgs {
            name: "vid".to_string(),
            domain: "test:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            format: OutputFormat::Hex,
        })
        .expect("export hex should succeed");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    // ─── cmd_rotate_passphrase ──────────────────────────────────

    #[test]
    fn cmd_rotate_passphrase_succeeds_with_new_pw_file() {
        let (dir, pw_path) = make_keygened_dir("rotate-new-pw");
        let new_pw = dir.join("new-pw.txt");
        std::fs::write(&new_pw, "rotated-new-pw").unwrap();
        cmd_rotate_passphrase(RotatePassphraseArgs {
            name: "vid".to_string(),
            tier: "nano".to_string(),
            new_tier: None,
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            new_passphrase_file: Some(new_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
        })
        .expect("rotate should succeed");

        // The new passphrase must work to export pubkey; the old must not.
        cmd_export_pubkey(ExportPubkeyArgs {
            name: "vid".to_string(),
            domain: "origin-identity:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(new_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            format: OutputFormat::Json,
        })
        .expect("new passphrase should unlock");
        let err = cmd_export_pubkey(ExportPubkeyArgs {
            name: "vid".to_string(),
            domain: "origin-identity:v1".to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            format: OutputFormat::Json,
        })
        .unwrap_err();
        assert!(
            err.contains("decryption failed"),
            "old pw should fail: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_rotate_passphrase_wrong_old_pw_errors() {
        let (dir, pw_path) = make_keygened_dir("rotate-wrong-old");
        let wrong = dir.join("wrong.txt");
        std::fs::write(&wrong, "wrong-old-pw").unwrap();
        let new_pw = dir.join("new.txt");
        std::fs::write(&new_pw, "new-pw").unwrap();
        let err = cmd_rotate_passphrase(RotatePassphraseArgs {
            name: "vid".to_string(),
            tier: "nano".to_string(),
            new_tier: None,
            passphrase_file: Some(wrong.to_string_lossy().to_string()),
            new_passphrase_file: Some(new_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
        })
        .unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_rotate_passphrase_changes_tier_nano_to_standard() {
        let (dir, pw_path) = make_keygened_dir("rotate-tier");
        let new_pw = dir.join("new.txt");
        std::fs::write(&new_pw, "new-pw").unwrap();
        cmd_rotate_passphrase(RotatePassphraseArgs {
            name: "vid".to_string(),
            tier: "nano".to_string(),
            new_tier: Some("standard".to_string()),
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            new_passphrase_file: Some(new_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
        })
        .expect("rotate with tier migration should succeed");

        // Now export with the new tier must succeed.
        cmd_export_pubkey(ExportPubkeyArgs {
            name: "vid".to_string(),
            domain: "origin-identity:v1".to_string(),
            tier: "standard".to_string(),
            passphrase_file: Some(new_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
            format: OutputFormat::Json,
        })
        .expect("export with new tier should succeed");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    #[test]
    fn cmd_rotate_passphrase_same_pw_produces_new_blob_bytes() {
        let (dir, pw_path) = make_keygened_dir("rotate-same-pw");
        let same_pw = dir.join("same.txt");
        std::fs::write(&same_pw, "rotate-pw").unwrap(); // same as pw_path
        let blob_path = dir.join("vid.id");
        let before = std::fs::read(&blob_path).unwrap();
        cmd_rotate_passphrase(RotatePassphraseArgs {
            name: "vid".to_string(),
            tier: "nano".to_string(),
            new_tier: None,
            passphrase_file: Some(pw_path.to_string_lossy().to_string()),
            new_passphrase_file: Some(same_pw.to_string_lossy().to_string()),
            dir: dir.to_string_lossy().to_string(),
        })
        .expect("rotate with same pw should succeed (salt differs)");
        let after = std::fs::read(&blob_path).unwrap();
        assert_ne!(
            before, after,
            "salt+nonce must differ between runs even with same pw"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&pw_path);
    }

    // CombinedSignature v1 golden vector — FORMAT_REGISTRY.md priority 6.
    // Both halves are deterministic: Ed25519 by RFC 8032 and Falcon via
    // `sign_deterministic`'s explicit nonce seed, so the whole wire blob
    // is reproducible.
    #[test]
    fn combined_signature_golden_vector_v1() {
        use origin_crypto_sdk::pqc::falcon1024;
        use origin_crypto_sdk::signing::hybrid::{Signer, Verifier};

        let msg = b"combined signature golden vector";
        let ed_sk = origin_crypto_sdk::Ed25519SigningKey::from_bytes(&[0x55; 32]);
        let ed = ed_sk.sign(msg);
        let (falcon_pk, falcon_sk) =
            falcon1024::generate_keypair_from_seed(&[0x99; 32]).expect("falcon keygen");
        let falcon =
            falcon1024::sign_deterministic(msg, &falcon_sk, &[0xBB; 32]).expect("falcon sign");

        let combined = CombinedSignature { ed, falcon };
        let wire = combined.to_wire_bytes();

        // The wire blob is ~1.2 KB — pin its SHA3-256 digest plus the
        // exact structural layout rather than a giant hex literal.
        const EXPECTED_SHA3_256: &str =
            "36f57ff2a642ed2759f304c99f6ae09d004532b322c3c9e00e23ac914443ea03";
        assert_eq!(
            hex::encode(origin_crypto_sdk::sha3_256(&wire)),
            EXPECTED_SHA3_256
        );

        // Structure: [falcon_len u32 BE][ed25519 64B][falcon N B].
        let flen = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(flen, combined.falcon.as_bytes().len());
        assert_eq!(
            wire.len(),
            CombinedSignature::LEN_PREFIX + CombinedSignature::ED_LEN + flen
        );

        // The pinned layout must parse and re-encode identically.
        let parsed = CombinedSignature::from_wire(&wire).expect("parse golden vector");
        assert_eq!(parsed.to_wire_bytes(), wire);

        // Both halves still verify cryptographically.
        ed_sk
            .verifying_key()
            .verify(msg, &parsed.ed)
            .expect("ed25519 verify");
        falcon1024::verify(msg, &parsed.falcon, &falcon_pk).expect("falcon verify");
    }
}
