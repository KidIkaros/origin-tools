// SPDX-License-Identifier: Apache-2.0

//! Vault primitives for `origin-pass`.
//!
//! Wire format: see `origin-crypto-sdk/docs/tools/DESIGN.md` §4 (OVLT
//! header, ChaCha20-BLAKE3 committing AEAD, per-entry nonces, encrypted
//! entry index inside the header).
//!
//! Concurrency: `init_vault`, `unlock_vault`, `persist_vault` are
//! individually atomic (write + fsync, or read + decrypt); concurrent
//! processes racing on the same vault file is the user's responsibility
//! (we recommend single-writer at a time — see DESIGN.md §3.1 T5.5).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use origin_common::{argon2_builder, tier_from_byte, tier_from_str, tier_to_byte};
use origin_crypto_sdk::{
    chacha20_blake3::{ChaCha20Blake3, TAG_SIZE},
    kdf::hkdf::hkdf_sha3_256,
    sha3_256,
    tier::MemoryTier,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ── On-disk wire-format constants ─────────────────────────────────────

/// File magic ("OVLT").
pub const MAGIC: [u8; 4] = *b"OVLT";

/// Current vault wire format version.
pub const VERSION: u8 = 0x01;

/// Cipher-suite byte value for ChaCha20-BLAKE3 AEAD.
pub const CIPHER_CHACHA20_BLAKE3: u8 = 0x00;

/// Argon2id salt length (16 bytes).
pub const KDF_SALT_LEN: usize = 16;

/// Header AEAD nonce length (24 bytes for ChaCha20-BLAKE3).
pub const HEADER_NONCE_LEN: usize = 24;

/// EntryName hash length (32 bytes of SHA3-256).
pub const NAME_HASH_LEN: usize = 32;

/// Per-entry AEAD nonce length.
pub const ENTRY_NONCE_LEN: usize = 24;

/// Entry ciphertext-length field (big-endian u32).
pub const ENTRY_CT_LEN_FIELD: usize = 4;

/// Reserved block (16 bytes per EntryMetadata).
#[allow(dead_code)]
pub const ENTRY_RESERVED_LEN: usize = 16;

/// Total EntryMetadata on-disk size.
pub const ENTRY_METADATA_LEN: usize = 76; // 32 + 24 + 4 + 16

/// Index payload layout (plaintext inside encrypted header): 4 entry_count + 4 version.
pub const INDEX_HEADER_LEN: usize = 8;

/// Index format version inside the encrypted header.
pub const INDEX_VERSION: u32 = 0x01;

/// Size of the unencrypted header bytes (magic + version + cipher + tier + reserved + salt + header_nonce + header_ct_len).
/// Header CT length (u16 BE) is the last 2 bytes; without it, `unlock_vault` would have to scan + retry every plausible
/// header CT length, which is O(N) ChaCha20-BLAKE3 attempts per unlock — a DoS vector if the file is hostile.
pub const HEADER_BYTES_LEN: usize =
    4 + 1 + 1 + 1 + 1 + KDF_SALT_LEN + HEADER_NONCE_LEN + 2 /* header_ct_len u16 BE */;

/// Maximum vault file size: 256 MiB. Prevents memory exhaustion from oversized inputs.
pub const MAX_VAULT_LEN: usize = 256 * 1024 * 1024;

// ── Type tags inside the 16B `entry_reserved` block ────────────────────

/// Type tag: password entry.
pub const TYPE_PASSWORD: u8 = 0x00;
/// Type tag: TOTP entry.
pub const TYPE_TOTP: u8 = 0x01;
/// Type tag: HOTP entry.
pub const TYPE_HOTP: u8 = 0x02;
/// Type tag: OCRA entry.
pub const TYPE_OCRA: u8 = 0x03;

/// Algorithm tag (encoding differs from SDK's `HashAlgorithm` enum which
/// is `Sha1=0 / Sha256=1 / Sha512=2`; we +1-offset here for no good
/// reason other than to keep `0x00` reserved for "unspecified").
pub const ALGO_UNSPECIFIED: u8 = 0x00;
pub const ALGO_SHA1: u8 = 0x01;
pub const ALGO_SHA256: u8 = 0x02;
pub const ALGO_SHA512: u8 = 0x03;

// ── Tier helpers ──────────────────────────────────────────────────────

/// Parse a tier label ("nano" / "standard" / "sovereign") into the SDK
/// `MemoryTier` enum. Delegates to `origin_common::tier_from_str`.
pub fn parse_tier(s: &str) -> Result<MemoryTier, String> {
    tier_from_str(s)
}

/// Map `MemoryTier` to its single-byte wire format.
/// Delegates to `origin_common::tier_to_byte`.
pub fn tier_byte(t: MemoryTier) -> u8 {
    tier_to_byte(t)
}

// ── Argon2id tier-to-params ────────────────────────────────────────────

/// Argon2id derivation for the vault master key, tier-specific.
///
/// Uses `origin_common::argon2_builder` which reads the authoritative
/// parameters from `MemoryTier::argon2_params` in the SDK.
fn argon2id_derive(
    passphrase: &[u8],
    salt: &[u8; KDF_SALT_LEN],
    tier: MemoryTier,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let key_vec = argon2_builder(tier, 32)
        .derive(passphrase, salt)
        .map_err(|e| format!("Argon2id derivation failed: {e:?}"))?;

    if key_vec.len() != 32 {
        return Err(format!(
            "Argon2id returned {} bytes; expected 32",
            key_vec.len()
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&key_vec);
    Ok(key)
}

// ── HKDF subkey derivation ─────────────────────────────────────────────

fn derive_header_key(master: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    hkdf_sha3_256(master, Some(b"origin-vault"), b"header-key", &mut k)
        .expect("hkdf 32B output is well within 8160B ceiling");
    k
}

fn derive_entry_key(master: &[u8], nonce: &[u8; ENTRY_NONCE_LEN]) -> [u8; 32] {
    let mut k = [0u8; 32];
    hkdf_sha3_256(master, Some(nonce), b"entry-key", &mut k)
        .expect("hkdf 32B output is well within 8160B ceiling");
    k
}

/// SHA3-256 hash of an entry name (lowercased UTF-8) — deterministic
/// identifier for index lookups.
fn hash_name(name: &str) -> [u8; NAME_HASH_LEN] {
    sha3_256(name.as_bytes())
}

/// Build AAD = `name_hash || entry_nonce` per DESIGN.md §4.
fn build_entry_aad(name_hash: &[u8; NAME_HASH_LEN], nonce: &[u8; ENTRY_NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(NAME_HASH_LEN + ENTRY_NONCE_LEN);
    aad.extend_from_slice(name_hash);
    aad.extend_from_slice(nonce);
    aad
}

// ── Wire-format types ─────────────────────────────────────────────────

/// Per-entry metadata stored in the encrypted header index.
///
/// 76 bytes total: `name_hash (32) ‖ entry_nonce (24) ‖ entry_ct_len (4BE) ‖ entry_reserved (16)`.
///
/// Inside `entry_reserved` (per `origin-tools/DESIGN.md` §2.3):
/// - byte 60: `type_tag`
/// - byte 61: `algo`
/// - bytes 62-63: `period_secs` (big-endian u16)
/// - byte 64: `digits`
/// - bytes 65-75: zeroed (forward-compatible)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    pub name_hash: [u8; NAME_HASH_LEN],
    pub name: String,
    pub entry_nonce: [u8; ENTRY_NONCE_LEN],
    pub entry_ct_offset: u64,
    pub entry_ct_len: u32,
    pub type_tag: u8,
    pub algo: u8,
    pub period_secs: u16,
    pub digits: u8,
}

impl EntryMetadata {
    /// Serialize to the 76-byte on-disk form. Layout:
    /// `name_hash(32) ‖ entry_nonce(24) ‖ entry_ct_len(BE u32)(4) ‖ type_tag(1) ‖ algo(1) ‖ period_secs(BE u16)(2) ‖ digits(1) ‖ zeroed(11)`
    pub fn to_wire(&self) -> [u8; ENTRY_METADATA_LEN] {
        let mut buf = [0u8; ENTRY_METADATA_LEN];
        buf[..NAME_HASH_LEN].copy_from_slice(&self.name_hash);
        buf[NAME_HASH_LEN..NAME_HASH_LEN + ENTRY_NONCE_LEN].copy_from_slice(&self.entry_nonce);
        let len_be = self.entry_ct_len.to_be_bytes();
        buf[NAME_HASH_LEN + ENTRY_NONCE_LEN..NAME_HASH_LEN + ENTRY_NONCE_LEN + ENTRY_CT_LEN_FIELD]
            .copy_from_slice(&len_be);
        let off = NAME_HASH_LEN + ENTRY_NONCE_LEN + ENTRY_CT_LEN_FIELD;
        buf[off] = self.type_tag;
        buf[off + 1] = self.algo;
        let period_be = self.period_secs.to_be_bytes();
        buf[off + 2..off + 4].copy_from_slice(&period_be);
        buf[off + 4] = self.digits;
        // remaining 11 bytes in `entry_reserved` are zeroed by `[0u8; 76]` above.
        buf
    }

    /// Inverse of `to_wire`. Does NOT populate `name` or `entry_ct_offset` —
    /// those are filled in by the unlock flow.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < ENTRY_METADATA_LEN {
            return Err(format!(
                "entry metadata too short: {} bytes (need {ENTRY_METADATA_LEN})",
                bytes.len()
            ));
        }
        let mut name_hash = [0u8; NAME_HASH_LEN];
        name_hash.copy_from_slice(&bytes[..NAME_HASH_LEN]);
        let mut entry_nonce = [0u8; ENTRY_NONCE_LEN];
        entry_nonce.copy_from_slice(&bytes[NAME_HASH_LEN..NAME_HASH_LEN + ENTRY_NONCE_LEN]);
        let entry_ct_len = u32::from_be_bytes([
            bytes[NAME_HASH_LEN + ENTRY_NONCE_LEN],
            bytes[NAME_HASH_LEN + ENTRY_NONCE_LEN + 1],
            bytes[NAME_HASH_LEN + ENTRY_NONCE_LEN + 2],
            bytes[NAME_HASH_LEN + ENTRY_NONCE_LEN + 3],
        ]);
        let off = NAME_HASH_LEN + ENTRY_NONCE_LEN + ENTRY_CT_LEN_FIELD;
        let type_tag = bytes[off];
        let algo = bytes[off + 1];
        let period_secs = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]);
        let digits = bytes[off + 4];
        Ok(Self {
            name_hash,
            name: String::new(),
            entry_nonce,
            entry_ct_offset: 0,
            entry_ct_len,
            type_tag,
            algo,
            period_secs,
            digits,
        })
    }

    /// Detect entry type from the `type_tag`.
    #[allow(dead_code)]
    pub fn entry_kind(&self) -> &'static str {
        match self.type_tag {
            TYPE_PASSWORD => "password",
            TYPE_TOTP => "totp",
            TYPE_HOTP => "hotp",
            TYPE_OCRA => "ocra",
            _ => "unknown",
        }
    }
}

/// Decrypted entry payload — JSON-serialized to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPayload {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotp: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocra: Option<serde_json::Value>,
}

impl EntryPayload {
    /// Build a password entry.
    pub fn password(name: &str, secret: &str) -> Self {
        Self {
            name: name.to_string(),
            entry_type: "password".to_string(),
            secret: Some(secret.as_bytes().to_vec()),
            url: None,
            notes: None,
            created_at: 0,
            updated_at: 0,
            totp: None,
            hotp: None,
            ocra: None,
        }
    }

    /// Build a TOTP entry.
    pub fn totp(name: &str, secret: &str, period: u32, digits: u32, algo: &str) -> Self {
        Self {
            name: name.to_string(),
            entry_type: "otp".to_string(),
            secret: Some(secret.as_bytes().to_vec()),
            url: None,
            notes: None,
            created_at: 0,
            updated_at: 0,
            totp: Some(serde_json::json!({
                "kind": "totp",
                "period": period,
                "digits": digits,
                "algo": algo,
            })),
            hotp: None,
            ocra: None,
        }
    }

    /// Build an HOTP entry. `counter` is required by RFC 4226 / RFC 6238;
    /// importing a `otpauth://hotp/?counter=0` URI stores counter=0 and the
    /// verifier is responsible for incrementing per use.
    pub fn hotp(name: &str, secret: &str, counter: u64, digits: u32, algo: &str) -> Self {
        Self {
            name: name.to_string(),
            entry_type: "otp".to_string(),
            secret: Some(secret.as_bytes().to_vec()),
            url: None,
            notes: None,
            created_at: 0,
            updated_at: 0,
            totp: None,
            hotp: Some(serde_json::json!({
                "kind": "hotp",
                "counter": counter,
                "digits": digits,
                "algo": algo,
            })),
            ocra: None,
        }
    }

    /// Create an OCRA entry payload. `counter` is the initial counter
    /// for suites with a `C` component; it auto-increments per use (like
    /// HOTP) inside `cmd_code_ocra`.
    pub fn ocra(
        name: &str,
        key: &[u8],
        suite: &str,
        digits: u32,
        algo: &str,
        counter: u64,
    ) -> Self {
        Self {
            name: name.to_string(),
            entry_type: "ocra".to_string(),
            secret: Some(key.to_vec()),
            url: None,
            notes: None,
            created_at: 0,
            updated_at: 0,
            totp: None,
            hotp: None,
            ocra: Some(serde_json::json!({
                "suite": suite,
                "digits": digits,
                "algo": algo,
                "counter": counter,
            })),
        }
    }
}

/// On-disk vault header layout. Contains the *unencrypted* bytes only;
/// the encrypted entry index lives in the file bytes after offset
/// `HEADER_BYTES_LEN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub cipher_suite: u8,
    pub kdf_tier: MemoryTier,
    pub kdf_salt: [u8; KDF_SALT_LEN],
    pub header_nonce: [u8; HEADER_NONCE_LEN],
    pub header_ct_len: usize,
}

impl VaultHeader {
    pub fn to_wire(&self) -> [u8; HEADER_BYTES_LEN] {
        let mut buf = [0u8; HEADER_BYTES_LEN];
        buf[..4].copy_from_slice(&MAGIC);
        buf[4] = VERSION;
        buf[5] = self.cipher_suite;
        buf[6] = tier_byte(self.kdf_tier);
        buf[7] = 0; // reserved
        buf[8..8 + KDF_SALT_LEN].copy_from_slice(&self.kdf_salt);
        let off_salt = 8 + KDF_SALT_LEN;
        buf[off_salt..off_salt + HEADER_NONCE_LEN].copy_from_slice(&self.header_nonce);
        let off_nonce = off_salt + HEADER_NONCE_LEN;
        let ct_len = self.header_ct_len as u16;
        buf[off_nonce..off_nonce + 2].copy_from_slice(&ct_len.to_be_bytes());
        buf
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_BYTES_LEN {
            return Err(format!(
                "vault header too short: {} bytes (need {HEADER_BYTES_LEN})",
                bytes.len()
            ));
        }
        if bytes[..4] != MAGIC {
            return Err("vault magic mismatch — not an OVLT file (or wrong version)".to_string());
        }
        if bytes[4] != VERSION {
            return Err(format!(
                "vault version mismatch: got 0x{:02x}, expected 0x{:02x}",
                bytes[4], VERSION
            ));
        }
        let cipher_suite = bytes[5];
        if cipher_suite != CIPHER_CHACHA20_BLAKE3 {
            return Err(format!(
                "unsupported cipher suite 0x{cipher_suite:02x}; only ChaCha20-BLAKE3 (0x00) is implemented"
            ));
        }
        if bytes[7] != 0 {
            return Err(format!(
                "unsupported reserved vault header byte: 0x{:02x}",
                bytes[7]
            ));
        }
        let kdf_tier = tier_from_byte(bytes[6])?;
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        kdf_salt.copy_from_slice(&bytes[8..8 + KDF_SALT_LEN]);
        let off_salt = 8 + KDF_SALT_LEN;
        let mut header_nonce = [0u8; HEADER_NONCE_LEN];
        header_nonce.copy_from_slice(&bytes[off_salt..off_salt + HEADER_NONCE_LEN]);
        let off_nonce = off_salt + HEADER_NONCE_LEN;
        let header_ct_len = u16::from_be_bytes([bytes[off_nonce], bytes[off_nonce + 1]]) as usize;
        if header_ct_len < TAG_SIZE {
            return Err(format!(
                "vault header ciphertext too short: {header_ct_len} bytes (need at least {TAG_SIZE})"
            ));
        }
        Ok(Self {
            cipher_suite,
            kdf_tier,
            kdf_salt,
            header_nonce,
            header_ct_len,
        })
    }
}

// ── In-memory unlocked vault ───────────────────────────────────────────

/// In-process unlocked vault. `Drop` zeroizes `master_key` and best-
/// effort zeroes each `EntryPayload::secret` byte. The struct never
/// implements `Clone` (cloning the master key would defeat Zeroizing).
pub struct Vault {
    pub header: VaultHeader,
    /// Decrypted entry payloads keyed by entry name.
    pub entries: BTreeMap<String, EntryPayload>,
    /// Per-entry metadata (offsets, type info) — populated on unlock.
    #[allow(dead_code)]
    pub metadata: Vec<EntryMetadata>,
    /// Master key wrapped in Zeroizing (scrubs on drop).
    pub master_key: Zeroizing<[u8; 32]>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Best-effort: zero out each entry's secret bytes. Zeroizing on
        // `master_key` already covers the master key.
        for entry in self.entries.values_mut() {
            if let Some(ref mut s) = entry.secret {
                for b in s.iter_mut() {
                    *b = 0;
                }
            }
        }
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("cipher_suite", &self.header.cipher_suite)
            .field("kdf_tier", &self.header.kdf_tier)
            .field("entry_count", &self.entries.len())
            .field("master_key", &"<32B zeroized>")
            .finish()
    }
}

/// Extension methods used by both `commands.rs` (production) and tests.
impl Vault {
    /// Add or replace an entry. Currently infallible (just inserts into
    /// the map) but returns `Result` for forward-compatibility — future
    /// versions may validate entry names (max length, character set,
    /// etc.) before insertion.
    pub fn add_entry(&mut self, payload: EntryPayload) -> Result<(), String> {
        self.entries.insert(payload.name.clone(), payload);
        Ok(())
    }

    /// Look up the OCRA key bytes for an entry. Rejects:
    /// - unknown entry name
    /// - entry whose `type` is not `ocra`
    pub fn get_ocra_key(&self, name: &str) -> Result<Vec<u8>, String> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| format!("entry not found: {name}"))?;
        if entry.entry_type != "ocra" {
            return Err(format!(
                "entry '{name}' is type '{}'; OCRA requires type 'ocra'",
                entry.entry_type
            ));
        }
        entry
            .secret
            .clone()
            .ok_or_else(|| format!("entry '{name}' has no secret bytes stored (data corruption?)"))
    }

    /// Look up a full OCRA entry (key + stored `ocra` JSON) for
    /// `cmd_code_ocra`, which needs the stored suite string, counter, and
    /// digit/algorithm parameters in addition to the key bytes.
    pub fn get_ocra_entry(&self, name: &str) -> Result<&EntryPayload, String> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| format!("entry not found: {name}"))?;
        if entry.entry_type != "ocra" {
            return Err(format!(
                "entry '{name}' is type '{}'; OCRA requires type 'ocra'",
                entry.entry_type
            ));
        }
        Ok(entry)
    }
}

// ── Top-level operations ──────────────────────────────────────────────

/// Initialize a new vault file at `path` using `passphrase` and the
/// given `MemoryTier`. Writes header + empty entry index.
pub fn init_vault(path: &Path, passphrase: &str, tier: MemoryTier) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create vault parent {}: {e}", parent.display()))?;
        }
    }
    if path.exists() {
        return Err(format!(
            "vault file already exists: {} (refusing to overwrite)",
            path.display()
        ));
    }

    // 1. Generate Argon2id salt + master key.
    let mut kdf_salt = [0u8; KDF_SALT_LEN];
    origin_crypto_sdk::fill_random(&mut kdf_salt)
        .map_err(|e| format!("salt generation failed: {e}"))?;
    let master_key = argon2id_derive(passphrase.as_bytes(), &kdf_salt, tier)?;
    let header_key = derive_header_key(master_key.as_ref());

    // 2. Header nonce + encrypt the empty entry index.
    let header_nonce = ChaCha20Blake3::try_generate_nonce()
        .map_err(|e| format!("nonce generation failed: {e}"))?;
    let index_bytes = build_index_bytes(&[])?;
    let header_ct = ChaCha20Blake3::encrypt(&header_key, &header_nonce, &index_bytes, &[])
        .map_err(|e| format!("ChaCha20-BLAKE3 header encrypt: {e:?}"))?;

    let header = VaultHeader {
        cipher_suite: CIPHER_CHACHA20_BLAKE3,
        kdf_tier: tier,
        kdf_salt,
        header_nonce,
        header_ct_len: header_ct.len(),
    };

    // 3. Write header + header_ct atomically (write tmp + rename).
    write_atomic(path, &header.to_wire(), &header_ct, &[])?;
    Ok(())
}

/// Read a vault file into `(header, full data)` with size checks.
fn read_vault_file(path: &Path) -> Result<(VaultHeader, Vec<u8>), String> {
    let mut data = Vec::new();
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("cannot read vault {}: {e}", path.display()))?;
    file.read_to_end(&mut data)
        .map_err(|e| format!("read vault: {e}"))?;
    drop(file);

    if data.len() < HEADER_BYTES_LEN {
        return Err(format!(
            "vault file too short: {} bytes (need ≥ {HEADER_BYTES_LEN})",
            data.len()
        ));
    }
    if data.len() > MAX_VAULT_LEN {
        return Err(format!(
            "vault file too large: {} bytes (max {MAX_VAULT_LEN})",
            data.len()
        ));
    }
    let header_bytes = &data[..HEADER_BYTES_LEN];
    let header = VaultHeader::from_wire(header_bytes)?;

    if header.cipher_suite != CIPHER_CHACHA20_BLAKE3 {
        return Err(format!(
            "unsupported cipher suite 0x{:02x}; only ChaCha20-BLAKE3 (0x00) is implemented",
            header.cipher_suite
        ));
    }
    Ok((header, data))
}

/// Read a vault file, derive keys, decrypt all entries, and return
/// the in-memory `Vault`. Errors are formatted strings per CLI conventions.
pub fn unlock_vault(path: &Path, passphrase: &str) -> Result<Vault, String> {
    let (header, data) = read_vault_file(path)?;

    // 1. Derive master key + header key.
    let master_key = argon2id_derive(passphrase.as_bytes(), &header.kdf_salt, header.kdf_tier)
        .map_err(|e| {
            // Don't leak the Argon2id internals — same opaque string
            // whether password was wrong or some other failure.
            let _ = e;
            "vault unlock failed (Argon2id)".to_string()
        })?;
    decrypt_vault(&header, &data, master_key.as_ref())
}

/// Unlock a vault with a pre-derived master key (session-token path).
/// The master key must be the 32-byte key derived from the vault's
/// passphrase + salt — obtained via `session::read_session_token`.
pub fn unlock_vault_with_key(path: &Path, master_key: &[u8]) -> Result<Vault, String> {
    let (header, data) = read_vault_file(path)?;
    decrypt_vault(&header, &data, master_key)
}

/// Shared decryption core for `unlock_vault` / `unlock_vault_with_key`.
fn decrypt_vault(
    header: &VaultHeader,
    data: &[u8],
    master_key_bytes: &[u8],
) -> Result<Vault, String> {
    if master_key_bytes.len() != 32 {
        return Err(format!(
            "master key must be 32 bytes; got {}",
            master_key_bytes.len()
        ));
    }
    let mut master_key = Zeroizing::new([0u8; 32]);
    master_key.copy_from_slice(master_key_bytes);

    let header_key = derive_header_key(master_key.as_ref());

    // 2. Decrypt header CT — length is now explicitly recorded in the
    //    unencrypted header (the high byte of byte 48 + low byte of byte 49),
    //    avoiding the O(N) retry scan that was the original `decrypt_header_ct`
    //    implementation.
    let header_ct = &data[HEADER_BYTES_LEN..HEADER_BYTES_LEN + header.header_ct_len];
    let index_bytes = ChaCha20Blake3::decrypt(&header_key, &header.header_nonce, header_ct, &[])
        .map_err(|_| {
            "vault unlock failed (decryption — wrong passphrase or corrupt header)".to_string()
        })?;
    let mut metadata = parse_index_bytes(&index_bytes)?;
    let _total_len = read_total_entry_len(&metadata)?;

    // 3. Walk entries sequentially after the encrypted header index.
    //    NOTE: do NOT add `total_len` here — `total_len` is summed into
    //    `cursor` as we iterate each entry's metadata below. Double-adding
    //    it pushed the cursor past EOF (v0.4.0-RC regression that caused
    //    6 vault round-trip tests to fail with "truncated or corrupt").
    let mut cursor: u64 = (HEADER_BYTES_LEN + header.header_ct_len) as u64;
    for meta in metadata.iter_mut() {
        meta.entry_ct_offset = cursor;
        cursor = cursor
            .checked_add(meta.entry_ct_len as u64)
            .ok_or_else(|| "entry length overflow".to_string())?;
    }
    let file_len = data.len() as u64;
    if cursor != file_len {
        return Err(format!(
            "entry payloads end at byte {cursor} but file is {file_len} bytes — vault is truncated or corrupt"
        ));
    }

    // 4. Decrypt each entry into EntryPayload.
    let mut entries: BTreeMap<String, EntryPayload> = BTreeMap::new();
    for meta in &metadata {
        let start = meta.entry_ct_offset as usize;
        let end = start + meta.entry_ct_len as usize;
        if end > data.len() {
            return Err(format!(
                "entry '{}' CT extends past EOF",
                String::from_utf8_lossy(&meta.name_hash)
            ));
        }
        let ct = &data[start..end];
        let entry_key = derive_entry_key(master_key.as_ref(), &meta.entry_nonce);
        let aad = build_entry_aad(&meta.name_hash, &meta.entry_nonce);
        let plaintext =
            ChaCha20Blake3::decrypt(&entry_key, &meta.entry_nonce, ct, &aad).map_err(|e| {
                let _ = e;
                format!(
                    "entry decryption failed (entry name_hash={})",
                    hex::encode(&meta.name_hash[..4])
                )
            })?;
        let mut payload: EntryPayload = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("entry JSON parse failed: {e}"))?;
        // Prefer the name from the payload over the index's stored name.
        // (We didn't store payload names in the encrypted index — they're
        // only inside the encrypted payload — so the `name` field of the
        // freshly-parsed payload is authoritative.)
        if payload.name.is_empty() {
            payload.name = format!("entry-{}", hex::encode(&meta.name_hash[..4]));
        }
        entries.insert(payload.name.clone(), payload);
    }

    Ok(Vault {
        header: header.clone(),
        entries,
        metadata,
        master_key,
    })
}

/// Re-encrypt the vault file with the current `entries` map.
///
/// Strategy: keep the same `master_key` + salt (we have to know the
/// passphrase to derive them); encrypt each entry with fresh nonces;
/// rebuild the entry index; re-encrypt it under a fresh `header_nonce`.
pub fn persist_vault(path: &Path, vault: &Vault) -> Result<(), String> {
    // 1. Re-encrypt each entry with a fresh nonce.
    let mut entry_data: Vec<(EntryMetadata, Vec<u8>)> = Vec::new();
    for (name, payload) in &vault.entries {
        let entry_nonce = ChaCha20Blake3::try_generate_nonce()
            .map_err(|e| format!("nonce generation failed: {e}"))?;
        let name_hash = hash_name(name);
        let entry_key = derive_entry_key(vault.master_key.as_ref(), &entry_nonce);
        let aad = build_entry_aad(&name_hash, &entry_nonce);
        let json =
            serde_json::to_vec(payload).map_err(|e| format!("serialize entry payload: {e}"))?;
        let ct = ChaCha20Blake3::encrypt(&entry_key, &entry_nonce, &json, &aad)
            .map_err(|e| format!("ChaCha20-BLAKE3 encrypt entry: {e:?}"))?;

        // Determine type_tag + algo + period + digits from payload.
        let (type_tag, algo, period_secs, digits) = payload_to_type_tag_algo_period_digits(payload);
        let meta = EntryMetadata {
            name_hash,
            name: name.clone(),
            entry_nonce,
            entry_ct_offset: 0, // filled in below
            entry_ct_len: ct.len() as u32,
            type_tag,
            algo,
            period_secs,
            digits,
        };
        entry_data.push((meta, ct));
    }

    // 2. Compute entry index bytes.
    let index_bytes = build_index_bytes(
        &entry_data
            .iter()
            .map(|(m, _)| m.clone())
            .collect::<Vec<_>>(),
    )?;

    // 3. Encrypt the index.
    let header_nonce = ChaCha20Blake3::try_generate_nonce()
        .map_err(|e| format!("nonce generation failed: {e}"))?;
    let header_key = derive_header_key(vault.master_key.as_ref());
    let header_ct = ChaCha20Blake3::encrypt(&header_key, &header_nonce, &index_bytes, &[])
        .map_err(|e| format!("ChaCha20-BLAKE3 header encrypt: {e:?}"))?;

    // 4. Build the full new file: header || header_ct || entry_payloads.
    let new_header = VaultHeader {
        cipher_suite: vault.header.cipher_suite,
        kdf_tier: vault.header.kdf_tier,
        kdf_salt: vault.header.kdf_salt,
        header_nonce,
        header_ct_len: header_ct.len(),
    };
    let mut payload_bytes = Vec::new();
    for (_, ct) in &entry_data {
        payload_bytes.extend_from_slice(ct);
    }
    write_atomic(path, &new_header.to_wire(), &header_ct, &payload_bytes)?;
    Ok(())
}

/// Update the passphrase of an existing vault. Reads with the old
/// passphrase, derives a new master key from the new passphrase, and
/// re-encrypts every entry + the header under the new key.
pub fn change_vault_passphrase(
    path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    tier: MemoryTier,
) -> Result<(), String> {
    // 1. Unlock with the old passphrase (this validates it).
    let mut vault = unlock_vault(path, old_passphrase)?;

    // 2. Generate a fresh salt + derive new master key.
    let mut new_salt = [0u8; KDF_SALT_LEN];
    origin_crypto_sdk::fill_random(&mut new_salt)
        .map_err(|e| format!("salt generation failed: {e}"))?;
    let new_master = argon2id_derive(new_passphrase.as_bytes(), &new_salt, tier)?;

    // 3. Replace the master key + salt on the in-memory vault.
    *vault.master_key = *new_master;
    vault.header.kdf_salt = new_salt;
    vault.header.kdf_tier = tier;

    // 4. Persist under the new key.
    persist_vault(path, &vault)?;
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Build the on-disk index bytes: `entry_count(u32 BE) ‖ version(u32 BE) ‖ entries…`.
fn build_index_bytes(entries: &[EntryMetadata]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(INDEX_HEADER_LEN + entries.len() * ENTRY_METADATA_LEN);
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    buf.extend_from_slice(&INDEX_VERSION.to_be_bytes());
    for e in entries {
        let wire = e.to_wire();
        buf.extend_from_slice(&wire);
    }
    Ok(buf)
}

/// Parse index bytes back into metadata. The `entry_ct_offset` is
/// populated by the caller (depends on file layout).
fn parse_index_bytes(index_bytes: &[u8]) -> Result<Vec<EntryMetadata>, String> {
    if index_bytes.len() < INDEX_HEADER_LEN {
        return Err(format!(
            "index too short: {} bytes (need ≥ {INDEX_HEADER_LEN})",
            index_bytes.len()
        ));
    }
    let entry_count = u32::from_be_bytes([
        index_bytes[0],
        index_bytes[1],
        index_bytes[2],
        index_bytes[3],
    ]) as usize;
    let index_version = u32::from_be_bytes([
        index_bytes[4],
        index_bytes[5],
        index_bytes[6],
        index_bytes[7],
    ]);
    if index_version != INDEX_VERSION {
        return Err(format!(
            "index version mismatch: got {index_version}, expected {INDEX_VERSION}"
        ));
    }
    let need = INDEX_HEADER_LEN + entry_count * ENTRY_METADATA_LEN;
    if index_bytes.len() < need {
        return Err(format!(
            "index truncated: {entry_count} entries need {need}B, got {}",
            index_bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let start = INDEX_HEADER_LEN + i * ENTRY_METADATA_LEN;
        let end = start + ENTRY_METADATA_LEN;
        let mut meta = EntryMetadata::from_wire(&index_bytes[start..end])?;
        meta.entry_ct_offset = 0; // filled by `unlock_vault`
        out.push(meta);
    }
    Ok(out)
}

/// Sum of all entry CT lengths (in bytes). Used by `unlock_vault` to
/// determine where the entry payload section begins.
fn read_total_entry_len(metadata: &[EntryMetadata]) -> Result<usize, String> {
    let mut total: usize = 0;
    for meta in metadata {
        total = total
            .checked_add(meta.entry_ct_len as usize)
            .ok_or_else(|| "entry length overflow".to_string())?;
    }
    Ok(total)
}

/// Try decrypting the header CT starting at `HEADER_BYTES_LEN`. Legacy
/// implementation that retries per candidate size — superseded by
/// recording `header_ct_len` directly in the unencrypted header (see
/// `VaultHeader::to_wire`/`from_wire`). Kept here for documentation; not
/// called. Marked `#[allow(dead_code)]` so the symbol remains export-able
/// for any test that wants to introspect the behavior.
#[allow(dead_code)]
fn decrypt_header_ct_legacy(
    file_bytes: &[u8],
    header_key: &[u8; 32],
    header_nonce: &[u8; HEADER_NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let _ = (file_bytes, header_key, header_nonce);
    Err("decrypt_header_ct_legacy is no longer used; header_ct_len is recorded in the unencrypted header".to_string())
}

/// Atomic file write: write header + header_ct + payload to a tmp
/// sibling in the same directory, then rename. Single fsync on the
/// renamed file.
fn write_atomic(
    path: &Path,
    header_bytes: &[u8],
    header_ct: &[u8],
    entry_payload: &[u8],
) -> Result<(), String> {
    use std::io::Write;
    let pid = std::process::id();
    let nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("vault");
    let tmp_name = format!("{base_name}.{pid}.{nano}.tmp");
    let tmp = path.with_file_name(tmp_name);

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("cannot create vault tmp {}: {e}", tmp.display()))?;
        file.write_all(header_bytes)
            .map_err(|e| format!("write header to {}: {e}", tmp.display()))?;
        file.write_all(header_ct)
            .map_err(|e| format!("write header CT to {}: {e}", tmp.display()))?;
        file.write_all(entry_payload)
            .map_err(|e| format!("write entry payloads to {}: {e}", tmp.display()))?;
        file.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Best-effort: extract (type_tag, algo, period_secs, digits) from an
/// EntryPayload. Used to populate the `entry_reserved` block on persist.
fn payload_to_type_tag_algo_period_digits(p: &EntryPayload) -> (u8, u8, u16, u8) {
    let type_tag = match p.entry_type.as_str() {
        "password" => TYPE_PASSWORD,
        "otp" if p.totp.is_some() => TYPE_TOTP,
        "otp" if p.hotp.is_some() => TYPE_HOTP,
        "ocra" => TYPE_OCRA,
        _ => TYPE_PASSWORD,
    };
    // For OCRA entries, use the configured algo/digits; fall back to
    // sensible defaults. For passwords, the algo/period/digits are
    // meaningless but we still write the byte so older readers can
    // round-trip the metadata block.
    let (algo, period_secs, digits) = if let Some(ref totp) = p.totp {
        let a = match totp.get("algo").and_then(|v| v.as_str()) {
            Some("SHA1") | Some("sha1") => ALGO_SHA1,
            Some("SHA256") | Some("sha256") => ALGO_SHA256,
            Some("SHA512") | Some("sha512") => ALGO_SHA512,
            _ => ALGO_SHA256,
        };
        let digits = totp.get("digits").and_then(|v| v.as_u64()).unwrap_or(6) as u8;
        let period = totp.get("period").and_then(|v| v.as_u64()).unwrap_or(30) as u16;
        (a, period, digits)
    } else if let Some(ref ocra) = p.ocra {
        let a = match ocra.get("algo").and_then(|v| v.as_str()) {
            Some("SHA1") | Some("sha1") => ALGO_SHA1,
            Some("SHA256") | Some("sha256") => ALGO_SHA256,
            Some("SHA512") | Some("sha512") => ALGO_SHA512,
            _ => ALGO_SHA256,
        };
        let digits = ocra.get("digits").and_then(|v| v.as_u64()).unwrap_or(6) as u8;
        (a, 0, digits)
    } else {
        (ALGO_UNSPECIFIED, 0, 0)
    };
    (type_tag, algo, period_secs, digits)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn tier_round_trip_byte() {
        for t in [
            MemoryTier::Nano,
            MemoryTier::Standard,
            MemoryTier::Sovereign,
        ] {
            let b = tier_byte(t);
            let back = tier_from_byte(b).expect("tier from byte");
            assert_eq!(t, back);
        }
    }

    #[test]
    fn tier_from_byte_rejects_invalid() {
        assert!(tier_from_byte(3).is_err());
        assert!(tier_from_byte(255).is_err());
    }

    #[test]
    fn header_to_wire_then_from_wire_round_trip() {
        let h = VaultHeader {
            cipher_suite: CIPHER_CHACHA20_BLAKE3,
            kdf_tier: MemoryTier::Standard,
            kdf_salt: [42u8; 16],
            header_nonce: [7u8; 24],
            header_ct_len: 99,
        };
        let wire = h.to_wire();
        let h2 = VaultHeader::from_wire(&wire).expect("from_wire");
        assert_eq!(h.cipher_suite, h2.cipher_suite);
        assert_eq!(h.kdf_tier, h2.kdf_tier);
        assert_eq!(h.kdf_salt, h2.kdf_salt);
        assert_eq!(h.header_nonce, h2.header_nonce);
    }

    #[test]
    fn header_golden_vector_v1() {
        let header = VaultHeader {
            cipher_suite: CIPHER_CHACHA20_BLAKE3,
            kdf_tier: MemoryTier::Standard,
            kdf_salt: [42u8; 16],
            header_nonce: [7u8; 24],
            header_ct_len: 99,
        };
        assert_eq!(
            hex::encode(header.to_wire()),
            "4f564c54010001002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0707070707070707070707070707070707070707070707070063"
        );
    }

    #[test]
    fn header_magic_mismatch_rejected() {
        let mut bad = VaultHeader {
            cipher_suite: CIPHER_CHACHA20_BLAKE3,
            kdf_tier: MemoryTier::Standard,
            kdf_salt: [0u8; 16],
            header_nonce: [0u8; 24],
            header_ct_len: 0,
        }
        .to_wire();
        bad[0] = b'X';
        assert!(VaultHeader::from_wire(&bad).is_err());
    }

    #[test]
    fn header_rejects_unknown_cipher_suite() {
        let mut wire = VaultHeader {
            cipher_suite: CIPHER_CHACHA20_BLAKE3,
            kdf_tier: MemoryTier::Standard,
            kdf_salt: [0u8; 16],
            header_nonce: [0u8; 24],
            header_ct_len: TAG_SIZE,
        }
        .to_wire();
        wire[5] = 0xFF;
        let error = VaultHeader::from_wire(&wire).unwrap_err();
        assert!(error.contains("unsupported cipher suite"));
    }

    #[test]
    fn header_rejects_nonzero_reserved_byte() {
        let mut wire = VaultHeader {
            cipher_suite: CIPHER_CHACHA20_BLAKE3,
            kdf_tier: MemoryTier::Standard,
            kdf_salt: [0u8; 16],
            header_nonce: [0u8; 24],
            header_ct_len: TAG_SIZE,
        }
        .to_wire();
        wire[7] = 1;
        let error = VaultHeader::from_wire(&wire).unwrap_err();
        assert!(error.contains("reserved vault header byte"));
    }

    #[test]
    fn header_rejects_ciphertext_shorter_than_tag() {
        let wire = VaultHeader {
            cipher_suite: CIPHER_CHACHA20_BLAKE3,
            kdf_tier: MemoryTier::Standard,
            kdf_salt: [0u8; 16],
            header_nonce: [0u8; 24],
            header_ct_len: TAG_SIZE - 1,
        }
        .to_wire();
        let error = VaultHeader::from_wire(&wire).unwrap_err();
        assert!(error.contains("ciphertext too short"));
    }

    #[test]
    fn entry_metadata_golden_vector_v1() {
        let meta = EntryMetadata {
            name_hash: [1u8; 32],
            name: "github.com".into(),
            entry_nonce: [2u8; 24],
            entry_ct_offset: 0,
            entry_ct_len: 256,
            type_tag: TYPE_OCRA,
            algo: ALGO_SHA1,
            period_secs: 0,
            digits: 6,
        };
        assert_eq!(
            hex::encode(meta.to_wire()),
            "01010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020000010003010000060000000000000000000000"
        );
    }

    #[test]
    fn entry_metadata_wire_round_trip() {
        let meta = EntryMetadata {
            name_hash: [1u8; 32],
            name: "github.com".into(),
            entry_nonce: [2u8; 24],
            entry_ct_offset: 0,
            entry_ct_len: 256,
            type_tag: TYPE_OCRA,
            algo: ALGO_SHA1,
            period_secs: 0,
            digits: 6,
        };
        let wire = meta.to_wire();
        let back = EntryMetadata::from_wire(&wire).unwrap();
        assert_eq!(meta.name_hash, back.name_hash);
        assert_eq!(meta.entry_nonce, back.entry_nonce);
        assert_eq!(meta.entry_ct_len, back.entry_ct_len);
        assert_eq!(meta.type_tag, back.type_tag);
        assert_eq!(meta.algo, back.algo);
        assert_eq!(meta.digits, back.digits);
    }

    #[test]
    fn init_then_unlock_empty_vault() {
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        init_vault(&path, "correct horse battery staple", MemoryTier::Nano).expect("init");
        // File should exist + minimum header size + minimal header CT.
        let bytes = std::fs::read(&path).expect("read");
        assert!(bytes.len() > HEADER_BYTES_LEN);

        let vault = unlock_vault(&path, "correct horse battery staple").expect("unlock");
        assert_eq!(vault.entries.len(), 0);
        assert_eq!(vault.header.cipher_suite, CIPHER_CHACHA20_BLAKE3);
        assert_eq!(vault.header.kdf_tier, MemoryTier::Nano);
        assert_eq!(vault.master_key.len(), 32);
    }

    #[test]
    fn unlock_with_wrong_passphrase_rejected() {
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        init_vault(&path, "good password", MemoryTier::Nano).expect("init");
        let err = unlock_vault(&path, "bad password").expect_err("must reject");
        assert!(err.contains("decryption") || err.contains("wrong") || err.contains("Argon2id"));
    }

    #[test]
    fn encrypted_secret_never_appears_in_file_bytes() {
        // Defense-in-depth: a plaintext secret should not appear anywhere
        // in the on-disk file. This catches accidental leaks through
        // header CT, JSON serialization, name encoding, etc.
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        let mut vault = unlock_vault_for_init(&path, MemoryTier::Nano);
        let secret = "SECRET_THAT_SHOULD_NEVER_LEAK_INTO_THE_FILE_AAAAAAAAAA";
        vault
            .add_entry(EntryPayload::password("github.com", secret))
            .expect("add");
        persist_vault(&path, &vault).expect("persist");

        let bytes = std::fs::read(&path).expect("read");
        let needle = secret.as_bytes();
        assert!(
            bytes.windows(needle.len()).all(|w| w != needle),
            "the secret string appeared verbatim in the on-disk vault — possible leak",
        );
    }

    /// Smoke test: round-trip a TOTP entry through init → add → unlock.
    #[test]
    fn totp_entry_round_trip() {
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        init_vault(&path, "pw", MemoryTier::Nano).unwrap();
        {
            let mut vault = unlock_vault(&path, "pw").expect("unlock empty");
            vault
                .add_entry(EntryPayload::totp(
                    "github",
                    "JBSWY3DPEHPK3PXP",
                    30,
                    6,
                    "SHA1",
                ))
                .expect("add");
            persist_vault(&path, &vault).expect("persist");
        }
        let v2 = unlock_vault(&path, "pw").expect("unlock populated");
        assert_eq!(v2.entries.len(), 1);
        let entry = v2.entries.get("github").expect("github entry");
        assert_eq!(entry.entry_type, "otp");
        assert_eq!(entry.secret.as_deref(), Some(&b"JBSWY3DPEHPK3PXP"[..]));
        assert!(entry.totp.is_some());
    }

    /// Smoke test: OCRA entry round-trip.
    #[test]
    fn ocra_entry_round_trip() {
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        init_vault(&path, "pw", MemoryTier::Nano).unwrap();
        let key = b"12345678901234567890"; // 20 bytes — RFC 6287 test key
        {
            let mut vault = unlock_vault(&path, "pw").unwrap();
            vault
                .add_entry(EntryPayload::ocra(
                    "bank-ocra",
                    key,
                    "OCRA-1:HOTP-SHA1-6:QN08",
                    6,
                    "SHA1",
                    0,
                ))
                .unwrap();
            persist_vault(&path, &vault).unwrap();
        }
        let v2 = unlock_vault(&path, "pw").unwrap();
        let entry = v2.entries.get("bank-ocra").expect("entry");
        assert_eq!(entry.entry_type, "ocra");
        let stored = entry.secret.as_deref().expect("secret");
        assert_eq!(stored, key);
    }

    /// Smoke test: password entry round-trip + get_ocra_key returns Err.
    #[test]
    fn non_ocra_entry_ocra_lookup_errors() {
        // This protects cmd_code --ocra from accidentally grabbing the
        // wrong entry type and computing an OCRA response over a
        // password's UTF-8 bytes.
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        init_vault(&path, "pw", MemoryTier::Nano).unwrap();
        {
            let mut vault = unlock_vault(&path, "pw").unwrap();
            vault
                .add_entry(EntryPayload::password("github.com", "hunter2"))
                .unwrap();
            persist_vault(&path, &vault).unwrap();
        }
        let vault = unlock_vault(&path, "pw").unwrap();
        let err = vault
            .get_ocra_key("github.com")
            .expect_err("must reject non-OCRA entry");
        assert!(err.to_lowercase().contains("ocra") || err.to_lowercase().contains("type"));
    }

    /// change-passphrase: the new passphrase works, the old does not.
    #[test]
    fn change_passphrase_old_fails_new_succeeds() {
        let dir = fresh_dir();
        let path = dir.path().join("test.vault");
        init_vault(&path, "old-pw", MemoryTier::Nano).unwrap();
        {
            let mut vault = unlock_vault(&path, "old-pw").unwrap();
            vault
                .add_entry(EntryPayload::password("github.com", "pw"))
                .unwrap();
            persist_vault(&path, &vault).unwrap();
        }
        change_vault_passphrase(&path, "old-pw", "new-pw", MemoryTier::Nano).unwrap();
        // Old passphrase rejected.
        assert!(unlock_vault(&path, "old-pw").is_err());
        // New passphrase unlocks and entry survives.
        let v = unlock_vault(&path, "new-pw").unwrap();
        assert!(v.entries.contains_key("github.com"));
    }

    // Production impl Vault { pub fn add_entry; pub fn get_ocra_key } is
    // declared above (before the "Top-level operations" section). The
    // tests use those production methods directly.

    /// Test-only convenience: init + unlock in one shot.
    fn unlock_vault_for_init(path: &Path, tier: MemoryTier) -> Vault {
        init_vault(path, "pw", tier).unwrap();
        unlock_vault(path, "pw").unwrap()
    }
}
