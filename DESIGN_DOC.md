# Origin Secrets v1.0 Design Document

**Version:** 1.0.0
**Status:** Draft
**Date:** July 30, 2026

---

## Overview

Origin Secrets v1.0 is a threshold secrets management CLI that eliminates single-point-of-failure (SPOF) outages for human teams. It provides K-of-N threshold recovery using Reed-Solomon erasure coding, post-quantum verification via Ed25519 + Falcon-1024 hybrid signatures, and compliance-ready audit trails (SOC2, PCI-DSS, HIPAA export).

**Scope: CLI only.** Web dashboard, integrations, and enterprise features are deferred to v2.0.

**Target Users:** DevOps, SRE, Security teams dealing with Vault SPOF outages, Shamir implementation flaws, and compliance requirements.

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (origin-secrets)               │
├─────────────────────────────────────────────────────────────┤
│  Commands:                                                  │
│  - init      : Initialize vault                             │
│  - shard     : Shard master key                            │
│  - export    : Export share to file                         │
│  - recover   : Recover master key from shares              │
│  - verify    : Verify signatures/integrity                  │
│  - audit     : View/export audit logs                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ├──────────────────────────────┐
                              │                              │
                              ▼                              ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│   origin-common          │  │   origin-tools crates     │
├──────────────────────────┤  ├──────────────────────────┤
│ - Config management      │  │ - origin-identity         │
│ - Home directory setup   │  │ - origin-pass              │
│ - Passphrase resolution  │  │ - origin-shard             │
│ - Error handling         │  │ - origin-entropy (opt)     │
└──────────────────────────┘  └──────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     origin-crypto-sdk                        │
├─────────────────────────────────────────────────────────────┤
│ - Argon2id KDF (Nano/Standard/Sovereign)                   │
│ - XChaCha20-Poly1305 AEAD                                   │
│ - Ed25519 + Falcon-1024 hybrid signatures                   │
│ - BLAKE3 hashing                                            │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

**Init Flow:**
```
User input (passphrase) → Argon2id KDF → Master seed → Vault file (encrypted)
                                                            ↓
                                                    Audit log entry
```

**Shard Flow:**
```
Master key (from vault) → Reed-Solomon (K-of-N) → N shares
                                                    ↓
                                    Encrypt each share (optional)
                                                    ↓
                                    Sign each share (Ed25519 + Falcon-1024)
                                                    ↓
                                                    Store share metadata
                                                            ↓
                                                    Audit log entry
```

**Recover Flow:**
```
N shares (≥ K) → Verify signatures (Ed25519 + Falcon-1024)
                → Check threshold condition
                → Reed-Solomon reconstruction → Master key
                                                     ↓
                                            Write to vault / stdout
                                                     ↓
                                            Audit log entry
```

**Audit Flow:**
```
Audit log file → Parse → Filter (by date, key, user)
                            ↓
                    Export (SOC2/PCI-DSS/HIPAA format)
```

---

## Data Structures

### Vault File Format

```rust
pub struct Vault {
    pub version: u8,
    pub created_at: String,  // ISO 8601
    pub tier: MemoryTier,    // Nano | Standard | Sovereign
    pub fingerprint: String, // BLAKE3(salt || nonce)[..4].hex()
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>, // Encrypted master seed + metadata
    pub mac: [u8; 32],       // AEAD tag
}

pub enum MemoryTier {
    Nano,      // 16 MB
    Standard,  // 64 MB
    Sovereign, // 256 MB
}
```

### Share File Format

```rust
pub struct Share {
    pub version: u8,
    pub key_id: String,           // "vault-master-key"
    pub share_number: u8,         // 1-N
    pub threshold: u8,            // K
    pub total_shares: u8,         // N
    pub share_data: Vec<u8>,      // Encrypted share data
    pub fingerprint: String,      // BLAKE3(share_data)
    pub signature: HybridSignature,
    pub created_at: String,       // ISO 8601
    pub recipient: Option<String>, // "alice@company.com" or None
}

pub struct HybridSignature {
    pub ed25519: Vec<u8>,  // 64 bytes
    pub falcon1024: Vec<u8>, // 1332 bytes
}
```

### Audit Log Format

```rust
pub struct AuditEntry {
    pub entry_id: String,  // "audit-001-20260730-212745"
    pub operation: Operation,
    pub key_id: String,
    pub timestamp: String,  // ISO 8601
    pub operator: String,  // "alice@company.com"
    pub details: OperationDetails,
    pub signature: HybridSignature,
}

pub enum Operation {
    Init,
    Shard { threshold: u8, total_shares: u8 },
    ExportShare { share_number: u8, recipient: String },
    Recover { shares_used: Vec<String> },
    Verify { target: VerifyTarget },
    AuditExport { format: ComplianceFormat },
}

pub enum OperationDetails {
    Success { message: String },
    Failure { error: String },
}
```

### Compliance Export Format

```rust
pub struct ComplianceExport {
    pub framework: ComplianceFramework,
    pub version: String,
    pub export_date: String,  // ISO 8601
    pub period: String,       // "2026-Q3"
    pub evidence: Vec<EvidenceItem>,
}

pub enum ComplianceFramework {
    SOC2,
    PciDss { version: String },   // "3.2.1"
    Hipaa { section: String },    // "164.312"
}

pub struct EvidenceItem {
    pub control_id: String,
    pub control_description: String,
    pub evidence_type: String,
    pub evidence_data: serde_json::Value,
}
```

---

## CLI Specification

### Global Options

```bash
origin-secrets [OPTIONS] <COMMAND>

OPTIONS:
    --vault <PATH>           Vault file path [default: ~/.origin/secrets.vault]
    --passphrase-file <PATH> Passphrase file path [default: interactive]
    --config <PATH>          Config file path [default: ~/.origin/config.toml]
    --verbose, -v            Verbose output
    --quiet, -q              Quiet mode (errors only)
    --help, -h               Print help
    --version, -V            Print version
```

### Commands

#### `init` — Initialize Vault

```bash
origin-secrets init [OPTIONS]

OPTIONS:
    --vault <PATH>              Vault file path [default: ~/.origin/secrets.vault]
    --tier <TIER>               Argon2id memory tier [default: standard]
                                  [possible values: nano, standard, sovereign]
    --passphrase-file <PATH>    Passphrase file path [default: interactive]
    --no-prompt                 Skip passphrase confirmation (dangerous)

BEHAVIOR:
  1. Prompt for passphrase (interactive) or read from --passphrase-file
  2. Confirm passphrase (unless --no-prompt)
  3. Derive master key via Argon2id KDF (specified tier)
  4. Generate master seed (256 bits)
  5. Encrypt master seed with XChaCha20-Poly1305
  6. Write vault file
  7. Print vault fingerprint

OUTPUT:
  Vault initialized: ~/.origin/secrets.vault
  Tier: standard
  Fingerprint: 3af4c01e

ERRORS:
  - Vault already exists (use --force to overwrite)
  - Passphrase too weak (min 12 chars)
  - Derivation failed (Argon2id error)
```

#### `shard` — Shard Master Key

```bash
origin-secrets shard [OPTIONS] --key <KEY_ID> --threshold <K> --shares <N>

OPTIONS:
    --key <KEY_ID>              Key identifier to shard [required]
    --threshold <K>             Minimum shares required (K) [required]
    --shares <N>                Total shares to generate (N) [required]
    --vault <PATH>              Vault file path [default: ~/.origin/secrets.vault]
    --passphrase-file <PATH>    Passphrase file path [default: interactive]

BEHAVIOR:
  1. Read passphrase
  2. Decrypt vault
  3. Retrieve master key by key_id
  4. Generate N shares via Reed-Solomon (K-of-N)
  5. Sign each share with Ed25519 + Falcon-1024
  6. Store share metadata in vault
  7. Print share fingerprints

OUTPUT:
  Generated 5 shares for key 'vault-master-key' (3-of-5 threshold)
  Share fingerprints:
    share1: a1b2c3d4
    share2: e5f6g7h8
    share3: i9j0k1l2
    share4: m3n4o5p6
    share5: q7r8s9t0

  Distribute shares to trusted recipients. Recovery requires any 3 shares.
  Run 'origin-secrets export-share' to export each share to a file.

ERRORS:
  - Key not found in vault
  - Threshold > total_shares (invalid)
  - Threshold < 1 (invalid)
  - Total_shares < threshold (invalid)
```

#### `export-share` — Export Share to File

```bash
origin-secrets export-share [OPTIONS] --share <NUMBER> --out <PATH>

OPTIONS:
    --share <NUMBER>            Share number (1-N) [required]
    --out <PATH>                Output file path [required]
    --recipient <RECIPIENT>     Recipient identifier [optional]
    --vault <PATH>              Vault file path [default: ~/.origin/secrets.vault]
    --passphrase-file <PATH>    Passphrase file path [default: interactive]

BEHAVIOR:
  1. Read passphrase
  2. Decrypt vault
  3. Retrieve share metadata by share number
  4. Encrypt share with recipient-specific key (if --recipient provided)
  5. Write share to file
  6. Print share fingerprint

OUTPUT:
  Exported share 1 to share1.alice.enc
  Fingerprint: a1b2c3d4
  Recipient: alice@company.com

  Distribute this file to the recipient. Do not share via unencrypted channels.

ERRORS:
  - Share not found in vault
  - Output file already exists (use --force to overwrite)
  - Recipient public key not found (if --recipient provided)
```

#### `recover` — Recover Master Key from Shares

```bash
origin-secrets recover [OPTIONS] --shares <SHARES>... [--out <PATH>]

OPTIONS:
    --shares <SHARES>...        List of share files [required]
    --vault <PATH>              Vault file path [default: ~/.origin/secrets.vault]
    --out <PATH>                Output file path (or stdout if omitted)
    --passphrase-file <PATH>    Passphrase file path [default: interactive]

BEHAVIOR:
  1. Read share files
  2. Verify each share's hybrid signature
  3. Check threshold condition (≥ K shares)
  4. Reconstruct master key via Reed-Solomon
  5. Write master key to vault or stdout
  6. Record recovery operation in audit log
  7. Print recovery ID

OUTPUT:
  Recovered key 'vault-master-key' from 3 shares
  Recovery ID: rec-001-20260730-212745
  Shares used:
    share1.alice (a1b2c3d4) ✓
    share2.bob (e5f6g7h8) ✓
    share3.carol (i9j0k1l2) ✓

  Audit log updated. Run 'origin-secrets audit --show-recovery-log' to view.

ERRORS:
  - Insufficient shares (need ≥ K, got N)
  - Share signature verification failed
  - Reed-Solomon reconstruction failed
  - Vault write failed
```

#### `verify` — Verify Signatures/Integrity

```bash
origin-secrets verify [OPTIONS] <TARGET>

TARGET:
    --vault <PATH>              Verify vault integrity
    --share <SHARE_FILE>        Verify share integrity
    --recovery-log <LOG_FILE>   Verify recovery log entry

OPTIONS:
    --verbose, -v               Show verification details

BEHAVIOR:
  1. Read target file
  2. Verify hybrid signature (Ed25519 + Falcon-1024)
  3. Check integrity (fingerprint, metadata)
  4. Print verification status

OUTPUT (vault):
  ✓ Verified (Ed25519: 3af4c01e, Falcon-1024: 7f8d2e9a)
  Vault: ~/.origin/secrets.vault
  Created at: 2026-07-30T21:27:45Z
  Tier: standard

OUTPUT (share):
  ✓ Verified (Ed25519: 3af4c01e, Falcon-1024: 7f8d2e9a)
  Share: share1.alice
  Key ID: vault-master-key
  Share number: 1
  Threshold: 3
  Total shares: 5

OUTPUT (recovery log):
  ✓ Verified (Ed25519: 3af4c01e, Falcon-1024: 7f8d2e9a)
  Recovery ID: rec-001-20260730-212745
  Key ID: vault-master-key
  Recovered at: 2026-07-30T21:27:45Z
  Recovered by: alice@company.com

ERRORS:
  - Signature verification failed
  - Fingerprint mismatch
  - Metadata corruption
```

#### `audit` — View/Export Audit Logs

```bash
origin-secrets audit [OPTIONS]

OPTIONS:
    --show-recovery-log         Show recovery log entries
    --show-all-logs             Show all audit entries
    --filter-key <KEY_ID>       Filter by key ID
    --filter-user <USER>        Filter by user
    --filter-start <DATE>       Filter start date (ISO 8601)
    --filter-end <DATE>         Filter end date (ISO 8601)
    --export-soc2 <PATH>        Export SOC2 evidence
    --export-pcidss <PATH>      Export PCI-DSS evidence
    --export-hipaa <PATH>       Export HIPAA evidence
    --vault <PATH>              Vault file path [default: ~/.origin/secrets.vault]

BEHAVIOR (show):
  1. Read audit log from vault
  2. Apply filters (if specified)
  3. Print audit entries

BEHAVIOR (export):
  1. Read audit log from vault
  2. Apply filters (if specified)
  3. Transform to compliance format
  4. Write to file

OUTPUT (show):
  Audit log (last 10 entries):
    rec-001-20260730-212745  RECOVER  vault-master-key  alice@company.com  ✓
    audit-002-20260730-213000  EXPORT   vault-master-key  alice@company.com  ✓
    audit-003-20260730-213030  SHARD    vault-master-key  alice@company.com  ✓
    ...

OUTPUT (export):
  Exported SOC2 evidence to soc2-evidence-2026-Q3.json
  Period: 2026-Q3
  Evidence items: 15

ERRORS:
  - Audit log not found
  - Export file already exists (use --force to overwrite)
  - Compliance format invalid
```

---

## Error Handling

### Error Types

```rust
pub enum Error {
    // Vault errors
    VaultNotFound { path: PathBuf },
    VaultAlreadyExists { path: PathBuf },
    VaultCorrupted { details: String },
    VaultDecryptionFailed { details: String },
    VaultEncryptionFailed { details: String },

    // Key errors
    KeyNotFound { key_id: String },
    KeyAlreadyExists { key_id: String },

    // Share errors
    ShareNotFound { share_number: u8 },
    InsufficientShares { needed: u8, provided: u8 },
    ShareVerificationFailed { share_number: u8, details: String },
    ShareCorrupted { share_number: u8 },

    // Threshold errors
    InvalidThreshold { threshold: u8, total_shares: u8 },

    // Signature errors
    SignatureVerificationFailed { details: String },
    SignatureGenerationFailed { details: String },

    // Compliance errors
    ComplianceExportFailed { framework: String, details: String },
    AuditLogNotFound,

    // I/O errors
    IoError { details: String },

    // Crypto errors
    CryptoError { details: String },

    // User errors
    PassphraseTooWeak { min_length: usize },
    PassphraseMismatch,
}
```

### Error Messages

**User-facing errors:**
```
Error: Vault already exists at ~/.origin/secrets.vault
Use --force to overwrite (dangerous).

Error: Key 'vault-master-key' not found in vault.
Run 'origin-secrets list-keys' to view available keys.

Error: Insufficient shares: need 3, got 2.
Recovery requires at least 3 shares.

Error: Share verification failed: share1.alice
Hybrid signature mismatch. The share may be corrupted or tampered with.

Error: Passphrase too weak (minimum 12 characters).
Use a stronger passphrase to protect your vault.
```

**Technical errors (verbose mode):**
```
Error: VaultDecryptionFailed { details: "Invalid MAC tag" }
  Vault file may be corrupted or passphrase may be incorrect.
  Run 'origin-secrets verify --vault ~/.origin/secrets.vault' to check integrity.

Error: CryptoError { details: "Argon2id derivation failed: memory allocation failed" }
  Tier 'sovereign' requires 256 MB of RAM. Try 'standard' or 'nano' tiers.
```

---

## Security Considerations

### Passphrase Security

- **Minimum length:** 12 characters (configurable)
- **Confirmation required:** Interactive prompt (skip with `--no-prompt`)
- **No echo:** Terminal in raw mode during passphrase entry
- **No storage:** Passphrase never written to disk or logs

### Vault Security

- **Encryption:** XChaCha20-Poly1305 AEAD (256-bit key)
- **Key derivation:** Argon2id KDF (Nano/Standard/Sovereign tiers)
- **Integrity:** AEAD tag (128-bit) detects tampering
- **Secure deletion:** Zeroize master key and passphrase after use

### Share Security

- **Signatures:** Ed25519 + Falcon-1024 hybrid (non-repudiation)
- **Encryption (optional):** Recipient-specific public key encryption
- **Integrity:** Fingerprint (BLAKE3) detects corruption
- **Verification required:** Recover operation verifies all signatures

### Audit Log Security

- **Append-only:** Audit log cannot be modified after entry
- **Signed entries:** Each entry signed with hybrid signature
- **Tamper detection:** Verification detects log tampering
- **Export integrity:** Compliance exports include signature verification

### Post-Quantum Security

- **Hybrid signatures:** Ed25519 (classical) + Falcon-1024 (post-quantum)
- **Future-proof:** Both signatures required for verification
- **Migration path:** Planned support for Kyber-1024 (KEM) in v2.0

---

## Testing Strategy

### Unit Tests

**Coverage target:** 90%+ (measured via cargo-tarpaulin)

**Test categories:**
- Vault operations (init, decrypt, encrypt)
- Key operations (generate, retrieve, delete)
- Share operations (generate, verify, reconstruct)
- Signature operations (sign, verify)
- Audit log operations (append, parse, filter)
- Compliance export (SOC2, PCI-DSS, HIPAA)

### Integration Tests

**Test workflows:**
1. **Init → Shard → Export → Recover → Verify**
   - Initialize vault
   - Shard master key (3-of-5)
   - Export shares
   - Recover from threshold shares
   - Verify integrity

2. **Threshold Validation**
   - Shard (2-of-3)
   - Attempt recovery with 1 share (should fail)
   - Attempt recovery with 2 shares (should succeed)
   - Attempt recovery with 3 shares (should succeed)

3. **Signature Verification**
   - Shard shares
   - Tamper with one share (modify a byte)
   - Attempt recovery (should fail with verification error)

4. **Compliance Export**
   - Generate audit entries
   - Export SOC2 evidence
   - Verify export format (JSON schema validation)

### Property-Based Tests

**Test properties:**
- **Reed-Solomon:** Any K shares can reconstruct the original secret
- **Threshold:** < K shares cannot reconstruct the secret
- **Signatures:** Signature verification fails for tampered data
- **Audit log:** Append-only property enforced

### Security Tests

**Test security properties:**
- **Passphrase weakness:** Reject passphrases < 12 characters
- **Vault tampering:** Verification fails for corrupted vault
- **Share tampering:** Verification fails for corrupted shares
- **Audit log tampering:** Verification fails for modified logs

---

## Dependencies

### Origin-Tools Crates

```toml
[dependencies]
origin-common = { path = "../origin-common" }
origin-identity = { path = "../origin-identity" }
origin-pass = { path = "../origin-pass" }
origin-shard = { path = "../origin-shard" }
origin-entropy = { path = "../origin-entropy", optional = true }  # For entropy validation

[dev-dependencies]
tempfile = "3"
```

### External Dependencies

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
rpassword = "7"
zeroize = { version = "1", features = ["derive"] }
thiserror = "2"

[dev-dependencies]
cargo-tarpaulin = "0.27"
```

---

## Deliverables

### v1.0 Deliverables

1. **CLI binary:** `origin-secrets`
   - Commands: init, shard, export-share, recover, verify, audit
   - Global options: --vault, --passphrase-file, --config, --verbose, --quiet

2. **Documentation:**
   - README.md (installation, quick start, examples)
   - MAN page (CLI reference)
   - SECURITY.md (threat model, security considerations)

3. **Tests:**
   - Unit tests (90%+ coverage)
   - Integration tests (5 workflows)
   - Property-based tests (Reed-Solomon, signatures)
   - Security tests (passphrase, vault, shares, audit log)

4. **Artifacts:**
   - Cargo package (origin-secrets)
   - Release binary (Linux, macOS, Windows)
   - Checksum verification (BLAKE3)

---

## Success Criteria

### Technical Criteria

- [ ] 90%+ coverage (cargo-tarpaulin)
- [ ] All integration tests pass
- [ ] All security tests pass
- [ ] No critical bugs (P0/P1)
- [ ] Rust lint clean (clippy)
- [ ] Rust fmt consistent

### Functional Criteria

- [ ] Init creates valid vault
- [ ] Shard generates valid shares (K-of-N)
- [ ] Export-share creates encrypted share file
- [ ] Recover reconstructs master key from ≥ K shares
- [ ] Verify detects tampering (vault, share, audit log)
- [ ] Audit exports valid compliance evidence (SOC2, PCI-DSS, HIPAA)

### User Experience Criteria

- [ ] CLI help is clear and complete
- [ ] Error messages are actionable
- [ ] Passphrase prompt is secure (no echo)
- [ ] Progress indicators for long operations (sharding, recovery)
- [ ] Verbose mode provides technical details

---

## Open Questions

1. **Entropy validation:** Should we use `origin-entropy` to validate share entropy? (Optional dependency)

2. **Share encryption:** Should we encrypt shares by default, or make it opt-in? (Current: opt-in via `--recipient`)

3. **Recovery authorization:** Should we require passphrase for recovery? (Current: yes, vault passphrase required)

4. **Audit log storage:** Should we store audit log in vault or separate file? (Current: in vault)

5. **Compliance export formats:** Should we support additional formats (ISO 27001, FedRAMP)? (Current: SOC2, PCI-DSS, HIPAA only)

---

## Appendix

### A. File Paths

**Default paths:**
```
Vault:           ~/.origin/secrets.vault
Config:          ~/.origin/config.toml
Audit log:       ~/.origin/secrets.vault (embedded)
Share files:     ./share*.enc (user-specified)
Compliance:      ./soc2-evidence-*.json (user-specified)
```

### B. Exit Codes

```rust
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    UsageError = 2,
    VaultError = 3,
    KeyError = 4,
    ShareError = 5,
    SignatureError = 6,
    ComplianceError = 7,
    IoError = 8,
    CryptoError = 9,
}
```

### C. Version Compatibility

**v1.0 vault format:**
- Version: 1
- Backward compatibility: Not required (v1.0 is initial release)
- Forward compatibility: Unknown (planned for v2.0)

---

**Document Version:** 1.0.0
**Last Updated:** July 30, 2026
**Author:** Hermes Agent (with user guidance)
**Status:** Draft — ready for review and implementation