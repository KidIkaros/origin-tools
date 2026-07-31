# Origin Secrets v1.0 Implementation Plan

**Version:** 1.0.0
**Status:** Draft
**Date:** July 30, 2026

---

## Overview

This implementation plan covers the 4-week build phase for Origin Secrets v1.0 CLI. Each week focuses on a core feature area, with clear deliverables and acceptance criteria.

**Timeline:** 4 weeks (Weeks 1-4)
**Scope:** CLI only (dashboard, integrations, enterprise features deferred to v2.0)
**Success Criteria:** 90%+ coverage, all tests pass, no critical bugs

---

## Week 1: Vault Initialization

### Goals

Implement `origin-secrets init` command:
- Create encrypted vault with Argon2id KDF
- Support Nano/Standard/Sovereign tiers
- Generate master seed
- Write vault file with metadata

### Tasks

#### Task 1.1: Create Crate Structure (Day 1)

**Actions:**
- [ ] Create `origin-secrets` crate under `origin-tools/`
- [ ] Add `origin-secrets` to workspace members in `Cargo.toml`
- [ ] Create directory structure:
  ```
  origin-secrets/
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs
    │   ├── cli.rs
    │   ├── commands/
    │   │   ├── mod.rs
    │   │   ├── init.rs
    │   │   ├── shard.rs
    │   │   ├── export.rs
    │   │   ├── recover.rs
    │   │   ├── verify.rs
    │   │   └── audit.rs
    │   ├── vault.rs
    │   ├── share.rs
    │   ├── audit.rs
    │   └── error.rs
    └── tests/
        ├── integration/
        │   ├── init_shard_recover.rs
        │   ├── threshold_validation.rs
        │   ├── signature_verification.rs
        │   └── compliance_export.rs
        └── security/
            ├── passphrase_validation.rs
            ├── vault_tampering.rs
            └── share_tampering.rs
  ```

**Acceptance:**
- [ ] `cargo build -p origin-secrets` succeeds
- [ ] `cargo test -p origin-secrets` passes (empty test suite)

#### Task 1.2: Implement Error Types (Day 1)

**Actions:**
- [ ] Define `Error` enum in `src/error.rs`
- [ ] Implement `Display` and `From` traits
- [ ] Add `thiserror` derive macros
- [ ] Write unit tests for error types

**Acceptance:**
- [ ] All error variants compile
- [ ] Error messages are clear and actionable
- [ ] Unit tests cover all error variants

#### Task 1.3: Implement Vault Data Structures (Day 2)

**Actions:**
- [ ] Define `Vault` struct in `src/vault.rs`
- [ ] Define `MemoryTier` enum
- [ ] Implement `Serialize` and `Deserialize` traits
- [ ] Write unit tests for vault structures

**Acceptance:**
- [ ] Vault structure matches design spec
- [ ] Serialization/deserialization round-trip works
- [ ] Unit tests cover vault fields

#### Task 1.4: Implement Vault Encryption (Day 2-3)

**Actions:**
- [ ] Implement `Vault::encrypt()` method (XChaCha20-Poly1305)
- [ ] Implement `Vault::decrypt()` method
- [ ] Wire origin-crypto-sdk for XChaCha20-Poly1305
- [ ] Write unit tests for encryption/decryption

**Acceptance:**
- [ ] Encryption produces valid ciphertext
- [ ] Decryption recovers original plaintext
- [ ] MAC tag verification fails for tampered data
- [ ] Unit tests cover encryption, decryption, MAC verification

#### Task 1.5: Implement Argon2id KDF (Day 3)

**Actions:**
- [ ] Implement passphrase derivation via Argon2id
- [ ] Support Nano (16 MB), Standard (64 MB), Sovereign (256 MB) tiers
- [ ] Wire origin-crypto-sdk for Argon2id
- [ ] Write unit tests for KDF

**Acceptance:**
- [ ] KDF produces consistent output for same passphrase
- [ ] KDF produces different output for different passphrases
- [ ] Memory tiers are enforced
- [ ] Unit tests cover all tiers

#### Task 1.6: Implement CLI for `init` (Day 4)

**Actions:**
- [ ] Define `Cli` struct in `src/cli.rs` using `clap` derive
- [ ] Define `InitArgs` struct
- [ ] Implement `cmd_init()` function in `src/commands/init.rs`
- [ ] Add passphrase prompt (interactive, no echo)
- [ ] Add passphrase confirmation
- [ ] Write unit tests for CLI parsing

**Acceptance:**
- [ ] `origin-secrets init --help` prints usage
- [ ] `origin-secrets init --tier nano` creates vault with nano tier
- [ ] `origin-secrets init --passphrase-file ~/.pw-demo` reads passphrase from file
- [ ] `origin-secrets init --no-prompt` skips confirmation
- [ ] Unit tests cover all CLI options

#### Task 1.7: Implement `init` Command Logic (Day 4-5)

**Actions:**
- [ ] Implement vault initialization in `cmd_init()`
- [ ] Generate master seed (256 bits)
- [ ] Encrypt master seed with derived key
- [ ] Write vault file to disk
- [ ] Print vault fingerprint
- [ ] Write unit tests for init logic

**Acceptance:**
- [ ] `origin-secrets init` creates valid vault file
- [ ] Vault file can be decrypted with correct passphrase
- [ ] Vault file cannot be decrypted with wrong passphrase
- [ ] Fingerprint is printed and stored in metadata
- [ ] Unit tests cover init, decrypt, fingerprint

#### Task 1.8: Integration Test (Day 5)

**Actions:**
- [ ] Write integration test: `init → decrypt → verify`
- [ ] Run `cargo test -p origin-secrets`
- [ ] Verify 90%+ coverage (cargo-tarpaulin)

**Acceptance:**
- [ ] Integration test passes
- [ ] Coverage ≥ 90%

### Week 1 Deliverables

- [ ] `origin-secrets` crate created
- [ ] `init` command implemented
- [ ] Unit tests (vault, encryption, KDF, CLI)
- [ ] Integration test (init → decrypt → verify)
- [ ] Coverage ≥ 90%

---

## Week 2: Threshold Sharding

### Goals

Implement `origin-secrets shard` command:
- Generate K-of-N shares via Reed-Solomon
- Sign each share with Ed25519 + Falcon-1024
- Store share metadata in vault

### Tasks

#### Task 2.1: Implement Share Data Structures (Day 1)

**Actions:**
- [ ] Define `Share` struct in `src/share.rs`
- [ ] Define `HybridSignature` struct
- [ ] Implement `Serialize` and `Deserialize` traits
- [ ] Write unit tests for share structures

**Acceptance:**
- [ ] Share structure matches design spec
- [ ] Serialization/deserialization round-trip works
- [ ] Unit tests cover share fields

#### Task 2.2: Implement Reed-Solomon Sharding (Day 1-2)

**Actions:**
- [ ] Implement share generation via Reed-Solomon
- [ ] Wire origin-shard crate
- [ ] Validate K-of-N parameters (K ≤ N, K ≥ 1)
- [ ] Write unit tests for sharding

**Acceptance:**
- [ ] Sharding produces N shares
- [ ] Any K shares can reconstruct the original secret
- [ ] < K shares cannot reconstruct the secret
- [ ] Unit tests cover all K/N combinations (2-of-3, 3-of-5, 5-of-7)

#### Task 2.3: Implement Hybrid Signatures (Day 2-3)

**Actions:**
- [ ] Implement Ed25519 signing
- [ ] Implement Falcon-1024 signing
- [ ] Implement hybrid signature generation
- [ ] Wire origin-identity crate
- [ ] Write unit tests for signatures

**Acceptance:**
- [ ] Ed25519 signature is valid
- [ ] Falcon-1024 signature is valid
- [ ] Hybrid signature combines both
- [ ] Verification fails for tampered data
- [ ] Unit tests cover Ed25519, Falcon-1024, hybrid

#### Task 2.4: Implement Share Metadata Storage (Day 3)

**Actions:**
- [ ] Extend `Vault` struct to store share metadata
- [ ] Implement share lookup by share number
- [ ] Implement share listing
- [ ] Write unit tests for metadata storage

**Acceptance:**
- [ ] Share metadata can be stored and retrieved
- [ ] Share lookup returns correct share
- [ ] Share listing returns all shares
- [ ] Unit tests cover storage, lookup, listing

#### Task 2.5: Implement CLI for `shard` (Day 4)

**Actions:**
- [ ] Define `ShardArgs` struct in `src/cli.rs`
- [ ] Implement `cmd_shard()` function in `src/commands/shard.rs`
- [ ] Add validation for K-of-N parameters
- [ ] Write unit tests for CLI parsing

**Acceptance:**
- [ ] `origin-secrets shard --help` prints usage
- [ ] `origin-secrets shard --key X --threshold 3 --shares 5` parses correctly
- [ ] Invalid parameters are rejected (threshold > shares)
- [ ] Unit tests cover all CLI options and validation

#### Task 2.6: Implement `shard` Command Logic (Day 4-5)

**Actions:**
- [ ] Implement sharding in `cmd_shard()`
- [ ] Generate shares via Reed-Solomon
- [ ] Sign each share with hybrid signature
- [ ] Store share metadata in vault
- [ ] Print share fingerprints
- [ ] Write unit tests for shard logic

**Acceptance:**
- [ ] `origin-secrets shard` generates valid shares
- [ ] Share fingerprints are unique
- [ ] Share metadata is stored in vault
- [ ] Unit tests cover sharding, signing, storage

#### Task 2.7: Integration Test (Day 5)

**Actions:**
- [ ] Write integration test: `init → shard → verify shares`
- [ ] Run `cargo test -p origin-secrets`
- [ ] Verify 90%+ coverage (cargo-tarpaulin)

**Acceptance:**
- [ ] Integration test passes
- [ ] Coverage ≥ 90%

### Week 2 Deliverables

- [ ] `shard` command implemented
- [ ] Reed-Solomon sharding working
- [ ] Hybrid signatures (Ed25519 + Falcon-1024)
- [ ] Share metadata storage
- [ ] Unit tests (shares, signatures, metadata)
- [ ] Integration test (init → shard → verify)
- [ ] Coverage ≥ 90%

---

## Week 3: Share Export & Recovery

### Goals

Implement `origin-secrets export-share` and `origin-secrets recover` commands:
- Export shares to encrypted files
- Recover master key from threshold shares
- Record recovery operations in audit log

### Tasks

#### Task 3.1: Implement Share Encryption (Day 1)

**Actions:**
- [ ] Implement share encryption (recipient-specific key)
- [ ] Implement share decryption
- [ ] Wire origin-crypto-sdk for XChaCha20-Poly1305
- [ ] Write unit tests for share encryption

**Acceptance:**
- [ ] Share encryption produces valid ciphertext
- [ ] Share decryption recovers original plaintext
- [ ] Decryption fails for wrong key
- [ ] Unit tests cover encryption, decryption

#### Task 3.2: Implement CLI for `export-share` (Day 1-2)

**Actions:**
- [ ] Define `ExportArgs` struct in `src/cli.rs`
- [ ] Implement `cmd_export_share()` function in `src/commands/export.rs`
- [ ] Add recipient validation
- [ ] Write unit tests for CLI parsing

**Acceptance:**
- [ ] `origin-secrets export-share --help` prints usage
- [ ] `origin-secrets export-share --share 1 --out share1.enc` parses correctly
- [ ] Invalid share numbers are rejected
- [ ] Unit tests cover all CLI options

#### Task 3.3: Implement `export-share` Command Logic (Day 2)

**Actions:**
- [ ] Implement share export in `cmd_export_share()`
- [ ] Retrieve share from vault
- [ ] Encrypt share (if recipient specified)
- [ ] Write share to file
- [ ] Print share fingerprint
- [ ] Write unit tests for export logic

**Acceptance:**
- [ ] `origin-secrets export-share` creates valid share file
- [ ] Share file can be decrypted with correct key
- [ ] Share file contains correct metadata
- [ ] Unit tests cover export, encryption, file writing

#### Task 3.4: Implement Audit Log Data Structures (Day 3)

**Actions:**
- [ ] Define `AuditEntry` struct in `src/audit.rs`
- [ ] Define `Operation` enum
- [ ] Define `ComplianceExport` struct
- [ ] Implement `Serialize` and `Deserialize` traits
- [ ] Write unit tests for audit structures

**Acceptance:**
- [ ] Audit entry structure matches design spec
- [ ] Serialization/deserialization round-trip works
- [ ] Unit tests cover audit entry fields

#### Task 3.5: Implement Audit Log Storage (Day 3)

**Actions:**
- [ ] Extend `Vault` struct to store audit log
- [ ] Implement audit log append (append-only)
- [ ] Implement audit log parsing
- [ ] Write unit tests for audit log storage

**Acceptance:**
- [ ] Audit entries can be appended
- [ ] Audit log can be parsed
- [ ] Append-only property is enforced
- [ ] Unit tests cover append, parse, append-only

#### Task 3.6: Implement Reed-Solomon Recovery (Day 3-4)

**Actions:**
- [ ] Implement secret reconstruction via Reed-Solomon
- [ ] Validate threshold condition (≥ K shares)
- [ ] Wire origin-shard crate
- [ ] Write unit tests for recovery

**Acceptance:**
- [ ] Recovery succeeds with ≥ K shares
- [ ] Recovery fails with < K shares
- [ ] Recovered secret matches original
- [ ] Unit tests cover all K/N combinations

#### Task 3.7: Implement CLI for `recover` (Day 4)

**Actions:**
- [ ] Define `RecoverArgs` struct in `src/cli.rs`
- [ ] Implement `cmd_recover()` function in `src/commands/recover.rs`
- [ ] Add threshold validation
- [ ] Write unit tests for CLI parsing

**Acceptance:**
- [ ] `origin-secrets recover --help` prints usage
- [ ] `origin-secrets recover --shares share1 share2 share3` parses correctly
- [ ] Insufficient shares are rejected
- [ ] Unit tests cover all CLI options

#### Task 3.8: Implement `recover` Command Logic (Day 4-5)

**Actions:**
- [ ] Implement recovery in `cmd_recover()`
- [ ] Verify share signatures
- [ ] Validate threshold condition
- [ ] Reconstruct master key via Reed-Solomon
- [ ] Write master key to vault or stdout
- [ ] Record recovery operation in audit log
- [ ] Print recovery ID
- [ ] Write unit tests for recover logic

**Acceptance:**
- [ ] `origin-secrets recover` reconstructs master key
- [ ] Recovery fails for invalid signatures
- [ ] Recovery fails for insufficient shares
- [ ] Audit log entry is recorded
- [ ] Recovery ID is printed
- [ ] Unit tests cover recovery, validation, audit

#### Task 3.9: Integration Test (Day 5)

**Actions:**
- [ ] Write integration test: `init → shard → export → recover → verify`
- [ ] Run `cargo test -p origin-secrets`
- [ ] Verify 90%+ coverage (cargo-tarpaulin)

**Acceptance:**
- [ ] Integration test passes
- [ ] Coverage ≥ 90%

### Week 3 Deliverables

- [ ] `export-share` command implemented
- [ ] `recover` command implemented
- [ ] Share encryption/decryption
- [ ] Audit log storage
- [ ] Reed-Solomon recovery
- [ ] Unit tests (export, recover, audit)
- [ ] Integration test (init → shard → export → recover → verify)
- [ ] Coverage ≥ 90%

---

## Week 4: Verification & Audit

### Goals

Implement `origin-secrets verify` and `origin-secrets audit` commands:
- Verify signatures/integrity
- View/export audit logs
- Export compliance evidence (SOC2, PCI-DSS, HIPAA)

### Tasks

#### Task 4.1: Implement CLI for `verify` (Day 1)

**Actions:**
- [ ] Define `VerifyArgs` struct in `src/cli.rs`
- [ ] Implement `cmd_verify()` function in `src/commands/verify.rs`
- [ ] Add target validation (vault, share, recovery log)
- [ ] Write unit tests for CLI parsing

**Acceptance:**
- [ ] `origin-secrets verify --help` prints usage
- [ ] `origin-secrets verify --vault ~/.origin/secrets.vault` parses correctly
- [ ] Invalid targets are rejected
- [ ] Unit tests cover all CLI options

#### Task 4.2: Implement Vault Verification (Day 1-2)

**Actions:**
- [ ] Implement vault integrity check
- [ ] Verify vault metadata
- [ ] Verify vault signature (if present)
- [ ] Print verification status
- [ ] Write unit tests for vault verification

**Acceptance:**
- [ ] `origin-secrets verify --vault` detects tampering
- [ ] Verification status is printed clearly
- [ ] Verbose mode shows details
- [ ] Unit tests cover verification, tampering detection

#### Task 4.3: Implement Share Verification (Day 2)

**Actions:**
- [ ] Implement share integrity check
- [ ] Verify share metadata
- [ ] Verify hybrid signature (Ed25519 + Falcon-1024)
- [ ] Print verification status
- [ ] Write unit tests for share verification

**Acceptance:**
- [ ] `origin-secrets verify --share` detects tampering
- [ ] Verification fails for invalid signatures
- [ ] Verification status is printed clearly
- [ ] Unit tests cover verification, signature validation

#### Task 4.4: Implement Recovery Log Verification (Day 2)

**Actions:**
- [ ] Implement recovery log integrity check
- [ ] Verify recovery log signature
- [ ] Print verification status
- [ ] Write unit tests for recovery log verification

**Acceptance:**
- [ ] `origin-secrets verify --recovery-log` detects tampering
- [ ] Verification fails for invalid signatures
- [ ] Verification status is printed clearly
- [ ] Unit tests cover verification, signature validation

#### Task 4.5: Implement CLI for `audit` (Day 3)

**Actions:**
- [ ] Define `AuditArgs` struct in `src/cli.rs`
- [ ] Implement `cmd_audit()` function in `src/commands/audit.rs`
- [ ] Add filter options (key, user, date range)
- [ ] Add export options (SOC2, PCI-DSS, HIPAA)
- [ ] Write unit tests for CLI parsing

**Acceptance:**
- [ ] `origin-secrets audit --help` prints usage
- [ ] `origin-secrets audit --show-recovery-log` parses correctly
- [ ] `origin-secrets audit --export-soc2 evidence.json` parses correctly
- [ ] Unit tests cover all CLI options

#### Task 4.6: Implement Audit Log Viewing (Day 3-4)

**Actions:**
- [ ] Implement audit log retrieval from vault
- [ ] Implement filtering (by key, user, date range)
- [ ] Implement formatting (table view)
- [ ] Print audit entries
- [ ] Write unit tests for audit log viewing

**Acceptance:**
- [ ] `origin-secrets audit --show-recovery-log` prints recovery entries
- [ ] Filters work correctly (by key, user, date range)
- [ ] Table view is readable
- [ ] Unit tests cover retrieval, filtering, formatting

#### Task 4.7: Implement Compliance Export (Day 4)

**Actions:**
- [ ] Implement SOC2 export format
- [ ] Implement PCI-DSS export format
- [ ] Implement HIPAA export format
- [ ] Validate export format (JSON schema)
- [ ] Write unit tests for compliance export

**Acceptance:**
- [ ] `origin-secrets audit --export-soc2` generates valid SOC2 export
- [ ] `origin-secrets audit --export-pcidss` generates valid PCI-DSS export
- [ ] `origin-secrets audit --export-hipaa` generates valid HIPAA export
- [ ] Exports pass JSON schema validation
- [ ] Unit tests cover all export formats

#### Task 4.8: Security Tests (Day 4-5)

**Actions:**
- [ ] Write security test: passphrase validation
- [ ] Write security test: vault tampering
- [ ] Write security test: share tampering
- [ ] Write security test: audit log tampering
- [ ] Run all security tests

**Acceptance:**
- [ ] Passphrase validation rejects weak passphrases
- [ ] Vault tampering is detected
- [ ] Share tampering is detected
- [ ] Audit log tampering is detected
- [ ] All security tests pass

#### Task 4.9: Integration Tests (Day 5)

**Actions:**
- [ ] Write integration test: threshold validation
- [ ] Write integration test: signature verification
- [ ] Write integration test: compliance export
- [ ] Run `cargo test -p origin-secrets`
- [ ] Verify 90%+ coverage (cargo-tarpaulin)

**Acceptance:**
- [ ] All integration tests pass
- [ ] Coverage ≥ 90%

#### Task 4.10: Polish & Documentation (Day 5)

**Actions:**
- [ ] Write README.md (installation, quick start, examples)
- [ ] Write SECURITY.md (threat model, security considerations)
- [ ] Generate MAN page (CLI reference)
- [ ] Polish error messages
- [ ] Polish help text

**Acceptance:**
- [ ] README.md is clear and complete
- [ ] SECURITY.md covers threat model
- [ ] MAN page documents all commands
- [ ] Error messages are actionable
- [ ] Help text is consistent

### Week 4 Deliverables

- [ ] `verify` command implemented
- [ ] `audit` command implemented
- [ ] Compliance export (SOC2, PCI-DSS, HIPAA)
- [ ] Security tests (passphrase, vault, shares, audit log)
- [ ] Integration tests (threshold, signatures, compliance)
- [ ] Documentation (README, SECURITY, MAN)
- [ ] Coverage ≥ 90%

---

## Weekly Deliverables Summary

| Week | Commands | Tests | Coverage |
|------|----------|-------|----------|
| **Week 1** | init | Unit + Integration (init) | ≥ 90% |
| **Week 2** | shard | Unit + Integration (shard) | ≥ 90% |
| **Week 3** | export-share, recover | Unit + Integration (export/recover) | ≥ 90% |
| **Week 4** | verify, audit | Unit + Integration + Security | ≥ 90% |

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

- [ ] `init` creates valid vault
- [ ] `shard` generates valid shares (K-of-N)
- [ ] `export-share` creates encrypted share file
- [ ] `recover` reconstructs master key from ≥ K shares
- [ ] `verify` detects tampering (vault, share, audit log)
- [ ] `audit` exports valid compliance evidence (SOC2, PCI-DSS, HIPAA)

### User Experience Criteria

- [ ] CLI help is clear and complete
- [ ] Error messages are actionable
- [ ] Passphrase prompt is secure (no echo)
- [ ] Progress indicators for long operations
- [ ] Verbose mode provides technical details

---

## Risk Mitigation

### Technical Risks

| Risk | Mitigation |
|------|------------|
| **Falcon-1024 integration issues** | Monitor origin-identity crate; fallback to Ed25519 only if needed |
| **Reed-Solomon reconstruction failures** | Leverage origin-shard crate (already tested); add property-based tests |
| **Coverage below 90%** | Prioritize test coverage; add tests for uncovered branches |

### Timeline Risks

| Risk | Mitigation |
|------|------------|
| **Task overrun** | Defer non-critical features (verbose mode, progress indicators) to v1.1 |
| **Integration test failures** | Allocate buffer time (Day 5 each week) for debugging |
| **Dependency issues** | Version-lock dependencies; monitor upstream changes |

---

## Open Questions

1. **Entropy validation:** Should we use `origin-entropy` to validate share entropy? (Optional dependency, defer to v1.1)

2. **Share encryption:** Should we encrypt shares by default? (Current: opt-in via `--recipient`, consistent with design spec)

3. **Recovery authorization:** Should we require additional authorization (beyond passphrase)? (Current: passphrase only, consistent with design spec)

4. **Audit log storage:** Should we store audit log in separate file? (Current: in vault, consistent with design spec)

5. **Compliance export formats:** Should we add ISO 27001, FedRAMP? (Defer to v1.1)

---

## Appendix

### A. Daily Standup Checklist

Each day, verify:
- [ ] All tasks completed
- [ ] All tests pass
- [ ] Coverage ≥ 90%
- [ ] No critical bugs
- [ ] Rust lint clean

### B. Weekly Review Checklist

Each week, verify:
- [ ] All deliverables complete
- [ ] All integration tests pass
- [ ] Coverage ≥ 90%
- [ ] Documentation updated
- [ ] Ready for next week

### C. Release Checklist

At end of Week 4, verify:
- [ ] All success criteria met
- [ ] All tests pass
- [ ] Coverage ≥ 90%
- [ ] Documentation complete
- [ ] Ready for v1.0 release

---

**Document Version:** 1.0.0
**Last Updated:** July 30, 2026
**Author:** Hermes Agent (with user guidance)
**Status:** Draft — ready for review and implementation