# Origin Secrets: Threshold Secrets Management Platform

**Product Name:** Origin Secrets
**Status:** Draft v0.1
**Date:** July 30, 2026

---

## Executive Summary

Origin Secrets is a threshold secrets management platform that eliminates single-point-of-failure (SPOF) outages for human teams. Built on battle-tested Rust cryptography (origin-shard + origin-pass + origin-identity), it provides K-of-N threshold recovery, post-quantum verification, and compliance-ready audit trails.

**Problem Solved:** Vault sealed after power loss = lab-wide outage. No distributed unseal keys. Recovery requires manual intervention.

**Solution:** K-of-N threshold recovery. Distribute master key shards across trusted humans/locations. Recover from any subset of threshold shares. Autonomous verification via post-quantum hybrid signatures.

**Market:** DevOps, SRE, Security teams dealing with:
- Vault SPOF outages
- Shamir implementation flaws
- SOC2/PCI-DSS/HIPAA compliance requirements
- Key recovery runbook gaps

**Differentiation:**
- Post-quantum ready (Falcon-1024 + Ed25519 hybrid)
- Battle-tested Rust (fixes Shamir flaws in pybtc/jsbtc)
- Sovereign-tier Argon2id (user's explicit requirement)
- Unified CLI (identity → shard → recover → verify)

---

## Product Vision

**One system, one closed loop.** No parallel API surfaces. A developer runs `origin-secrets init`, shards their master key, distributes shares to trusted humans, and recovers from any threshold subset. The system handles verification, audit trails, and compliance export automatically.

**Builder-not-maintainer philosophy.** Once configured, the system runs autonomously. No daily hand-holding. Threshold recovery works without operator intervention. Compliance evidence is auto-generated.

**Post-quantum first.** All verification uses Ed25519 + Falcon-1024 hybrid signatures. Future-proof against quantum attacks.

---

## User Stories

### DevOps Engineer (Lab SPOF Outage Victim)

> "Our Vault sealed after a power loss. The lab went down for 4 hours because no one had the unseal keys. I need a way to distribute recovery keys across my team so any 3 of us can recover, without risking a single point of failure."

**Solution:**
```bash
# Initialize vault
origin-secrets init --vault ~/.origin/secrets.vault --tier sovereign

# Shard master key (3-of-5)
origin-secrets shard --key vault-master-key --threshold 3 --shares 5

# Distribute shares to team members
origin-secrets export-share --share 1 --out share1.alice.enc --recipient alice@company.com
origin-secrets export-share --share 2 --out share2.bob.enc --recipient bob@company.com
# ... (repeat for all 5 shares)

# Recovery (Alice, Bob, Carol combine their shares)
origin-secrets recover --shares share1.alice share2.bob share3.carol --vault ~/.origin/secrets.vault
```

### Security Lead (SOC2 Compliance)

> "SOC2 auditors want evidence of our key recovery process. They need to see who recovered which keys, when, and from which shares. I need audit trails that export to SOC2 format."

**Solution:**
```bash
# View recovery audit log
origin-secrets audit --show-recovery-log

# Export SOC2 evidence
origin-secrets audit --export-soc2 --out soc2-evidence-2026-Q3.json

# Export PCI-DSS evidence
origin-secrets audit --export-pcidss --out pcidss-evidence-2026-Q3.json
```

### CISO (Quantum Threat Model)

> "We're preparing for Y2Q. I need post-quantum signatures for all key recovery operations. Ed25519 alone is not enough."

**Solution:**
All verification operations use Ed25519 + Falcon-1024 hybrid signatures:
```bash
# Verify recovery operation (hybrid signature)
origin-secrets verify --recovery-log recovery-001.json

# Output: ✓ Verified (Ed25519: 3af4c01e, Falcon-1024: 7f8d2e9a)
```

---

## Core Features

### 1. Vault Initialization

**CLI:**
```bash
origin-secrets init \
  --vault ~/.origin/secrets.vault \
  --tier sovereign \
  --passphrase-file ~/.pw-master
```

**Parameters:**
- `--vault`: Path to vault file (default: `~/.origin/secrets.vault`)
- `--tier`: Argon2id memory tier (nano | standard | sovereign)
- `--passphrase-file`: Path to passphrase file (interactive if omitted)

**Behavior:**
- Creates new vault encrypted with Argon2id KDF
- Generates master seed for vault operations
- Stores vault metadata (creation time, tier, fingerprint)
- Returns vault fingerprint for verification

### 2. Threshold Sharding

**CLI:**
```bash
origin-secrets shard \
  --key vault-master-key \
  --threshold 3 \
  --shares 5 \
  --passphrase-file ~/.pw-master
```

**Parameters:**
- `--key`: Key identifier to shard (must exist in vault)
- `--threshold`: Minimum shares required for recovery (K)
- `--shares`: Total shares to generate (N)
- `--passphrase-file`: Vault passphrase

**Behavior:**
- Uses Reed-Solomon erasure coding (origin-shard)
- Generates N shares, each threshold K of N can recover
- Encrypts each share with recipient-specific key (optional)
- Signs share metadata with hybrid signature (Ed25519 + Falcon-1024)
- Stores share distribution metadata in vault

**Output:**
```
Generated 5 shares for key 'vault-master-key' (3-of-5 threshold)
Share fingerprints:
  share1: a1b2c3d4
  share2: e5f6g7h8
  share3: i9j0k1l2
  share4: m3n4o5p6
  share5: q7r8s9t0

Distribute shares to trusted recipients. Recovery requires any 3 shares.
```

### 3. Share Export

**CLI:**
```bash
origin-secrets export-share \
  --share 1 \
  --out share1.alice.enc \
  --recipient alice@company.com \
  --passphrase-file ~/.pw-master
```

**Parameters:**
- `--share`: Share number (1-N)
- `--out`: Output file path
- `--recipient`: Recipient identifier (email, service name)
- `--passphrase-file`: Vault passphrase

**Behavior:**
- Exports share to encrypted file
- Encrypts with recipient-specific public key (if provided)
- Includes share metadata (fingerprint, threshold, created-at)
- Signs with hybrid signature for verification

### 4. Threshold Recovery

**CLI:**
```bash
origin-secrets recover \
  --shares share1.alice share2.bob share3.carol \
  --vault ~/.origin/secrets.vault \
  --passphrase-file ~/.pw-master
```

**Parameters:**
- `--shares`: List of share files (minimum: threshold)
- `--vault`: Path to vault file
- `--passphrase-file`: Vault passphrase

**Behavior:**
- Verifies each share's hybrid signature
- Checks threshold condition (≥ K shares)
- Reconstructs master key using Reed-Solomon
- Records recovery operation in audit log
- Returns recovered key (or writes to vault)

**Output:**
```
Recovered key 'vault-master-key' from 3 shares
Recovery ID: rec-001-20260730-212745
Shares used:
  share1.alice (a1b2c3d4) ✓
  share2.bob (e5f6g7h8) ✓
  share3.carol (i9j0k1l2) ✓

Audit log updated. Run 'origin-secrets audit --show-recovery-log' to view.
```

### 5. Audit Trails

**CLI:**
```bash
# View recovery log
origin-secrets audit --show-recovery-log

# Export SOC2 evidence
origin-secrets audit --export-soc2 --out soc2-evidence-2026-Q3.json

# Export PCI-DSS evidence
origin-secrets audit --export-pcidss --out pcidss-evidence-2026-Q3.json

# Export HIPAA evidence
origin-secrets audit --export-hipaa --out hipaa-evidence-2026-Q3.json
```

**Audit Log Format:**
```json
{
  "recovery_id": "rec-001-20260730-212745",
  "key_id": "vault-master-key",
  "threshold": 3,
  "shares_used": 3,
  "share_fingerprints": ["a1b2c3d4", "e5f6g7h8", "i9j0k1l2"],
  "recovered_at": "2026-07-30T21:27:45Z",
  "recovered_by": "alice@company.com",
  "signature": {
    "ed25519": "3af4c01e...",
    "falcon1024": "7f8d2e9a..."
  }
}
```

**SOC2 Export Format:**
```json
{
  "compliance_framework": "SOC2",
  "export_date": "2026-07-30T21:30:00Z",
  "period": "2026-Q3",
  "evidence": [
    {
      "control_id": "CC6.1",
      "control_description": "Logical and physical access controls",
      "evidence_type": "key_recovery_log",
      "evidence_data": [...]
    }
  ]
}
```

### 6. Verification

**CLI:**
```bash
# Verify recovery operation
origin-secrets verify --recovery-log recovery-001-20260730-212745.json

# Verify share integrity
origin-secrets verify --share share1.alice

# Verify vault integrity
origin-secrets verify --vault ~/.origin/secrets.vault
```

**Behavior:**
- Verifies hybrid signature (Ed25519 + Falcon-1024)
- Checks share integrity (threshold, fingerprint)
- Checks vault integrity (metadata, encrypted data)
- Returns verification status

**Output:**
```
✓ Verified (Ed25519: 3af4c01e, Falcon-1024: 7f8d2e9a)
Recovery ID: rec-001-20260730-212745
Key ID: vault-master-key
Recovered at: 2026-07-30T21:27:45Z
```

---

## Web Dashboard

### Features

**Identity Management**
- View all identities in vault
- Rotate master keys (with new sharding)
- Revoke compromised shares
- Export identity fingerprints

**Shard Distribution**
- View all shares for each key
- Track share recipients and status
- Check recovery readiness (≥ threshold shares available)
- Export share distribution report

**Audit Trails**
- View recovery log with filtering (by date, key, user)
- Export compliance evidence (SOC2, PCI-DSS, HIPAA)
- View verification status for each operation
- Download audit reports

**Integration Status**
- View Vault/OpenBao connection status
- View AWS KMS integration status
- View Google KMS integration status
- Test recovery workflows (dry-run)

### Dashboard Architecture

**Tech Stack:**
- Frontend: React + TypeScript + Vite
- Backend: Hono API (Cloudflare Workers)
- Database: Neon Postgres (PostGIS for audit geolocation)
- Auth: NextAuth.js (GitHub, Google, Email)

**Deployment:**
- Cloudflare Pages (frontend)
- Cloudflare Workers (API)
- Neon (database)
- Cloudflare D1 (cache)

---

## Integrations

### Vault / OpenBao

**Use Case:** Use Origin Secrets as backup recovery for Vault master key.

**Integration:**
```bash
# Backup Vault master key to Origin Secrets
origin-secrets vault-backup \
  --vault http://vault:8200 \
  --key vault-master-key \
  --threshold 3 \
  --shares 5

# Recover Vault master key from Origin Secrets
origin-secrets vault-recover \
  --shares share1 share2 share3 \
  --vault http://vault:8200
```

**Behavior:**
- Reads Vault master key via API
- Shards with Origin Secrets
- Writes recovery instructions to Vault storage
- Supports auto-unseal configuration

### AWS KMS

**Use Case:** Use Origin Secrets as backup recovery for AWS KMS master keys.

**Integration:**
```bash
# Backup KMS key to Origin Secrets
origin-secrets kms-backup \
  --key-id aws/kms/master-key \
  --region us-east-1 \
  --threshold 3 \
  --shares 5

# Recover KMS key from Origin Secrets
origin-secrets kms-recover \
  --shares share1 share2 share3 \
  --key-id aws/kms/master-key \
  --region us-east-1
```

**Behavior:**
- Reads KMS key material via AWS SDK
- Shards with Origin Secrets
- Stores backup in S3 (encrypted)
- Supports cross-region replication

### Google KMS

**Use Case:** Use Origin Secrets as backup recovery for Google Cloud KMS keys.

**Integration:**
```bash
# Backup KMS key to Origin Secrets
origin-secrets gcp-kms-backup \
  --key-id projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key \
  --threshold 3 \
  --shares 5

# Recover KMS key from Origin Secrets
origin-secrets gcp-kms-recover \
  --shares share1 share2 share3 \
  --key-id projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key
```

**Behavior:**
- Reads KMS key material via GCP SDK
- Shards with Origin Secrets
- Stores backup in GCS (encrypted)
- Supports multi-region backup

---

## Security Model

### Threat Model

**Adversary Capabilities:**
- Network eavesdropping
- Compromised share holder (up to K-1 shares)
- Vault compromise (encrypted data only)
- Physical theft of vault file

**What Adversary Cannot Do:**
- Recover master key without ≥ K shares
- Forge hybrid signatures (Ed25519 + Falcon-1024)
- Decrypt vault without passphrase
- Modify audit logs without detection

### Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| **Key Derivation** | Argon2id (Nano/Standard/Sovereign) | Vault passphrase → master key |
| **Encryption** | XChaCha20-Poly1305 | Vault data encryption |
| **Threshold Sharing** | Reed-Solomon (K-of-N) | Master key sharding |
| **Signing** | Ed25519 + Falcon-1024 (hybrid) | Share/recovery verification |
| **Hashing** | BLAKE3 | Fingerprint generation |

### Post-Quantum Strategy

**Hybrid Signatures:**
- Ed25519 (classical security)
- Falcon-1024 (post-quantum security)
- Both signatures required for verification
- Future-proof against quantum attacks

**Migration Path:**
- v1.0: Hybrid signatures (Ed25519 + Falcon-1024)
- v2.0: Lattice-based KEM (Kyber-1024) for key exchange
- v3.0: Full post-quantum stack (Falcon + Kyber + BLAKE3)

### Compliance Mapping

| Requirement | Origin Secrets Feature |
|-------------|------------------------|
| **SOC2 CC6.1** | Audit trails, access controls |
| **PCI-DSS 3.2.1** | Key rotation, recovery logs |
| **HIPAA 164.312** | Encryption at rest, audit trails |
| **NIST SP 800-53** | Cryptographic module validation |

---

## Implementation Plan

### Phase 1: Core CLI (Weeks 1-4)

**Week 1: Vault Initialization**
- Implement `origin-secrets init`
- Wire origin-pass (vault storage)
- Wire origin-identity (master seed generation)
- Add Argon2id KDF (nano/standard/sovereign tiers)
- Tests: init, passphrase validation, tier selection

**Week 2: Threshold Sharding**
- Implement `origin-secrets shard`
- Wire origin-shard (Reed-Solomon)
- Add share metadata (fingerprint, threshold)
- Add hybrid signature (Ed25519 + Falcon-1024)
- Tests: shard 2-of-3, 3-of-5, threshold validation

**Week 3: Share Export & Recovery**
- Implement `origin-secrets export-share`
- Implement `origin-secrets recover`
- Add share encryption (recipient-specific)
- Add audit log recording
- Tests: export, recover from threshold shares, fail with <K shares

**Week 4: Verification & Audit**
- Implement `origin-secrets verify`
- Implement `origin-secrets audit`
- Add SOC2/PCI-DSS/HIPAA export formats
- Add audit log filtering
- Tests: verify signatures, export compliance evidence

**Deliverable:**
- CLI binary (`origin-secrets`)
- 90%+ coverage (tarpaulin)
- Integration tests (real workflow: init → shard → recover → audit)

### Phase 2: Web Dashboard (Weeks 5-8)

**Week 5: Dashboard Scaffold**
- Create React + TypeScript + Vite project
- Set up Hono API (Cloudflare Workers)
- Configure Neon Postgres database
- Add NextAuth.js (GitHub, Google, Email)

**Week 6: Identity & Shard Management**
- Implement identity list view
- Implement shard distribution view
- Add recovery readiness checker
- Tests: UI components, API endpoints

**Week 7: Audit Trails & Compliance**
- Implement recovery log view
- Add filtering (by date, key, user)
- Implement compliance export (SOC2, PCI-DSS, HIPAA)
- Tests: audit rendering, export validation

**Week 8: Integration Status**
- Implement Vault/OpenBao connection test
- Implement AWS KMS integration test
- Implement Google KMS integration test
- Tests: integration health checks

**Deliverable:**
- Dashboard deployed (Cloudflare Pages + Workers)
- API documentation (OpenAPI)
- User guide (installation, usage, troubleshooting)

### Phase 3: Integrations (Weeks 9-12)

**Week 9: Vault/OpenBao Integration**
- Implement `origin-secrets vault-backup`
- Implement `origin-secrets vault-recover`
- Add auto-unseal configuration
- Tests: backup, recover, auto-unseal

**Week 10: AWS KMS Integration**
- Implement `origin-secrets kms-backup`
- Implement `origin-secrets kms-recover`
- Add S3 backup storage
- Tests: backup, recover, cross-region

**Week 11: Google KMS Integration**
- Implement `origin-secrets gcp-kms-backup`
- Implement `origin-secrets gcp-kms-recover`
- Add GCS backup storage
- Tests: backup, recover, multi-region

**Week 12: Documentation & Testing**
- Write integration documentation
- Add integration test suite
- Performance benchmarking (shard/recover latency)
- Security audit (external)

**Deliverable:**
- Integration documentation
- Integration test suite
- Performance benchmarks
- Security audit report

### Phase 4: Launch (Weeks 13-16)

**Week 13: Pilot Deployment**
- Deploy to 5 pilot teams
- Monitor recovery operations
- Collect feedback
- Iterate on UX

**Week 14: Bug Fixes & Polish**
- Fix reported bugs
- Polish CLI UX
- Polish dashboard UX
- Add error messages and hints

**Week 15: Documentation & Training**
- Write user documentation
- Record training videos
- Create troubleshooting guide
- Publish API documentation

**Week 16: Launch**
- Release v1.0.0
- Announce on GitHub, Hacker News, Reddit
- Publish case studies (pilot teams)
- Gather testimonials

**Deliverable:**
- v1.0.0 release
- Documentation website
- Training materials
- Launch announcement

---

## Success Metrics

### Technical Metrics

- **Coverage**: 90%+ (tarpaulin)
- **Latency**: Shard < 100ms, Recover < 200ms (p50)
- **Uptime**: 99.9% (dashboard API)
- **Bugs**: < 5 critical bugs in pilot

### Adoption Metrics

- **Pilot teams**: 5 teams (DevOps, SRE, Security)
- **Recovery operations**: 10+ successful recoveries in pilot
- **Compliance exports**: 5+ SOC2 exports in pilot
- **Feedback**: 4+ / 5 rating (pilot satisfaction)

### Business Metrics

- **GitHub stars**: 100+ in first month
- **Hacker News front page**: Top 20
- **Reddit engagement**: 50+ upvotes, 20+ comments
- **Enterprise inquiries**: 5+ inquiries in first month

---

## Open Questions

1. **Share distribution model**: How do we verify share holders are trusted? Manual verification or reputation system?

2. **Recovery authorization**: Should we require multi-factor authentication for recovery? Or is threshold enough?

3. **Share rotation**: How often should shares be rotated? Manual trigger or automated schedule?

4. **Cloud dependency**: Should the dashboard require cloud (Cloudflare Workers + Neon) or support self-hosting?

5. **Pricing**: Open-source (CLI only) vs. SaaS (dashboard + integrations)?

---

## Appendix

### A. origin-tools Crate Map

| Crate | Use in Origin Secrets |
|-------|----------------------|
| `origin-identity` | Master seed generation, hybrid signing |
| `origin-pass` | Vault storage, Argon2id KDF |
| `origin-shard` | Reed-Solomon threshold recovery |
| `origin-entropy` | Entropy auditing (quality gates) |
| `origin-proof` | MMR-based audit log (optional) |

### B. Competitor Analysis

| Product | Strength | Weakness | Origin Advantage |
|---------|----------|----------|------------------|
| **HashiCorp Vault** | Mature, widely adopted | No threshold recovery, SPOF risk | K-of-N recovery, post-quantum |
| **OpenBao** | Open-source Vault fork | Same SPOF risk as Vault | K-of-N recovery, battle-tested Rust |
| **AWS KMS** | Cloud-native, integrated | No threshold recovery, vendor lock-in | K-of-N recovery, multi-cloud |
| **Google KMS** | Cloud-native, integrated | No threshold recovery, vendor lock-in | K-of-N recovery, multi-cloud |
| **Shamir libs (pybtc, jsbtc)** | Simple implementation | Critical security flaws | Battle-tested Rust, post-quantum |

### C. Compliance Evidence Templates

**SOC2 Template:**
```json
{
  "compliance_framework": "SOC2",
  "export_date": "2026-07-30T21:30:00Z",
  "period": "2026-Q3",
  "evidence": [
    {
      "control_id": "CC6.1",
      "control_description": "Logical and physical access controls",
      "evidence_type": "key_recovery_log",
      "evidence_data": {
        "total_recoveries": 10,
        "successful_recoveries": 10,
        "failed_recoveries": 0,
        "audit_trail_complete": true
      }
    }
  ]
}
```

**PCI-DSS Template:**
```json
{
  "compliance_framework": "PCI-DSS",
  "version": "3.2.1",
  "export_date": "2026-07-30T21:30:00Z",
  "period": "2026-Q3",
  "evidence": [
    {
      "requirement_id": "3.2.1",
      "requirement_description": "Do not store sensitive authentication data",
      "evidence_type": "key_recovery_log",
      "evidence_data": {
        "key_rotation_performed": true,
        "recovery_log_complete": true,
        "no_plaintext_keys_stored": true
      }
    }
  ]
}
```

**HIPAA Template:**
```json
{
  "compliance_framework": "HIPAA",
  "section": "164.312",
  "export_date": "2026-07-30T21:30:00Z",
  "period": "2026-Q3",
  "evidence": [
    {
      "requirement_id": "164.312(a)(2)(iv)",
      "requirement_description": "Encryption and decryption",
      "evidence_type": "key_recovery_log",
      "evidence_data": {
        "encryption_at_rest": true,
        "audit_trail_complete": true,
        "access_controls_enabled": true
      }
    }
  ]
}
```

---

**Document Version:** 0.1
**Last Updated:** July 30, 2026
**Author:** Hermes Agent (with user guidance)
**Status:** Draft — ready for review and iteration