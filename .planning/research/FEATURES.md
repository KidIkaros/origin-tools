# Feature Landscape

**Domain:** Digital Wallet with Origin Tools
**Researched:** 2026-08-14

## Table Stakes

Features users expect. Missing = product feels incomplete.

| Feature | Why Expected | Complexity | Notes | Existing Crate |
|---------|--------------|------------|-------|----------------|
| Master Seed Management | Root of trust | Low | Already implemented | `origin-identity` |
| HD Key Derivation | Wallet key hierarchy | Low | Already implemented | `origin-seed` |
| Transaction Signing | Authenticated transfers | Low | Already implemented (hybrid PQ) | `origin-identity`, `origin-seal` |
| Address Generation | User-facing addresses | Medium | Need address encoding | `origin-stealth` (raw) |
| Balance Tracking | User visibility | Medium | Need wallet state | NEW (`origin-wallet`) |
| Transaction History | Audit trail | Medium | MMR exists | `origin-proof` |
| Backup/Recovery | Seed backup | Low | Already implemented | `origin-shard` |
| Encryption at Rest | Data privacy | Low | Already implemented | `origin-seal` |

## Differentiators

Features that set product apart. Not expected, but valued.

| Feature | Value Proposition | Complexity | Notes | Existing Crate |
|---------|-------------------|------------|-------|----------------|
| Post-Quantum Signatures | Future-proof security | Low | Ed25519 + Falcon-1024 hybrid | `origin-crypto-sdk` |
| Stealth Addresses | Privacy | Low | One-time addresses | `origin-stealth` |
| ZK Proofs | Key ownership without reveal | Medium | secp256k1 Schnorr | `origin-schnorr` |
| K-of-N Recovery | Threshold backup | Low | Reed-Solomon | `origin-shard` |
| P2P Communication | Decentralized transfers | High | Identity-addressed routing | `origin-network` |
| Tamper-Evident History | Append-only proofs | Low | MMR | `origin-proof` |

## Anti-Features

Features to explicitly NOT build.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Full Blockchain Node | Complexity, scope | Use RPC client to external nodes |
| Smart Contracts | Scope creep | Keep as ledger system |
| Mobile App (initially) | Platform complexity | Start with CLI + API |
| Multi-Chain (initially) | Protocol complexity | Start with one chain |

## Feature Dependencies

```
Master Seed → HD Key Derivation → Address Generation → Transaction Signing
HD Key Derivation → Stealth Addresses → Privacy Layer
Transaction Signing → Transaction Construction → Balance Tracking
MMR (origin-proof) → Transaction History → Audit Trail
Secret Sharing (origin-shard) → Backup/Recovery → Threshold Recovery
```

## MVP Recommendation

Prioritize:
1. **Wallet Core** (compose existing crates)
2. **Address Encoding** (Bech32/Base58)
3. **Wallet State** (encrypted RocksDB)
4. **Transaction Construction** (unsigned tx builder)
5. **CLI Interface** (user-facing commands)

Defer: P2P networking (add after core works), Multi-chain support (add after single chain works).

## Sources

- `/home/ikaaros/Coding/Gold/origin-tools/` (workspace analysis)
- System Design Notes: Digital Wallet
