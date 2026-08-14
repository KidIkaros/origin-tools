# Research Summary: Digital Wallet with Origin Tools

**Domain:** High-performance financial transaction system
**Researched:** 2026-08-14
**Overall Confidence:** HIGH

## Executive Summary

The origin-tools monorepo already contains **most of the foundational components** needed for a Digital Wallet system. The analysis reveals a comprehensive suite of 18 crates that provide:

- **Identity & Key Management**: `origin-identity`, `origin-seed` (HD derivation)
- **Privacy**: `origin-stealth` (one-time addresses), `origin-schnorr` (ZK proofs)
- **Cryptography**: `origin-seal` (encryption/decryption), `origin-crypto-sdk` (post-quantum primitives)
- **Data Integrity**: `origin-proof` (MMR transaction history), `origin-attest` (audit trails)
- **Recovery**: `origin-shard` (K-of-N secret sharing), `origin-secrets` (threshold management)
- **Networking**: `origin-network` (P2P transport), `origin-channel` (encrypted sessions)

**What's Missing**: The gap is in **wallet-specific orchestration** -- composing these primitives into a cohesive wallet product with state management, transaction construction, address encoding, and blockchain connectivity.

**Post-Quantum Advantage**: `origin-crypto-sdk` already supports hybrid Ed25519 + Falcon-1024 signing, which is forward-looking. The challenge is integrating this into a wallet architecture that handles the size/performance trade-offs.

**Recommendation**: Create a new `origin-wallet` crate that:
1. Composes existing crates (identity, seed, stealth, schnorr, seal, shard, proof)
2. Adds wallet-specific functionality (state management, transaction building, address encoding)
3. Provides a clean API for wallet operations
4. Can be packaged as a standalone product

## Key Findings

**Stack**: Rust (workspace already uses it), leveraging 12+ existing crates
**Architecture**: Composition over reimplementation -- use existing primitives
**Critical advantage**: Post-quantum signatures (Ed25519 + Falcon-1024) are future-proof
**Critical advantage**: HD key derivation with domain separation is wallet-native
**Critical advantage**: Stealth addresses provide built-in privacy

## PQC Pain Points Summary

| Pain Point | Impact | Mitigation |
|------------|--------|------------|
| Transaction bloat (20-70x larger signatures) | Reduced throughput, higher fees | Use FN-DSA (smallest PQC sigs), signature aggregation |
| Key management complexity | More storage, complex migration | HD derivation, encrypted storage, tiered memory |
| Migration is hard | Backward compatibility, user education | Hybrid signatures, clear migration tools |
| Performance overhead | Slower signing | Batch verification, hardware offloading |
| Harvest Now, Decrypt Later | Forward secrecy risk | Stealth addresses, never reuse addresses |

## Implications for Roadmap

Based on research, suggested phase structure:

1.  **Core Wallet Crate** - Create `origin-wallet` that composes existing crates.
    - Addresses: Unified wallet API, state management, transaction construction.
    - Avoids: Reimplementing cryptographic primitives.

2.  **Address Encoding** - Add Base58/Bech32/Bech32m support.
    - Addresses: Standard address format compatibility.
    - Avoids: Custom address formats.

3.  **Wallet State Persistence** - Encrypted key-value store for accounts, addresses, transactions.
    - Addresses: Wallet data at rest, multi-account support.
    - Avoids: Plaintext storage.

4.  **Blockchain Connectivity** - RPC client for node communication.
    - Addresses: Real-time balance updates, transaction broadcasting.
    - Avoids: Manual block scanning.

5.  **CLI & API Layer** - User-facing wallet commands and REST API.
    - Addresses: User interaction, integration with other systems.
    - Avoids: Library-only usage.

**Phase ordering rationale:**
- Core crate first (foundation).
- Address encoding second (standardization).
- State persistence third (data layer).
- Blockchain connectivity fourth (network layer).
- CLI/API last (user-facing layer).

**Research flags for phases:**
- Phase 1: Low complexity (composition of existing crates).
- Phase 2: Low complexity (standard encoding libraries exist).
- Phase 3: Medium complexity (encrypted storage design).
- Phase 4: High complexity (blockchain protocol integration).
- Phase 5: Medium complexity (API design).

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Workspace already uses Rust; 12+ crates exist. |
| Features | HIGH | Digital Wallet requirements are well-defined; gaps are clear. |
| Architecture | HIGH | Composition pattern is proven; existing crates are modular. |
| Pitfalls | HIGH | Distributed systems pitfalls are well-documented. |
| PQC | HIGH | NIST standards finalized; hybrid signatures already supported. |

## Gaps to Address

- Blockchain-specific protocol integration (Bitcoin, Ethereum, etc.).
- Wallet state schema design (UTXO vs account model).
- Multi-signature support design.
- Hardware wallet integration (optional).
- PQC signature aggregation strategy.
