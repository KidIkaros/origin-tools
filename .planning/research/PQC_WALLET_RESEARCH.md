# Post-Quantum Cryptography for Digital Wallets: Pain Points & Considerations

**Research Date:** 2026-08-14
**Domain:** Post-Quantum Cryptography in Wallet Systems
**Confidence:** HIGH

## Executive Summary

Post-quantum cryptography (PQC) is no longer theoretical for wallets. The threat is real, the standards are finalized, and the migration window is closing. However, PQC introduces significant practical challenges that wallet builders must address:

1. **Signature sizes are 20-70x larger** than classical (Ed25519/ECDSA)
2. **Key sizes are 10-30x larger** than classical
3. **Transaction bloat** reduces blockchain throughput
4. **Migration is the hard part** — not the cryptography itself
5. **Hybrid signatures are the interim solution** — but add complexity

**Your advantage:** `origin-crypto-sdk` already supports hybrid Ed25519 + Falcon-1024 signing, which is forward-looking. The challenge is integrating this into a wallet architecture that handles the size/performance trade-offs.

---

## 1. NIST PQC Standards (Finalized August 2024)

### Primary Algorithms

| Algorithm | NIST Standard | Purpose | Key Size | Signature Size | Security Level |
|-----------|---------------|---------|----------|----------------|----------------|
| **ML-KEM** (CRYSTALS-Kyber) | FIPS 203 | Key Encapsulation | 800-1568 bytes | N/A (KEM) | L1-L5 |
| **ML-DSA** (CRYSTALS-Dilithium) | FIPS 204 | Digital Signatures | 1312-2592 bytes | 2420-4627 bytes | L1-L5 |
| **SLH-DSA** (SPHINCS+) | FIPS 205 | Hash-Based Signatures | 32-64 bytes | 7856-49856 bytes | L1-L5 |
| **FN-DSA** (Falcon) | FIPS 206 (draft) | Compact Lattice Signatures | 897-1793 bytes | 666-1280 bytes | L1-L5 |

### Comparison with Classical Cryptography

| Algorithm | Public Key | Signature | Security |
|-----------|------------|-----------|----------|
| Ed25519 (current) | 32 bytes | 64 bytes | ~128-bit classical |
| ECDSA secp256k1 | 33 bytes | 64-72 bytes | ~128-bit classical |
| **FN-DSA-1024** | 1,793 bytes | 1,280 bytes | NIST Level 5 |
| **ML-DSA-87** | 2,592 bytes | 4,627 bytes | NIST Level 5 |
| **SLH-DSA-256s** | 64 bytes | 29,792 bytes | NIST Level 5 |

**Key insight:** FN-DSA (Falcon) produces signatures ~20x larger than Ed25519. ML-DSA (Dilithium) is ~70x larger. This is the fundamental trade-off for quantum resistance.

---

## 2. Pain Points for Wallet Builders

### Pain Point 1: Transaction Bloat

**Problem:** PQC signatures dramatically increase transaction size.

**Impact:**
- Bitcoin: ~1MB block size → fewer transactions per block
- Ethereum: Gas costs increase proportionally to data size
- Storage: Ledger grows faster
- Network: More bandwidth required

**Quantified:**
- Ed25519 transaction: ~200 bytes total
- FN-DSA transaction: ~2,500 bytes total (12.5x increase)
- ML-DSA transaction: ~5,000 bytes total (25x increase)

**Mitigation strategies:**
1. Use FN-DSA (Falcon) for smallest PQC signatures
2. Implement signature aggregation where possible
3. Consider off-chain signature storage with on-chain proofs
4. Adjust block size limits (requires consensus)

### Pain Point 2: Key Management Complexity

**Problem:** Larger keys require more storage and careful management.

**Impact:**
- Hardware wallets: Limited secure element storage
- Memory-constrained devices: More RAM needed for signing
- Key backup: Larger seeds to backup
- Key rotation: More complex migration

**Mitigation strategies:**
1. Use HD derivation (already in `origin-seed`) to derive PQC keys from master seed
2. Store PQC keys encrypted at rest (already in `origin-seal`)
3. Use tiered memory (already in `origin-common`: Nano/Standard/Sovereign)

### Pain Point 3: Migration is the Hard Part

**Problem:** Existing wallets use classical signatures. Migration to PQC is complex.

**Challenges:**
- Backward compatibility: Old transactions still use classical signatures
- User education: Users must actively migrate funds
- Timeline uncertainty: When will quantum threat materialize?
- Consensus required: Blockchains need protocol changes

**Current timeline (2026):**
- Bitcoin: BIP-360 (quantum-resistant addresses) proposed, not merged
- Ethereum: Formal PQC roadmap published February 2026
- No major blockchain has fully migrated yet

**Mitigation strategies:**
1. Support hybrid signatures (classical + PQC) during transition
2. Provide clear migration tools and guidance
3. Use address types that hide public keys until spending (BIP-360 style)

### Pain Point 4: Performance Overhead

**Problem:** PQC operations are computationally expensive.

**Benchmarks (approximate):**
- Ed25519 sign: ~87,000 cycles
- Ed25519 verify: ~174,000 cycles
- ML-DSA-44 sign: ~150,000 cycles
- ML-DSA-44 verify: ~50,000 cycles (faster than Ed25519!)
- FN-DSA sign: ~500,000 cycles
- FN-DSA verify: ~200,000 cycles

**Key insight:** ML-DSA verification is actually faster than Ed25519. The bottleneck is signing, not verification.

**Mitigation strategies:**
1. Offload signing to secure hardware when possible
2. Use batch verification for multiple signatures
3. Cache frequently used public keys

### Pain Point 5: Harvest Now, Decrypt Later (HNDL)

**Problem:** Adversaries are collecting encrypted data today to decrypt when quantum computers are available.

**Impact on wallets:**
- Public keys on blockchain are visible
- Transaction data can be captured
- Long-lived assets are at highest risk

**Mitigation strategies:**
1. Use stealth addresses (already in `origin-stealth`) to hide public keys
2. Never reuse addresses (standard wallet practice)
3. Implement PQC encryption for sensitive data at rest
4. Use hybrid signatures for forward secrecy

---

## 3. Hybrid Signatures: The Interim Solution

### What Are Hybrid Signatures?

Combine classical (Ed25519) + post-quantum (Falcon/Dilithium) signatures:
- Both must verify for transaction to be valid
- If either algorithm is broken, the other still protects
- Provides defense-in-depth during transition

### Your Advantage: `origin-crypto-sdk` Already Does This

```rust
// From origin-crypto-sdk documentation
use origin_crypto_sdk::prelude::*;

let master_seed = [0x42u8; 32];
let bundle = HybridSigningKeyBundle::from_seed(&master_seed, "my-app")
    .expect("valid seed");
let msg = b"sign this";
let sig = bundle.sign_hybrid(msg);
// sig is an Ed25519 + Falcon-1024 hybrid signature
```

### Hybrid Signature Size Impact

| Combination | Signature Size | vs Classical |
|-------------|----------------|--------------|
| Ed25519 only | 64 bytes | 1x |
| Ed25519 + FN-DSA | 1,344 bytes | 21x |
| Ed25519 + ML-DSA | 4,691 bytes | 73x |

**Recommendation:** Use Ed25519 + FN-DSA for smallest hybrid signatures.

---

## 4. Blockchain-Specific Considerations

### Bitcoin

**Current state:**
- Uses ECDSA secp256k1 (64-byte signatures)
- BIP-360 proposes quantum-resistant addresses
- BIP-361 outlines migration plan
- Community has not reached consensus

**Wallet considerations:**
- Support Pay-to-Merkle-Root (BIP-360) address type
- Hide public keys until spending (reduces attack surface)
- Provide migration tools for existing UTXOs

### Ethereum

**Current state:**
- Uses ECDSA secp256k1
- Formal PQC roadmap published February 2026
- Account abstraction as migration mechanism
- Likely requires hard fork

**Wallet considerations:**
- Support ERC-4337 account abstraction
- Implement PQC signing in smart contract wallets
- Plan for protocol-level PQC support

### Custom/Permissioned Chains

**Advantage:** You control the protocol
**Considerations:**
- Can design PQC-native from the start
- No migration headaches
- Full control over signature verification

---

## 5. Recommendations for `origin-wallet`

### Architecture Decisions

1. **Default to hybrid signatures:** Use Ed25519 + FN-DSA for all signing operations
2. **Support multiple PQC algorithms:** Allow users to choose based on size/performance trade-offs
3. **Implement stealth addresses:** Hide public keys until spending (already in `origin-stealth`)
4. **Design for migration:** Support multiple address types for smooth transition

### Implementation Priorities

| Priority | Feature | Rationale |
|----------|---------|-----------|
| 1 | Hybrid signing (Ed25519 + FN-DSA) | Future-proof by default |
| 2 | Stealth addresses | Prevent HNDL attacks |
| 3 | Encrypted key storage | Protect keys at rest |
| 4 | Migration tools | Help users transition |
| 5 | Batch verification | Optimize performance |

### Key Size Management

```rust
// Proposed wallet key structure
pub struct WalletKeys {
    // Classical (for backward compatibility)
    ed25519_pubkey: [u8; 32],
    ed25519_privkey: [u8; 32],
    
    // Post-quantum (for future-proofing)
    falcon_pubkey: Vec<u8>,  // ~897 bytes
    falcon_privkey: Vec<u8>, // ~1281 bytes
    
    // Derived from master seed via HD derivation
    // Domain-separated: "wallet-ed25519", "wallet-falcon"
}
```

### Transaction Format

```rust
pub struct PqTransaction {
    pub id: String,
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    
    // Hybrid signature
    pub classical_sig: [u8; 64],      // Ed25519
    pub pq_sig: Vec<u8>,              // FN-DSA (~1280 bytes)
    
    pub timestamp: u64,
}
```

---

## 6. Open Questions for Your Wallet

1. **Which blockchain(s) to support first?**
   - Custom chain: Full PQC control
   - Bitcoin: Requires BIP-360 support
   - Ethereum: Requires account abstraction

2. **Hybrid vs pure PQC?**
   - Hybrid: Safer transition, larger signatures
   - Pure PQC: Smaller signatures, no classical fallback

3. **Signature aggregation?**
   - Reduces transaction size for multi-signature
   - Complex to implement

4. **Hardware wallet support?**
   - Secure element storage constraints
   - PQC signing performance on embedded devices

---

## Sources

- NIST FIPS 203, 204, 205, 206 (Post-Quantum Cryptography Standards)
- Hedera Blog: "Post-Quantum Cryptography and Blockchain" (April 2026)
- Project Eleven: "The Quantum Threat to Blockchains — 2026 Report"
- Tangem Blog: "Your Guide to Post-Quantum Cryptography (PQC) [2026 update]"
- Crypto Encryption: "Post-Quantum Cryptography 2026: Securing Crypto Wallets"
- Bitcoin Cash Research: "CHIP-2026-06: Post-Quantum and Hybrid Signatures"
- `origin-crypto-sdk` documentation
