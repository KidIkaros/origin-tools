# Origin Wallet Implementation Plan

**Created:** 2026-08-14
**Status:** Ready for Execution
**Estimated Duration:** 8 weeks (full-time)

## Executive Summary

This plan details the implementation of `origin-wallet`, a post-quantum-secure Digital Wallet built on the OriginSDK. The wallet is a **thin orchestration layer** that composes existing SDK primitives — hybrid signing, stealth addresses, MMR transaction history, AEAD encryption, and seed management — into a cohesive product.

**Key Insight:** The SDK already provides 90% of the cryptographic functionality. The wallet crate adds address encoding, state persistence, CLI interface, and orchestration logic.

## Task Prioritization Matrix

| Priority | Task | Dependencies | Risk | Value |
|----------|------|--------------|------|-------|
| **P0** | Create crate structure | None | Low | Foundation |
| **P0** | Wallet create/open/save | Crate structure | Low | Core functionality |
| **P0** | Account management | Wallet | Low | Core functionality |
| **P1** | Transaction signing (hybrid) | Account | Medium | PQC security |
| **P1** | Transaction verification | Account | Medium | Security |
| **P1** | Address encoding (Bech32) | Account | Low | Usability |
| **P2** | Encrypted state persistence | Wallet | Low | Security |
| **P2** | Stealth address generation | Account | Medium | Privacy |
| **P2** | Transaction history (MMR) | Wallet | Low | Auditability |
| **P3** | Backup/Recovery (shards) | Wallet | Medium | Resilience |
| **P3** | Recovery phrases | Wallet | Low | Backup |
| **P3** | CLI polish | All | Low | Usability |
| **P4** | Documentation | All | Low | Maintainability |
| **P4** | Performance benchmarks | All | Low | Optimization |

## Detailed Task Breakdown

### Phase 1: Foundation (Week 1-2) — P0 Tasks

#### Task 1.1: Create Crate Structure
**Priority:** P0 | **Effort:** 1 hour | **Dependencies:** None

**Acceptance Criteria:**
- [ ] `origin-wallet/Cargo.toml` created with all dependencies
- [ ] `src/lib.rs` with public API re-exports
- [ ] `src/error.rs` with error types
- [ ] Crate compiles: `cargo check -p origin-wallet`
- [ ] Basic test passes: `cargo test -p origin-wallet`

**Implementation Notes:**
```toml
# Cargo.toml
[package]
name = "origin-wallet"
version = "0.1.0"
edition = "2021"

[dependencies]
origin-crypto-sdk = { workspace = true }
origin-common = { workspace = true }
origin-identity = { workspace = true }
origin-seed = { workspace = true }
origin-stealth = { workspace = true }
origin-schnorr = { workspace = true }
origin-seal = { workspace = true }
origin-shard = { workspace = true }
origin-proof = { workspace = true }
origin-entropy = { workspace = true }
bech32 = "0.11"
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
uuid = { version = "1", features = ["v4"] }
chrono = "0.4"
bincode = "1.3"
```

---

#### Task 1.2: Wallet Create
**Priority:** P0 | **Effort:** 4 hours | **Dependencies:** 1.1

**Acceptance Criteria:**
- [ ] `Wallet::create(passphrase: &str) -> Result<Wallet>`
- [ ] Generates seed using SDK's `seed::gen::generate(SeedVariant::Blake2bShake256)`
- [ ] Validates entropy using SDK's `entropy::analyze()` (reject if Shannon < 7.5)
- [ ] Creates `SeedHandle` with 1-hour TTL and Sovereign tier (mlock)
- [ ] Derives identity using `IdentityStore::from_seed()`
- [ ] Test: Create wallet, verify seed is valid, verify identity is derived

**Implementation Notes:**
```rust
pub fn create(passphrase: &str) -> Result<Self> {
    // 1. Generate seed
    let generated = origin_crypto_sdk::seed::gen::generate(
        origin_crypto_sdk::seed::gen::SeedVariant::Blake2bShake256
    );
    
    // 2. Validate entropy
    let metrics = origin_crypto_sdk::entropy::analyze(&generated.seed);
    if metrics.shannon_entropy < 7.5 {
        return Err(WalletError::InsufficientEntropy {
            required: 7.5,
            actual: metrics.shannon_entropy,
        });
    }
    
    // 3. Create SeedHandle with TTL and mlock
    let seed_handle = SeedHandle::with_tier(
        &generated.seed,
        Some(Duration::from_secs(3600)),
        MemoryTier::Sovereign,
    );
    
    // 4. Derive identity
    let identity = IdentityStore::from_seed(&seed_handle)?;
    
    Ok(Self {
        seed_handle,
        identity,
        history: Mmr::new(),
        metadata: WalletMetadata::new(),
    })
}
```

---

#### Task 1.3: Wallet Open/Save
**Priority:** P0 | **Effort:** 6 hours | **Dependencies:** 1.2

**Acceptance Criteria:**
- [ ] `Wallet::save(path: &Path, passphrase: &str) -> Result<()>`
- [ ] `Wallet::open(path: &Path, passphrase: &str) -> Result<Wallet>`
- [ ] State encrypted using SDK's `aead::XChaCha20Poly1305`
- [ ] Encryption key derived from passphrase using HKDF
- [ ] Nonce stored as prefix in file
- [ ] Test: Save wallet, reopen, verify seed matches
- [ ] Test: Wrong passphrase fails to decrypt

**Implementation Notes:**
```rust
pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
    // 1. Serialize state
    let state = WalletState::from(self);
    let serialized = bincode::serialize(&state)?;
    
    // 2. Derive key from passphrase
    let key = derive_key_from_passphrase(passphrase)?;
    
    // 3. Encrypt
    let nonce = origin_crypto_sdk::aead::generate_nonce();
    let encrypted = XChaCha20Poly1305::encrypt(&key, &nonce, &serialized)?;
    
    // 4. Write: [nonce (24 bytes)][encrypted data]
    let mut file = File::create(path)?;
    file.write_all(&nonce)?;
    file.write_all(&encrypted)?;
    
    Ok(())
}

fn derive_key_from_passphrase(passphrase: &str) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    origin_crypto_sdk::kdf::hkdf::hkdf_sha3_256(
        passphrase.as_bytes(),
        Some(b"wallet:state:encryption"),
        b"origin-wallet-v1",
        &mut key,
    )?;
    Ok(key)
}
```

---

#### Task 1.4: Account Management
**Priority:** P0 | **Effort:** 4 hours | **Dependencies:** 1.2

**Acceptance Criteria:**
- [ ] `Account` struct with name, index, keys, address, balance, nonce
- [ ] `Wallet::derive_account(index: u32) -> Result<Account>`
- [ ] Key derivation using SDK's HKDF with domain separation
- [ ] `Wallet::accounts() -> Vec<Account>`
- [ ] `Account::address() -> &Address`
- [ ] Test: Derive 3 accounts, verify unique addresses

**Implementation Notes:**
```rust
pub fn derive_account(&self, index: u32) -> Result<Account> {
    let domain = format!("wallet:account:{}", index);
    
    // Derive Ed25519 key (32 bytes)
    let ed_key = self.seed_handle.derive_key(&domain, "ed25519", 32)?;
    
    // Derive Falcon-1024 key (1280 bytes)
    let falcon_key = self.seed_handle.derive_key(&domain, "falcon1024", 1280)?;
    
    // Generate address from Ed25519 public key
    let ed_sk = Ed25519SigningKey::from_bytes(&ed_key.try_into()?);
    let address = Address::from_ed25519(&ed_sk.verifying_key(), AddressType::Bech32, Network::Mainnet)?;
    
    Ok(Account {
        name: format!("Account {}", index),
        index,
        ed25519_sk: ed_key,
        falcon_sk: falcon_key,
        address,
        balance: 0,
        nonce: 0,
    })
}
```

---

### Phase 2: Transactions (Week 3-4) — P1 Tasks

#### Task 2.1: Transaction Struct
**Priority:** P1 | **Effort:** 3 hours | **Dependencies:** 1.4

**Acceptance Criteria:**
- [ ] `Transaction` struct with id, from, to, amount, fee, nonce, signature, timestamp
- [ ] `Transaction::new(from, to, amount, fee) -> Result<Transaction>`
- [ ] `Transaction::to_bytes() -> Vec<u8>` (for signing)
- [ ] `Transaction::from_bytes(bytes) -> Result<Transaction>`
- [ ] Serialization using bincode
- [ ] Test: Create transaction, serialize/deserialize, verify data matches

---

#### Task 2.2: Hybrid Transaction Signing
**Priority:** P1 | **Effort:** 4 hours | **Dependencies:** 2.1, 1.4

**Acceptance Criteria:**
- [ ] `Account::sign_transaction(tx: &mut Transaction) -> Result<()>`
- [ ] Uses SDK's `Ed25519Falcon1024::sign()` for hybrid signature
- [ ] Signature size: ~1344 bytes (64 Ed25519 + ~1280 Falcon)
- [ ] Test: Sign transaction, verify signature is valid

**Implementation Notes:**
```rust
pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<()> {
    // Parse keys
    let ed_sk = Ed25519SigningKey::from_bytes(&self.ed25519_sk.try_into()?);
    let falcon_sk = FalconPrivateKey::from_bytes(&self.falcon_sk)?;
    
    // Sign with both algorithms
    let signature = Ed25519Falcon1024::sign(&ed_sk, &falcon_sk, &tx.to_bytes());
    tx.signature = signature;
    
    Ok(())
}
```

---

#### Task 2.3: Transaction Verification
**Priority:** P1 | **Effort:** 3 hours | **Dependencies:** 2.2

**Acceptance Criteria:**
- [ ] `Transaction::verify(from_pk, falcon_pk) -> Result<()>`
- [ ] Uses SDK's `Ed25519Falcon1024::verify()` (both must verify)
- [ ] Returns error if either signature fails
- [ ] Test: Verify valid transaction passes
- [ ] Test: Verify tampered transaction fails

---

#### Task 2.4: Encrypted Memo
**Priority:** P1 | **Effort:** 2 hours | **Dependencies:** 2.1

**Acceptance Criteria:**
- [ ] `Transaction::encrypt_memo(key, memo) -> Result<()>`
- [ ] Uses SDK's `XChaCha20Poly1305::encrypt_aad()`
- [ ] AAD is transaction ID (authenticated but not encrypted)
- [ ] `Transaction::decrypt_memo(key) -> Result<Vec<u8>>`
- [ ] Test: Encrypt/decrypt memo roundtrip

---

### Phase 3: Addresses (Week 5) — P1/P2 Tasks

#### Task 3.1: Bech32 Address Encoding
**Priority:** P1 | **Effort:** 3 hours | **Dependencies:** 1.4

**Acceptance Criteria:**
- [ ] `Address::from_ed25519(pk, type, network) -> Self`
- [ ] `Address::to_bech32() -> String` (HRP: "origin" for mainnet)
- [ ] `Address::from_bech32(s: &str) -> Result<Self>`
- [ ] Test: Encode/decode roundtrip
- [ ] Test: Invalid addresses fail gracefully

---

#### Task 3.2: Base58Check Encoding
**Priority:** P2 | **Effort:** 2 hours | **Dependencies:** 3.1

**Acceptance Criteria:**
- [ ] `Address::to_base58check() -> String`
- [ ] `Address::from_base58check(s: &str) -> Result<Self>`
- [ ] Version byte: 0x00 (mainnet), 0x6F (testnet)
- [ ] Test: Encode/decode roundtrip

---

#### Task 3.3: Stealth Address Generation
**Priority:** P2 | **Effort:** 4 hours | **Dependencies:** 1.4

**Acceptance Criteria:**
- [ ] `Account::generate_stealth_address(index) -> Result<StealthAddress>`
- [ ] Uses SDK's `stealth::kdf::derive_stealth_at_index()`
- [ ] Returns one-time spending address
- [ ] Test: Generate stealth address, verify it's unique per index

---

### Phase 4: State Persistence (Week 6) — P2 Tasks

#### Task 4.1: Wallet State Struct
**Priority:** P2 | **Effort:** 3 hours | **Dependencies:** 1.3

**Acceptance Criteria:**
- [ ] `WalletState` struct with accounts, pending, confirmed, metadata
- [ ] Serialization using bincode
- [ ] Encryption using SDK's AEAD
- [ ] Test: Serialize/deserialize roundtrip

---

#### Task 4.2: Balance Tracking
**Priority:** P2 | **Effort:** 4 hours | **Dependencies:** 4.1

**Acceptance Criteria:**
- [ ] `Account::balance() -> u64`
- [ ] `WalletState::update_balance(account, amount)`
- [ ] Balance synced from network (mock for MVP)
- [ ] Test: Update balance, verify persistence

---

#### Task 4.3: Transaction History (MMR)
**Priority:** P2 | **Effort:** 3 hours | **Dependencies:** 4.1

**Acceptance Criteria:**
- [ ] `Wallet::add_transaction(tx) -> Result<()>`
- [ ] Appends to SDK's MMR
- [ ] `Wallet::prove_transaction(index) -> Result<MmrProof>`
- [ ] Test: Add 10 transactions, verify proofs

---

### Phase 5: Backup/Recovery (Week 7) — P3 Tasks

#### Task 5.1: Shard-Based Backup
**Priority:** P3 | **Effort:** 4 hours | **Dependencies:** 1.3

**Acceptance Criteria:**
- [ ] `Wallet::backup(shards: u32, threshold: u32) -> Result<Vec<Shard>>`
- [ ] Uses `origin-shard` for Reed-Solomon K-of-N splitting
- [ ] Each shard encrypted with shard-specific key
- [ ] Test: Split into 5 shards, recover with any 3

---

#### Task 5.2: Recovery Phrase Backup
**Priority:** P3 | **Effort:** 3 hours | **Dependencies:** 1.3

**Acceptance Criteria:**
- [ ] `Wallet::export_phrase() -> Result<String>`
- [ ] Uses SDK's `recovery::unicode_cipher::encode_phrase()`
- [ ] `Wallet::from_phrase(phrase: &str) -> Result<Wallet>`
- [ ] Test: Export/import phrase roundtrip

---

#### Task 5.3: Backup/Restore Commands
**Priority:** P3 | **Effort:** 2 hours | **Dependencies:** 5.1, 5.2

**Acceptance Criteria:**
- [ ] CLI: `origin wallet backup --shards 5 --threshold 3`
- [ ] CLI: `origin wallet recover --shard-dir ./shards/`
- [ ] CLI: `origin wallet recover --phrase "..."`
- [ ] Test: Full backup/restore flow

---

### Phase 6: Polish (Week 8) — P3/P4 Tasks

#### Task 6.1: CLI Polish
**Priority:** P3 | **Effort:** 4 hours | **Dependencies:** All

**Acceptance Criteria:**
- [ ] All commands have help text
- [ ] Error messages are user-friendly
- [ ] Progress indicators for long operations
- [ ] Test: Run all CLI commands, verify output

---

#### Task 6.2: Documentation
**Priority:** P4 | **Effort:** 4 hours | **Dependencies:** All

**Acceptance Criteria:**
- [ ] README.md with quick start guide
- [ ] API documentation with examples
- [ ] Architecture diagram
- [ ] Security considerations

---

#### Task 6.3: Performance Benchmarks
**Priority:** P4 | **Effort:** 3 hours | **Dependencies:** All

**Acceptance Criteria:**
- [ ] Benchmark: Wallet creation time
- [ ] Benchmark: Transaction signing time
- [ ] Benchmark: Encryption/decryption speed
- [ ] Benchmark: Signature size (hybrid vs classical)
- [ ] Document performance characteristics

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SDK API changes | Low | High | Pin SDK version, document breaking changes |
| PQC signature bloat | High | Medium | Use Falcon-512 for less critical txs, compress |
| Entropy validation too strict | Medium | Low | Allow configurable thresholds |
| MMR performance | Low | Low | Benchmark early, optimize if needed |
| Recovery phrase compatibility | Medium | Low | Document non-BIP-39 clearly |

## Success Criteria

### MVP (Week 4)
- [ ] Wallet create/open/save works
- [ ] Account derivation works
- [ ] Transaction signing with hybrid signatures works
- [ ] Basic CLI commands work
- [ ] All tests pass

### Full Release (Week 8)
- [ ] All P0-P3 tasks complete
- [ ] 80%+ test coverage
- [ ] Documentation complete
- [ ] Performance benchmarks documented
- [ ] Security review complete

## Open Questions

1. **Network Integration**: How does wallet sync with blockchain? (Mock for MVP)
2. **Multi-Signature**: M-of-N multi-sig support? (Phase 2+)
3. **Hardware Wallet**: Ledger/Trezor integration? (Future)
4. **Mobile Support**: WASM compilation? (SDK already supports)

## Next Steps

1. **Immediate**: Start Phase 1, Task 1.1 (Create crate structure)
2. **This Week**: Complete Phase 1 (Foundation)
3. **Next Week**: Complete Phase 2 (Transactions)
4. **Month End**: MVP ready for testing

---

**Plan Author:** Claude
**Last Updated:** 2026-08-14
**Status:** Ready for execution
