# Origin Wallet Crate Design (Refined)

**Project:** New `origin-wallet` crate for Digital Wallet
**Researched:** 2026-08-14
**Status:** Refined based on OriginSDK deep dive

## Executive Summary

`origin-wallet` composes existing OriginSDK primitives into a post-quantum-secure Digital Wallet. The SDK provides **everything needed** — hybrid signing (Ed25519+Falcon-1024), stealth addresses, MMR transaction history, entropy analysis, AEAD encryption, and seed management with TTL/mlock. The wallet crate is a **thin orchestration layer**, not a cryptographic implementation.

## OriginSDK Capabilities (Verified)

### What the SDK Already Provides

| Module | Capability | Wallet Use |
|--------|------------|------------|
| `signing/hybrid.rs` | Ed25519+Falcon1024, Ed25519+Falcon512, Ed448+Falcon1024 hybrid signatures | Transaction signing, message authentication |
| `stealth.rs` | One-time stealth addresses with HKDF domain separation | Privacy-preserving address generation |
| `mmr.rs` | Append-only Merkle Mountain Range with membership proofs | Transaction history, state commitments |
| `entropy.rs` | Shannon, Min-entropy, Collision entropy, Chi-squared, Serial correlation | Seed quality validation |
| `aead/` | XChaCha20-Poly1305 with streaming support | Wallet state encryption, transaction encryption |
| `seed/mod.rs` | SeedHandle with TTL, mlock, HKDF derivation, fingerprinting | Master seed management |
| `seed/gen.rs` | Multi-hash seed generation (Blake2b+Shake256, Blake2b+Sha3_256, etc.) | Wallet creation |
| `recovery/` | Unicode cipher recovery phrases (non-BIP-39) | Backup/recovery |
| `kdf/hkdf.rs` | HKDF-SHA3-256 with domain separation | Key derivation |
| `pqc/` | Falcon-1024, Falcon-512, ML-DSA, SLH-DSA, Ed448, Curve41417 | Post-quantum primitives |

### What the Wallet Crate Must Build

| Component | Why Not in SDK | Complexity |
|-----------|----------------|------------|
| Address encoding (Bech32/Base58) | SDK uses raw pubkey hashes | Low — standard encoding |
| Wallet state persistence | SDK is stateless crypto primitives | Medium — RocksDB/SQLite |
| Transaction construction | SDK signs, doesn't construct | Low — serialization |
| Account management | SDK derives keys, doesn't manage | Low — wrapper |
| CLI interface | SDK is library, not application | Low — clap/structopt |
| Balance tracking | SDK has no blockchain context | Medium — requires network |

## Architecture: Thin Orchestration Layer

```
origin-wallet/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API re-exports
│   ├── wallet.rs           # Wallet struct (orchestrates SDK)
│   ├── account.rs          # Account management (wraps SDK key derivation)
│   ├── transaction.rs      # Transaction construction (uses SDK signing)
│   ├── address.rs          # Address encoding (Bech32/Base58)
│   ├── state.rs            # Wallet state persistence (encrypted storage)
│   ├── history.rs          # Transaction history (wraps SDK MMR)
│   ├── backup.rs           # Backup/recovery (wraps SDK shard + recovery)
│   ├── commands.rs         # CLI commands
│   └── error.rs            # Error types
└── tests/
    ├── wallet_tests.rs
    ├── transaction_tests.rs
    └── integration_tests.rs
```

## Core Types (Refined)

### Wallet
```rust
use origin_crypto_sdk::seed::SeedHandle;
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;
use origin_crypto_sdk::mmr::Mmr;

pub struct Wallet {
    /// Master seed with TTL and memory protection
    seed_handle: SeedHandle,
    /// Identity store for key management
    identity: IdentityStore,
    /// Transaction history (MMR)
    history: Mmr,
    /// Wallet metadata
    metadata: WalletMetadata,
}

impl Wallet {
    /// Create new wallet with fresh seed
    pub fn create(passphrase: &str) -> Result<Self> {
        // 1. Generate seed using SDK's multi-hash generation
        let generated = origin_crypto_sdk::seed::gen::generate(
            origin_crypto_sdk::seed::gen::SeedVariant::Blake2bShake256
        );
        
        // 2. Validate entropy using SDK's analysis
        let metrics = origin_crypto_sdk::entropy::analyze(&generated.seed);
        if metrics.shannon_entropy < 7.5 {
            return Err(WalletError::InsufficientEntropy);
        }
        
        // 3. Create SeedHandle with TTL and Sovereign tier (mlock)
        let seed_handle = SeedHandle::with_tier(
            &generated.seed,
            Some(Duration::from_secs(3600)), // 1 hour TTL
            MemoryTier::Sovereign,
        );
        
        // 4. Derive identity using HKDF
        let identity = IdentityStore::from_seed(&seed_handle)?;
        
        Ok(Self { seed_handle, identity, history: Mmr::new(), metadata: ... })
    }
    
    /// Open existing wallet
    pub fn open(path: &Path, passphrase: &str) -> Result<Self>;
    
    /// Save wallet state (encrypted)
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()>;
    
    /// Derive account at index (BIP-32 style)
    pub fn derive_account(&self, index: u32) -> Result<Account> {
        // Uses SDK's HKDF-SHA3-256 with domain separation
        let domain = format!("wallet:account:{}", index);
        let ed_key = self.seed_handle.derive_key(&domain, "ed25519", 32)?;
        let falcon_key = self.seed_handle.derive_key(&domain, "falcon1024", 1280)?;
        
        Ok(Account { ed_key, falcon_key, index, ... })
    }
}
```

### Account
```rust
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;

pub struct Account {
    name: String,
    index: u32,
    /// Ed25519 signing key (32 bytes)
    ed25519_sk: Vec<u8>,
    /// Falcon-1024 signing key (1280 bytes)
    falcon_sk: Vec<u8>,
    /// Derived address
    address: Address,
    /// Current balance (synced from network)
    balance: u64,
    /// Transaction nonce
    nonce: u64,
}

impl Account {
    /// Sign transaction with hybrid signature (Ed25519 + Falcon-1024)
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<()> {
        // Parse keys
        let ed_sk = Ed25519SigningKey::from_bytes(&self.ed25519_sk.try_into()?);
        let falcon_sk = FalconPrivateKey::from_bytes(&self.falcon_sk)?;
        
        // Sign with both algorithms (SDK enforces "both must verify")
        let signature = Ed25519Falcon1024::sign(&ed_sk, &falcon_sk, &tx.to_bytes());
        tx.signature = signature;
        Ok(())
    }
    
    /// Generate stealth address for one-time payments
    pub fn generate_stealth_address(&self, index: u64) -> Result<StealthAddress> {
        // Uses SDK's stealth address derivation
        let keys = origin_crypto_sdk::stealth::kdf::derive_stealth_at_index(
            &self.stealth_master,
            index,
        )?;
        // ... construct address from spending_secret
    }
}
```

### Transaction
```rust
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;
use origin_crypto_sdk::aead::XChaCha20Poly1305;

#[derive(Serialize, Deserialize)]
pub struct Transaction {
    pub id: [u8; 32],
    pub from: Address,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    /// Hybrid signature: Ed25519 (64 bytes) + Falcon-1024 (~1280 bytes)
    pub signature: Ed25519Falcon1024,
    pub timestamp: u64,
    /// Optional encrypted memo (using SDK's AEAD)
    pub encrypted_memo: Option<Vec<u8>>,
}

impl Transaction {
    /// Create new transaction
    pub fn new(from: &Account, to: &Address, amount: u64, fee: u64) -> Result<Self>;
    
    /// Verify both signatures (SDK enforces "both must verify")
    pub fn verify(&self, from_pk: &Ed25519VerifyingKey, falcon_pk: &FalconPublicKey) -> Result<()> {
        Ed25519Falcon1024::verify(from_pk, falcon_pk, &self.to_bytes(), &self.signature)
    }
    
    /// Encrypt memo using SDK's AEAD
    pub fn encrypt_memo(&mut self, key: &[u8; 32], memo: &[u8]) -> Result<()> {
        let nonce = origin_crypto_sdk::aead::generate_nonce();
        let encrypted = XChaCha20Poly1305::encrypt_aad(key, &nonce, memo, &self.id)?;
        self.encrypted_memo = Some(encrypted);
        Ok(())
    }
}
```

### Address
```rust
pub enum AddressType {
    Bech32,    // Modern, lowercase, checksum
    Bech32m,   // Version with explicit encoding
    Base58Check, // Legacy compatibility
}

pub struct Address {
    /// 20-byte pubkey hash (RIPEMD-160(SHA-256(pubkey)))
    pubkey_hash: [u8; 20],
    address_type: AddressType,
    network: Network,
}

impl Address {
    /// Generate from Ed25519 public key
    pub fn from_ed25519(pk: &Ed25519VerifyingKey, type: AddressType, network: Network) -> Self {
        let pubkey_bytes = pk.as_bytes();
        let hash = ripemd160(sha256(pubkey_bytes));
        Self { pubkey_hash: hash, address_type: type, network }
    }
    
    /// Encode as Bech32 string
    pub fn to_bech32(&self) -> String {
        // Bech32 encoding with HRP "origin" for mainnet
    }
    
    /// Decode from string
    pub fn from_string(s: &str) -> Result<Self>;
}
```

### WalletState (Persistence)
```rust
use origin_crypto_sdk::aead::XChaCha20Poly1305;

pub struct WalletState {
    accounts: Vec<Account>,
    pending_transactions: Vec<Transaction>,
    confirmed_height: u64,
    metadata: WalletMetadata,
}

impl WalletState {
    /// Save encrypted state to disk
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        // 1. Serialize to JSON/bincode
        let serialized = bincode::serialize(self)?;
        
        // 2. Derive encryption key from passphrase using SDK's HKDF
        let key = derive_key_from_passphrase(passphrase)?;
        
        // 3. Encrypt using SDK's AEAD
        let nonce = origin_crypto_sdk::aead::generate_nonce();
        let encrypted = XChaCha20Poly1305::encrypt(&key, &nonce, &serialized)?;
        
        // 4. Write to disk with nonce prefix
        let mut file = File::create(path)?;
        file.write_all(&nonce)?;
        file.write_all(&encrypted)?;
        Ok(())
    }
    
    /// Load and decrypt state from disk
    pub fn load(path: &Path, passphrase: &str) -> Result<Self>;
}
```

## Transaction Size Analysis (PQC Impact)

| Component | Classical Only | Hybrid (Ed25519+Falcon-1024) | Impact |
|-----------|---------------|------------------------------|--------|
| Signature | 64 bytes | ~1344 bytes | **21x larger** |
| Public Key | 32 bytes | ~1792 bytes | **56x larger** |
| Transaction Total | ~200 bytes | ~1500 bytes | **7.5x larger** |

**Mitigation Strategies:**
1. Use Falcon-512 (smaller signatures) for less critical transactions
2. Compress signatures with zlib before broadcast
3. Store signatures separately from transaction body
4. Use signature aggregation when available

## CLI Commands (Refined)

```bash
# Wallet management
origin wallet create --name "My Wallet" --entropy-check
origin wallet open --path wallet.dat
origin wallet list
origin wallet info  # Shows entropy metrics, PQC status

# Account management
origin wallet account create --name "Savings" --index 0
origin wallet account list
origin wallet account balance --account "Savings"
origin wallet account stealth --account "Savings" --generate

# Transaction management
origin wallet send \
  --from "Savings" \
  --to "origin1qypq8p7..." \
  --amount 1000 \
  --fee 10 \
  --memo "Payment for services" \
  --encrypt-memo
origin wallet history --account "Savings" --verify-proofs
origin wallet transaction --id <txid> --decrypt

# Backup/Recovery
origin wallet backup --shards 5 --threshold 3 --output ./shards/
origin wallet recover --shard-dir ./shards/ --passphrase "..."
origin wallet recover --phrase "unicode unicode unicode..."

# Address management
origin wallet address generate --account "Savings" --type bech32
origin wallet address generate --account "Savings" --stealth --index 0
origin wallet address list --account "Savings"

# Diagnostics
origin wallet entropy --check-seed
origin wallet verify --check-all-signatures
```

## Dependencies (Refined)

```toml
[dependencies]
# OriginSDK (crypto engine)
origin-crypto-sdk = { workspace = true }

# Origin crates (composition layer)
origin-common = { workspace = true }
origin-identity = { workspace = true }
origin-seed = { workspace = true }
origin-stealth = { workspace = true }
origin-schnorr = { workspace = true }
origin-seal = { workspace = true }
origin-shard = { workspace = true }
origin-proof = { workspace = true }
origin-entropy = { workspace = true }

# External (minimal additions)
bech32 = "0.11"           # Address encoding
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
uuid = { version = "1", features = ["v4"] }
chrono = "0.4"
bincode = "1.3"           # Efficient serialization
```

**Note:** No RocksDB dependency — use SDK's existing encrypted file storage via `origin-seal` for simplicity.

## Implementation Phases (Refined)

### Phase 1: Core Wallet (Week 1-2) — **Foundation**
- [ ] Create `origin-wallet` crate structure
- [ ] Implement `Wallet::create()` using SDK's seed generation + entropy analysis
- [ ] Implement `Wallet::open/save()` using SDK's AEAD encryption
- [ ] Implement `Account` struct wrapping SDK's key derivation
- [ ] Basic CLI: create, open, list, info

### Phase 2: Transactions (Week 3-4) — **PQC Signing**
- [ ] Implement `Transaction` struct with hybrid signature field
- [ ] Implement `Account::sign_transaction()` using SDK's `Ed25519Falcon1024::sign()`
- [ ] Implement `Transaction::verify()` using SDK's `Ed25519Falcon1024::verify()`
- [ ] Add encrypted memo support using SDK's AEAD
- [ ] CLI: send, history, transaction

### Phase 3: Addresses (Week 5) — **Encoding**
- [ ] Implement Bech32/Bech32m address encoding
- [ ] Implement Base58Check for legacy compatibility
- [ ] Implement stealth address generation using SDK's stealth module
- [ ] CLI: address generate, address list

### Phase 4: State Persistence (Week 6) — **Storage**
- [ ] Implement encrypted wallet state files using SDK's AEAD
- [ ] Add multi-account support with BIP-32 style derivation
- [ ] Implement balance tracking (placeholder for network sync)
- [ ] Add transaction history using SDK's MMR with proofs

### Phase 5: Backup/Recovery (Week 7) — **Resilience**
- [ ] Integrate `origin-shard` for K-of-N backup
- [ ] Integrate SDK's recovery phrases (Unicode cipher)
- [ ] Implement backup/restore commands
- [ ] Add entropy verification on recovery

### Phase 6: Polish & Testing (Week 8) — **Quality**
- [ ] Add comprehensive tests (SDK has 111+ tests, wallet needs parity)
- [ ] Documentation with examples
- [ ] CLI polish and help text
- [ ] Performance benchmarks (signature size, encryption speed)

## Key Design Decisions

1. **Thin Layer, Not Reinvention**: Wallet orchestrates SDK primitives, doesn't reimplement crypto
2. **Hybrid Signatures by Default**: All transactions use Ed25519+Falcon-1024 for PQC security
3. **Stealth Addresses for Privacy**: One-time addresses via SDK's stealth module
4. **Encrypted Everything**: State, transactions, memos all encrypted with SDK's AEAD
5. **Entropy Validation**: Wallet creation validates seed quality using SDK's analysis
6. **MMR for History**: Append-only transaction log with membership proofs

## Open Questions

1. **Network Layer**: How does wallet sync with blockchain? (Out of scope for MVP — mock for now)
2. **Multi-Signature**: Support for M-of-N multi-sig transactions? (Phase 2+)
3. **Hardware Wallet Integration**: Support for Ledger/Trezor? (Future)
4. **Mobile Support**: WASM compilation for mobile? (SDK already compiles to WASM)

## Sources

- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/signing/hybrid.rs` — Hybrid signing implementation
- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/stealth.rs` — Stealth address primitives
- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/mmr.rs` — MMR implementation
- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/entropy.rs` — Entropy analysis
- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/aead/` — AEAD encryption
- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/seed/` — Seed management
- `/home/ikaaros/Coding/Gold/origin-crypto-sdk/src/recovery/` — Recovery phrases
- `/home/ikaaros/Coding/Gold/origin-tools/.planning/research/PQC_WALLET_RESEARCH.md` — PQC analysis
