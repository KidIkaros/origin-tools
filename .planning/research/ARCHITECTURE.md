# Architecture Patterns

**Domain:** Digital Wallet with Origin Tools
**Researched:** 2026-08-14

## Recommended Architecture

Composition-based architecture: New `origin-wallet` crate orchestrates existing primitives.

### Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| **origin-wallet** | Wallet orchestration, state management, transaction construction | All origin crates, Blockchain RPC |
| **origin-identity** | Master seed, hybrid signing | origin-wallet |
| **origin-seed** | HD key derivation | origin-wallet |
| **origin-stealth** | One-time addresses | origin-wallet |
| **origin-schnorr** | secp256k1 ZK proofs | origin-wallet |
| **origin-seal** | Encryption/decryption | origin-wallet |
| **origin-shard** | Secret sharing | origin-wallet |
| **origin-proof** | MMR transaction history | origin-wallet |
| **origin-network** | P2P transport | origin-wallet (optional) |
| **Blockchain RPC** | Node communication | origin-wallet |

### Data Flow

1. User creates wallet → `origin-identity` generates master seed.
2. User derives keys → `origin-seed` creates HD keys with domain separation.
3. User generates address → `origin-stealth` creates one-time address.
4. User signs transaction → `origin-identity`/`origin-schnorr` provides hybrid signatures.
5. Wallet persists state → `origin-seal` encrypts, RocksDB stores.
6. Transaction history → `origin-proof` appends to MMR.
7. Backup → `origin-shard` splits seed into K-of-N shards.

## Patterns to Follow

### Pattern 1: Composition Over Reimplementation
**What:** Use existing crates as building blocks; don't reimplement cryptography.
**When:** Always. The origin-tools suite is well-tested and production-ready.
**Example:**
```rust
// In origin-wallet
use origin_identity::CombinedSignature;
use origin_seed::derive_child_seed;
use origin_stealth::generate_stealth_address;

pub fn create_transaction(wallet: &Wallet, to: &Address, amount: u64) -> Transaction {
    let from_key = derive_child_seed(&wallet.master_seed, "wallet", 0);
    let stealth_addr = generate_stealth_address(&to.viewing_key, 0);
    let sig = wallet.identity.sign(&tx_data);
    Transaction { from: from_key.pubkey(), to: stealth_addr, amount, sig }
}
```

### Pattern 2: Domain-Separated Key Derivation
**What:** Use HKDF with domain strings to derive purpose-specific keys.
**When:** Always for key derivation. Prevents cross-context key reuse.
**Example:**
```rust
// Derive wallet-specific key from master identity
let wallet_key = derive_child_seed(&master_seed, "wallet", 0);
let signing_key = derive_child_seed(&master_seed, "signing", 0);
let encryption_key = derive_child_seed(&master_seed, "encryption", 0);
```

### Pattern 3: Encrypted State at Rest
**What:** All wallet data encrypted with tiered Argon2id + XChaCha20-Poly1305.
**When:** Always for persistent storage. Uses existing `origin-common` envelope.
**Example:**
```rust
// Encrypt wallet state
let envelope = Envelope::encrypt(&wallet_state, passphrase, MemoryTier::Standard)?;
std::fs::write("wallet.dat", envelope.to_bytes())?;

// Decrypt wallet state
let envelope = Envelope::from_bytes(&data)?;
let wallet_state = envelope.decrypt(passphrase)?;
```

## Anti-Patterns to Avoid

### Anti-Pattern 1: Reimplementing Cryptography
**What:** Writing custom signing, encryption, or hashing code.
**Why bad:** Security vulnerabilities, bugs, wasted effort.
**Instead:** Use `origin-crypto-sdk` and existing crates.

### Anti-Pattern 2: Plaintext Key Storage
**What:** Storing private keys without encryption.
**Why bad:** Key theft, funds loss.
**Instead:** Always encrypt with `origin-seal` or `origin-common` envelope.

### Anti-Pattern 3: Monolithic Wallet Crate
**What:** Building everything in one large crate.
**Why bad:** Hard to maintain, test, and reuse.
**Instead:** Compose small, focused crates; keep `origin-wallet` as orchestration layer.

## Scalability Considerations

| Concern | At 100 users | At 10K users | At 1M users |
|---------|--------------|--------------|-------------|
| Key Derivation | Local | Local | Local (fast) |
| Transaction Signing | Local | Local | Local (parallel) |
| State Persistence | Local RocksDB | Sharded RocksDB | Distributed storage |
| P2P Communication | Direct | Relay fallback | Distributed network |

## Sources

- `/home/ikaaros/Coding/Gold/origin-tools/` (workspace analysis)
- System Design Notes: Digital Wallet
- Raft paper (Ongaro & Ousterhout)
- Event Sourcing pattern documentation
