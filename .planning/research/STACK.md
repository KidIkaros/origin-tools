# Technology Stack

**Project:** Digital Wallet with Origin Tools
**Researched:** 2026-08-14

## Recommended Stack

### Core Framework
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| Rust | 2021 edition | Primary language | Workspace already uses it; all crates are Rust. |
| Tokio | 1.x | Async runtime | Already a workspace dependency; used by `origin-network`. |

### Existing Origin Crates (Composition Layer)
| Crate | Version | Purpose | Why |
|-------|---------|---------|-----|
| `origin-common` | 0.4.3 | Foundation (identity store, envelope, I/O) | Every other crate depends on it. |
| `origin-identity` | 0.3.0 | Master seed, hybrid signing | CRITICAL: Root of trust for wallet. |
| `origin-seed` | 0.4.3 | HD key derivation | CRITICAL: Wallet key hierarchy. |
| `origin-stealth` | 0.4.3 | One-time addresses, PoW | CRITICAL: Privacy layer. |
| `origin-schnorr` | 0.4.3 | secp256k1 ZK proofs | HIGH: Bitcoin-compatible signatures. |
| `origin-seal` | 0.4.1 | Encryption/decryption | HIGH: Data at rest, transaction signing. |
| `origin-shard` | 0.4.3 | K-of-N secret sharing | HIGH: Wallet backup/recovery. |
| `origin-proof` | 0.4.3 | MMR transaction history | HIGH: Tamper-evident audit trail. |
| `origin-entropy` | 0.4.3 | Entropy analysis | MEDIUM: Seed quality assurance. |
| `origin-network` | 0.4.3 | P2P transport | HIGH: Wallet-to-wallet communication. |
| `origin-channel` | 0.4.3 | Encrypted sessions | HIGH: Secure messaging. |
| `origin-attest` | 0.4.3 | Trust graphs, audit logs | MEDIUM: Compliance, revocation. |
| `origin-crypto-sdk` | 0.7.1-rc.5 | Post-quantum primitives | CRITICAL: Signing, encryption, KDF. |

### New Crate (To Be Created)
| Crate | Version | Purpose | Why |
|-------|---------|---------|-----|
| `origin-wallet` | 0.1.0 | Wallet orchestration, state management, transaction construction | Composes existing crates into cohesive product. |

### Supporting Libraries
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `bech32` | Latest | Bech32/Bech32m address encoding | For Bitcoin-compatible addresses. |
| `base58` | Latest | Base58Check address encoding | For legacy Bitcoin addresses. |
| `reqwest` | Latest | HTTP client | For blockchain RPC calls. |
| `rocksdb` | Latest | Local key-value storage | For wallet state persistence. |

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Wallet State | RocksDB | SQLite | RocksDB optimized for write-heavy workloads; better for append-only logs. |
| Address Encoding | bech32 crate | Custom implementation | Standard libraries are battle-tested. |
| Blockchain RPC | reqwest | ureq | reqwest is more widely used, better ecosystem. |

## Installation

```bash
# Add to workspace Cargo.toml
[workspace.dependencies]
origin-wallet = { path = "origin-wallet" }

# Add to origin-wallet/Cargo.toml
[dependencies]
origin-common = { workspace = true }
origin-identity = { workspace = true }
origin-seed = { workspace = true }
origin-stealth = { workspace = true }
origin-schnorr = { workspace = true }
origin-seal = { workspace = true }
origin-shard = { workspace = true }
origin-proof = { workspace = true }
origin-entropy = { workspace = true }
origin-crypto-sdk = { workspace = true }

# External dependencies
bech32 = "0.11"
base58 = "0.2"
reqwest = { version = "0.12", features = ["json"] }
rocksdb = "0.22"
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
```

## Sources

- `/home/ikaaros/Coding/Gold/origin-tools/` (workspace analysis)
- `origin-crypto-sdk` documentation
- System Design Notes: Digital Wallet
