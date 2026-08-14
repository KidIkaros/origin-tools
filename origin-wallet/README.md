# origin-wallet

A post-quantum secure Digital Wallet built on the [OriginSDK](https://github.com/liquidslr/origin-tools).

## Features

- **Hybrid Signatures** — Ed25519 + Falcon-1024 for post-quantum security
- **Stealth Addresses** — Privacy-preserving one-time payment addresses
- **MMR Transaction History** — Merkle Mountain Range proofs for auditability
- **AEAD Encryption** — XChaCha20-Poly1305 for state and memo confidentiality
- **Shard Backup** — Reed-Solomon error correction for resilient seed backup
- **Recovery Phrases** — Human-readable backup via Unicode cipher

## Quick Start

### Create a Wallet

```bash
# Build the CLI
cargo build -p origin-wallet

# Create a new wallet
./target/debug/origin-wallet create --output my-wallet.dat

# You'll be prompted to enter a passphrase
```

### Rust API

```rust
use origin_wallet::Wallet;

// Create a new wallet with fresh seed
let wallet = Wallet::create("my-secure-passphrase")?;

// Derive an account
let account = wallet.derive_account(0)?;

// Get address
println!("Address: {}", account.address());

// Save wallet
wallet.save(std::path::Path::new("wallet.dat"), "my-secure-passphrase")?;
```

## CLI Commands

```bash
# Create a new wallet
origin-wallet create

# Open and inspect wallet
origin-wallet open

# List accounts
origin-wallet accounts

# Derive new account
origin-wallet account derive --name "Savings"

# Check balance
origin-wallet balance --account 0

# Create backup shards (5 shards, need 3 to recover)
origin-wallet backup --shards 5 --threshold 3 --output ./shards/

# Recover from shards
origin-wallet recover --shards ./shards/ --output recovered.dat

# Export recovery phrase
origin-wallet phrase export

# Recover from phrase
origin-wallet phrase recover --phrase "your recovery phrase here"
```

## Architecture

```
origin-wallet
├── lib.rs          # Public API re-exports
├── wallet.rs       # Wallet struct: create/open/save, backup/recovery
├── account.rs      # Account management, stealth addresses
├── transaction.rs  # Hybrid signing, encrypted memos
├── address.rs      # Bech32/Base58Check encoding
├── error.rs        # WalletError enum
├── commands.rs     # CLI command implementations
└── main.rs         # CLI entry point
```

## Security

### Post-Quantum Protection

All signatures use hybrid cryptography:
- **Ed25519** — Classical security (128-bit)
- **Falcon-1024** — Post-quantum security (NIST Level 5)

An attacker would need to break **both** algorithms to forge signatures.

### Seed Protection

- Seeds are generated with multi-hash entropy (Blake2b + SHAKE-256)
- Entropy is validated (Shannon entropy ≥ 7.5 bits/byte)
- Seeds are stored in memory-protected handles with TTL
- Wallet files are encrypted with XChaCha20-Poly1305

### Backup Strategy

Shard backup uses Reed-Solomon error correction:
- Split seed into N shards
- Any K shards can reconstruct the original
- Example: 5 shards, threshold 3 — lose 2 shards and still recover

## Dependencies

- `origin-crypto-sdk` — Core cryptographic primitives
- `ed25519-dalek` — Ed25519 signatures
- `clap` — CLI argument parsing
- `serde` / `bincode` — Serialization
- `rpassword` — Secure passphrase input

## License

Apache-2.0
