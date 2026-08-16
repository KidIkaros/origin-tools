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

## The Stoa network (the embedded P2P node)

Each wallet derives a **Stoa node identity** from its master seed
(`Wallet::stoa_node_keys`), so the node's `MeshId` is stable across
unlocks and distinct per wallet. The node is the wallet's presence on the
mesh: it gossips heartbeats, syncs registries, and carries payments,
discovery, and mail. There is no separate daemon — the node lives for the
duration of each command.

> **Automation**: every command accepts `--passphrase <p>` to skip the
> interactive prompt (`rpassword` reads the TTY, so scripts and spawned
> processes can't pipe it). Use it only where the passphrase can't be
> observed — process lists and shell history are visible to local users.
> The wallet file itself stays encrypted; the flag only supplies the
> unlock key.

### Pay on the native rail

```bash
# Send 500 units to a counterparty's node (they must be reachable at that
# address), recording the receipt in the wallet's MMR history.
origin-wallet pay --file wallet.dat --to <64-hex-meshid> \
    --amount 500 --peer-addr 1.2.3.4:8443 --memo "inference run #42"
```

The payment is streamed over an opened channel; the signed ledger entry
is evidence that settles on both sides (the counterparty's node ingests it
via gossip). The wallet's own MMR history is the human-facing record.

#### Pay through a relay (A→relay→C)

```bash
# The counterparty need not be dialable by you — connect only to a relay
# and pay across the mesh. The ledger entries gossip to the relay (fanout)
# and the payee's node ingests them via registry sync (SPEC §6.2, default
# 60 s cadence).
origin-wallet pay --file wallet.dat --to <64-hex-meshid> \
    --amount 500 --relay <relay-meshid> --relay-addr 1.2.3.4:8443 \
    --memo "inference run #42"
```

`--relay` + `--relay-addr` are the standing-network shape: the payer never
dials the payee, so a payee behind NAT or a fixed relay still receives.
`--peer-addr` is required only for a direct pay (no `--relay`).

### Discover services

```bash
# Rank known services by semantic fit × trust for a free-text query.
origin-wallet discover --file wallet.dat --query "reliable inference"

# Scope to a rendezvous room's members (dial a peer first so DHT lookups
# can reach it).
origin-wallet discover --query "cheap storage" \
    --room providers:storage --point <rendezvous-meshid> --peer-addr 5.6.7.8:8443
```

Each hit prints the service MeshId, payment address, profile, cosine
similarity, and trust score — the brief, never the raw graph. Stealth
payments ride the same path: a discovered service can advertise a
`StealthAddress`, and paying it resolves through `pay_stealth` so the
payment surface is unlinkable (SPEC §10.4).

### Contacts table

```bash
# Add a label → MeshId mapping (validated; persisted as a plain JSON
# sidecar next to the wallet file — public data, no passphrase needed).
origin-wallet contact add --label alice --mesh <64-hex-meshid>
origin-wallet contact list
```

### Mail (store-and-forward)

```bash
# Send an encrypted message to a node's mailbox DHT slot. The sender
# needs the recipient's identity record (their KEM key), which arrives
# via the on-connect registry sync.
origin-wallet mail send --to <64-hex-meshid> --peer-addr 1.2.3.4:8443 --body "meet at the stoa"

# Read this wallet's decrypted inbox (persisted deduped mailbox — the
# receive side of the contract). Mail lands here when this node is
# running to ingest it, or after a later bind syncs the registry.
origin-wallet mail inbox
```

The mail contract: a recipient that wants mail must publish its identity
record (their node's KEM key) — then any sender can encrypt to it, and
only the recipient can decrypt (they poll their slot, surfaced by `mail
inbox`). Mail is the store-and-forward rail; chat is the real-time rail.

A running `chat repl` node is a full mail client: it publishes its
identity at startup and polls the mailbox every ~5 s, printing incoming
mail inline (`✉ mail from …`).

### Chat (dial-based, real-time)

```bash
# Listen for chat on this wallet's addressed topic (blocks; prints sender
# + body).
origin-wallet chat listen --file wallet.dat

# Send one message: opens a session — an encrypted L3 pipe through a
# relay (upgraded to a direct leg when possible), or the addressed topic
# on a direct mesh link. --wait-reply awaits one frame back.
origin-wallet chat send --file wallet.dat --to <64-hex-meshid> \
    --peer-addr 1.2.3.4:8443 --body "hello" --wait-reply

# Dial through a named relay (the NAT'd case).
origin-wallet chat send --file wallet.dat --to <64-hex-meshid> \
    --relay <relay-meshid> --relay-addr 5.6.7.8:8443 --body "hello"
```

Chat is the real-time rail (mail is store-and-forward). `chat listen`
subscribes to the addressed topic; `chat send` reports which tier
carried it (`direct`, `relayed`, or `direct-upgraded`).

For a conversation, `chat repl` keeps one long-lived node: incoming
messages print inline while a prompt accepts `send <meshid|label>
<text…>` (labels resolve via the contacts table), `contacts`, `whoami`,
`help`, and `quit`. When the real-time rail has no live route, `send`
escalates to store-and-forward mail automatically (the recipient must
have published its identity and must poll). `--peer`/`--peer-addr` is
the optional way in — a known node to dial at startup.

```bash
origin-wallet contact add --label alice --mesh <64-hex-meshid>
origin-wallet chat repl --file wallet.dat --peer <peer-meshid> \
    --peer-addr 1.2.3.4:8443
> send alice hello over the mesh
  (contact 'alice' → <64-hex-meshid>)
✓ sent over the direct
> ✉ <64-hex-meshid>: hi back
```

`discover` can save its top hit straight into the contacts table:
`discover --query <q> [--room <r> --point <meshid> --peer-addr
<host:port>] --save <label>` writes the ranked winner as a contact in
one step.

### Help the network: serve as a relay

```bash
# Opt the wallet's node into serving as a circuit relay (off by default —
# a wallet is a client first). Runs until Ctrl-C; cookie/eviction state
# persists under $STOA_HOME/nodes/<meshid>/.
origin-wallet relay serve --file wallet.dat --difficulty 16 \
    --stun-server stun.l.google.com:19302
```

### Relay abuse-control (the operator's surface)

```bash
# Show live circuits, validated clients, eviction set, challenges issued.
origin-wallet relay stats --file wallet.dat

# Revoke a client's circuits and refuse its opens (persists across restarts).
origin-wallet relay evict --file wallet.dat --peer <64-hex-meshid>

# Remove a client from the eviction set (persists across restarts).
origin-wallet relay pardon --file wallet.dat --peer <64-hex-meshid>
```

These commands bind the wallet's node with the relay role *loaded* (state
restored from the store, no circuits served, no hint published), act, and
shut down — the R4 cookie/eviction state (RELAY.md §9) survives each one.

### Pay a discovered service ("call this provider")

```bash
# Resolve a service's signed record (local cache or DHT) and pay its
# payment address — the discover → pay loop closed in one command.
origin-wallet pay --file wallet.dat --service <service-meshid> \
    --amount 500 --peer-addr 1.2.3.4:8443 --memo "inference run #42"
```

### Settle a channel (time-boxed finality)

```bash
# Record the total paid out as an ENTRY_SETTLE; the peer's symmetric
# settle is the double-entry leg, and finality is 60 s with no
# counter-evidence (SPEC §10.3).
origin-wallet settle --file wallet.dat --to <64-hex-meshid> \
    [--peer-addr 1.2.3.4:8443]
```

### Network doctor

```bash
# Full §13 probes under the wallet's own identity: transport self-test,
# store, live metrics, STUN reachability, and the relayed-circuit test.
origin-wallet network doctor --file wallet.dat [--stun-server <host:port>]
```

### Network status

```bash
# Bind the node, fire a heartbeat, and print live mesh metrics.
origin-wallet network status
```

## Architecture

```
origin-wallet
├── lib.rs          # Public API re-exports
├── wallet.rs       # Wallet struct: create/open/save, backup/recovery
├── account.rs      # Account management, stealth addresses
├── transaction.rs  # Hybrid signing, encrypted memos
├── address.rs      # Bech32/Base58Check encoding
├── network.rs      # Stoa integration: pay / discover / mail / relay
├── contacts.rs     # label → MeshId phone book (plain JSON sidecar)
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
- Entropy is validated (Shannon entropy ≥ 4.5 bits/byte — the empirical
  cap for a 32-byte seed is log2(32) = 5.0, so 4.5 cleanly separates a
  random seed ≈4.7–4.9 from a biased one)
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
