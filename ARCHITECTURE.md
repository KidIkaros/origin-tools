# Architecture

origin-tools is a suite of 10 composable cryptographic CLI tools modeled on
the Office 365 / Google Workspace pattern: one identity, one shared home,
tools that compose.

---

## Crate Dependency Graph

```
                    origin-crypto-sdk (v0.7.1-rc.10, exact sibling candidate)
                    ├── XChaCha20-Poly1305 AEAD (+ AAD)
                    ├── Argon2id KDF (tiered)
                    ├── HKDF-SHA3-256
                    ├── Reed-Solomon erasure coding
                    ├── MMR (Merkle Mountain Range)
                    ├── Stealth addresses + PoW
                    ├── EC-Schnorr (secp256k1)
                    ├── Ed25519 + Falcon-1024 hybrid signing
                    └── Compression (LZ4)
                            │
                    origin-common
                    ├── IdentityStore (create/load/derive)
                    ├── Envelope (authenticated encryption)
                    ├── OriginHome (~/.origin management)
                    ├── Passphrase resolution
                    └── I/O helpers
                            │
        ┌───────────┬───────┼───────┬───────────┐
        │           │       │       │           │
   origin-identity  │  origin-seed  │      origin-pass
   (hybrid sign)    │  (HD seeds)   │      (password vault)
        │           │       │       │           │
   origin-schnorr   │  origin-shard │      origin-seal
   (ZK proofs)      │  (erasure)    │      (file encryption)
        │           │       │       │
   origin-stealth   │  origin-proof │
   (stealth addr)   │  (MMR proofs) │
        │           │       │       │
   origin-entropy   │       │       │
   (quality gates)  │       │       │
        └───────────┴───────┴───────┘
                    │
              origin-cross-tests
              (end-to-end composability)
```

### origin-payments (payment backend)

`origin-payments` composes the suite into a payment backend (design:
[PAYMENT_SYSTEM_DESIGN.md](PAYMENT_SYSTEM_DESIGN.md)): payment events and
orders with an idempotent status machine, a double-entry journal
(hash-chained, sum-zero batches), a native-rail executor over
`origin-wallet`, identity-signed orders and envelopes (`origin-identity`
via the SDK's Ed25519 + Falcon-1024 hybrid bundle), and reconciliation
against PSP settlement files. It depends on every suite crate plus the
SDK; the Stoa pay surface is reached through `origin-wallet` (which owns
`stoa` as its embedded mesh).

## Platform taxonomy and repository boundaries

`origin-tools` is an internal platform/incubator, not the canonical repository
for every project that consumes its capabilities.

### SDK adapters and reference tools

These crates are thin adapters around `origin-crypto-sdk` or small reference
implementations: `origin-seed`, `origin-shard`, `origin-proof`,
`origin-entropy`, `origin-schnorr`, `origin-stealth`, and `origin-seal`.
They expose typed APIs, CLI adapters, compatibility logic, and dogfood
examples. They must not duplicate SDK primitives.

### Platform infrastructure

`origin-common`, `origin-identity`, `origin-provenance`, `origin-attest`,
`origin-channel`, and `origin-secrets` provide shared application seams,
identity/home conventions, protocol adapters, and versioned formats.
Dependencies point inward toward the SDK and stable platform abstractions.

### Suite products and integrations

`origin-pass`, `origin-wallet`, `origin-payments`, `origin-network`,
`origin-vcs`, `origin-archive`, and `origin-crawler` compose the platform into
product-oriented workflows. They may depend on platform crates, but lower
layers must not depend on product behavior.

### Standalone sibling projects

`origin-db`, `origin-memory`, and `origin-web` are independent repositories
under the parent `Gold/` directory. They are not workspace members. They
consume released or Git versions of the platform crates and use local Cargo
path patches only for development. Their own persistence, memory-graph, and
WASM/browser lifecycles remain outside this workspace.

### Promotion lifecycle and stability

Reusable work follows:

```text
experiment → reference crate → reusable library → standalone project
```

Each capability is labeled `experimental`, `reference`, `stable`, or
`frozen`; definitions and the problem-oriented catalog live in
`CAPABILITIES.md`. A promotion requires a typed API, a dogfood example,
negative-path tests, and compatibility notes for persisted formats.

## Design Principles

### 1. One Identity
All tools derive from a single master seed at `~/.origin/identity.seed`.
The seed is encrypted with XChaCha20-Poly1305 + Argon2id. The tier is
stored in the blob so `load()` always uses the correct KDF parameters.

### 2. One Home
`~/.origin/` (or `$ORIGIN_HOME`) holds config, identity, vault, keys,
and backups. Created with `0700` permissions. Config is TOML.

### 3. One Crypto Provider
`origin-crypto-sdk` is the sole cryptographic provider. No tool implements
its own crypto. All primitives go through the SDK's public API.

### 4. Composability
Tools are designed to pipe together. Output formats are consistent
(hex by default, configurable). Cross-tool workflows are tested in
`origin-cross-tests`.

### 5. Library-First
Every crate ships a typed library API (`src/api.rs` with typed public
structs/functions and a typed error type) as the primary surface; the CLI is a
thin shell over the library — never the other way around. Each crate keeps an
`examples/dogfood.rs` demonstrating the programmatic path. Cross-crate seams
(like `NativeRail`) live in the lowest crate that owns the domain.

#### The dogfood example convention

Every crate's `examples/dogfood.rs` is the copy-paste entry point for an app
builder — it must demonstrate the *programmatic* path, not the CLI:

- **Call the typed API directly** (`origin_shard::split`,
  `origin_schnorr::prove`), never `Cli::parse_from` + `commands::dispatch`.
- **Assert on typed errors** (`matches!(err, ShardError::NotEnoughShards(_))`),
  never on process exit codes or stdout text.
- **In-memory bytes only** — no scratch files, no temp dirs, no subprocess
  probes; storage is the caller's concern.
- **Cover the negative paths** (tampered input, wrong key, exhausted budget)
  so the example doubles as a behavioral contract.
- **End with the standard line**
  `origin-<crate> dogfood OK — usable as a foundational dependency`.

Run any of them with `cargo run -p origin-<crate> --example dogfood`; CI runs
them as regression gates for the library surface.

### 6. Authenticated Everything
- Envelopes use AAD to authenticate header fields.
- Stealth PoW is identity-bound (includes identity_pk in hash).
- MMR proofs use full authentication paths.
- RS recovery uses erasure-based decoding.

## Memory Tiers

| Tier        | Argon2id Memory | Iterations | Parallelism | Use Case          |
|-------------|-----------------|------------|-------------|-------------------|
| `nano`      | 64 MiB          | 3          | 4           | CI, testing       |
| `standard`  | 256 MiB         | 4          | 4           | Default           |
| `sovereign` | 1 GiB           | 6          | 4           | High-security     |

## Envelope Format

```
Offset  Size  Field
0       4     Magic ("ORIG")
4       1     Version (1)
5       1     PayloadType
6       1     Flags (bit 0: compressed)
7       1     Tier
8       16    Salt
24      24    Nonce
48      ...   Ciphertext + Poly1305 tag
```

AAD = Magic || Version || PayloadType || Flags || Tier || Salt || Nonce

## Identity Blob Format

```
Offset  Size  Field
0       16    Salt
16      24    Nonce
40      1     Tier
41      ...   Ciphertext (32-byte seed + Poly1305 tag)
```

## Testing Strategy

- **Unit tests**: In each crate's `src/commands.rs` (`#[cfg(test)]`).
- **Integration tests**: `origin-common/tests/`, per-crate `tests/`.
- **Cross-tool tests**: `origin-cross-tests/tests/cross_tool.rs` — 7
  end-to-end composability workflows.
- **CI**: GitHub Actions — fmt check, clippy `-D warnings`, full suite.
- **Isolation**: Tests use `ORIGIN_HOME` env var + tempdir for isolation.
