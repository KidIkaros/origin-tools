# Architecture

origin-tools is a suite of 10 composable cryptographic CLI tools modeled on
the Office 365 / Google Workspace pattern: one identity, one shared home,
tools that compose.

---

## Crate Dependency Graph

```
                    origin-crypto-sdk (v0.7.1-rc.2, immutable sibling candidate)
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

### 5. Authenticated Everything
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
