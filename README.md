# origin-tools

A coherent, interoperable suite of cryptographic CLI tools built on the
[origin-crypto-sdk](../origin-crypto-sdk). Modeled on Office 365 / Google
Workspace: one identity, one shared store, tools that compose.

## Architecture

```
~/.origin/
  identity.seed    Encrypted master seed (Argon2id + XChaCha20-Poly1305)
  config.toml      Suite configuration (default tier, etc.)

origin-common/     Shared infrastructure crate
  OriginHome       Resolves ~/.origin/, loads/saves config
  IdentityStore    Loads/derives from encrypted master seed
  Envelope         Unified ORGN binary format
  MemoryTier       Re-exported from SDK + tier_ext helpers
  resolve_passphrase  Shared passphrase prompt (file or interactive)
  read_input/write_output  Shared IO helpers

origin-crypto-sdk/ Sole cryptographic provider (all tools depend on this)
```

## Tools

| Tool | Purpose | Key Operations |
|------|---------|----------------|
| `origin-identity` | Identity keys | keygen, sign, verify, list, rotate, export |
| `origin-pass` | Vault + 2FA | passwords, TOTP/HOTP, vault init/unlock/add |
| `origin-seal` | Data ops | encrypt, decrypt, sign, verify, hash, MAC, stream |
| `origin-seed` | Seed lifecycle | generate, derive, encode/decode, blob create/recover |
| `origin-shard` | Secret sharing | Reed-Solomon split, K-of-N threshold recover |
| `origin-proof` | Integrity proofs | MMR append, root, prove, verify |
| `origin-stealth` | Stealth addresses | master keys, address derivation, PoW solve/verify |
| `origin-entropy` | Entropy audit | Shannon, chi-squared, min-entropy, quality gates |
| `origin-schnorr` | ZK proofs | EC Schnorr keygen, prove, verify |

## Interoperability

All tools share:
- One identity (`~/.origin/identity.seed`)
- One home directory (`~/.origin/`)
- The `origin-common` crate (shared infrastructure)
- The `origin-crypto-sdk` as sole crypto provider

Tools compose through the `--identity` flag:
```bash
# Sign data using your suite identity
echo "hello" | origin-seal sign --identity --domain myapp

# Derive a child seed from your suite identity
origin-seed derive --identity --domain wallet

# Generate a Schnorr keypair from your suite identity
origin-schnorr keygen --identity

# Derive stealth master keys from your suite identity
origin-stealth master --identity
```

## Scripting Conventions

All tools follow Unix CLI conventions:
- `stdin`/`stdout` as defaults (pipe-friendly)
- `--json` / `--format json` for machine-readable output
- Proper exit codes (0 = success, 1 = failure)
- Hex-encoded binary output for easy piping

## Building

```bash
cargo build --workspace
cargo test --workspace
```

## Status

- **origin-identity**: Production. Full keygen/sign/verify, blob support.
- **origin-pass**: Production. Vault + TOTP/HOTP, tiered Argon2id.
- **origin-seal**: Production. Encrypt/decrypt/sign/verify/hash/MAC/streaming.
- **origin-seed**: Functional. Generate/derive/encode/blob create+recover.
- **origin-shard**: Functional. RS split/recover with metadata.
- **origin-proof**: Functional. BLAKE3 MMR append/root/prove/verify.
- **origin-stealth**: Functional. Address derivation + PoW.
- **origin-entropy**: Functional. Shannon/chi-squared/min-entropy + quality gates.
- **origin-schnorr**: Functional. Keygen/prove/verify.

193 tests green across the workspace.

## License

Apache-2.0
