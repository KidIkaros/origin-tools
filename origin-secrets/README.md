# origin-secrets

Threshold secrets management for the Origin ecosystem. `origin-secrets`
eliminates the single-point-of-failure of a traditional secrets vault by
splitting a master key into **K-of-N** shares, each carrying a post-quantum
hybrid signature (Ed25519 + Falcon-1024). Recovery requires any `K` shares;
no single share — or the vault — can reconstruct the secret alone.

## Why

A conventional encrypted vault is a SPOF: lose the vault or its passphrase and
you are locked out; compromise either and you are fully exposed. `origin-secrets`
distributes trust across N custodians. Compromise of fewer than K shares reveals
nothing (information-theoretic, via Reed-Solomon erasure coding over GF(256)).
Every share is cryptographically bound to the master seed by a post-quantum
hybrid signature, so tampering is detected rather than silently accepted.

## Threat model

| Asset | Protection |
|---|---|
| Master seed | Split into K-of-N Reed-Solomon shares; never stored whole after `init` |
| Vault at rest | XChaCha20-Poly1305 (SDK) + Argon2id KDF, tier-selected (nano…sovereign) |
| Each share | Hybrid Ed25519 + Falcon-1024 signature over share data |
| Audit trail | Append-only recovery/audit log, exportable as SOC2 / PCI-DSS / HIPAA evidence |

Out of scope (v1.0): transport security between custodians, hardware key
storage, and a web dashboard (planned v2.0).

## Build

```bash
cargo build --release -p origin-secrets
# binary: target/release/origin-secrets
```

## Usage

All commands accept a global `-V/--vault <PATH>` (default
`~/.origin/secrets.vault`) and an optional `-p/--passphrase-file <PATH>`
(default: a demo passphrase — **set a real one in production**).

### 1. Initialize a vault (Week 1)

```bash
origin-secrets -V ./secrets.vault init --tier standard --no-prompt
```

Creates an encrypted vault, derives a master seed, and prints a fingerprint.

### 2. Shard the master key (Week 2)

```bash
origin-secrets -V ./secrets.vault shard --key master --threshold 3 --shares 5
```

Writes `shares/share_001.json … share_005.json`, each signed.

### 3. Export a share to a custodian (Week 3)

```bash
origin-secrets -V ./secrets.vault export-share --share 1 --out share1.json --recipient alice
```

Produces an encrypted, recipient-bound share file.

### 4. Recover the master key (Week 3)

```bash
origin-secrets -V ./secrets.vault recover shares/share_001.json shares/share_002.json shares/share_003.json -o recovered.seed
```

Any 3 of the 5 shares reconstruct the seed. Fewer than K fails closed.

### 5. Verify integrity (Week 4)

```bash
origin-secrets -V ./secrets.vault verify --vault-path ./secrets.vault
origin-secrets -V ./secrets.vault verify --share shares/share_001.json   # full hybrid-sig check when vault present
```

`verify --share` performs **full Ed25519 + Falcon-1024 verification** when the
vault is supplied (it derives the share-signing bundle from the master seed).

### 6. Audit & compliance export (Week 4)

```bash
origin-secrets -V ./secrets.vault audit --show-recovery-log
origin-secrets -V ./secrets.vault audit --export-soc2   soc2.json
origin-secrets -V ./secrets.vault audit --export-pcidss pcidss.json
origin-secrets -V ./secrets.vault audit --export-hipaa hipaa.json
```

## Testing

```bash
cargo test -p origin-secrets --release
```

- 106 unit tests (inline `#[cfg(test)]`)
- 11 integration + security test binaries under `tests/integration/` and
  `tests/security/`
- Coverage target: ≥ 90 % (cargo-tarpaulin)

## Security notes

- **No critical bugs** in v1.0 scope.
- Tampering with the vault (ciphertext / salt / nonce) or any share
  (data / signature / recipient) is detected at `verify` / `recover`.
- The default passphrase in `dispatch` is a placeholder for demos only.
  Production deployments MUST supply `-p/--passphrase-file`.

See [SECURITY.md](./SECURITY.md) for the full threat model and disclosure
process, and [DESIGN_DOC.md](./../DESIGN_DOC.md) for architecture.
