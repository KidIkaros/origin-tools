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

## Install and build

### Build from source

The current supported installation path is a reproducible source build from the
workspace:

```bash
cargo build --release -p origin-secrets
install -m 0755 target/release/origin-secrets ~/.local/bin/origin-secrets
origin-secrets --version
```

For a release or support bundle, record the exact version and a SHA-256 digest
of the binary. Do not replace a deployed binary without first checking the
version and digest against the release source:

```bash
sha256sum target/release/origin-secrets
origin-secrets --version
```

Shell completions and the man page are generated/shipped separately:

```bash
origin-secrets completions bash > ~/.local/share/bash-completion/completions/origin-secrets
man ./man/origin-secrets.1
```

Package-manager and signed prebuilt releases are product follow-ups; until
those exist, avoid documenting an unsupported download URL or install method.

## Compatibility and upgrades

Vaults, encrypted shares, custodian handoff manifests, and diagnostic bundles
carry independent format/version fields. Before upgrading a production install:

1. Run `origin-secrets diagnose --out pre-upgrade-diagnostic.json`.
2. Back up the vault and verify its fingerprint.
3. Run `origin-secrets status` and record share readiness.
4. Upgrade the binary and run `origin-secrets verify` plus `origin-secrets status`.
5. Keep the prior binary available until the vault and share workflows pass.

Legacy plaintext exported shares remain readable for compatibility. A future
format-incompatible release must provide an explicit migration command and
must never silently rewrite vaults or shares.

## Usage

All commands accept a global `-V/--vault <PATH>` (default
`~/.origin/secrets.vault` — the leading `~` is expanded to your home
directory) and a passphrase source. In an interactive TTY, omitting
`-p/--passphrase-file` securely prompts for the passphrase. Non-interactive
callers must provide a **file** (`-p ./pw.txt`) or, for scripting without
writing the secret to disk, **stdin** (`-p -`, e.g.
`echo "$PW" | origin-secrets -p - verify`). Use `--prompt` to require the TTY
prompt explicitly. There is never a built-in default passphrase.

Add `--json` to any command for a structured success payload on stdout
(e.g. `{"ok":true,"command":"init","vault":...,"tier":"standard",
"fingerprint":"..."}`). Errors are always emitted as a JSON envelope when
`--json` is set: `{"ok":false,"code":"VAULT_NOT_FOUND","severity":"warn",
"message":...}` and exit with code `3`.

### 1. Initialize a vault (Week 1)

```bash
# Pass the passphrase via a file (required for every command)
echo "correct horse battery staple" > ./pw.txt
origin-secrets -V ./secrets.vault -p ./pw.txt init --tier standard
```

Creates an encrypted vault, derives a master seed, and prints a fingerprint.
When run interactively, `init` confirms the passphrase, explains the backup
responsibility, and prints the next `shard` command. File and stdin passphrase
sources remain suitable for non-interactive automation and do not prompt for
confirmation.

### 2. Shard the master key (Week 2)

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt shard --label master --threshold 3 --shares 5
```

Writes `shares/share_001.json … share_005.json`, each signed. A prior set of
shares in the vault's `shares/` directory is **refused** (stale-share guard) —
use `--force` only if you intend to overwrite.

Optionally set an expiry (P3.2) with `--expires <ISO-8601>`; once past, the
share is rejected by `verify` and `recover`:

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt shard --label master --threshold 3 --shares 5 --expires 2026-12-31T23:59:59Z
```

### 3. Export a share to a custodian (Week 3)

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt export-share --share 1 --out share1.json --recipient alice
```

Produces an encrypted, recipient-bound share file. Writing to an existing
`--out` path is refused unless `--force` is given.

### 4. Prepare a custodian handoff

Create a portable manifest for an exported or moved share. The manifest contains
only share metadata and verification status; it never contains share data or
signatures. It can be created offline for a plaintext/exported share, or with
`-V` and `-p` for an encrypted local share:

```bash
origin-secrets handoff --share share1.json --out alice.handoff.json --recipient alice
origin-secrets -V ./secrets.vault -p ./pw.txt handoff \
  --share shares/share_001.json --out alice.handoff.json --recipient alice
```

The manifest records the fingerprint, threshold, recipient, expiry, and whether
embedded offline hybrid verification passed. It is a receipt/coordination
artifact, not a replacement for securely transferring the share file.

### 5. Recovery preflight and recovery (Week 3)

Before reconstructing anything, inspect readiness without emitting or rebuilding
secret material:

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt recover \
  shares/share_001.json shares/share_002.json shares/share_003.json \
  --preflight
```

The preflight reports usable and invalid shares, threshold, total shares,
offline verification count, and the next action. Run the same command without
`--preflight` to perform recovery after the inputs are ready.

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt recover \
  shares/share_001.json shares/share_002.json shares/share_003.json \
  -o recovered.seed
```

Any 3 of the 5 shares reconstruct the seed. Fewer than K fails closed.
In human mode the seed is **never** printed to the terminal — capture it with
`-o/--out` (to a file) or `--json` (in the `seed_hex` field). A rebuilt vault
A rebuilt vault can be written with `--vault-out <PATH>` (refuses to overwrite unless
`--force`). Pass `--source-vault <PATH>` to **carry the source vault's audit history and
keys** into the rebuilt vault (P2.4) — the rebuilt vault records a `Recover` entry and,
when a source is supplied, preserves the prior `Shard`/`Rotate`/etc. history. Without
`--source-vault` the rebuilt vault still records a single `Recover` entry.

### 5. Verify integrity (Week 4)

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt verify --vault-path ./secrets.vault
origin-secrets -V ./secrets.vault -p ./pw.txt verify --share shares/share_001.json   # full hybrid-sig check when vault present
origin-secrets -V ./secrets.vault -p ./pw.txt verify --recovery-log                  # confirm a Recover entry exists
```

`verify --share` performs **full Ed25519 + Falcon-1024 verification** when the
vault is supplied (it derives the share-signing bundle from the master seed).
Even **without** the vault, `verify --share` performs a full offline hybrid-sig
check (P3.4) because each share embeds its verifier public keys at shard time —
no vault required to prove authenticity:

```bash
origin-secrets verify --share shares/share_001.json          # offline: full crypto check via embedded verifier
origin-secrets -V ./secrets.vault -p ./pw.txt verify --share shares/share_001.json   # also enforces revocation/expiry
```

### 6. Audit & compliance export (Week 4)

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt audit --show-recovery-log
origin-secrets -V ./secrets.vault -p ./pw.txt audit --export-soc2   soc2.json
origin-secrets -V ./secrets.vault -p ./pw.txt audit --export-pcidss pcidss.json
origin-secrets -V ./secrets.vault -p ./pw.txt audit --export-hipaa hipaa.json
```

Compliance exports refuse to overwrite an existing file unless `--force` is
given. Only one compliance export may be requested per invocation.

### 6b. Day-2 operations (lifecycle)

These commands cover ongoing vault maintenance without re-initializing.

**Rotate the passphrase (and optionally the tier)** — re-encrypts the vault under a new
passphrase with a fresh salt + nonce (forward secrecy); the old passphrase can no longer
decrypt it. Audit history is preserved. Supplying `--tier` also upgrades the KDF cost
(P2.5) without rebuilding:

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt rotate-passphrase --new-passphrase-file ./new-pw.txt
origin-secrets -V ./secrets.vault -p ./pw.txt rotate-passphrase --new-passphrase-file ./new-pw.txt --tier sovereign
```

The new passphrase follows the same `resolve_passphrase` policy as every command
(`--new-passphrase-file` accepts `-` for stdin) and must be ≥ 12 characters.

**List the keys in a vault** — shows the share labels recorded at shard time (from the
audit log) plus any explicit key entries:

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt list-keys
```

**List the shares beside a vault** — scans `<vault_dir>/shares/` and reports each share's
number, threshold, total, label, recipient, expiry (P3.2), and revocation status (P3.1):

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt list-shares
```

### 7. Share hardening (P3)

**Revoke a share (P3.1)** — mark a share number as revoked in the vault without
re-sharding. Once revoked, `recover` and `verify --share` reject it. The vault's
audit history is preserved (a `Revoke` entry is appended):

```bash
origin-secrets -V ./secrets.vault -p ./pw.txt revoke-share 2
```

**Encrypted shares at rest (P3.3)** — share files written by `shard` are
encrypted with XChaCha20-Poly1305 using a key derived from the vault master
seed (via the `origin-crypto-sdk`). Without the vault they are opaque; with it,
`recover` / `verify` / `list-shares` transparently decrypt them. Legacy
plaintext share files are still read for backward compatibility. Exported
custodian shares (`export-share`) remain a deliberate, operator-controlled
artifact and are encrypted at rest too.

**Offline verification (P3.4)** — every share embeds the verifier public keys
(ed25519 + Falcon-1024), so `verify --share` can prove the hybrid signature
**without** the vault. This is the recommended check for a custodian holding a
share file.

### 8. Check product readiness

`status` is safe to run before initialization and gives an operator the next
recommended action. Once a vault exists, it decrypts the vault and reports its
tier, fingerprint, audit count, share readiness, and unavailable share files
without exposing the master seed or share contents:

```bash
origin-secrets status
origin-secrets -V ./secrets.vault -p ./pw.txt status
origin-secrets -V ./secrets.vault -p ./pw.txt status --json
```

### 10. Create a support diagnostic bundle

Use `diagnose` when reporting an installation or filesystem problem. It never
decrypts the vault or reads share contents. Paths are redacted to `$HOME`, and
the output contains only versions, platform, file presence/size, share counts,
and failure counts:

```bash
origin-secrets diagnose
origin-secrets diagnose --out support-diagnostic.json
origin-secrets diagnose --out support-diagnostic.json --force
```

### 11. Failure journal (vault-independent)

Failures are recorded to `~/.origin/failures.log` (one JSON line per event)
independent of any vault, so you can audit *denied* operations even when the
vault is missing or the passphrase is wrong:

```bash
origin-secrets -p ./pw.txt audit --show-failures
origin-secrets     audit --show-failures --json   # vault-independent, structured output
```

## Testing

```bash
cargo test -p origin-secrets --release
```

- 155 lib unit tests (inline `#[cfg(test)]`)
- 11 integration + security test binaries under `tests/integration/` and
  `tests/security/`
- Coverage target: ≥ 90 % (cargo-llvm-cov); current lib coverage ≈ 88 % lines
  / 89 % regions (P3 modules: revoke 89 %, share_io 89 %, recover 91 %, verify 91 %)

## Security notes

- **No critical bugs** in v1.0 scope.
- Tampering with the vault (ciphertext / salt / nonce) or any share
  (data / signature / recipient) is detected at `verify` / `recover`.
- A passphrase is **mandatory** for every command. Interactive TTY sessions
  prompt securely when `-p/--passphrase-file` is omitted; non-interactive
  callers must use `-p/--passphrase-file` or `-p -` for stdin. There is no
  built-in default; non-interactive use without a source fails with
  `PassphraseRequired` rather than silently using a weak key.

See [SECURITY.md](./SECURITY.md) for the full threat model and disclosure
process, and [DESIGN_DOC.md](./../DESIGN_DOC.md) for architecture.

## Exit codes & error model

| Code | Meaning | Example |
|---|---|---|
| `0` | Success | — |
| `1` | Internal / runtime error | crypto failure |
| `2` | Operator-fixable input/auth error | `PassphraseRequired`, `PassphraseTooWeak`, `VaultDecryptionFailed` (wrong passphrase) |
| `3` | Not-found / input error | `VaultNotFound`, `ShareNotFound`, `InvalidThreshold`, `FileAlreadyExists` |
| `127` | CLI parse error (clap) | unknown flag |

With `--json`, both success and error payloads are emitted as JSON on stdout:
`{"ok":true,"command":..., ...}` or `{"ok":false,"code":...,"severity":...,
"message":...}`. The failure journal (`~/.origin/failures.log`) records every
error regardless of `--json`, keyed by `code` and `severity`.
