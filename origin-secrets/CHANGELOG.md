# Changelog

All notable changes to `origin-secrets` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this crate's releases are
versioned independently of the `origin-tools` workspace (workspace `version = 0.4.1`).

## [0.4.2] — 2026-08-01

First stable release of the Origin Secrets CLI: post-quantum threshold secret
management over the `origin-crypto-sdk`.

### Added
- `init` — create an encrypted vault (XChaCha20-Poly1305 + Argon2id) holding a
  master seed; supports `nano` / `standard` / `sovereign` Argon2id memory tiers.
- `shard` — split the master seed into K-of-N Reed-Solomon erasure shares, each
  signed with a deterministic Ed25519+Falcon-1024 hybrid key derived from the seed.
- `export-share` — export a share file, optionally re-binding it to a recipient and
  logging the export to the vault audit log.
- `recover` — reconstruct the master seed from any K shares, with full hybrid-signature
  verification of every share; optional `--vault-out` rebuilds an encrypted vault.
- `verify` — integrity-check a vault (decrypt + fingerprint) or a share (full
  cryptographic hybrid-signature verification when the source vault is present).
- `audit` — append structured, hybrid-signed audit-log entries (Init, Shard,
  ExportShare, Recover, Verify) and export SOC2 / PCI-DSS / HIPAA evidence bundles.
- Global `-p/--passphrase-file` flag: the passphrase is read from a file (no echo)
  and applied uniformly across `init`, `shard`, `export-share`, `recover`, `verify`,
  and `audit`.
- Man page (`man/origin-secrets.1`), `README.md`, and `SECURITY.md`.

### Security
- **Nonce hygiene:** vault re-encryption on `shard`/`export-share` uses a fresh random
  24-byte nonce per operation (salt is stable). Reusing the original nonce under the
  same derived key would have been deterministic nonce reuse in XChaCha20-Poly1305 and
  leaked the plaintext delta of the growing audit log.
- **Share verification binding:** `verify --share` verifies against the share's *own*
  source vault (derived from the share's on-disk location), not a default/resolved
  vault, preventing false tamper-positives across multiple vaults.
- **Passphrase discipline:** no command falls back to a hardcoded default. `init`
  and the dispatcher both refuse to proceed without a passphrase source
  (`-p/--passphrase-file` or interactive prompt). The dispatcher returns a new
  `PassphraseRequired` error for `shard`/`export-share`/`recover`/`verify`/`audit`
  when `-p` is absent, so an operator can never silently encrypt or decrypt a vault
  against a known weak string. A subcommand-local `-p` is intentionally ignored in
  favor of the global one so all commands share one key-derivation path.

### Fixed (post-QC, same release)
- `dispatch` previously fell back to a hardcoded demo passphrase for every command
  other than `init` when `-p` was absent, so `shard`/`export-share`/`recover`/`verify`/
  `audit` would silently encrypt/decrypt against a publicly-known string. The dispatcher
  now returns `PassphraseRequired` for those commands when no `-p` is supplied, and the
  demo fallback is gone entirely.
- `init` previously ignored the global `-p/--passphrase-file` flag and silently
  encrypted the vault with a demo passphrase, causing every subsequent command using
  the real passphrase to fail with `VaultDecryptionFailed`. The passphrase now flows
  through a single global path shared by all subcommands.
- `verify --share` performed only structural checks when a vault was present; it now
  runs full hybrid-signature verification.
- `cmd_init` honored `-V/--vault` only partially; the resolved vault path is now used
  consistently.
- Dead threshold-validation branch in `verify_share` replaced with a meaningful check
  (`threshold == 0 || total == 0 || threshold > total`).

### Tested
- 132 tests (109 unit + 23 integration/security) pass in `--release`.
- Line coverage 93.6% (tarpaulin).
- `cargo clippy -p origin-secrets --all-targets -- -D warnings` clean.
- `cargo fmt -p origin-secrets -- --check` clean.

### Known limitations
- `Cargo.toml` declares sibling workspace crates (`origin-common`, `origin-identity`,
  `origin-pass`, `origin-shard`) and `rpassword`/`zeroize` that are not yet consumed by
  this release; they are reserved for the v2.0 web-dashboard surface and kept as
  protocol-stack dependencies rather than removed.
- `origin-crypto-sdk` (path dependency) emits pre-existing clippy warnings (unused
  NTT/Karatsuba/Mmr internals). The `origin-tools` CI `clippy` job now gates strictly on
  `-p origin-secrets -- -D warnings` and runs a non-failing `cargo clippy --workspace`
  pass for visibility, so the SDK's intentional dead internals no longer block the
  pipeline. A future SDK-side `#[allow]` cleanup remains desirable.
- Crate version is `0.4.2` (tagged `origin-secrets-v0.4.2`), intentionally ahead of the
  `origin-tools` workspace `version = 0.4.1`; the crate carries its own version.
