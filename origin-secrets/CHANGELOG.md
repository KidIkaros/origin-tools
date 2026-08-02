# Changelog

All notable changes to `origin-secrets` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this crate's releases are
versioned independently of the `origin-tools` workspace (workspace `version = 0.4.1`).

## [Unreleased] — pre-push audit remediation and DX/UX foundation

Remediation of the pre-push source/docs/UX audit (4 critical, 15 high, 10 medium,
7 low, 10 doc), plus the first systemic DX/UX slice. All changes are behavioral
hardening and documentation; no public command signatures changed except the
addition of `--force` opt-ins and the now-meaningful `--recovery-log` /
`--show-failures` flags.

### Product loop
- Added `status`, a passphrase-free pre-initialization readiness check and a
  decrypted non-secret vault/share readiness summary for existing vaults.
- `status` reports the next recommended action and surfaces unavailable share
  files instead of hiding product readiness problems.
- Interactive `init` now confirms the passphrase and gives backup guidance plus
  a concrete next `shard` command; file/stdin automation remains unchanged.
- Added `handoff` to create portable, non-secret custodian manifests with share
  metadata, recipient/expiry context, and offline verification status.
- Added `recover --preflight` to inspect usable, invalid, threshold, and offline
  verification state before reconstructing any secret material.
- Added vault-independent `diagnose` output and optional secret-free support
  bundles for installation, filesystem, and failure-journal troubleshooting.
- Synchronized the man-page version with the crate and documented source-build,
  checksum, completion, man-page, and upgrade-verification workflows.
- Clean-machine dogfood completed the documented status → diagnose → init → shard
  → export → handoff → preflight → recover → verify flow; duplicate export
  progress output was removed as a usability fix.
- Release packaging now includes the `origin-secrets` binary and product docs;
  CI checks crate/man/binary version consistency.
- Added TTY-aware semantic output styling with `NO_COLOR` support for product
  status output without affecting JSON or redirected output.

### DX / UX foundation
- Vaults, shares, recovered seeds, and compliance exports now use a shared
  atomic-write path so readers never observe partially written artifacts.
- Interactive TTY sessions securely prompt for a passphrase when no source is
  supplied; non-interactive callers continue to require an explicit file or
  stdin source.
- Passphrase errors and usage documentation now describe the TTY, file, and
  stdin workflows consistently.
- JSON error-envelope construction is centralized on `Error`, preserving the
  existing machine-readable fields while creating a single rendering seam.
- `verify` now uses typed success-response structs for vault, recovery-log, and
  share results while preserving existing JSON field names and secret behavior.
- `audit` now uses typed success-response structs for failure journals, summaries,
  log listings, and compliance export acknowledgements.
- All remaining lifecycle commands (`shard`, `export-share`, `recover`,
  `rotate-passphrase`, and `revoke-share`) now use typed success responses.
- Added a shared command JSON serializer to keep machine-readable output behavior
  consistent across the CLI, with direct serialization tests.

### Security (critical)
- `recover --json` no longer leaks the master seed hex in the success payload
  when `--out` is supplied (the seed lives in the written file / rebuilt vault,
  not on stdout). Seed is only present in `--json` output when `-o/--out` is set.
- Vault path default `~/.origin/secrets.vault` is now expanded via a new
  `expand_tilde()` helper; previously the literal `~` created a relative
  directory named `~` in the CWD.
- Audit compliance exports (`--export-soc2`/`--export-pcidss`/`--export-hipaa`)
  now refuse to overwrite an existing file (`FileAlreadyExists`) unless `--force`.
- `shard` refuses to leave stale shares from a prior run behind (it now errors
  if `shares/` already contains share files); use `--force` to overwrite.

### Changed (high)
- `audit --show-failures`, `--show-all-logs`, `--show-recovery-log`, and
  compliance exports now honor `--json` (previously printed human text).
- Failure journal now `create_dir_all`s its parent directory before writing, so
  the first failure on a fresh machine is recorded rather than dropped.
- Share load/validation errors carry the offending file path.
- Audit timestamps are now ISO-8601 UTC everywhere (a buggy epoch→UTC helper with
  a wrong leap-year rule was removed); date-range filters now compare consistently.
- `recover` passphrase is only required when `--vault-out` is set; otherwise the
  recovered seed is written to `-o/--out` and the passphrase is not needed.
- `--recovery-log` now performs a real check (vault must contain a `Recover`
  audit entry) instead of being a no-op.
- Freshly-initialized vaults (empty audit log) verify OK instead of erroring
  with `AuditLogNotFound`.
- `recover` cross-checks that every share shares the same `threshold`/`total_shares`.
- `--vault-out` refuses overwrite unless `--force`; rebuilt vault enforces a
  ≥12-char passphrase.
- Operator field in audit entries is now a constant (`origin-secrets-cli`)
  instead of the `USER` env var.

### Added / Fixed (medium + low)
- New error variants: `FileAlreadyExists`, `StdoutSecretRefused`.
- `--json` success payloads on every command (threaded through dispatch).
- `verify --share` warns when `--vault-path` is also given (ignored).
- `--tier` without `--vault-out` warns instead of silently ignoring.
- Passphrase is trimmed of trailing `\r`/`\n`.
- Empty `--key` rejected by `shard`; `share_number == 0` rejected by `export-share`.
- Conflicting / duplicate compliance exports are now errors or de-duplicated.
- Man page (`man/origin-secrets.1`) and README updated for `--json`, failure
  journal, error codes, and `--force` overwrite guards.

### Tested
- 133 tests (112 unit + integration/security) pass in `--release`.
- `cargo clippy -p origin-secrets --all-targets -- -D warnings` clean.
- `cargo fmt -p origin-secrets -- --check` clean.

### Share hardening (P3) — 2026-08
- **P3.1 Revocation** — new `revoke-share <NUM>` command marks a share number
  revoked in the vault (a `Revoke` audit entry is appended, history preserved).
  `recover` and `verify --share` reject revoked shares via `read_share_file`.
- **P3.2 Expiry / TTL** — `shard --expires <ISO-8601>` stamps a share with an
  expiry; `read_share_file` rejects expired shares (no vault required to check).
- **P3.3 Encrypted shares at rest** — `shard` writes an `EncryptedShare` envelope
  (XChaCha20-Poly1305, key derived from the master seed via `origin-crypto-sdk`).
  `recover` / `verify` / `list-shares` transparently decrypt; legacy plaintext
  shares still read for backward compatibility.
- **P3.4 Offline verification** — each share embeds its verifier public keys
  (Ed25519 + Falcon-1024), so `verify --share` performs a full hybrid-sig check
  with **no vault present**.

### Tested (P3)
- 155 lib unit tests + 11 integration/security test binaries pass.
- lib coverage ≈ 89 % regions / 88 % lines (P3 modules: revoke 89 %, share_io
  89 %, recover 91 %, verify 91 %).

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

### UX / DX (pre-prod quality pass)
- `init` no longer accepts the misleading `--no-prompt` flag (it was a no-op after
  the passphrase-fallback removal); the flag is gone from the CLI.
- Removed dead global flags `-c/--config`, `-v/--verbose`, `-q/--quiet` (parsed but
  never consumed). The surface is now exactly what the commands use.
- `--version` now works (`origin-secrets --version` → `origin-secrets 0.4.2`).
- New `completions <SHELL>` subcommand emits bash/zsh/fish completion scripts.
- Error output now uses a categorized exit code: `1` internal/runtime, `2` usage
  (passphrase missing/weak), `3` not-found/input (vault/share/key missing, bad
  threshold); clap parse errors use `127`.
- Per-subcommand `after_help` usage examples added.
- `man/origin-secrets.1` regenerated to match the current flags and exit codes.

### Tested
- 130 tests (109 unit + 21 integration/security) pass in `--release`.
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

### CI (workspace)
- `.github/workflows/ci.yml` now runs `cargo build --workspace --bins` before
  `cargo test --workspace`. Without this, integration tests that spawn sibling
  `origin-*` binaries (e.g. `origin-proof`) could race the build and fail with
  "failed to run <binary>"; the pre-build step makes the workspace suite
  deterministically green.
