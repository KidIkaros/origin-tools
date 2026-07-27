# Changelog

All notable changes to **Origin-Tools** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- `origin-pass` — TOTP / OCRA / password-manager CLI built on `origin-crypto-sdk::drbg::otp`.
- `origin-vault` — encrypted file vault using passphrase-derived keys + ChaCha20.

---

## [0.3.0] — 2026-07-27

First pre-release of the **Origin-Tools** suite published to GitHub as a private
repository. `origin-identity` is the inaugural CLI; subsequent binaries will be
siblings under `origin-tools/<binary>/`.

### Added
- **`show <name>`** — single-identity metadata dump (text + JSON formats). No
  passphrase required: reads unencrypted header bytes (`BLAKE3(salt‖nonce)[..4]`)
  for fingerprinting. Useful for shell scripting without unlocking the blob.
- **`rename <old> <new>`** — atomic filesystem rename. No key-material change.
  Refuses to overwrite existing target without `--force`.
- **`delete <name>`** — secure-delete per NIST SP 800-88 single-pass sanitization
  heuristics: writes `len` random bytes from `/dev/urandom` over the file,
  `fsync`s, truncates to 0, then `remove_file`. `--force` skips the interactive
  confirmation prompt. `--no-overwrite` skips the random-write pass for speed.
- **`export-pubkey <name>`** — recovers the master seed, derives the signing
  bundle, and emits ONLY the public keys (Ed25519 + Falcon-1024) as JSON or
  hex. The recovered seed never leaves the function. Includes the `domain`
  label in the JSON output for audit-trail correlation.
- **`rotate-passphrase`** — re-encrypts an identity blob with a new passphrase
  via atomic tmp+rename (`O_CREAT | O_EXCL` semantics on the tmp side to
  prevent symlink-follow TOCTOU). Optionally migrates the Argon2id tier
  (`--new-tier`, e.g. `nano → standard`) in the same pass.
- **All 5 new arg structs now derive `Clone, Debug`** (precedent set by
  `OutputFormat` and `ListFormat` in v0.1.0) so they can participate in the
  unit-test sentinel that exercises every CLI struct's trait impls.

### Changed
- **Workspace version bumped** `0.1.0 → 0.3.0` (skipping `0.2.0` for the
  unreleased shell-recovery branch).
- **`README.md` subcommand map** expanded from 5 to 10 rows with one-line
  descriptions for each new command.
- **`README.md` test counts** updated to reflect the new test surface
  (91 unit / 20 integration; was 23 unit / 10 integration).

### Security
- `cmd_rotate_passphrase` writes via tmp+rename — original blob survives any
  intermediate failure (disk full, permission denied, fsync error).
- `cmd_export_pubkey` never logs the recovered master seed; only public
  material leaves the function.
- `cmd_delete`'s random-byte overwrite + `fsync` is best-effort for SSDs; the
  README explicitly caveats that cryptographic shred (TRIM / `blkdiscard`)
  requires root and is out of scope for a userland CLI.

### Test surface
- **91 unit tests** (was 23): helper functions, edge cases, error paths,
  cmd_*_full E2E for each new subcommand.
- **20 integration tests** (was 10): shell-out to the binary, including
  byte-exact `codepoints → phrase → import → blob → recover → export-pubkey`
  round-trip and the new `show` / `rename` / `delete` / `export-pubkey` /
  `rotate-passphrase` shell-out paths.

### Coverage (cargo llvm-cov)
| File         | Lines  | Functions |
|--------------|--------|-----------|
| `cli.rs`     | 100%   | 100%      |
| `commands.rs`| 95.08% | 74.62%    |
| `main.rs`    | 94.44% | 100%      |
| **TOTAL**    | **95.09%** | **75.00%** |

Function coverage is bounded by auto-derived `Clone::clone` / `Debug::fmt` /
`Drop::drop` impls on arg-struct fields; line coverage is at the practical
maximum for a CLI binary.

---

## [0.1.0] — initial commit (pre-release, not published)

Stub entry retroactively added in v0.3.0 to anchor the changelog history.
The actual `0.1.0` tag was never created — the workspace moved directly to
`0.3.0` for the first GitHub release.

### Included at v0.1.0

- **`keygen`** — generate a new identity with optional recovery phrase output.
  Modes: visual banner (default, requires Enter), file output via
  `--phrase-output <file>` (atomic tmp+rename), or silent via `--no-phrase`.
- **`sign`** — hybrid-sign a message (literal string, `@file`, or `--hex`
  raw bytes). Output formats: JSON (default) or hex length-prefixed wire
  format (`4B BE falcon_len ‖ 64B ed25519 ‖ N B falcon1024`).
- **`verify`** — verify a hybrid signature from a JSON file or `--hex`
  length-prefixed bytes. Both `sign --output hex` and `verify --hex` route
  through the shared `CombinedSignature` struct (encoder/decoder drift is
  impossible by construction).
- **`list`** — list identities in the default directory (`~/.origin/identities/`)
  with `BLAKE3(salt‖nonce)[..4].hex()` fingerprints. Output formats: table
  (default), CSV, JSON, names-only.
- **`import`** — restore an identity from a 24-codepoint Unicode recovery
  phrase. 12-word phrases are rejected with a clear error (256-bit master
  seed required). Accepts `@phrase.txt` file syntax; strips leading UTF-8 BOM.

### Test surface at v0.1.0
- 23 unit tests + 10 integration tests.
- The integration suite already exercised the byte-exact phrase round-trip
  through the binary CLI (codepoints → phrase-file → `import --phrase @file`
  → encrypted blob → SDK recovery → seed equality).

[Unreleased]: https://github.com/KidIkaros/origin-tools/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/KidIkaros/origin-tools/releases/tag/v0.3.0
[0.1.0]: https://github.com/KidIkaros/origin-tools/commit/c26eab3
