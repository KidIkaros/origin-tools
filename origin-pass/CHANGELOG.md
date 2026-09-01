# Changelog

All notable changes to `origin-pass` are documented in this file.

## [0.5.0] — 2026-09-01

### Added

- **`generate` command** — random passwords (`--length`, `--exclude-symbols`,
  `--exclude-digits`, `--exclude-upper`) and word-based passphrases
  (`--passphrase --words <n>`). Secret → stdout, entropy estimate → stderr
  (exact bits from the actual charset / 256-word list, never nominal).
  Randomness comes from the SDK CSPRNG with rejection sampling (no modulo
  bias).
- **Persisted session tokens** — `unlock --session-token <path>` now writes
  a real token (ChaCha20-BLAKE3-sealed master key, `--session-ttl` default
  8h, mode 0600) instead of the old per-process-only no-op. Every vault
  command (`add`, `get`, `list`, `rm`, `code`, `export-qr`, `import-qr`)
  accepts `--session-token` as a passphrase-free unlock source
  (mutually exclusive with `--passphrase-file`). `lock --session-token`
  revokes the file. `change-passphrase` rejects `--session-token` (rotating
  the passphrase re-derives the master key, invalidating tokens).
- **`add --type ocra` fully wired** — `--suite` takes an RFC 6287 OCRASuite
  string (`OCRA-1:HOTP-SHA1-6:QN08`, `C-QN08-PSHA1`, `QA10-T1M`, `QH8-S512`,
  …); the suite parser validates the crypto function, challenge format
  (QN/QH/QA + length), counter, PIN, session, and timestamp components.
  Binary keys via `--secret-file`/`--secret-stdin` (≥ 16 bytes).
- **Suite-driven `code --ocra`** — algorithm, digits, challenge format,
  counter, timestamp, and PIN now come from the entry's stored suite
  (CLI overrides still win). `--pin <string>` for P-suites. Counter suites
  auto-increment + persist per use (like HOTP); timestamp suites compute
  `now / step` (T1M/T20S/T24H).
- **OCRA replay-nonce ledger** — `<vault>.ocra-ledger.json` records a
  SHA3-256 fingerprint of every (challenge, counter) use per entry (bounded
  to the most recent 64); re-issuing an already-used challenge is refused
  unless `--force`. Applies to challenge-based, non-time-based suites.
- **`tokens` command** — manage persisted session tokens without touching
  the vault: `tokens list` (table or `--format json`, showing token id,
  created/expiry UTC, bound vault, and valid/expired/unreadable status),
  `tokens revoke <name>` (bare names resolve into the store),
  `tokens rotate <name> [--ttl <secs>]`, and `tokens revoke-all
  [--expired-only]`. The managed store defaults to `~/.origin/tokens/`
  and is overridable with `--dir` (mirroring the `origin-identity` store
  convention). `--session-token <bare-name>` on any command now resolves
  into the same store, so tokens written by `unlock --session-token work`
  can be listed/revoked by name.
- **`tokens rotate`** — refresh a still-valid token in place (new token
  id, bearer key, nonce, and expiry; vault binding preserved) by
  unsealing the master key from the *current* token, so no passphrase is
  needed. `--ttl` overrides the lifetime (default: original). Expired
  tokens are refused — re-mint with `unlock --session-token`.
- **`lock-all`** — strict session end: revokes every token in the store
  and errors with `nothing to lock` when there was nothing to revoke
  (matching `lock`'s strictness, so scripts can't mistake no-op for
  success). `--vault <path>` scopes revocation to tokens bound to one
  vault; `lock --session-token <bare-name>` now resolves into the store
  like every other token argument.
- **`docs/session-tokens.md`** — man-page-style reference covering the
  on-disk token format (ChaCha20-BLAKE3 seal, hex fields, version),
  store layout, lifecycle commands, and the threat model (bearer
  credential, expiry, tamper detection, copy/leak handling).
- **`$ORIGIN_PASS_TOKEN` env var** — any token-consuming command (`get`,
  `list`, `add`, `rm`, `code`, `export-qr`, `import-qr`, `lock`) falls
  back to the env var when `--session-token` is absent; explicit flags
  (`--session-token`, `--passphrase-file`) always win, and the value
  resolves like the flag (bare store names work).
- **`unlock --auto-rotate`** — attaches a rotation policy
  (`--auto-rotate-threshold`, default 15m; `--auto-rotate-ttl`, default
  `--session-ttl`) to a token. Every use of the token by any command
  refreshes it in place when remaining lifetime drops below the
  threshold — new bearer key + id + expiry, no passphrase — so
  long-running workflows keep their session alive. The policy survives
  `tokens rotate`, is shown in `tokens list` (`auto_rotate`), and is
  documented (with its uptime trade-off) in `docs/session-tokens.md`.
- **`tokens list` richer output** — table gains a time-remaining column
  (`3d 4h`, `2h 5m`, `45m`, `10s`, `expired`) and a stderr summary line
  (`N valid, M expired, K unreadable`); JSON adds `expires_in_secs`
  (null for unreadable) and `auto_rotate`.
- **`tokens list --remaining <mins>`** — filters to tokens expiring
  within the window (expired tokens always match) and **exits 1 when
  any match, 0 otherwise** — a scriptable "needs attention" signal for
  cron/shell checks (summary line suppressed in filtered mode).
- **Auto-rotate policy surfaced** — `tokens list` now shows the policy
  as a table column (`15m→8h` = threshold→fresh ttl) and as
  `auto_rotate_threshold` / `auto_rotate_ttl` in JSON, via new
  `TokenInfo` fields.
- **`tokens renew <name> [--ttl <secs>]`** — extends a token's expiry in
  place while keeping the **same** bearer key, token id, nonce, and
  AEAD seal (contrast `rotate`, which mints a fresh key). `--ttl`
  default is the token's lifetime span from creation; the auto-rotate
  policy is preserved; expired tokens are refused.
- **`tokens prune`** — cleanup verb: revokes expired **and** unreadable
  (corrupt/foreign) tokens, reports each pruned file with its reason
  and a final count, never touches valid tokens, and succeeds leniently
  with `nothing to prune` when there is nothing to do.
- **`--remaining` × `--format json`** — `tokens list --remaining <mins>
  --format json` shares the table mode's exit semantics for scripts:
  matches → JSON array + exit 1; no matches → `[]` + exit 0. Documented
  in README, `docs/session-tokens.md`, and the new man page.
- **`docs/origin-pass.1.md`** — man-page-style reference for the whole
  CLI (vault + 2FA + tokens): synopsis, per-command options, exit
  status, environment, security notes, and examples, linking to
  `docs/session-tokens.md` for token internals.

### Changed

- `EntryPayload::ocra` now takes an initial counter (stored in the entry
  and advanced by `code --ocra` for `C-` suites).
- Removed the vestigial per-process `Mutex<Option<Vault>>` unlock state:
  `unlock` no longer retains anything in memory (every command already
  re-unlocked from disk), and `lock` now **requires** `--session-token`
  (a bare `lock` errors with guidance instead of silently no-oping).
  The persisted session token is the only cross-process credential.
- `--session-token` now accepts a bare store name (e.g. `work`) resolved
  into `~/.origin/tokens/`, alongside explicit paths; `tokens revoke`
  resolves bare names against its `--dir` store the same way.

### Fixed

- Password generator's rejection loop could hang forever for wordlists
  larger than 256 entries (rejection threshold collapsed to 0); the
  wordlist is exactly 256 words and `uniform_index` now asserts the bound.
- Suite parser was lax about non-conformant lengths: `QN8` (challenge
  length must be 1–2 digits — `QN08` *and* the RFC §6.4 `QH8` form are
  both valid), `S64` (session length must be 3 digits, `S064`), and
  out-of-range time steps (`T60S`, `T49H`) are now rejected.
- Challenge validation enforced the *exact* suite length; RFC §6.3's
  table is "Up to Length (xx)", so any length 1..=max of the right
  character set is now accepted (a QN08 suite accepts a 4-digit question).
- `code` (TOTP/HOTP) rejected `--session-token` in its pre-flight
  passphrase check — a passphrase OR a session token now both unlock.

### Debug pass (2026-09-01)

30-check shell harness against the real binary: OCRA edge suites (bare C,
QH/QA/QN formats, T1M timestamps, PSHA1 PINs, SDK-limited P-SHA256 and
S-suites, initial counters), session-token hardening (mode 0600, expiry,
tamper, clap conflicts, zero TTL, change-passphrase rejection, TOTP via
token), and an 8-way concurrent `code --ocra` race against the replay
ledger (ledger stays valid JSON and usable; the last atomic write wins —
accepted single-user behavior, documented in `ledger.rs`).

## [0.4.1] — 2026-07-28

### Added

- **TOTP/HOTP entry creation** via `add --type otp`:
  - `--secret-file <path>` for base32-encoded secret (no argv secrets)
  - `--period <secs>` (default 30), `--digits <n>` (default 6),
    `--algo <sha1|sha256|sha512>` (default sha1)
  - `--hotp` flag to create HOTP entries instead of TOTP
  - `--counter <n>` for initial HOTP counter value
  - Validates base32 secret, digits range (4–10), and period > 0
- **TOTP/HOTP code generation** via `code <name>`:
  - Auto-detects TOTP vs HOTP from stored entry type
  - CLI overrides: `--algo`, `--digits` take precedence over stored values
  - `--quiet` prints code to stderr (for scripting)
  - `--auto-clear <secs>` clears terminal after display
  - HOTP counter auto-increments and persists after each code generation
- **RFC 6238 test vectors**: SHA-1, SHA-256, SHA-512 at T=59
- **RFC 4226 test vectors**: HOTP counters 0–9
- **3 new integration tests**: OTP add→code, import-qr→code, HOTP counter
  increment (verifies RFC 4226 values 755224 → 287082)

### Changed

- `cmd_code` now dispatches to TOTP/HOTP path when `--ocra` is not set
  (previously returned "not yet implemented")
- `cmd_add --type otp` now creates entries (previously returned
  "not yet implemented")
- Pre-flight validation in `cmd_code_otp`: checks vault path and passphrase
  before attempting unlock (clear error messages on non-TTY)

### Fixed

- Removed all 7 compiler warnings (unused imports, dead code annotations)

## [0.4.0] — 2026-07-27

### Added

- OCRA (RFC 6287) challenge-response code generation via `code --ocra`
- QR code export (`export-qr`) and import (`import-qr`) for otpauth:// URIs
- Vault passphrase rotation (`change-passphrase`)
- Entry removal (`rm`)
- Full vault encryption/decryption with per-entry keys (HKDF-SHA3-256)
- Atomic file writes with fsync

## [0.3.0] — 2026-07-26

### Added

- `origin-identity` crate: keygen, sign, verify, list, import, show,
  rename, delete, export-pubkey, rotate-passphrase
- 91 unit tests + 20 integration tests

## [0.1.0] — 2026-07-25

### Added

- Initial scaffold with CLI argument parsing (clap)
- Vault format design (DESIGN.md)
