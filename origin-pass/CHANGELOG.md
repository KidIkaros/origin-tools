# Changelog

All notable changes to `origin-pass` are documented in this file.

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
