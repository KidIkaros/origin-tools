# Changelog

All notable changes to `origin-seal` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] — 2026-07-28

Initial release.

### Added
- `hash` — SHA3-256, SHA3-512, BLAKE3, HMAC-SHA3-256.
- `encrypt` / `decrypt` — XChaCha20-Poly1305 AEAD with Argon2id key
  derivation (Nano / Standard / Sovereign tiers) and optional zstd
  compression.
- `--stream` — chunked streaming encryption/decryption for files larger than
  memory, with unique per-chunk nonces and zero-length sentinel truncation
  detection.
- `sign` / `verify` — hybrid Ed25519 + Falcon-1024 signatures, JSON or hex
  wire formats, seed- or pubkey-only verification, domain separation.
- `kdf` — Argon2id passphrase-to-key derivation with configurable output
  length and tier.
- `mac` — HMAC-SHA3-256.
- Scripting conventions: stdin/stdout by default, `--raw` binary output,
  status on stderr, proper exit codes.

### Security
- Streaming implemented with per-chunk nonces (counter XOR'd into a random
  base nonce). The SDK's `aead::streaming` is intentionally not used because
  it reuses a single nonce across all chunks (nonce-reuse vulnerability).
- Streamed envelopes carry a zero-length sentinel to detect truncation.
