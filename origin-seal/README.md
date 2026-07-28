# `origin-seal`

Data operations CLI — encrypt, decrypt, sign, verify, hash, MAC, and KDF —
built entirely on
[`origin-crypto-sdk`](https://github.com/ikaros-digital/origin-crypto-sdk).

> **Status**: v0.4.1 — fully functional CLI. All commands implemented.

`origin-seal` is a thin, scriptable wrapper over the SDK's cryptographic
primitives. It adds **no cryptographic dependencies of its own** — every
primitive (AEAD, signing, hashing, KDF, compression) routes through
`origin-crypto-sdk`. The only non-SDK dependencies are CLI ergonomics
(`clap`, `serde`, `hex`, `rpassword`) and OS entropy (`rand`).

## Features

- **Encryption**: XChaCha20-Poly1305 AEAD with Argon2id key derivation
  (Nano / Standard / Sovereign memory tiers). Optional zstd compression.
- **Streaming**: `--stream` encrypts/decrypts in length-framed chunks with
  **unique per-chunk nonces** (counter XOR'd into a random base nonce) and a
  zero-length sentinel for truncation detection. Handles files larger than
  memory. (The SDK's own `aead::streaming` reuses one nonce across chunks —
  a nonce-reuse vulnerability — so `origin-seal` implements its own correct
  chunked scheme on top of the SDK's single-shot AEAD.)
- **Signing**: Hybrid Ed25519 + Falcon-1024 (post-quantum). JSON or hex wire
  formats. Verify with seed or pubkey-only.
- **Hashing**: SHA3-256, SHA3-512, BLAKE3, HMAC-SHA3-256.
- **KDF**: Argon2id passphrase-to-key derivation with configurable output
  length and memory tier.
- **MAC**: HMAC-SHA3-256.
- **Scripting**: stdin/stdout by default, `--raw` for binary output, status
  messages on stderr so stdout stays pipe-clean, proper exit codes.

## Quick start

```bash
# Hash a file (SHA3-256, hex to stdout):
origin-seal hash -i data.bin --algo sha3-256

# Encrypt with a passphrase (Argon2id Standard tier):
origin-seal encrypt -i secret.txt -o secret.seal \
    --passphrase-file ~/.pw --tier standard

# Decrypt:
origin-seal decrypt -i secret.seal -o recovered.txt \
    --passphrase-file ~/.pw --tier standard

# Encrypt + compress a large file, streaming in 1 MiB chunks:
origin-seal encrypt -i big.iso -o big.seal \
    --passphrase-file ~/.pw --tier nano --stream --chunk-size 1048576

# Hybrid-sign a message (seed as hex):
origin-seal sign -i msg.txt --seed $(cat seed.hex) \
    --domain myapp --format json -o msg.sig

# Verify (with seed, or pubkey-only via --ed25519-pubkey + --falcon-pubkey):
origin-seal verify -i msg.txt --signature msg.sig \
    --seed $(cat seed.hex) --domain myapp

# Derive a key from a passphrase:
origin-seal kdf --passphrase-file ~/.pw \
    --salt 00112233445566778899aabbccddeeff --tier nano --len 32

# HMAC:
origin-seal mac -i data.bin --key-file key.bin
```

## Envelope format

`encrypt` produces a self-describing binary envelope:

```
offset  size  field
0       4     magic "SEAL"
4       1     version (1)
5       1     flags (bit0=compressed, bit1=streamed)
6       1     Argon2id tier
7       1     reserved
8       16    Argon2id salt
24      24    XChaCha20-Poly1305 nonce (base nonce if streamed)
48      ...   ciphertext (+ 16-byte Poly1305 tag)
```

Streamed envelopes append length-framed chunks after the header:

```
[4-byte BE chunk_len ‖ ciphertext+tag]* ‖ 4-byte 0 (sentinel)
```

Each chunk uses `nonce = base_nonce XOR counter` (big-endian counter in the
low 8 bytes), guaranteeing nonce uniqueness. The zero-length sentinel lets
the decryptor distinguish a clean end-of-stream from a truncation attack.

## Commands

| Command   | Purpose                                              |
|-----------|------------------------------------------------------|
| `hash`    | SHA3-256 / SHA3-512 / BLAKE3 / HMAC-SHA3-256         |
| `encrypt` | XChaCha20-Poly1305 + Argon2id (+ `--compress`, `--stream`) |
| `decrypt` | Reverse of `encrypt` (auto-detects streamed/compressed) |
| `sign`    | Hybrid Ed25519 + Falcon-1024 signature               |
| `verify`  | Verify a hybrid signature (seed or pubkey-only)      |
| `kdf`     | Argon2id passphrase → key derivation                 |
| `mac`     | HMAC-SHA3-256                                        |

## Exit codes

- `0` — success
- `1` — any error (bad input, wrong passphrase, tampered data, truncation)

## Security notes

- **No nonce reuse.** Streaming uses a distinct nonce per chunk. The SDK's
  `aead::streaming` is deliberately avoided because it reuses one nonce for
  all chunks (catastrophic for XChaCha20-Poly1305).
- **Truncation detection.** Streamed envelopes carry a zero-length sentinel;
  a missing sentinel is rejected as a possible truncation attack.
- **Domain separation.** Signatures bind a `--domain` string so a signature
  for one context cannot verify in another.
- **Tier pinning.** `decrypt` refuses if the CLI `--tier` does not match the
  tier recorded in the envelope, preventing silent KDF downgrades.

## Development

```bash
cargo test -p origin-seal           # 8 unit + 19 integration tests
cargo build -p origin-seal --release
```

## License

Apache-2.0
