# `origin-pass`

Encrypted password vault + 2FA authenticator (TOTP/HOTP/OCRA) built on
[`origin-crypto-sdk`](https://github.com/ikaros-digital/origin-crypto-sdk).

> **Status**: v0.4.1 — fully functional CLI. All commands implemented.

See `../DESIGN.md` for the full design specification (vault format, threat
model, implementation sequence).

## Features

- **Password vault**: Argon2id KDF (Nano/Standard/Sovereign tiers),
  ChaCha20-BLAKE3 AEAD encryption, per-entry keys via HKDF-SHA3-256.
- **TOTP/HOTP**: RFC 6238 / RFC 4226 compliant. SHA-1, SHA-256, SHA-512.
  Configurable period and digits. HOTP counter auto-increments and persists.
- **OCRA**: RFC 6287 challenge-response (Q-only suite, SHA-1/256/512).
- **QR provisioning**: `export-qr` renders otpauth:// URIs as terminal QR
  codes. `import-qr` parses them back into vault entries.
- **Atomic writes**: vault persistence uses tmp-file + rename + fsync.
- **Zeroizing**: master key and secrets scrubbed on drop.

## Quick start

```bash
# 1. Initialize a new vault:
origin-pass init --vault ~/.origin/pass.vault --tier nano

# 2. Add a password entry:
origin-pass add github.com --type password \
    --secret-file /tmp/pw.txt \
    --passphrase-file ~/.pw-demo

# 3. Add a TOTP entry:
origin-pass add github-2fa --type otp \
    --secret-file /tmp/totp-secret.b32 \
    --passphrase-file ~/.pw-demo

# 4. Add an HOTP entry:
origin-pass add bank-token --type otp --hotp \
    --secret-file /tmp/hotp-secret.b32 \
    --passphrase-file ~/.pw-demo

# 5. List entries (no secrets shown):
origin-pass list --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 6. Retrieve a password:
origin-pass get github.com --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 7. Compute a TOTP/HOTP code:
origin-pass code github-2fa --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 8. Import from an otpauth:// URI:
origin-pass import-qr --vault ~/.origin/pass.vault \
    "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme" \
    --passphrase-file ~/.pw-demo

# 9. Export as QR code:
origin-pass export-qr github-2fa --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-demo

# 10. Change passphrase:
origin-pass change-passphrase --vault ~/.origin/pass.vault \
    --passphrase-file ~/.pw-old --new-passphrase-file ~/.pw-new
```

## Security notes

- Secrets are never passed via argv (use `--secret-file` or `--secret-stdin`).
- The vault passphrase is sourced from `--passphrase-file` or an interactive
  TTY prompt (never argv).
- HOTP counters auto-increment after each `code` call and persist to disk.
- `--auto-clear <secs>` overwrites the terminal after displaying a code.

## Testing

```bash
cargo test -p origin-pass
```

39 unit tests (RFC 4226/6238/6287 vectors, vault round-trips, CLI dispatch)
+ 8 shell-out integration tests (real binary, real clap parsing).

## License

Apache-2.0 (matches `origin-crypto-sdk`).
