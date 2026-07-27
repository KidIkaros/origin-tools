# `origin-pass`

Encrypted password vault + 2FA authenticator (TOTP/HOTP) built on
[`origin-crypto-sdk`](https://crates.io/crates/origin-crypto-sdk).

> **Status**: v0.1.0 (scaffold only; command bodies stubbed with `todo!()`)

See `../DESIGN.md` for the full design specification (vault format, threat
model, implementation sequence).

## Quick start (post-implementation)

```bash
# 1. Initialize a new vault:
origin-pass init --vault ~/.origin/pass.vault

# 2. Add a password entry:
origin-pass add github.com --type password \
    --passphrase-file ~/.pw-demo

# 3. Add a TOTP entry:
origin-pass add github-2fa --type otp \
    --passphrase-file ~/.pw-demo
# (then paste the base32 secret when prompted)

# 4. List entries (no secrets shown):
origin-pass list --passphrase-file ~/.pw-demo

# 5. Retrieve a password:
origin-pass get github.com --passphrase-file ~/.pw-demo

# 6. Compute a TOTP code:
origin-pass code github-2fa --passphrase-file ~/.pw-demo

# 7. Provision a new device via QR:
origin-pass export-qr github-2fa --passphrase-file ~/.pw-demo

# 8. Lock the session:
origin-pass lock
```

## License

Apache-2.0 (matches `origin-crypto-sdk`).
