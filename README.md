# Origin-Tools

CLI tool suite built on [origin-crypto-sdk](https://crates.io/crates/origin-crypto-sdk) — hybrid post-quantum cryptography for identity, secrets, and authentication.

## Tools

| Tool | Status | Purpose |
|------|--------|---------|
| `origin-identity` | ✅ Active | Identity key management, hybrid sign/verify |
| `origin-vault`   | 📋 Planned | Encrypted password/secret store |
| `origin-auth`    | 📋 Planned | TOTP/HOTP/OCRA 2FA authenticator |
| `origin-kdf`     | 📋 Planned | Key derivation utility |
| `origin-backup`  | 📋 Planned | Recovery phrases + encrypted backup |

## Quick start

```bash
cargo run --bin origin-identity -- keygen --name personal
# → Recovery phrase shown, blob saved to ~/.origin/identities/personal.id

cargo run --bin origin-identity -- sign --name personal --message "Hello"
# → Hybrid signature (Ed25519 + Falcon-1024)

cargo run --bin origin-identity -- verify --name personal \
    --message "Hello" --signature '{"ed25519":"...","falcon1024":"..."}'
# → "valid"
```

## Design

See [docs/tools/DESIGN.md](../origin-crypto-sdk/docs/tools/DESIGN.md) for the full specification.
