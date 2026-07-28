# `origin-seed`

Hierarchical deterministic seed management built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Generate, derive, inspect, and encrypt seeds using HKDF-SHA3-256.

---

## Commands

| Command   | Description                                      |
|-----------|--------------------------------------------------|
| `generate`| Generate a new random 32-byte seed               |
| `derive`  | Derive a child seed via HKDF (domain-separated)  |
| `inspect` | Show seed fingerprint and derivation info        |
| `blob`    | Encrypt a seed into a portable encrypted blob    |
| `recover` | Decrypt a seed blob back to raw seed             |

## Usage

```bash
# Generate a new seed
origin-seed generate

# Derive a child seed for a specific domain
origin-seed derive --seed <hex> --domain "signing" --index 0

# Encrypt a seed for storage
origin-seed blob --seed <hex> --passphrase-file pass.txt

# Recover a seed from an encrypted blob
origin-seed recover --input blob.bin --passphrase-file pass.txt
```

## Security Notes

- Empty derivation domains are rejected (SDK contract).
- Encrypted blobs use XChaCha20-Poly1305 with Argon2id key derivation.
- Seeds are zeroized from memory after use.

## License

Apache-2.0
