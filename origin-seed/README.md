# `origin-seed`

Hierarchical deterministic seed management built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Generate, derive, encode/decode, and encrypt seeds using HKDF-SHA3-256.

---

## Commands

| Command        | Description                                      |
|----------------|--------------------------------------------------|
| `generate`     | Generate a new random 32-byte seed               |
| `derive`       | Derive a child seed via HKDF (domain-separated)  |
| `encode`       | Encode a seed as a mnemonic/unicode phrase       |
| `decode`       | Decode a seed from a mnemonic/unicode phrase     |
| `blob-create`  | Encrypt a seed into a passphrase-protected blob  |
| `blob-recover` | Recover a seed from an encrypted blob            |

## Usage

```bash
# Generate a new seed
origin seed generate

# Derive a child seed for a specific domain
origin seed derive --seed <hex> --domain "signing"

# Derive from your suite identity instead of an explicit seed
origin seed derive --identity --domain "wallet" --passphrase-file pass.txt

# Encode a seed as a recovery phrase
origin seed encode --seed <hex>

# Encrypt a seed for storage
origin seed blob-create --seed <hex> --output seed.blob --passphrase-file pass.txt

# Recover a seed from an encrypted blob
origin seed blob-recover --input seed.blob --passphrase-file pass.txt
```

## Security Notes

- Empty derivation domains are rejected (SDK contract).
- Encrypted blobs use XChaCha20-Poly1305 with Argon2id key derivation.
- Seeds are zeroized from memory after use.

## License

Apache-2.0
