# `origin-schnorr`

Schnorr signature proofs over secp256k1, built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Generate keypairs, create zero-knowledge proofs of knowledge, and
verify single or batch signatures.

---

## Commands

| Command        | Description                                     |
|----------------|-------------------------------------------------|
| `keygen`       | Generate a Schnorr keypair from a seed          |
| `prove`        | Create a proof of knowledge of a secret key     |
| `verify`       | Verify a single proof                           |
| `batch-verify` | Verify multiple proofs from a JSON array file   |

## Usage

```bash
# Generate a keypair from a seed
origin schnorr keygen --seed <hex>

# Generate a keypair from your suite identity
origin schnorr keygen --identity --passphrase-file pass.txt

# Create a proof of knowledge
origin schnorr prove --input message.txt --secret <hex> --public <hex>

# Verify a proof
origin schnorr verify --proof proof.json --input message.txt

# Batch verify multiple proofs from a JSON array file
origin schnorr batch-verify --input proofs.json
```

## Batch Verify Format

The `--input` file is a JSON array of objects:

```json
[
  { "proof": "...", "public_key": "...", "message": "..." },
  { "proof": "...", "public_key": "...", "message": "..." }
]
```

## How It Works

- Keys are derived from a 32-byte seed via secp256k1 scalar multiplication.
- Proofs use the SDK's `ec_schnorr::prove()` / `verify()` / `batch_verify()`.
- Batch verification is more efficient than verifying individually.

## License

Apache-2.0
