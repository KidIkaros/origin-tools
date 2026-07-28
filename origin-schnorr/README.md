# `origin-schnorr`

Schnorr signature proofs over secp256k1, built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Generate keypairs, create zero-knowledge proofs of knowledge, and
verify single or batch signatures.

---

## Commands

| Command      | Description                                     |
|--------------|-------------------------------------------------|
| `keygen`     | Generate a Schnorr keypair from a seed          |
| `prove`      | Create a proof of knowledge for data            |
| `verify`     | Verify a single proof                           |
| `batch-verify` | Verify multiple proofs in a batch             |

## Usage

```bash
# Generate a keypair
origin-schnorr keygen --seed <hex>

# Create a proof
origin-schnorr prove --input message.txt --seed <hex> --output proof.json

# Verify a proof
origin-schnorr verify --proof proof.json --input message.txt

# Batch verify multiple proofs
origin-schnorr batch-verify --proofs proofs/ --inputs messages/
```

## How It Works

- Keys are derived from a 32-byte seed via secp256k1 scalar multiplication.
- Proofs use the SDK's `ec_schnorr::prove()` / `verify()` / `batch_verify()`.
- Batch verification is more efficient than verifying individually.

## License

Apache-2.0
