# `origin-proof`

Merkle Mountain Range (MMR) append-only proofs built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Append data to an MMR, generate authentication paths, and verify
membership proofs against a root hash.

---

## Commands

| Command   | Description                                        |
|-----------|----------------------------------------------------|
| `append`  | Append data to an MMR and output the new state     |
| `root`    | Compute the current MMR root hash                  |
| `prove`   | Generate a membership proof for a leaf             |
| `verify`  | Verify a membership proof against a root hash      |

## Usage

```bash
# Append data to an MMR (creates state file if new)
origin proof append --state mmr.json --data <hex> --output mmr.json

# Get the current root
origin proof root --state mmr.json

# Generate a proof for leaf index 0
origin proof prove --state mmr.json --index 0 > proof.json

# Verify a proof against a root
origin proof verify --proof proof.json --root <hex>
```

## How It Works

- MMR is an append-only authenticated data structure.
- Proofs use mountain-based authentication paths (not just peak hashes).
- Verification reconstructs the root from the leaf + auth path.

## Security Notes

- Full MMR auth-path verification replaced the earlier peak-only stub.
- Each leaf is hashed with its position to prevent second-preimage attacks.

## License

Apache-2.0
