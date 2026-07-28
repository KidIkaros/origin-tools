# `origin-stealth`

Stealth address and proof-of-work system built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Derive stealth master keys, generate one-time stealth addresses, and
create/verify identity-bound proofs of work.

---

## Commands

| Command   | Description                                        |
|-----------|----------------------------------------------------|
| `master`  | Derive stealth master keys from a seed             |
| `address` | Generate a stealth address at a specific index     |
| `solve`   | Solve a proof-of-work challenge                    |
| `verify`  | Verify a proof-of-work solution                    |

## Usage

```bash
# Derive stealth master keys
origin stealth master --seed <hex>

# Generate a stealth address at index 0
origin stealth address --seed <hex> --index 0

# Solve a PoW challenge (difficulty = leading zero bits)
origin stealth solve --seed <hex> --index 0 --difficulty 20

# Verify a PoW proof
origin stealth verify --proof proof.json --index 0 --seed <hex>

# Use your suite identity instead of an explicit seed
origin stealth solve --identity --index 0 --difficulty 20 --passphrase-file pass.txt
```

## How It Works

- Stealth addresses use ECDH with a one-time nonce at a given index.
- PoW is identity-bound: the hash includes `identity_pk`, `destination_hint`,
  `nonce`, `extra`, and `counter`.
- Verification uses the SDK's `stealth::pow::verify()` — not an ad-hoc hash.

## Security Notes

- The old `nonce || index` hash was replaced with full SDK verification.
- All hash inputs are identity-bound to prevent cross-context replay.

## License

Apache-2.0
