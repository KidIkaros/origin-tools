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
| `address` | Generate a one-time stealth address                |
| `solve`   | Solve a proof-of-work challenge                    |
| `verify`  | Verify a proof-of-work solution                    |

## Usage

```bash
# Derive stealth master keys
origin-stealth master --seed <hex>

# Generate a stealth address
origin-stealth address --seed <hex> --index 0

# Solve a PoW challenge (identity-bound)
origin-stealth solve --seed <hex> --difficulty 20 --destination "hint"

# Verify a PoW proof
origin-stealth verify --proof proof.json --destination "hint"
```

## How It Works

- Stealth addresses use ECDH with a one-time nonce.
- PoW is identity-bound: the hash includes `identity_pk`, `destination_hint`,
  `nonce`, `extra`, and `counter`.
- Verification uses the SDK's `stealth::pow::verify()` — not an ad-hoc hash.

## Security Notes

- The old `nonce || index` hash was replaced with full SDK verification.
- All hash inputs are identity-bound to prevent cross-context replay.

## License

Apache-2.0
