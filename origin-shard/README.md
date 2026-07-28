# `origin-shard`

Reed-Solomon erasure coding for data sharding and recovery, built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Split any data into data + parity shards. Recover from missing shards
using erasure-based decoding.

---

## Commands

| Command   | Description                                        |
|-----------|----------------------------------------------------|
| `split`   | Split data into data + parity shards (RS code)     |
| `recover` | Recover original data from available shards        |

## Usage

```bash
# Split a file into 3 data + 2 parity shards (defaults)
origin shard split --input secret.dat --output ./shards

# Custom shard counts: 4 data + 2 parity
origin shard split --input secret.dat --output ./shards \
  --data-shards 4 --parity-shards 2

# Recover from shards (tolerates up to `parity-shards` missing)
origin shard recover --input ./shards --output recovered.dat

# Recover from stdin/stdout for piping
origin shard recover --input ./shards > recovered.dat
```

## How It Works

Uses a systematic Reed-Solomon code over GF(256):
- `data-shards` contain the original data
- `parity-shards` enable recovery
- Recovery uses `decode_shards()` with explicit erasure locations
- Can recover from up to `parity-shards` missing shards

## Security Notes

- Flat `decode()` is a single-error correction path only.
- `recover` uses erasure-based `decode_shards()` for robust recovery.
- Missing shards are treated as erasures, not unknown errors.

## License

Apache-2.0
