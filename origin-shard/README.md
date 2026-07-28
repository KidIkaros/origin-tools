# `origin-shard`

Reed-Solomon erasure coding for data sharding and recovery, built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Split any data into N shards with configurable redundancy. Recover from
missing shards using erasure-based decoding.

---

## Commands

| Command   | Description                                        |
|-----------|----------------------------------------------------|
| `split`   | Split data into N shards (systematic RS code)      |
| `recover` | Recover original data from available shards        |
| `info`    | Show shard metadata and integrity info             |

## Usage

```bash
# Split a file into 6 shards (4 data + 2 parity)
origin-shard split --input secret.dat --output-dir ./shards --total 6 --data 4

# Recover from shards (tolerates up to 2 missing)
origin-shard recover --input-dir ./shards --output recovered.dat

# Inspect a shard
origin-shard info --input ./shards/shard_0.bin
```

## How It Works

Uses a systematic `[N, K]` Reed-Solomon code over GF(256):
- `K` data shards contain the original data
- `N - K` parity shards enable recovery
- Recovery uses `decode_shards()` with explicit erasure locations
- Can recover from up to `N - K` missing shards

## Security Notes

- Flat `decode()` is a single-error correction path only.
- `recover` uses erasure-based `decode_shards()` for robust recovery.
- Missing shards are treated as erasures, not unknown errors.

## License

Apache-2.0
