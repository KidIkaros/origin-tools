# `origin-entropy`

Entropy analysis and quality gating built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Analyze the entropy of data, run quality checks, and generate
cryptographically secure random bytes.

---

## Commands

| Command   | Description                                        |
|-----------|----------------------------------------------------|
| `analyze` | Compute Shannon entropy and byte distribution      |
| `check`   | Run quality gates (min entropy, chi-squared)       |
| `generate`| Generate cryptographically secure random bytes     |

## Usage

```bash
# Analyze entropy of a file
origin-entropy analyze --input data.bin

# Check if data meets quality thresholds
origin-entropy check --input data.bin --min-entropy 7.5

# Generate 32 random bytes
origin-entropy generate --bits 256
```

## Quality Gates

- Shannon entropy threshold (configurable, default 7.5 bits/byte)
- Chi-squared uniformity test
- Byte distribution histogram

## License

Apache-2.0
