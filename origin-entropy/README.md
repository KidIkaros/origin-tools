# `origin-entropy`

Entropy analysis and quality gating built on
[`origin-crypto-sdk`](https://github.com/KidIkaros/OriginSDK).

Analyze the entropy of data and run quality checks against requirements
for a given bit size.

---

## Commands

| Command   | Description                                        |
|-----------|----------------------------------------------------|
| `analyze` | Compute Shannon entropy and byte distribution      |
| `check`   | Check quality against requirements for a bit size  |

## Usage

```bash
# Analyze entropy of a file
origin-entropy analyze --input data.bin

# Analyze from stdin, text output
cat data.bin | origin-entropy analyze --format text

# Check if data meets quality requirements for a 256-bit seed
origin-entropy check --input data.bin --bits 256
```

## Quality Gates

- Shannon entropy measurement (bits/byte)
- Byte distribution analysis
- Quality check against expected bit size

## Notes

- This tool analyzes and gates entropy; it does not generate random bytes.
  For random generation, use `origin-seed generate`.

## License

Apache-2.0
