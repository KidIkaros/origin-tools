# origin-tools fuzz targets

Fuzz targets built with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz),
exercising the parsers and converters in `origin-common` that handle untrusted
input across the whole suite.

## Setup

```bash
cargo install cargo-fuzz
rustup toolchain install nightly   # libFuzzer requires nightly
```

## Running

```bash
# Run a single target for 60 seconds
cargo +nightly fuzz run fuzz_envelope -- -max_total_time=60

# Run all three
for t in fuzz_envelope fuzz_config fuzz_tier; do
  cargo +nightly fuzz run "$t" -- -max_total_time=60
done
```

## Targets

| Target          | What it fuzzes                              | Properties verified                                  |
|-----------------|---------------------------------------------|------------------------------------------------------|
| `fuzz_envelope` | `Envelope::from_bytes` (ORGN binary parser) | never panics; `to_bytes` round-trip is stable        |
| `fuzz_config`   | `toml::from_str::<Config>` + `Config::tier` | parsing never panics; tier resolution never panics   |
| `fuzz_tier`     | `tier_from_byte` / `tier_from_str`          | byte domain is exactly {0,1,2}; round-trip identity  |

## Why these targets

Every tool in the suite reads untrusted bytes through `origin-common`:
- Envelopes arrive from files/stdin and are parsed by `Envelope::from_bytes`
- `~/.origin/config.toml` is deserialized into `Config`
- The envelope tier byte and config tier string are converted via `tier_*`

These are the trust boundaries. A panic here is a DoS on every tool.

## Notes

- The fuzz crate is excluded from the main workspace (`exclude = ["fuzz"]`)
  and built separately by cargo-fuzz with ASan + coverage instrumentation.
- `libfuzzer-sys` must keep its default features (the libFuzzer runtime
  provides `main`); setting `default-features = false` breaks linking.
