# origin-tools — Agent Notes

## What this repository is

An internal platform/incubator and capability catalog. Build a capability
once here, then reuse it across projects. See `CAPABILITIES.md` for the
problem-oriented index and `LOCAL_DEVELOPMENT.md` for cross-repo overlays.

Repository boundaries:

- This workspace: reusable foundations, reference tools, suite products.
- Standalone siblings under `../`: `origin-db`, `origin-memory`, `origin-web`.
  Not workspace members; consume these crates via Git/published deps with
  local path patches for development.
- `origin-crypto-sdk` (sibling, `../origin-crypto-sdk`) is the sole
  cryptographic provider.

## Build and test

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo run -p origin-schnorr --example dogfood
```

### Resource-constrained machines (important)

Full-workspace builds on this machine have previously been OOM-killed and
have filled the disk. Verify one package at a time:

```bash
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  cargo test -p <crate> -j1 -- --test-threads=1
```

Check `free -h` and `df -h /` before a large build. Prefer writing long
runs to a log file and reading the tail rather than streaming output.

## Hard rules

1. **Never read a character device with an unbounded read.** `fs::read("/dev/urandom")`
   never returns — the device has no EOF — and allocates until the OOM
   killer fires. This has actually crashed this machine's desktop session.
   Use a bounded read or `origin_crypto_sdk::fill_random`.
2. **No crypto outside the SDK.** No `ed25519-dalek`, `x25519-dalek`,
   `rand`, `getrandom`, or `origin_crypto_sdk::internal` in downstream
   crates. Use the SDK's re-exports (`Ed25519SigningKey`,
   `Ed25519VerifyingKey`, `Ed25519Signature`, `Signer`, `Verifier`,
   `x25519::X25519KeyPair`, `fill_random`) and the `try_*` fallible RNG
   variants. Gaps go in `SDK_FOLLOW_UP.md`, not into a local reimplementation.
3. **SDK version is exact.** `origin-crypto-sdk = "=0.7.1-rc.10"` at the
   workspace root; do not loosen the constraint or introduce a second version.
4. **Tests must be deterministic.** Bind ports as `:0`, key temp paths by
   PID/tag, and never mutate `HOME`/`ORIGIN_HOME` without serialization.
5. **Library-first.** Typed API in `src/api.rs` is the primary surface; the
   CLI is a thin shell. Every crate keeps an `examples/dogfood.rs` that
   exercises the programmatic path and asserts on typed errors.

## Verification expectations

Before considering a change done:

- `cargo fmt --all -- --check`
- `cargo check --workspace`
- the affected crates' tests, serially per the recipe above
- the affected crates' dogfood example
- for network/protocol changes, `cargo test -p origin-cross-tests`

Do not claim a workspace-wide test pass without running it; report per-package
results if the full run was not performed.

## Promotion policy

```text
experiment → reference crate → reusable library → standalone project
```

Promotion to reusable requires a typed API, a dogfood example, negative-path
tests, and explicit compatibility treatment for any persisted format.
Stability labels: `experimental`, `reference`, `stable`, `frozen`.

A capability that becomes its own project moves to a sibling repository
under `../` and stops being a workspace member.

## Known warnings (not regressions)

- `origin-seal` dead constants `CHUNK_MIN`/`CHUNK_MAX`.
- SDK's own `unsafe-code` warnings in `origin-crypto-sdk/src/internal/`.
- `origin-web/spike` intentionally depends on raw primitive crates — it is a
  throwaway wasm feasibility probe, not production code.
