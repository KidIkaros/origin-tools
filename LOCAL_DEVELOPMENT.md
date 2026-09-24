# Local development across Origin repositories

The canonical dependency graph uses released or Git dependencies. Local path
patches are a development convenience only; they must not be required for CI,
publication, or a fresh checkout.

Expected sibling layout:

```text
Gold/
├── origin-crypto-sdk/
├── origin-tools/
├── origin-db/
├── origin-memory/
└── origin-web/
```

## Standalone projects

`origin-db` and `origin-memory` have their own Cargo workspace roots. Their
manifests declare Git dependencies on the reusable `origin-tools` crates and
patch those Git URLs to `../origin-tools/origin-*` during local development.
Their SDK patch points to `../origin-crypto-sdk`.

`origin-web/crate` is the standalone WASM crate. Its SDK patch points to
`../../origin-crypto-sdk` from the crate directory. The web repository owns
its own `wasm-pack` build and browser distribution lifecycle.

To test a standalone project against published/Git dependencies instead of
local checkouts, temporarily comment out the `[patch.crates-io]` and
`[patch."https://github.com/KidIkaros/origin-tools.git"]` sections in that
project's local manifest. Do not commit a local-only patch change as a release
configuration.

## Safe verification

Run one project or package at a time on constrained development machines:

```bash
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -j1 -- --test-threads=1
```

For a workspace package:

```bash
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  cargo test -p <crate> -j1 -- --test-threads=1
```

Before a large build, check both memory and disk. A test that reads a device
such as `/dev/urandom` with an unbounded `fs::read` can allocate forever
because the device has no EOF. Use a bounded read or
`origin_crypto_sdk::fill_random` instead.

## Promotion rule

When a capability proves reusable, promote it in this order:

1. experiment or example;
2. tested reference crate;
3. stable library API with typed errors and compatibility tests;
4. standalone project with its own repository and release lifecycle.

See `CAPABILITIES.md` for the capability-oriented index and stability labels.
