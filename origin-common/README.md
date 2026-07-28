# `origin-common`

Shared infrastructure for the origin-tools suite.

Provides identity management, encrypted envelopes, passphrase resolution,
I/O helpers, and home directory management used by all origin-tools crates.

---

## Modules

| Module        | Description                                      |
|---------------|--------------------------------------------------|
| `identity`    | `IdentityStore` — create, load, derive keys      |
| `envelope`    | `Envelope` — authenticated encrypted containers  |
| `home`        | `OriginHome` — `~/.origin` directory management  |
| `passphrase`  | Passphrase resolution (file or interactive)      |
| `io`          | `read_input` / `write_output` helpers            |
| `tier_ext`    | `MemoryTier` ↔ byte/string conversions           |

## Identity

```rust
use origin_common::{IdentityStore, OriginHome, MemoryTier};

let home = OriginHome::load()?;
let store = IdentityStore::create(&home, "passphrase", MemoryTier::Standard)?;
let child_key = store.derive_key("signing", 32)?;
```

- Identity seed is encrypted with XChaCha20-Poly1305 + Argon2id.
- The tier is stored in the blob so `load()` uses correct KDF params.
- `identity.seed` is created with `0600` permissions.
- Derived keys are zeroized after use.

## Envelope

```rust
use origin_common::{Envelope, PayloadType, MemoryTier};

let env = Envelope::encrypt(data, &key, MemoryTier::Nano, PayloadType::File, true)?;
let bytes = env.to_bytes();
let parsed = Envelope::from_bytes(&bytes)?;
let plaintext = parsed.decrypt(&key)?;
```

- Header fields are authenticated via AAD (version, type, flags, tier, salt, nonce).
- Optional LZ4 compression.
- Magic bytes `ORIG` + version for format identification.

## Home Directory

```rust
let home = OriginHome::load()?;        // ~/.origin (or $ORIGIN_HOME)
let home = OriginHome::with_root(p)?;  // custom path
```

- Respects `ORIGIN_HOME` env var for isolated test homes.
- Directory created with `0700` permissions.
- Config at `~/.origin/config.toml` (tier, format).

## License

Apache-2.0
