# `origin-identity`

CLI for identity key management built on
[`origin-crypto-sdk`](https://crates.io/crates/origin-crypto-sdk). Generates
master seeds, signs messages with **Ed25519 + Falcon-1024** hybrid signatures,
verifies them, lists stored identities, and restores identities from 24-word
Unicode recovery phrases.

> **Status**: v0.3.0 (pre-release, private)

---

## Installation

The SDK is a required dependency. Origin-tools currently builds against the
sibling `origin-crypto-sdk` `0.7.1-rc.2` candidate pinned by the workspace and CI.
The SDK is experimental until independently audited.

```bash
# 1. Use the sibling origin-crypto-sdk 0.7.1-rc.2 checkout required by origin-tools.
# The workspace and CI pin the exact SDK revision; no separate SDK install is needed.

# 2. Install origin-identity from a local checkout (origin-tools is
#    currently a private local repo; replace `/path/to/origin-tools`
#    with your actual checkout path):
cd /path/to/origin-tools/origin-identity
cargo install --path . --locked
```

After install:

```bash
origin-identity --version
origin-identity --help
```

---

## Subcommands

| Subcommand | Purpose |
|-----------|---------|
| `keygen`            | Generate a new identity, optionally print the 24-word recovery phrase |
| `sign`              | Hybrid-sign a message (literal string, `@file`, or `--hex` raw bytes) |
| `verify`            | Verify a hybrid signature (JSON file or `--hex` length-prefixed bytes) |
| `list`              | List identities in the default directory |
| `import`            | Restore an identity from a 24-word Unicode recovery phrase |
| `show`              | Display metadata (name, fingerprint, size) for a single identity — no decryption |
| `rename`            | Atomically rename an identity blob (filesystem only, no key change) |
| `delete`            | Secure-delete an identity blob (single-pass overwrite + unlink) |
| `export-pubkey`     | Export the public keys for an identity (JSON or hex, no secret material) |
| `rotate-passphrase` | Re-encrypt an identity blob with a new passphrase; optionally migrate Argon2id tier |

All subcommands accept `--tier {nano\|standard\|sovereign}` (default
`standard`) to choose the Argon2id memory cost. `--passphrase-file <path>`
skips the interactive prompt.

---

## Quick start

```bash
# 1. Generate a passphrase for demos (don't reuse this for anything real):
echo -n 'demo-passphrase' > ~/.pw-demo

# 2. Generate an identity:
origin-identity keygen --name demo \
    --no-phrase \
    --passphrase-file ~/.pw-demo

# 3. Sign a message:
echo 'hello, world' > msg.txt
origin-identity sign --name demo \
    --message @msg.txt \
    --passphrase-file ~/.pw-demo > sig.json

# 4. Verify:
origin-identity verify --name demo \
    --message @msg.txt \
    --signature sig.json \
    --passphrase-file ~/.pw-demo
# → valid

# 5. List identities:
origin-identity list
# NAME    SIZE     MODIFIED              FINGERPRINT
# demo    88 B     2026-07-27T...        3af4c01e
```

The 8-hex fingerprint is `BLAKE3(salt ‖ nonce)[..4].hex()` — derived from
**non-secret** bytes (salt + nonce are public once the blob is on disk). It
changes when the blob is `rotate_blob`-ed, so it doubles as a "blob epoch"
identifier.

---

## Hex-pipe mode

`sign --output hex` outputs a length-prefixed wire format that `verify --hex`
accepts **directly** via shell substitution — no JSON, no filesystem handoff.

**Important**: the binary's `--hex` flag applies to BOTH `--message` (raw
bytes as hex) AND `--signature` (length-prefixed bytes as hex). To use
hex-pipe mode, **both** the message and the signature must be in hex form,
with `--hex` passed exactly once.

```bash
# 1. Derive the message hex from the literal so the example stays
#    readable and self-syncing:
MSG_HEX=$(printf 'hello, world' | xxd -p -c 256)
# MSG_HEX is now '68656c6c6f2c20776f726c64'

# 2. Sign via hex-pipe output:
SIG=$(origin-identity sign --name demo \
    --hex --message "$MSG_HEX" \
    --output hex \
    --passphrase-file ~/.pw-demo)

# 3. Inspect the first 140 hex chars — this crosses the Ed25519 /
#    Falcon boundary so the reader can see the wire format in action:
echo -n "$SIG" | head -c 140
# 00000500<...128 hex chars of ed25519...><first 4 hex chars of falcon>
#       │ length of the Falcon portion (BE u32 = 1280 bytes here)
#       └──── ed25519 signature begins immediately after

# 4. Verify the piped signature (single `--hex` enables hex-mode for
#    both message and signature):
origin-identity verify --name demo \
    --message "$MSG_HEX" \
    --signature "$SIG" \
    --hex \
    --passphrase-file ~/.pw-demo
# → valid
```

A simpler variant for very short raw-byte messages:

```bash
SIG=$(origin-identity sign --name demo \
    --hex --message deadbeef00 \
    --output hex \
    --passphrase-file ~/.pw-demo)

origin-identity verify --name demo \
    --message deadbeef00 \
    --signature "$SIG" \
    --hex \
    --passphrase-file ~/.pw-demo
# → valid
```

Wire-format details: see [Hex-Pipe Wire Format](#hex-pipe-wire-format) below.

---

## Hex-Pipe Wire Format

```text
┌───────────────────────────┬──────────────────┬────────────────────────┐
│ falcon_len (4B, BE u32)   │ ed25519 (64B)    │ falcon1024 (N B)       │
└───────────────────────────┴──────────────────┴────────────────────────┘
```

| Field        | Bytes | Encoding          | Notes |
|--------------|-------|-------------------|-------|
| `falcon_len` | 4     | big-endian `u32`  | length of the Falcon portion |
| `ed25519`    | 64    | raw bytes         | Ed25519 is universally 64 B |
| `falcon1024` | `N` `≈ 1280` | raw bytes  | variable; max 1330 B per SDK `SIGNATURE_MAX` |

Total = `4 + 64 + N` bytes → hex-encoded as `(8 + 128 + 2N)` characters.
Example: `N = 1280` gives a 1348-byte / 2696-hex-char signature.

The 4-byte length prefix is **required** — Falcon-1024 signatures are
**variable-length** (padding depends on the message hash). A fixed-byte split
at offset 64 is impossible.

### Why a length prefix?

Without the prefix, the decoder has no way to tell where Ed25519 ends and
Falcon begins. A length-prefixed layout:

- **Self-delimiting**: the decoder reads `N = u32::from_be_bytes(raw[..4])`,
  then slices `raw[4..4+64]` for Ed25519 and `raw[4+64..4+64+N]` for Falcon.
- **Resource-safe**: an attacker can't trick the parser into an unbounded
  allocation — the size-mismatch check kicks in first.

### Implementation

The single source of truth is `CombinedSignature` in `src/commands.rs`:

```rust
pub struct CombinedSignature {
    pub ed: ed25519_dalek::Signature,
    pub falcon: FalconSignature,
}
impl CombinedSignature {
    pub const ED_LEN: usize = 64;
    pub const LEN_PREFIX: usize = 4;
    pub fn to_wire_bytes(&self) -> Vec<u8>;
    pub fn from_wire(raw: &[u8]) -> Result<Self, String>;
}
```

Both `sign --output hex` and `verify --hex` route through this struct —
encoder/decoder drift is impossible by construction.

Full spec & invariants: `../../origin-crypto-sdk/docs/tools/DESIGN.md` § 11.

---

## Recovery phrases (import / backup)

`origin-identity keygen` produces a 24-codepoint recovery phrase — the
**only** backup for the identity. Three presentation modes are
controllable per-invocation:

| Mode | Flags | Behavior |
|------|-------|----------|
| **Visual banner** (default) | `keygen --name X` | Prints a 6×4 grid of codepoints on STDERR, then prompts "Press Enter to continue" before the passphrase prompt |
| **File output** (machine-friendly, v0.2.0) | `keygen --name X --no-phrase --phrase-output <file>` | Writes the phrase to `<file>` atomically as 24 whitespace-separated codepoints with a trailing newline. Banner and interactive prompt are suppressed — the file IS the output. |
| **Silent** (no backup at all) | `keygen --name X --no-phrase` | Skips the banner/prompt. The identity will be **unrecoverable** if `~/.origin/identities/X.id` is lost. |

### Shell-driven recovery (v0.2.0 — recommended)

The `--phrase-output` flag replaces the v0.1.0 manual-paste workflow
with a script-friendly chain. The on-disk format is exactly what
`import --phrase @file` accepts, so the two-step restore is now:

```bash
# 1. Generate a fresh identity + write the phrase to a file:
origin-identity keygen --name shell-alice \
    --no-phrase \
    --phrase-output ~/.origin/phrases/shell-alice.txt \
    --passphrase-file ~/.pw-demo

# 2. Move the phrase file offline (USB, password manager, printout,
#    etc.) — the file IS the recovery material.

# 3. On a different machine (or after `rm` of ~/.origin/identities/…):
origin-identity import --name shell-alice-recovered \
    --phrase @~/.origin/phrases/shell-alice.txt \
    --passphrase-file ~/.pw-demo
# → Imported identity 'shell-alice-recovered' from 24-word phrase → …
```

On-disk format (`write_phrase_file` in `commands.rs`):

```text
<c1> <c2> <c3> … <c24>\n
```

- **Whitespace-separated, single line, trailing newline.** `read_phrase`
  uses `split_whitespace` so any whitespace kind is fine, but the
  on-disk form is one line for friendliness to `grep`, `awk`, and
  line-oriented tools.
- **Atomic via tmp + rename.** `O_CREAT | O_EXCL` semantics on the
  tmp-side (`create_new(true)`) refuses to follow symlinks at the
  predicted tmp path, closing the TOCTOU class where an attacker with
  parent-dir write access could redirect the phrase to a sensitive
  sink. If the write fails, **no target file is created**.
- **Phrase-write failure aborts the whole keygen** — if
  `--phrase-output` is unwritable, no blob is written. This avoids
  the worst-case scenario of a user with an unrecoverable identity.
- **Tier must match across keygen → import → sign → verify**. The
  default `Standard` Argon2id tier (64 MB) is used unless
  `--tier nano|standard|sovereign` is explicitly passed on both
  sides. Mixing tiers produces different Argon2id KDF bytes and AEAD
  opening will fail with a mismatch error.

### Visual banner (still supported)

For one-off restore on a fresh machine without scripting, the visual
banner is still the path of least friction — just leave `--no-phrase`
off and read the codepoints from the terminal:

```bash
# Default keygen with banner, no --phrase-output:
origin-identity keygen --name personal \
    --passphrase-file ~/.pw-demo

# Banner appears on STDERR. Hand-copy the 24 codepoints into:
#   phrase.txt
# One codepoint per whitespace-separated token, 24 of them.

origin-identity import --name recovered \
    --phrase @phrase.txt \
    --passphrase-file ~/.pw-demo
```

Notes:

- **24 words only.** 12-word phrases are rejected because the master
  seed must be 256 bits — HKDF-stretching or zero-padding would
  silently weaken.
- **`@phrase.txt` file syntax** is supported: `origin-identity import
  --phrase @phrase.txt …`. Lines / multiple spaces / tabs are all
  collapsed via `split_whitespace`.
- **UTF-8 BOM** at the start of a phrase file is stripped automatically
  (common when phrases are pasted from Windows-pinned notes or email
  bodies).

---

## Default data layout

```
~/.origin/
├── config.toml              # default tier, etc.
├── identities/
│   ├── personal.id           # encrypted 88-byte blob
│   ├── work.id
│   └── devices.id
```

Each `.id` file is exactly 88 bytes:
`create_blob(passphrase, tier, Some(&seed))` → `salt(16) ‖ nonce(24) ‖ ct(32) ‖ tag(16)`.
No plaintext header — the Tier/Version flags from `DESIGN.md` § 3 are a future
enhancement; the current implementation matches the SDK's basic `blob`
exactly.

---

## Reproducing the test suite

```bash
cd origin-tools/origin-identity

# Unit tests (91, ~106s):
cargo test --bin origin-identity

# Integration / shell-out tests (20, ~164s with --tier nano):
cargo test --test integration

# Both, stress-parallel:
cargo test --bin origin-identity -- --test-threads=8

# Documentation render (no broken intra-doc links):
cargo doc --no-deps
```

Integration tests exercise the full CLI surface end-to-end via
`std::process::Command`, including the byte-exact
`codepoints → phrase → import → blob → recover` round-trip.

---

## Threat model

See `../../origin-crypto-sdk/docs/tools/DESIGN.md` § 6 for the full per-tool
threat model. Key points for `origin-identity`:

| Threat | Mitigation |
|--------|-----------|
| **T1.1** Device stolen; blob exfiltrated | Argon2id memory-hard KDF (`Standard` = 64 MB, 2 lanes) |
| **T1.3** Forensic memory dump of seed | `SeedHandle` TTL + auto-zeroize on drop |
| **T1.4** Recovery phrase intercepted | Phrase displayed only at `keygen` time; user must store offline |
| **T1.5** Brute-force via leaked blob | `Sovereign` = 256 MB × 5 iter × 4 lanes = ~5 s per attempt |
| **T1.6** Blob rollback / downgrade | Encrypted payload includes `created_at` timestamp |

The CLI does **not** implement a duress/self-destruct primitive — see the SDK
duress-pattern application-level guidance
(`origin-crypto-sdk/docs/duress-pattern.md`) for how to layer that on top
using `create_blob` + `recover_seed`.

---

## License

Apache-2.0 (matches `origin-crypto-sdk`).
