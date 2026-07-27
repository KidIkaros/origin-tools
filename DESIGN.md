# Origin-Tools Design Specification

> **Status**: Draft (v0.3.0+)  
> **SDK dependency**: `origin-crypto-sdk ^0.6.3`  
> **Last updated**: 2026-07-27

This document covers the **origin-tools** workspace. The shared cryptographic
format, key-derivation tree, and cross-cutting threat model are inherited
verbatim from
[`origin-crypto-sdk/docs/tools/DESIGN.md`](https://github.com/KidIkaros/origin-crypto-sdk/blob/main/docs/tools/DESIGN.md);
sections 1.1 (tool inventory), 2 (directory layout), 4 (vault format), 5
(key derivation), 6 (threat model), and 7 (CLI design principles) apply
unchanged. This document only restates the parts that deviate from the SDK
design and adds per-binary details that the SDK doc does not pin down.

---

## 1. Tool inventory

| Tool             | Crate              | Purpose                                                      | Status  |
|------------------|--------------------|--------------------------------------------------------------|---------|
| `origin-identity`| `origin-identity/` | Identity key generation, hybrid sign/verify, blob lifecycle  | v0.3.0  |
| `origin-pass`    | `origin-pass/`     | Encrypted password vault + 2FA authenticator (TOTP/HOTP)    | design  |
| `origin-vault`   | _deferred_         | Standalone encrypted file vault (no 2FA)                    | backlog |
| `origin-backup`  | _deferred_         | Reed-Solomon sharded backup for identity + vault            | backlog |

`origin-pass` and `origin-vault` were folded into one binary for v1 because
the cryptographic primitive (HKDF → ChaCha20-BLAKE3 vault) and the threat
model (Argon2id-derived master key, AEAD per-entry) are identical. Splitting
them prematurely would force users to maintain two separate vaults with two
separate passphrases for what is effectively one secret store.

`origin-backup` is a separate binary because its threat model is **inverse**
to `origin-pass`: a backup must survive total device loss (the opposite of
durability; the goal is redundancy across media), which requires entirely
different erasure-coding primitives (`Reed-Solomon` over the recovery
phrase) and physical-distribution assumptions.

---

## 2. `origin-pass` scope (v1)

### 2.1 Subcommand surface

| Subcommand          | Purpose                                                           |
|---------------------|-------------------------------------------------------------------|
| `init <vault>`      | Create a new vault (one per machine, default `~/.origin/pass.vault`) |
| `unlock <vault>`    | Unlock the vault in agent/session memory; prints a session token  |
| `lock`              | Drop the in-memory unlocked vault                                  |
| `add <vault> <name>`| Add or update an entry (`--type password\|otp` + secret / key / digits / period) |
| `get <vault> <name>`| Retrieve a single entry (auto-cleared from screen after `--auto-clear` seconds) |
| `list <vault>`      | List entry names + types (no secrets)                             |
| `rm <vault> <name>` | Remove an entry                                                    |
| `code <vault> <name>`| Compute and display a TOTP/HOTP code from a stored secret         |
| `export-qr <vault> <name>` | Print the `otpauth://` URI to stdout for QR provisioning        |
| `import-qr <vault> <qr-uri-or-file>` | Add an entry by parsing an `otpauth://` URI              |
| `change-passphrase <vault>` | Re-encrypt the vault header with a new master passphrase  |

11 subcommands — three above the `5-8` cap the thinker proposed, justified
because (a) `init` / `unlock` / `lock` are inseparable from the threat model
(see §3), and (b) `export-qr` / `import-qr` are the only way to onboard a
new device without copy-pasting a base32 secret. Removing either creates a
real UX dead-end.

### 2.2 What v1 does NOT include

- **OCRA (RFC 6287)**: deferred. The SDK has `origin_crypto_sdk::ocra::ocra`
  implemented but adding `origin-pass code --ocra` doubles the entry-type
  state machine without unlocking a use case that TOTP/HOTP cannot serve
  today. Tracked as a v1.x addition.
- **Sync / remote storage**: vault format is file-local; cloud sync would
  require conflict resolution (CRDTs or last-writer-wins) and a transport
  layer that is out of scope.
- **Browser integration**: the binary is CLI-first. A `pass <name> | xdotool
  type --clearmodifiers --delay 50 -` pipeline is the documented shell
  escape hatch.
- **Hardware token support (FIDO2 / YubiKey)**: deferred. The vault
  master-key derivation is `Argon2id(passphrase)` only.

### 2.3 Vault format

Reuses the SDK design doc §4 verbatim — file magic `OVLT`, ChaCha20-BLAKE3
committing AEAD, per-entry nonces, encrypted entry index inside the header.
**Deviation**: `origin-pass` reuses the existing 16-byte `entry_reserved` block
of `EntryMetadata` to add 5 bytes of entry-type metadata. The struct stays
76 bytes total — the new fields fit within the reserved block:

```
EntryMetadata (76 bytes) — layout unchanged; new fields repurpose reserved
─────────────────────────────────────────────────────────────────
 0      32   name_hash                 name_hash
32      24   entry_nonce               entry_nonce
56       4   entry_ct_len              entry_ct_len
60      16   entry_reserved            type_tag (1B) + algo (1B) + period_secs (2B) + digits (1B) + 11B still-zeroed
─────────────────────────────────────────────────────────────────
```

| Field            | Bytes | Meaning                                                                |
|------------------|-------|------------------------------------------------------------------------|
| `type_tag`       | 1     | `0x00` = password, `0x01` = TOTP, `0x02` = HOTP                        |
| `algo`           | 1     | `0x01` = SHA1, `0x02` = SHA256, `0x03` = SHA512 (for OTP secrets)        |
| `period_secs`    | 2     | TOTP period (typically 30); unused for password / HOTP                   |
| `digits`         | 1     | OTP code width (typically 6 or 8)                                        |
| `reserved`       | 11    | Zeroed for future use                                                   |

This addition is **backward compatible** with the SDK's V1 metadata (the 16B
reserved block is reused). Older readers ignore the new fields; newer writers
always set them.

### 2.4 Entry plaintext payload

When decrypted, an entry is JSON (UTF-8):

```json
{
  "name": "github.com",
  "type": "password",
  "secret": "hunter2-but-actually-much-longer-and-random",
  "url": "https://github.com/login",
  "notes": "Created 2026-07-27. 2FA via origin-pass github.",
  "created_at": 1753632000,
  "updated_at": 1753632000,
  "totp": null,
  "hotp": null
}
```

For OTP entries, `password` is `null` and either `totp` or `hotp` is the
per-type config object:

```json
{
  "name": "github-2fa",
  "type": "otp",
  "secret": null,
  "url": null,
  "notes": null,
  "created_at": 1753632000,
  "updated_at": 1753632000,
  "totp": { "period": 30, "digits": 6, "algo": "SHA256" },
  "hotp": { "counter": 0, "digits": 6, "algo": "SHA256" }
}
```

JSON (vs. a binary struct) keeps the wire format human-debuggable and
forward-compatible. Backward compat: a field that a future reader does not
understand is ignored.

### 2.5 Identity storage

`origin-pass` does **not** manage its own master seed. The vault master key
is derived directly from the vault passphrase via Argon2id (same KDF as
`origin-identity`'s blob decryption), keeping the two systems cryptographically
independent:

- Losing `~/.origin/identities/personal.id` does not lose the vault.
- Losing `~/.origin/pass.vault` does not lose the identity.

If a user wants a single-sign-on across both, the recommended workflow is
to use **the same passphrase** for both — Argon2id is deterministic, so
identical `(passphrase, salt)` produce identical keys. But the salts differ
across the two files, so an attacker who exfiltrates one cannot reuse it on
the other without breaking the per-tool Argon2id pre-hash.

We deliberately do **not** support `origin-pass` reading `origin-identity`'s
seed to derive the vault key. This would couple the two threat surfaces and
make `origin-identity`'s recovery phrase implicitly the `origin-pass`
recovery, which is the wrong default. Coupling is a v2 decision (explicit
user opt-in, with separate documentation).

---

## 3. Threat model additions (extends SDK §6)

The SDK threat model covers the base layers (Argon2id KDF, ChaCha20-BLAKE3
AEAD, mlock for Sovereign tier). `origin-pass` adds:

### 3.1 `origin-pass` specific threats

Note: T-codes in this section are numbered from **T5.x** to avoid collision
with the SDK doc's T2.x (origin-vault) and T3.x (origin-auth) prefixes.

| ID    | Threat                                         | Mitigation                                                                                                  |
|-------|------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| T5.1  | Vault file stolen                              | Header AEAD + per-entry AEAD with independent nonces (inherited from SDK §6)                              |
| T5.2  | Brute-force vault passphrase                   | Argon2id configurable up to Sovereign tier (inherited)                                                       |
| T5.3  | Coerced decryption                              | No `origin-pass` self-destruct primitive — see SDK duress-pattern application guidance                       |
| T5.4  | TOTP secret read by screen scraper             | Vault payload is encrypted at rest; secrets never written to stdout in cleartext (always via `get` only)   |
| T5.5  | TOTP code captured by screen-capture malware   | `code` output auto-clears from terminal after `--auto-clear` seconds (default 30s, configurable via `config.toml`) |
| T5.6  | Replay of an old TOTP code                     | TOTP counter is `(timestamp / period)`; a code older than `±1` step is rejected by RFC 6238 verifier       |
| T5.7  | Shoulder-surfing during `code`                 | `code --quiet` suppresses echo; `--auto-clear` truncates display                                              |
| T5.8  | `import-qr` from an untrusted source           | The `otpauth://` URI is parsed; the secret is stored encrypted; no callback / fetch ever happens              |
| T5.9  | Session token theft (if `--session-token` used)| Token is a random 32B value in `~/.origin/pass.session` with mode `0600`; expired on `lock` or process exit  |
| T5.10 | `origin-pass code` shows secret in error       | Errors never include the secret material; only `code <name>` with successful decryption prints                |

### 3.2 Cross-tool threats (in addition to SDK §6 cross-tool)

Note: T-codes in this section are numbered from **T6.x** to avoid collision
with the SDK doc's T4.x prefix.

| ID    | Threat                                          | Mitigation                                                                                                  |
|-------|-------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| T6.1  | `~/.origin/pass.vault` co-located with identity  | Different file names; different salts; tooling cannot enumerate one from the other                            |
| T6.2  | `origin-pass` reads identity's passphrase file  | Reads only via `--passphrase-file <path>`, no implicit coupling                                                |
| T6.3  | `code` output captured by shell history         | `code` writes to stderr (not stdout) and to a tty-only pty if `--tty-only` is set                              |

---

## 4. CLI conventions (extends SDK §7)

Inherits SDK §7 verbatim. Additions specific to `origin-pass`:

| Flag                    | Description                                                                |
|-------------------------|----------------------------------------------------------------------------|
| `--type password\|otp`  | Specify entry type at `add` time                                          |
| `--period <secs>`       | TOTP period (default 30, RFC 6238)                                         |
| `--digits <n>`          | OTP digit count (default 6)                                                |
| `--algo sha1\|sha256\|sha512` | OTP hash algorithm (default sha256)                                   |
| `--auto-clear <secs>`   | Clear `code` output after N seconds (default 30)                           |
| `--quiet`               | Suppress `code` echo                                                       |
| `--session-token <path>`| Persist unlock to a token file for non-interactive shells                  |

---

## 5. Test plan

Mirror `origin-identity`'s pattern:
- ~80 unit tests across helpers + per-command logic
- ~15 integration tests shelling out via `std::process::Command`
- Coverage target: 95% lines, 70% functions (matches v0.3.0 baseline)

Notable test scenarios:
- `add` then `get` round-trip preserves secret exactly
- `code` produces RFC 6238 §A.1 Test Set 1 vectors (already in the SDK's
  `drbg/otp.rs` tests, so the wrapper just needs to verify the wiring)
- `change-passphrase` produces a new vault file that `unlock`s with the new
  passphrase and refuses the old
- `import-qr` parses a sample `otpauth://totp/...` URI from Google
  Authenticator's published examples
- `export-qr` round-trips through `import-qr` byte-for-byte

---

## 6. Implementation sequencing

1. **Crate scaffold** (this PR): `origin-tools/origin-pass/` with empty
   `Cargo.toml` + `src/main.rs` + `README.md` + `LICENSE` boilerplate
2. **Argon2id + HKDF + ChaCha20-BLAKE3 wiring**: prove the SDK primitives
   produce a working vault `init` → `add` → `get` cycle (smoke test only)
3. **Subcommand surface**: `init`, `unlock`, `lock`, `add`, `get`, `list`,
   `rm`, `change-passphrase` (the password-manager core)
4. **OTP support**: `code`, `export-qr`, `import-qr`, `add --type otp`
5. **Integration tests**: shell-out coverage of every subcommand + RFC
   test vectors
6. **Docs**: README.md expanded to match `origin-identity` style

Each step is a separate PR.

---

## 7. References

- `origin-crypto-sdk/docs/tools/DESIGN.md` — vault wire format, KDF tree,
  base threat model, CLI conventions
- RFC 4226 — HOTP
- RFC 6238 — TOTP
- RFC 6287 — OCRA (deferred from v1)
- Key URI format: `otpauth://` (Google Authenticator compatible)
