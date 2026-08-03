# Origin Crypto SDK Follow-up Ledger

This ledger records SDK concerns discovered while making `origin-tools` depend on the sibling `origin-crypto-sdk` `0.6.7` revision. The SDK remains the sole cryptographic implementation; origin-tools must not duplicate a primitive to work around an item in this ledger.

The SDK is experimental and has not received an independent security audit. The entries below are engineering follow-ups, not claims that the SDK is unsafe. Each item requires validation in the SDK repository before being promoted to a defect.

## Review status

- Reviewed SDK target: `0.6.7`
- Reviewed revision: `a692cbdcf92799ef9375d6a9e906416103d3aa99`
- Origin-tools policy: use SDK APIs and report missing or unsafe ergonomics upstream
- Confirmed critical vulnerabilities: none identified during the initial origin-tools dependency review

## Follow-up items

### SDK-001 — Stable public randomness API for downstream tools

- **Status:** Addressed in SDK working tree (unreleased)
- **Impact:** Origin-tools currently reaches `origin_crypto_sdk::internal::getrandom::fill` for some security-sensitive bytes. Depending on an `internal` module couples downstream tools to implementation layout and makes the intended CSPRNG contract unclear.
- **Evidence:** `origin-secrets/src/crypto.rs` uses the internal path for random bytes; other tools still use direct `getrandom` or `rand`.
- **Recommendation:** Expose a small documented public SDK randomness API with typed errors and platform guarantees. Migrate all downstream callers to it and remove direct RNG dependencies from origin-tools.
- **Required validation:** SDK unit/integration tests for short, empty, and large buffers plus native/WASM/platform behavior as supported.
- **Resolution:** SDK now exposes `origin_crypto_sdk::fill_random(&mut [u8]) -> Result<()>`. `origin-common/src/random.rs` and `origin-secrets/src/crypto.rs` migrated to it. Regression test `test_public_randomness_api_fills_empty_and_nonempty_buffers` added to SDK integration suite. Remaining direct `rand`/`getrandom` usage in other origin-tools crates is a separate follow-up.

### SDK-002 — Public serialization contract for `MemoryTier`

- **Status:** Needs SDK review
- **Impact:** `MemoryTier` is authoritative in the SDK, but downstream tools must currently add local string/byte conversion and serde adapters. This encourages duplicate tier enums and risks mismatched persisted values.
- **Evidence:** `origin-common/src/tier_ext.rs` implements local byte/string conversions; `origin-secrets/src/vault.rs` mirrors the enum and Argon2 parameters.
- **Recommendation:** Provide documented, stable label/parse and serialized representation APIs in the SDK, while keeping wire-format ownership explicit for consumers.
- **Required validation:** Golden values for all tiers, invalid values, and compatibility behavior.

### SDK-003 — Versioned artifact/format ownership

- **Status:** In progress — format registry created, parsing safety fixed
- **Impact:** The SDK exposes blob, envelope-adjacent, and other persistence-oriented primitives while warning that formats may change. Downstream foundational tools need explicit versioning and compatibility guidance before using these formats as organizational storage contracts.
- **Evidence:** SDK README experimental-format warning; origin-tools currently has identity blobs, ORGN envelopes, and origin-secrets JSON vault/share formats.
- **Recommendation:** Document which SDK formats are stable within a minor release, define version negotiation/reader behavior, and publish golden vectors for persisted formats.
- **Required validation:** Cross-version read/write fixtures and malformed-input tests in the SDK.
- **Resolution (partial):** Created `FORMAT_REGISTRY.md` in the SDK cataloguing all 14 binary formats with ownership, versioning, and validation coverage. Fixed `unwrap` → `map_err` in ORGN envelope and identity blob parsing. Added bounds checks to NTRU Prime decode functions. Added `from_bytes` constructors to Falcon-512. Implemented Seed Blob v2 format with `ORGB` magic, version byte, and embedded tier — v1 remains readable for backward compat, `rotate_blob` migrates v1→v2. Added `#[repr(u8)]` to `MemoryTier` for stable serialization. Added 5 golden vector tests for Seed Blob (structure, round-trip, v1 compat, migration, tamper detection). Remaining: add maximum size limits to downstream parsers, add magic/version to identity blob, golden vectors for remaining formats.

### SDK-004 — Error and panic audit for downstream-facing APIs

- **Status:** Addressed in SDK working tree (unreleased)
- **Impact:** Downstream tools need predictable typed errors and must not inherit avoidable panics from library APIs. This is especially important for a foundation used by many future projects.
- **Evidence:** SDK lint policy allows warnings for `unwrap_used`/`expect_used`; `MemoryTier::argon2_params` uses `expect` after constructing parameters.
- **Recommendation:** Audit every public API for panic conditions, document intentional invariants, and return typed errors where caller-controlled input can reach the path. Keep proven internal invariants explicit where an error is impossible.
- **Required validation:** Fuzz/property tests for all parsers and caller-controlled length/parameter paths.
- **Resolution:** Audited all non-test `unwrap`/`expect` in SDK source. Added fallible variants (`try_generate_nonce`, `try_generate_key`, `XNonce::try_random`, `CNonce::try_random`, `try_sign` on all hybrid signature types, `try_sign_hybrid` on `HybridSigningKeyBundle`, `try_argon2_params` on `MemoryTier`). Panicking variants retained with `# Panics` docs for backward compat. Proven invariants in `siphash` and `error_correction` documented with SAFETY comments. 8 regression tests added.

### SDK-005 — Warning debt obscures release quality signals

- **Status:** Needs SDK review
- **Impact:** Building origin-tools against SDK `0.6.7` emits 25 SDK warnings, including unsafe-code warnings, unused imports, dead NTRU/MMR code paths, and a missing `Debug` implementation. This does not establish a vulnerability, but it makes it harder to distinguish intentional experimental code from accidental defects and weakens downstream CI signal.
- **Evidence:** `cargo check --workspace` from origin-tools at SDK revision `a692cbdcf92799ef9375d6a9e906416103d3aa99`.
- **Recommendation:** Triage the warnings in the SDK repository. Remove dead code, correct unused exports, document or isolate intentional unsafe blocks, and either implement `Debug` for public/internal diagnostic types or explicitly justify the lint configuration.
- **Required validation:** SDK CI should run warning-clean checks for supported targets, with narrowly scoped allows for intentional experimental code.

### SDK-006 — Downstream panic and error-boundary audit (Phase 5)

- **Status:** Addressed in origin-tools working tree (unreleased)
- **Impact:** Downstream crates had several panic-prone paths in production code: silent fallback-zero MAC, `expect()` on CSPRNG failures, `unwrap()` on SystemTime, and missing maximum size limits on format parsers.
- **Evidence:** Phase 5 audit of all origin-tools crates.
- **Resolution:**
  - **CRITICAL: Fixed fallback-zero MAC** in `origin-attest/src/cookie.rs:67`. `hmac_sha3_256().unwrap_or([0u8; 32])` replaced with proper error handling that produces a non-predictable cookie on HMAC failure.
  - **CRITICAL: Replaced `expect()` on CSPRNG** with fallible `Result`-returning APIs in 5 sites:
    - `origin-attest/src/cookie.rs`: `CookieSecret::new()`, `force_rotate()`, `maybe_rotate()` now return `Result`
    - `origin-identity/src/delegation.rs`: `random_nonce()` now returns `Result`
    - `origin-channel/src/handshake.rs`: `random_static_secret()` now returns `Result`
    - `origin-channel/src/commands.rs`: `random_x25519_secret()` now returns `Result`
  - **Fixed `unwrap()` on SystemTime** in 3 sites:
    - `origin-secrets/src/crypto.rs:97`: `unwrap()` → `map_err(Error::CryptoError)?`
    - `origin-attest/src/registry.rs:173`: `unwrap()` → `unwrap_or_default()` (safe fallback to 0)
    - `origin-attest/src/trust.rs:479`: same fix
  - **Added maximum size limits** to 4 format parsers:
    - ORGN envelope: `MAX_PAYLOAD_LEN = 1 GiB`
    - Identity blob: `MAX_BLOB_LEN = 1 MiB`
    - SEAL envelope: `MAX_ENVELOPE_LEN = 4 GiB`
    - OVLT vault: `MAX_VAULT_LEN = 256 MiB`
    - CombinedSignature: Falcon length max 1280 bytes
  - All 345+ downstream tests pass after fixes.

### SDK-007 — Downstream duplicated tier/Argon2 and direct RNG usage

- **Status:** Addressed in origin-tools working tree (unreleased)
- **Impact:** `origin-pass` duplicated tier byte conversion and Argon2 parameter mapping instead of using the SDK's authoritative implementation. 5 crates used `getrandom`/`rand` directly instead of the SDK's `fill_random` API, creating version conflicts (downstream used getrandom 0.3, SDK uses 0.2).
- **Evidence:**
  - `origin-pass/src/vault.rs:106-124`: duplicates `tier_byte`/`tier_from_byte`
  - `origin-pass/src/vault.rs:135-171`: hardcodes Argon2 params mirroring `MemoryTier::argon2_params`
  - `origin-identity/src/delegation.rs:103`: direct `getrandom::fill`
  - `origin-channel/src/handshake.rs:33, commands.rs:23`: direct `getrandom::fill`
  - `origin-attest/src/cookie.rs:36,121`: direct `getrandom::fill`
  - `origin-seal/src/commands.rs:168,259,725`: direct `rand::RngCore`
  - `origin-pass/src/vault.rs:22`: direct `rand::RngCore`
- **Resolution:**
  - **`origin-pass` tier/Argon2 dedup:** Replaced local `tier_byte`/`tier_from_byte`/`parse_tier` with thin wrappers delegating to `origin_common::{tier_to_byte, tier_from_byte, tier_from_str}`. Replaced hardcoded Argon2 params in `argon2id_derive` with `origin_common::argon2_builder(tier, 32)` which reads authoritative params from `MemoryTier::argon2_params`.
  - **RNG migration to SDK `fill_random`:** All 7 direct `getrandom::fill` / `rand::thread_rng().fill_bytes` call sites migrated to `origin_crypto_sdk::fill_random`:
    - `origin-pass/src/vault.rs`: 2 salt generation sites
    - `origin-seal/src/commands.rs`: 4 sites (salt, nonce, base_nonce, random bytes)
    - `origin-identity/src/delegation.rs`: 1 nonce generation site
    - `origin-channel/src/handshake.rs`: 1 X25519 keygen site
    - `origin-channel/src/commands.rs`: 1 X25519 keygen site
    - `origin-attest/src/cookie.rs`: 2 cookie secret sites
  - **Removed direct `getrandom` dependency** from 3 crates: origin-channel, origin-attest, origin-identity
  - **Removed direct `rand` dependency** from 2 crates: origin-pass, origin-seal
  - All 344 downstream tests pass after migration.

## Process

1. Reproduce and validate each item in the SDK repository before filing or fixing it.
2. Prefer an SDK-side API or documentation improvement over an origin-tools workaround.
3. Link the SDK commit/issue/PR here when work begins.
4. Remove an entry only after the SDK change is released or the concern is disproven with evidence.
