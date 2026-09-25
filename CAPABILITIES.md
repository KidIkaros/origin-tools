# Origin Capability Catalog

`origin-tools` is an internal platform shelf and reference implementation workspace. This catalog is organized by problem so a new project can answer “have I already built this?” without scanning every crate.

## How to choose a capability

1. Prefer a stable platform crate over copying implementation code.
2. Use SDK adapters when the SDK already owns the primitive.
3. Treat persistence and wire formats as explicit compatibility boundaries.
4. Start with the dogfood example and typed library API, not the CLI implementation.
5. If a capability is useful outside this workspace, promote it through:

```text
experiment → reference crate → reusable library → standalone project
```

Stability labels:

- **experimental** — APIs and formats may change freely;
- **reference** — tested and reusable, but not compatibility-stable;
- **stable** — breaking changes require migration notes;
- **frozen** — compatibility is retained indefinitely.

## Identity and signing

- **Recommended:** `origin-common`, `origin-identity`
- **Use for:** shared identity home, encrypted identity seed, child-key derivation, hybrid Ed25519/Falcon signing and verification.
- **Boundary:** identity storage and suite conventions belong to `origin-common`; cryptographic primitives belong to `origin-crypto-sdk`.
- **Status:** stable/reference depending on the specific persisted format.

## Encrypted files and envelopes

- **Recommended:** `origin-seal`, `origin-common::Envelope`
- **Use for:** authenticated file encryption, streaming data operations, signing, verification, hashing, and MAC workflows.
- **Boundary:** SDK owns AEAD/KDF primitives; tools own CLI behavior and versioned file formats.
- **Status:** reference; persisted formats require migration fixtures before being treated as frozen.

## Password vaults and secret stores

- **Recommended:** `origin-pass`, `origin-secrets`
- **Use for:** Argon2id-tiered vaults, TOTP/HOTP/OCRA workflows, K-of-N secret recovery, encrypted shares, and audit trails.
- **Boundary:** `origin-pass` is a suite product; `origin-secrets` is a reference tool. Do not copy their vault or share crypto into a new application.
- **Status:** reference.

## Secret splitting and recovery

- **Recommended:** `origin-shard`
- **Use for:** Reed-Solomon split/recover workflows and typed shard metadata.
- **Boundary:** erasure coding is SDK-owned; shard metadata and CLI/wire compatibility are tool-owned.
- **Status:** stable API, reference formats.

## Integrity proofs and tamper evidence

- **Recommended:** `origin-proof`, `origin-attest`, `origin-provenance`
- **Use for:** MMR roots/proofs, signed attestations, revocation journals, provenance records, and verification reports.
- **Boundary:** proof primitives remain in the SDK where available; application records, journal formats, and verification policy remain in the platform layer.
- **Status:** reference; journal and envelope formats need explicit version migration before frozen status.

## Entropy analysis

- **Recommended:** `origin-entropy`
- **Use for:** Shannon/min-entropy statistics and SDK quality gates.
- **Boundary:** callers provide bounded byte slices; no filesystem or device-stream reads belong in tests or library APIs.
- **Status:** stable/reference.

## Schnorr and zero-knowledge proofs

- **Recommended:** `origin-schnorr`
- **Use for:** deterministic key generation, proving, verification, batch verification, and JSON adaptation.
- **Boundary:** SDK owns EC arithmetic, nonce generation, and public-key derivation; the tool owns typed API/CLI/JSON compatibility.
- **Status:** reference.

## Stealth addresses and derived identities

- **Recommended:** `origin-stealth`
- **Use for:** stealth master keys, indexed address derivation, proof-of-work solving, and verification.
- **Boundary:** SDK owns key derivation and cryptographic primitives; tool owns application representation.
- **Status:** reference.

## Secure channels and network transport

- **Recommended:** `origin-channel`, `origin-network`
- **Use for:** SDK-backed X25519 handshakes, ratchets, authenticated sessions, relay transport, and NAT/QUIC integration.
- **Boundary:** `origin-channel` is the reusable protocol seam; `origin-network` is a product/integration layer. New products should depend on the channel abstraction rather than network internals.
- **Status:** experimental/reference.

## Content-addressed repositories and archives

- **Recommended:** `origin-vcs`, `origin-archive`
- **Use for:** signed content-addressed history, encrypted-at-rest repository data, archive packaging, and transport adapters.
- **Boundary:** repository and archive formats are application-owned; do not assume compatibility without checking the format registry.
- **Status:** experimental/reference.

## Embedded provenance storage

- **Recommended sibling projects:** `origin-db`, then `origin-memory`
- **Use for:** provenance-tagged encrypted multi-table storage and higher-level memory graphs.
- **Boundary:** these are standalone projects, not parent-workspace members. Consume released/Git `origin-tools` foundations, using local path patches only during development.
- **Status:** `origin-db` is a production-shaped prototype (audited 2026-09; correctness/security blockers closed, `QueryEnv` seam, mutation funnel, migration + crash-safety tests — see its `AUDIT.md`; no external audit or scale validation). `origin-memory` remains reference/experimental.

## Browser/WASM bindings

- **Recommended sibling project:** `origin-web`
- **Use for:** browser-side SDK-backed hashing, signing, encryption, sharding, entropy analysis, and password generation.
- **Boundary:** WASM bindings own JavaScript-facing error/serialization behavior; SDK owns cryptography and browser entropy integration.
- **Status:** experimental/reference.
- **Not a pattern:** `origin-web/spike/` is a throwaway wasm feasibility probe that deliberately depends on raw primitive crates. It is not shipped and must not be copied as an example.

## Verification and composition

- **Recommended:** `origin-cross-tests`, crate `examples/dogfood.rs`, and golden-vector tests.
- **Use for:** proving that multiple capabilities compose without relying on private implementation details.
- **Rule:** every promoted reusable crate should have a typed dogfood example and at least one negative-path regression test.
- **Status:** stable process; individual fixtures may be versioned or frozen.
