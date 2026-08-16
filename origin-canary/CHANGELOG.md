# Changelog

All notable changes to `origin-canary` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/); this project adheres to
Semantic Versioning.

## [Unreleased]

### Added — Phases 2–5 (2026-08-16)

- **Phase 2 — Commitment signing.** `sign` derives a hybrid Ed25519 + Falcon-1024
  key bundle from an `origin-identity` blob (domain `canary-commitment-<project_id>`)
  and signs the canonical commitment bytes; `verify-commitment` checks both
  signatures with no secret material. Manifest structural digest (BLAKE3) binds
  the commitment to the manifest without leaking token secrets.
- **Phase 3 — Release fingerprinting.** `fingerprint` binds an archive
  (streaming BLAKE3 over the file) + the signed commitment into a single
  hybrid-PQC fingerprint (domain `canary-fingerprint-<project_id>`); it refuses
  to sign a fingerprint whose commitment/merkle-root doesn't match the manifest.
  `verify-fingerprint` re-hashes the archive and checks the signature chain.
  `publish` appends to a local, append-only JSONL ledger (no network).
- **Phase 4 — Evidence + CI.** `evidence` assembles a self-verifying litigation
  package (found secret → Merkle proof → root → commitment → optional fingerprint
  → optional ledger index); every link is re-checked at assembly and a broken
  link is a hard error. The package carries its own verifying keys, so it is
  verifiable by a third party with no secret material. `ci` is a pipeline gate
  (exit 3 on failure; `--json` for machine output).
- **Phase 5 — Docs, hardening, governance.** README rewritten to match the real
  CLI; added `GOVERNANCE.md` (no-network / stability / sunset / reproducibility
  policy), this `CHANGELOG.md`, `--version` flag, and a reproducibility test that
  asserts the no-network guarantee and byte-stable canonical commitment bytes.

### Verification status
- 57 tests green (3 Merkle + 10 commitment + 16 fingerprint + 9 evidence + 19
  integration).
- `cargo clippy -p origin-canary` clean; full workspace builds clean.
- Live end-to-end exercised: keygen → embed → sign → verify-commitment →
  fingerprint → verify-fingerprint → publish → evidence (SOUND) → ci (pass/fail).

## [0.1.0] — 2026-08-16

### Added — Phase 1
- Multi-strategy steganographic embedding (variable injection, watermark,
  dead code, string literal) with language templates.
- Deterministic per-distribution token generation from
  `project_id + distribution_id + salt + index`.
- BLAKE3 Merkle tree commitment over embedded tokens (level-walk proof
  generation; correct for odd leaf counts).
- `embed` / `verify` subcommands with JSON output.
- 19 integration tests covering edge cases (large files, UTF-8 truncation,
  subdirectory scans, negative scans).
