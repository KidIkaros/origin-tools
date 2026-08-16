# Governance & Stability Policy

This document is binding on `origin-canary` releases. It exists so adopters can
reason about trust, lifecycle, and supply-chain behavior.

## 1. No network, no telemetry, no blockchain

`origin-canary` is **fully offline by construction**:

- It makes **zero network calls** — no DNS, no sockets, no HTTP, no phone-home,
  no update checks, no analytics.
- It uses **no blockchain, no token, no on-chain registration** anywhere in its
  core or optional flows.
- All provenance artifacts (manifest, commitment, fingerprint, ledger,
  evidence package) are **local files**. `publish` writes to a local JSONL file
  you can host anywhere; the tool never uploads.

Verification: the crate has no `reqwest`/`hyper`/`ureq`/`curl`/tokio-network
dependency and no `TcpStream`/`UdpSocket`/`.connect()` call in `src/`.

## 2. CLI flag & format stability

- **Stable (won't break within a MAJOR version)**: all subcommand names
  (`embed`, `verify`, `sign`, `verify-commitment`, `fingerprint`,
  `verify-fingerprint`, `publish`, `evidence`, `ci`), their short/long flags,
  and JSON output schemas (manifest, commitment, fingerprint, evidence, ledger).
  Adding new JSON *fields* is non-breaking; reordering or removing fields is a
  MAJOR bump.
- **Exit codes** are part of the contract and will not change within a MAJOR:
  `0` = success/valid/pass, `1` = operational error (bad input, missing file),
  `2` = verified-invalid (commitment/fingerprint/evidence unsound),
  `3` = CI gate failed.
- A breaking CLI/format change requires a **MAJOR** version bump and a migration
  note in `CHANGELOG.md`.

## 3. Cryptography policy

- **Hashing**: BLAKE3 for all content. **Signing**: hybrid Ed25519 + Falcon-1024
  (both signatures required). These are fixed and will not be downgraded (e.g.
  no AES-GCM, no single-algorithm signature).
- When a primitive is deprecated (e.g. Falcon-1024 superseded), the new algorithm
  is added as an *additional* signature layer under a new signing domain; old
  signatures remain verifiable until a MAJOR bump with a sunset window (§5).

## 4. Reproducible builds

- Pin exact dependency versions (Cargo.lock is committed in the workspace).
- Release binaries are built from a tagged commit; `origin-canary --version`
  prints the semver. Record the version string alongside any published artifact
  so a verifier can reconstruct the toolchain.
- To reproduce: checkout the tag, `cargo build --release -p origin-canary`,
  compare `sha256sum` against the published checksum in the release notes.

## 5. Sunset / deprecation policy

- A feature is deprecated via a MAJOR bump + `CHANGELOG.md` entry + a minimum
  6-month grace noted in the release.
- Deprecated signing domains remain verifiable for the grace window; after it,
  verification of old artifacts is best-effort and documented, never silently
  dropped.

## 6. Scope & relationship to origin-tools

`origin-canary` is a **foundational crate** in the `origin-tools` workspace — a
starter pack creators run locally. It is **not** a hosted service, platform, or
daemon, and `origin-tools` as a whole is a set of libraries/CLIs, not a suite we
operate. Creator autonomy is paramount: identity, secrets, and commitments are
yours; the tool only signs what you ask it to.

## 7. Reporting

Security issues: report privately to the maintainers (see repository SECURITY
policy). Do not open public issues containing salts, manifests, or identity
blobs.
