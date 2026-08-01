# Security Policy — origin-secrets

## Threat model

`origin-secrets` is a threshold secrets-management CLI. Its job is to remove the
single point of failure inherent in a single encrypted vault.

### Assets & protections

| Asset | Confidentiality | Integrity |
|---|---|---|
| Master seed | Split via K-of-N Reed-Solomon (GF(256)); any < K shares reveal nothing | Vault MAC (XChaCha20-Poly1305) + per-share hybrid signatures |
| Vault file | XChaCha20-Poly1305 (origin-crypto-sdk) keyed by Argon2id(passphrase, salt) | Poly1305 tag; tampering is rejected on decrypt |
| Share files | Each share encrypted + signed (Ed25519 + Falcon-1024) | Signature verified at `verify`/`recover`; tampering rejected |
| Audit log | Stored inside the encrypted vault | Append-only; exported as compliance evidence |

### Memory tiers (`--tier`)

| Tier | Argon2id cost | Use |
|---|---|---|
| nano | low | CI / tests only |
| micro | moderate | dev |
| standard | high | default production |
| sovereign | highest | high-value keys |

## What v1.0 guarantees

- **Threshold secrecy**: information-theoretic — fewer than K shares yield no
  information about the master seed (Reed-Solomon erasure code over GF(256)).
- **Post-quantum binding**: every share is signed with a hybrid
  Ed25519 + Falcon-1024 key. Falcon-1024 is NIST-selected PQC; the hybrid keeps
  classical security if either primitive is weakened.
- **Tamper detection**: modification of the vault ciphertext/salt/nonce, or of
  any share's data/signature/recipient, is detected at `verify` and `recover`.
  There is no silent-accept path for corrupted material.
- **No critical bugs** in the v1.0 command surface (verified by unit +
  integration + security tests).

## Known limitations (out of v1.0 scope)

- Transport between custodians is not provided — shares are written to disk and
  must be moved over a secure channel by the operator.
- A passphrase is **mandatory** for every command (supplied via
  `-p/--passphrase-file`). There is no demo default — running without `-p`
  returns `PassphraseRequired`.
- Hardware security modules / secure enclaves are not used for key material.
- A web dashboard (custodian UX, quorum approvals) is planned for v2.0.

## Cryptographic dependencies

All primitives come from `origin-crypto-sdk` (the foundational Origin crypto
crate). `origin-secrets` contains **no raw cryptography** — no hand-rolled
AES, no custom KDF, no bespoke signature code. The SDK pins
`falcon-rust` for Falcon-1024 and uses XChaCha20-Poly1305 + Argon2id.

## Reporting a vulnerability

Do **not** open a public issue for security reports. Contact the maintainer
privately and include: affected version, reproduction steps, and impact. Fixed
releases are tagged and announced via CHANGELOG.

## Disclosure

We follow coordinated disclosure. Verified reports receive a fix in a tagged
release; the reporter is credited (unless anonymity is requested).
