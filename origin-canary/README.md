# Origin Canary Embedder

> Steganographic canary-token fingerprinting with **verifiable, hybrid
> post-quantum provenance** — for source-available and fair-source projects.

`origin-canary` is a standalone tool (part of the `origin-tools` workspace) that
embeds unique, per-distribution canary tokens into source code, then builds a
cryptographic chain of custody you can use in court if someone ships your code
without authorization:

```text
embed → manifest (Merkle root)
  └─ sign        → commitment   (hybrid Ed25519 + Falcon-1024, creator identity)
       └─ fingerprint → archive binding (release integrity)
            └─ ledger    (local, publishable public record)
                 └─ evidence  (self-verifying litigation package)
                      └─ ci      (automated gate in your pipeline)
```

No server. No blockchain. No phone-home. All cryptography is underwritten by
[`origin-crypto-sdk`](../../origin-crypto-sdk): **BLAKE3** for all content
hashing, **hybrid Ed25519 + Falcon-1024** for all signing.

## What it does

Origin Canary injects unique canary tokens into source files using multiple
steganographic strategies (variable injection, watermark comments, dead code,
string literals). The tokens look like normal code artifacts. If a project is
later copied or shipped without authorization, you scan the suspect code for
these tokens and — because each token is bound into a signed Merkle commitment —
you can prove *which release* was derived, and *that you authored it*.

Canary tokens are **evidence, not access control.** A determined adversary who
knows the tokens are present can strip them. The value is legal attribution,
not prevention.

## Install

```bash
# Build the workspace
cargo build --release -p origin-canary
./target/release/origin-canary --help

# Or install the binary
cargo install --path . --bin origin-canary
```

Requires Rust 1.97+. `origin-crypto-sdk` is consumed via a workspace path
dependency; for your own builds, point it at the published crate.

## Workflow (all 5 phases)

### Phase 1 — Embed + verify

```bash
# Generate a salt once and keep it OFFLINE.
SALT=$(openssl rand -hex 16)

# Embed canaries into a source tree (writes canary_manifest.json).
origin-canary embed \
  --source ./myproject/src \
  --project-id 42 \
  --distribution-id v1.3.0 \
  --salt "$SALT" \
  --num-canaries 10

# Scan a suspect codebase for those tokens.
origin-canary verify \
  --source ./suspect-codebase \
  --manifest canary_manifest.json
```

`verify` exits 0 if it finds any token, 1 on error. Add `--json` for
machine-readable matches (file, line, token id).

### Phase 2 — Sign the commitment (creator identity)

Keys are managed by the companion `origin-identity` tool (same
`origin-crypto-sdk` blob format — Argon2id-encrypted at `~/.origin/identities/`).
The same seed derives **distinct** signing keys per phase via the signing
domain, so one identity serves commit, fingerprint, and (future) release signing.

```bash
# Create an identity once (offline; passphrase-protected).
origin-identity keygen -n my-studio --passphrase-file ./pass.txt --no-phrase

# Sign the manifest → canary_commitment.json (carries its own verifying keys).
origin-canary sign \
  --manifest canary_manifest.json \
  --identity ~/.origin/identities/my-studio.id \
  --passphrase-file ./pass.txt

# Anyone can verify the signature with NO secret material.
origin-canary verify-commitment --commitment canary_commitment.json
```

`verify-commitment` exits 0 if BOTH Ed25519 and Falcon-1024 signatures pass over
the canonical commitment bytes, 2 if invalid, 1 on malformed input.

### Phase 3 — Fingerprint a release archive

```bash
# Build the release tarball, then bind it to the commitment.
tar czf release-v1.3.0.tar.gz -C ./myproject .

origin-canary fingerprint \
  --manifest canary_manifest.json \
  --commitment canary_commitment.json \
  --archive release-v1.3.0.tar.gz \
  --identity ~/.origin/identities/my-studio.id \
  --passphrase-file ./pass.txt

# Verify the archive later (re-hashes the file; catches modification + truncation).
origin-canary verify-fingerprint \
  --fingerprint canary_fingerprint.json \
  --archive release-v1.3.0.tar.gz \
  --commitment canary_commitment.json

# Publish the fingerprint to a local JSONL ledger (append-only; no network).
origin-canary publish --fingerprint canary_fingerprint.json --ledger ledger.jsonl
```

### Phase 4 — Evidence package + CI gate

```bash
# Assemble a self-verifying litigation package from a suspect tree.
origin-canary evidence \
  --source ./suspect-codebase \
  --manifest canary_manifest.json \
  --commitment canary_commitment.json \
  --fingerprint canary_fingerprint.json \
  --ledger ledger.jsonl \
  --output evidence.json

# CI gate: fail the build if canaries are missing or the chain is broken.
origin-canary ci --source ./myproject/src --manifest canary_manifest.json \
  --commitment canary_commitment.json --min-matches 10 --json
```

`evidence` exits 0 if every link in the chain verifies (`SOUND`), 2 if not.
`ci` exits 0 if the gate passes, **3 if it fails** (missing canaries or broken
commitment binding). `--json` emits one machine-readable line for pipelines.

The evidence package is **self-contained**: it embeds its own Ed25519 +
Falcon-1024 verifying keys, so a third party can verify it without your
identity blob or any secret.

## CLI reference

| Subcommand | Purpose | Exit codes |
|---|---|---|
| `embed` | Embed canaries, write manifest | 0 ok, 1 error |
| `verify` | Scan a tree for tokens | 0 found, 1 error |
| `sign` | Sign manifest → commitment (needs identity) | 0 ok, 1 error |
| `verify-commitment` | Verify a commitment | 0 valid, 2 invalid, 1 malformed |
| `fingerprint` | Bind archive to commitment (needs identity) | 0 ok, 1 error |
| `verify-fingerprint` | Verify fingerprint (vs archive/commitment) | 0 valid, 2 invalid, 1 error |
| `publish` | Append fingerprint to local JSONL ledger | 0 ok, 1 error |
| `evidence` | Assemble litigation package | 0 sound, 2 unsound, 1 error |
| `ci` | CI gate | 0 pass, **3 fail**, 1 error |

Run `origin-canary <subcommand> --help` for the full flag list. Key flags:

- `embed`: `--source/-S`, `--project-id/-p`, `--distribution-id/-d`,
  `--salt/-s`, `--num-canaries/-n` (default 10),
  `--manifest-out` (default `canary_manifest.json`),
  `--strategies` (default `variable.python,variable.javascript,watermark,deadcode.python`).
- `sign` / `fingerprint`: `--identity/-i`, `--passphrase-file/-P`,
  `--tier/-t` (default `standard`), `--output/-o`.
- `verify-commitment` / `verify-fingerprint`: read-only, no identity needed.
- `evidence`: `--source/-S`, `--manifest/-m`, `--commitment/-c`,
  `--fingerprint/-f` (opt), `--ledger/-l` (opt), `--output/-o`.
- `ci`: `--source/-S`, `--manifest/-m`, `--commitment/-c` (opt),
  `--min-matches/-n` (default 1), `--json`.

## Cryptography & security model

- **Hashing**: BLAKE3 for everything — token leaves, Merkle tree, source tree
  hash, archive hash, commitment/fingerprint canonical bytes.
- **Signing**: hybrid **Ed25519 + Falcon-1024** (NIST Round 3 PQC). A
  commitment/fingerprint is valid **only if both** signatures verify over the
  same canonical bytes. Falcon's randomized signing means signature *bytes* vary
  per run, but verification is deterministic.
- **Key derivation**: `HybridSigningKeyBundle::from_seed(seed, domain)` where
  `domain` is `canary-commitment-<project_id>` or `canary-fingerprint-<project_id>`.
  Same seed ⇒ distinct, reproducible keys per phase.
- **Salt**: keep your `--salt` offline. It is the only secret needed to
  *regenerate* tokens for verification; it is never embedded in output.
- **Identity blob**: Argon2id-encrypted at rest (`origin-identity`). The signing
  passphrase is never written anywhere.
- **Manifest**: contains token secrets. Store it as you would a private key.
- **No network**: the binary makes zero network calls. See [GOVERNANCE.md](./GOVERNANCE.md).

## Operational guidance

- Generate the salt with a CSPRNG and store it in a secret manager, not in the
  repo or the manifest.
- Keep `canary_manifest.json` and `canary_commitment.json` private until you
  need to assert authorship.
- Publish `canary_fingerprint.json` + `ledger.jsonl` (verifying keys are public)
  so third parties can independently confirm a release's provenance.
- The evidence package is safe to hand to counsel — it proves the chain without
  disclosing your salt or identity passphrase.

## License

Apache-2.0. Part of the `origin-tools` workspace.
