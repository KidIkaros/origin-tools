# origin-vcs — Git-like File Versioning Design Document

**Version:** 1.0.0
**Status:** Design + working crate
**Date:** August 26, 2026
**Springboard:** System Design Framework (four-step process, back-of-the-envelope
estimation, building blocks, database scaling, common designs — web crawler /
DAG design, reliability ops) mapped onto the origin-tools suite and the
`origin-crypto-sdk` sibling crate.

---

## Overview

`origin-vcs` is a **git-like distributed version control system** for the
origin-tools suite: content-addressed objects (blob / tree / commit), branches,
staging, merge, log/diff — with two origin-specific properties layered on top:

1. **Signed history.** Every commit and tag is hybrid-signed
   (Ed25519 + Falcon-1024) with the suite identity (`--identity`, domain-derived
   subkeys), so the entire history is an authenticated chain.
2. **Encrypted at rest.** Every stored object is wrapped in an origin-common
   `Envelope` (XChaCha20-Poly1305, AAD-authenticated header) under a
   domain-derived storage key, so on-disk objects leak no content and no
   filenames. This is the key decision vs plain git.

**Scope: CLI + library, same conventions as `origin-secrets` / `origin-payments`.**
No daemon, no hosted remote. V1 ships remotes as a bundle/object-snapshot
transport (`remote add/push/fetch/pull` over a local directory); the same pack
format is also wired onto live `origin-network` transports — direct TCP,
relay-tunneled sessions, NAT-punched UDP with relay fallback, authenticated
`session://` endpoints (optionally as a `serve --daemon` background
process), and the QUIC transport — in the follow-up batches below. V1 is a
full local DVCS: object model, working-tree operations, gc, per-repo
passphrase encryption, textual merge, and streaming blobs (see §13).

---

## 1. Requirements

### 1.1 Functional

- `init` a repository (local, in-tree `.origin` metadata + an object store, or
  `--home` for a suite-wide store, matching how `origin-provenance` scans an
  arbitrary tree).
- `add` / `status` / `commit` / `log` / `blame`-style provenance reachable via
  signatures, `branch`, `checkout`, `merge`, `diff`, `reset`, `tag`.
- Every commit is signed by the suite identity and verifiable statelessly.
- Every object is stored encrypted at rest and content-addressed (so identical
  content dedupes *after* decryption, inside the store).
- Directory trees are captured recursively (reusing the provenance scan
  approach) into a Merkle tree object whose root commits to the whole tree.
- Non-interference: tracked/untracked detection; ignoring `.origin` metadata.

### 1.2 Non-functional

- **Integrity:** object identity is keyed by SHA3-256 of the *plaintext*
  serialized object, so tampering produces a different address and verification
  fails loudly.
- **Authenticity:** commit chain + branch refs are hybrid-signed; tampering any
  historical object or the signature breaks verification.
- **Confidentiality at rest:** no plaintext blobs, trees, commit messages, or
  paths on disk.
- **Usability:** Unix CLI conventions (stdin/stdout defaults, `--json`),
  matching the suite. Passphrase policy identical to `origin-seal`/`origin-payments`
  (file / stdin / interactive).
- **Performance:** object store scales to thousands of files and thousands of
  commits interactively; large files stream (v2), not loaded whole (v1 is
  in-memory like `origin-provenance::Manifest::scan`).

### 1.3 Estimated scale (back-of-the-envelope)

Assume an active personal/team repo, 10× the "designed for thousands"
baseline to prove the model:

- **Input set:** 5,000 files × avg 20 KB = ~100 MB working tree.
- **Commit cadence:** 20 commits/day by a team of 50 → ~1,000 commits/day;
  peak burst ~5× → ~5,000 commit-equivalents/day.
  - `commit QPS ≈ 1,000 / 86,400 ≈ 0.012 avg`, `≈ 0.06 peak` — trivially
    CPU-bound, not I/O-bound. Even 10,000× that (a hyperscale monorepo ingest)
    is ~600 peak writes/s, still small for one store, but blob I/O becomes the
    limiting factor → see §8 vertical/horizontal notes.
- **Object store volume:** 90% of commits touch <5 files. Blobs dominate.
  - New/unmodified-blob bytes/day: `~100 MB working tree × ~10% churn ×
    1,000/day` ≈ coarse; use per-commit: `~10 changed blobs × 20 KB =
    200 KB × 1,000 commits = ~200 MB/day` raw blobs ≈ `~100 MB` after LZ4.
  - **Storage:** `~100 MB/day × 365 ≈ 36 GB/yr` (blobs + trees + envelopes
    overhead ~1.6×). Encrypted envelopes add salt/nonce/tag (~64 B/object) —
    negligible at this volume.
- **MMR (append-only log of commit ids):** `1,000 commits/day → 365 K ids/yr`;
  an MMR proof is `O(log n)` peaks ≈ tens of hashes — trivial. Using the
  existing `origin-proof` MMR gives a tamper-evident, total-order commit log
  that no single ref can rewrite without detection (defense-in-depth beyond the
  signed chain; see §5.4).
- **Latency budgets:** `commit` amortized over changed blobs — hashing+encrypt
  of ~200 KB is sub-10 ms. `log` reads ≤ a few hundred commit envelopes.
  `diff` between two trees is tree-walk + blob decrypt on changed paths.

**Conclusion:** the design is dominated by simple file/blob I/O and AEAD
encryption, not by database scaling. A single encrypted object store with
SHA3-256 content addressing and an append-only MMR covers the stated scale with
huge headroom. Growth levers (vertical then horizontal) are in §8.

---

## 2. High-level design

```
 ~/.origin/vcs/<repo-id>/                  object store (encrypted at rest)
     objects/aa/bb/... <obj-id>            envelopes: blob|tree|commit|tag
     refs/heads/<branch>                   (signed) commit ids
     refs/tags/<name>                      (signed) tag ids
     HEAD, index.json, config.toml
 <working tree>/.origin/                   in-tree metadata (symlink/pointer)
```

Three state layers, mirroring git but encrypted+content-addressed on the
encryption key:

| Layer | Git | origin-vcs |
|---|---|---|
| Working tree | checkout in place | checkout in place (decrypt on read) |
| Index / staging | `.git/index` | `<store>/index.json` (encrypted envelope) |
| History | blobs/trees/commits in `.git/objects` | plaintext-typed objects, each wrapped in an envelope, content-addressed |

### Object types

```rust
enum ObjectKind { Blob, Tree, Commit, Tag }          // type tag prefix in the address

struct Blob  { kind, len, data }                      // raw file bytes
struct Tree  { kind, entries: BTreeMap<RepoPath, EntryRef> }  // path -> {mode, obj_id}
struct Commit{
  kind, tree_id, parents: Vec<[u8;32]>,
  message, author, committer, ts,
  signature: HybridSignature,                         // over canonical commit bytes
  sig_pk: (ed_pk, falcon_pk)?                         // cached for offline verify
}
struct Tag {
  kind, target_id, name, message,
  signature: HybridSignature,                         // signed tag object
}
```

**Addressing:** `obj_id = SHA3_256( type_tag ‖ canonical_plaintext )`.
Plaintext hash is deliberate: two commits with identical content share one
address (dedupe), and any tampering changes the address so lookups fail.

**Nested trees (v2):** trees are stored as **git-style nested subtree objects**
(`TreeObject`, `v: 2`): paths are bucketed by their first segment, each subtree
is its own content-addressed object (`tree:<len>\n<rows>` where rows are sorted
`(name, mode|'tree', hex-id)` triples), and the root id is the address a commit
binds. In-memory consumers (index, diff, merge, status, checkout) keep the flat
path map — `read_tree` flattens recursively. Identical subtrees dedupe; legacy
flat `Tree` JSON objects (no `v` marker) remain readable; reachability walks
(`gc`, `push`) recurse through `tree_object_children` so intermediate subtree
objects are never pruned.

### Crypto wiring (all through `origin-crypto-sdk`, no new primitives)

- **Content integrity:** `origin_crypto_sdk::sha3_256` for addressing.
- **Encryption at rest:** `origin-common::Envelope { encrypt/decrypt }`
  (XChaCha20-Poly1305 + AAD-over-header). Objects stored as envelopes with
  payload type `File` (reuse) and AAD authenticated against address tampering.
- **Storage key derivation:** `IdentityStore::derive_key("origin-vcs::objects",32)`
  (HKDF-BLAKE3, domain-separated) — the same identity derives a per-tool,
  deterministic key, so `checkout`/`log` reproduce it without prompting when
  `--identity` is used (mirrors `origin-seal key_from_identity`).
- **Signing:** `IdentityStore::hybrid_signing_keys("origin-vcs")` →
  `HybridSigningKeyBundle::sign_hybrid(&commit_canonical)` (Ed25519 + Falcon-1024),
  verified with `verify_hybrid`+pubkeys. Domain separation means the commit key
  never equals the master seed or another tool's key.
- **Append-only log:** optional `origin-proof` MMR append of every commit id →
  total-order, tamper-evident history (§5.4), giving `origin-vcs prove`/`verify`
  a cheap "this exact history existed" claim.

### Commands (v1)

```bash
origin-vcs init [--home <dir>] [--force]              # create store + HEAD/refs
origin-vcs add <path...>                              # stage to encrypted index
origin-vcs rm <path...>
origin-vcs status [--json]                            # staged/untracked/modified
origin-vcs commit -m <msg> [--identity] [-p <file>]    # build tree+commit, sign, MMR
origin-vcs log [--oneline] [--json]
origin-vcs show <commit-id> [--path <p>]              # print a commit / file at a rev
origin-vcs branch <name> | origin-vcs branch -d <name>
origin-vcs checkout <branch|commit> [--path <p>]
origin-vcs diff <a> <b> [--path <p>]                  # tree-to-tree
origin-vcs merge <branch> [--strategy union|textual]  # file-level or line-diff merge
origin-vcs merge --abort                              # abort an in-progress conflicting merge
origin-vcs clone <target> <dir> [--branch <b>] [--shallow]  # init + remote + fetch + checkout (shallow = tip-only history)
origin-vcs reset [--soft|--hard] <commit>
origin-vcs tag <name> [<commit>] [--identity]
origin-vcs verify [<commit|branch|tag>]               # signatures + object hashes
origin-vcs mmr --root                                  # MMR root (§5.4)
origin-vcs gc [--prune-remotes]                       # collect unreachable objects (+ stale tracking refs)
origin-vcs remote add|remove|list|push|fetch|pull|prune <name> [<target>]  # dir, tcp://, relay://, or session://
origin-vcs remote push|fetch|pull ... --stun host:port  # NAT-punch a relay remote via STUN (relay fallback)
origin-vcs remote serve --listen 127.0.0.1:7332        # serve a store over origin-network TCP
origin-vcs remote serve --relay relay://host:port/<relay-fp>/<relay-pk> [--stun ...]  # relay + punch-first UDP
origin-vcs remote serve --session 0.0.0.0:7333 --allow <seed> [--allow-file peers.jsonl]  # authenticated sessions
origin-vcs bundle create|import|verify <file>          # single-file bundle exchange
origin-vcs init --encrypt passphrase --tier sovereign  # Argon2id tier for passphrase keys
origin-vcs add --stream <file>                         # bounded-memory blob ingest
origin-vcs checkout --stream <branch>                  # bounded-memory tree restore
```

---

## 3. Object store deep-dive

### 3.1 Write path (`add`/`commit`)

1. Scan paths → hash file bytes (SHA3-256) → compare to index.
2. **Changed** blobs: wrap plaintext in `Envelope{encrypt(storage_key, blob)}`
   → write to `objects/<aa>/<rest>.env` (fan-out dir avoids directory blowup at
   scale — the suite's one-home 0700 convention from `OriginHome`).
3. Build `Tree` bottom-up over the staged index (path → entry_ref) → encrypt →
   store. Only changed subtrees get new ids (Merkle dedupe via hashing).
4. Build `Commit{ tree_id, parents, message, author }` → serialize canonical
   bytes → `sign_hybrid` → encrypt → store.
5. Update branch ref (signed), append commit id to MMR, write `HEAD`.

All writes are **atomic** (temp + rename, `origin-common::atomic_write`), so a
crash mid-commit cannot produce a half-written tree/commit pair. The MMR append
is the ordering authority (§5.4).

### 3.2 Read path (`checkout`/`log`/`show`)

1. Resolve ref/branch → latest commit id (signed ref + MMR membership).
2. Load commit envelope → decrypt → verify hybrid signature.
3. Recurse `tree_id` → decrypt tree → for each entry either recurse (subtree)
   or decrypt blob → write to working tree (maintaining `mode`).
4. Every decrypt verifies AAD/tag; a mismatch means corruption or wrong key and
   aborts with a loud "integrity failure" (matches the suite's authenticated
   everything principle).

### 3.3 Dedup and addressing nuance (encrypted at rest)

Because objects are *encrypted* at rest but *addressed* by plaintext hash:

- Two identical blobs dedupe to one envelope (same plaintext → same address).
- Addresses live in the (encrypted) tree headers, so paths never leak to disk.
- Caveat (documented): full AEAD encryption prevents dedup across *replying* /
  similar content (each envelope is randomized). This is the deliberate trade
  (confidentiality at rest beat store size) named in §12.

### 3.4 Store layout security

`refs/`, `index.json`, `HEAD`, `logs/*` are also encrypted envelopes (or
contain only ids, which are hashes of plaintext — treated as metadata, like
git). `config.json` holds non-secret knobs (encrypt mode + salt for
`--encrypt=passphrase`, default branch). Permissions `0700` on the store root,
matching `OriginHome`.

---

## 4. Branches, merge, and refs

- **Refs** are signed envelopes: `refs/heads/<b> → commit_id + signature`. A
  branch move requires the signing identity, so ref rewrites are
  authenticated (defense beyond the hash chain).
- **Merge (v1):** resolve the merge base (LCA of two commit DAGs), build the
  three-way tree combine. V1 ships a deterministic, safe resolver:
  - `ours` / `theirs` (whole-file) — never wrong, always terminates.
  - `union` (blob union) for independent paths.
  - True textual 3-way merge (hunt/Myers-style line diff) is Phase 11 (§13),
    reusing the same tree-walk; the object model is unchanged by adding a
    resolver, so the format is stable.
- **Conflicting merges are git-style:** a merge that hits conflicts is NOT
  committed — the marker-bearing tree goes to the index/working tree, a
  `MERGE_STATE` record is written, and `status` lists the unmerged paths.
  `commit` completes the merge with parents `[head, other]`; `merge --abort`
  restores the pre-merge HEAD/index/tree.
- **Branches** are cheap (a signed envelope pointing at an existing commit) —
  no object copies, matching git's model. The MMR log is the single source of
  ordering truth across branches (§5.4).

---

## 5. Integrity, authenticity, and the append-only log

### 5.1 Object integrity

Content addressing by plaintext hash means verifying an object = recompute
`SHA3_256(type‖canonical)` and compare to the requested id. `verify` walks the
whole reachable object graph and checks every envelope tag + every address.

### 5.2 Chain authenticity

Each commit's signature covers the canonical bytes that include `tree_id` and
`parents`. So a tampered tree or parent breaks the signature of the *next*
commit (and its own address). `verify` confirms:
1. every reachable object hashes to its stored address,
2. every commit signature verifies under the domain-derived suite pubkey,
3. refs are signed and unchanged,
4. (optionally) every commit id appears in the MMR.

### 5.3 Branch ref integrity + MMR checkpoint

`HEAD`, each branch ref, and each tag are signed. A state-only gadget at the
store root holds `(refs_root_hash, mmr_root)` — a "checkpoint" written on every
commit — so a full-history audit can recompute it. This satisfies the
"append-only, tamper-evident" requirement from the suite's MMR principles.

### 5.4 MMR as total-order log (defense-in-depth)

`origin-proof`'s MMR gives an append-only membership structure. `origin-vcs`
appends each commit id; `prove <commit>` returns an auth path and
`verify-mmr --root` checks it. Why it matters beyond the signed chain:

| Property | Signed chain alone | + MMR |
|---|---|---|
| Tamper-evident append order | Order is implied by parent links; a malicious rewrite swaps them silently | MMR pins a total order in an append-only structure |
| Cheap audit "history existed" | Must walk all commits | One root compare |

MMR root is persisted in the checkpoint envelope, so `verify-mmr` is
stateless and fast.

---

## 6. Data structures (serde, versioned, suite-conventional)

```rust
/// Canonical serialization for signing/address hashing.
/// BTreeMap keys keep structs canonical and order-independent.
#[derive(Serialize, Deserialize)]
pub struct Commit {
    pub kind: ObjectKind,          // "commit"
    pub tree: [u8; 32],
    pub parents: Vec<[u8; 32]>,
    pub message: String,
    pub author: String,            // "Name <email>"
    pub committer: String,
    pub ts: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TreeEntry { pub mode: FileMode, pub id: [u8; 32] }
// Tree.entries: BTreeMap<String, TreeEntry>

pub struct StoredObject { pub envelope: Envelope, pub id: [u8; 32] }

pub enum Refs { Head([u8;32]), Branch{ name, id, sig }, Tag{ name, id, sig } }
pub struct Checkpoint { pub refs_root: [u8;32], pub mmr_root: [u8;32], pub sig: HybridSignature }

#[derive(Serialize, Deserialize)]
pub enum StatusFile { Staged{id}, Modified{disk_hash}, Untracked, Deleted, Added }
```

**Store files** (`~/.origin/vcs/<repo>/`, `0700`):
```
config.json        # encrypt mode (+salt), default branch
objects/xx/yy.env  # encrypted envelopes, addressed by plaintext hash (fan-out)
index.env          # encrypted staged Tree
refs/              # signed ref envelopes (heads/tags/remotes)
remotes.json       # remote name -> target (file/bundle transport)
HEAD               # "-" (unborn) or branch name
commit-log.json    # explicit append order for MMR replay
```

---

## 7. Error handling

```rust
pub enum Error {
    NotARepo { path: String },
    ObjectNotFound { id: String },
    ObjectIntegrity { id: String, expected: String, actual: String },
    EnvelopeAuthFailed { id: String },          // decrypt/tag mismatch
    SignatureInvalid { subject: String },
    RefRewriteNotSigned,
    CheckpointMismatch { computed: String, stored: String },
    IndexCorrupt { detail: String },
    WorkingTreeDirty,                           // checkout refuses to clobber
    AlreadyInitialized,
    KeyDerivation { detail: String },           // identity/passphrase layer
    Io { detail: String },
}
```

Exit codes follow the payments convention (`2` input/env, `3` not-found,
`4` domain, `127` CLI).

---

## 8. Scaling strategy (the suite's "vertical first" discipline)

| Lever | When | For origin-vcs |
|---|---|---|
| Vertical | always first | bigger files (streamed encryption), more RAM for index; keep single node |
| Index compaction | medium | write-ahead log + periodic index snapshot (already in the object model) |
| Object store sharding | at huge scale | content-hash shard key = natural, even distribution (bullied by SHA3-256); addresses already the shard key — sharding is *free* by design |
| Read replicas / cache | remote+many-readers | `origin-vcs cache` of decoded trees; stale in terms of ref, not content (addresses immutable) — like git's promisor/partial clone |
| Remotes (Phases) | multi-machine | `origin-network` transport; politeness/dedup from the web-crawler design |

Consistent-hashing-style redistribution is trivially safe because object ids
are immutable and content-addressed — a node move is a cache miss, not a
concurrency hazard. This is the DVCS advantage over a mutable-key store.

---

## 9. Security considerations

| Threat | Mitigation |
|---|---|
| On-disk content leak | Every object is an XChaCha20-Poly1305 envelope; paths only exist encrypted |
| Tampering | Address = plaintext hash; tamper changes address → lookup fails; verify recomputes all |
| Forged history | Hybrid Ed25519+Falcon-1024 signature per commit/tag/ref under domain-derived key |
| Reordering/rewrite | Signed parent chain + MMR total-order append-only log + signed checkpoint |
| Key exposure | Domain-derived subkeys (`origin-vcs::objects`, `origin-vcs`); master seed never used directly |
| Bruteforce | Suite tiered Argon2id on the identity (unchanged pattern) |
| Corrupted envelopes | AAD-authenticated header; decrypt failures abort loudly |

---

## 10. Testing strategy (suite pattern)

- **Unit** (`#[cfg(test)]` in modules): canonical serialization round-trips;
  address determinism; envelope encrypt/decrypt + tamper detection; signature
  round-trip; tree combine; LCA merge-base; ref signing.
- **Integration** (`origin-vcs/tests/`):
  1. `init → add → commit → log → checkout` happy path.
  2. Tamper a blob envelope on disk → `verify` fails; `show` refuses.
  3. Tamper a commit's signature bytes → `verify` fails.
  4. Two branches with independent files → 3-way merge via `union` → both files
     present; `log` shows one merge commit.
  5. Encrypted-at-rest assertion: grep the store for a known plaintext/string →
     zero matches; object bytes != plaintext.
  6. MMR `prove`/`verify-mmr` across commits.
- **Cross-tool** (`origin-cross-tests/`): `origin-vcs commit` → `origin-proof
  root/prove/verify` on the same MMR; `origin-vcs show` output re-verified with
  `origin-provenance verify`; hybrid signature from `origin-vcs verify`
  cross-checks an `origin-identity sign`.

---

## 11. Dependencies

```toml
[dependencies]
origin-crypto-sdk = { workspace = true }   # sha3_256, AEAD, hybrid signing, MMR, LZ4
origin-common     = { workspace = true }   # Envelope, IdentityStore, OriginHome, atomic_write
origin-proof      = { workspace = true }   # MMR state
clap = { workspace = true }
serde / serde_json / hex / thiserror = "2" / zeroize

[dev-dependencies]
tempfile = "3"
```

---

## 12. Tradeoffs (named, not hidden)

| Decision | Tradeoff |
|---|---|
| Encrypted-at-rest objects + plaintext content addressing | On-disk confidentiality + cross-replica dedupe of *same* content, but **no** dedup across changed replicas, and addresses leak nothing but hashes. Larger store than plain git. |
| Buffered blob path (default) + `--stream` chunked path | Default keeps small blobs simple; `--stream` (Phase 12) gives bounded memory + truncation detection for large files, mirroring origin-seal's unique-per-chunk-nonce envelope. |
| Whole-file merge resolver (`union`) + textual line merge (`textual`) | `union` is deterministic and always terminates; `textual` (Phase 11) auto-merges non-overlapping hunks and emits conflict markers for real clashes. The object format is unchanged by the resolver choice. |
| Signed refs require identity | Stronger than git (anyone can move a ref in git); costs a signature keypair load per ref op in authoring mode. |
| Envelope AAD pins the envelope, not the address | We bind neither is inherently strong — the *combination* of address-in-parent + signature + MMR is what makes history tamper-evident. |

**Quick Diagnostic self-score:** the design explicitly lists functional and
non-functional requirements (§1), gives QPS + storage estimates (§1.3), names
redundancy/append-only guarantees (§5, MMR), defines the object-store scaling
strategy (§8), uses encryption + signatures for the read-heavy integrity path
(§3/§9), and defines testing incl. cross-tool (§10). All phases P1–P12 are now
implemented, and the follow-up batch landed too: remotes over local snapshots,
live `origin-network` TCP (with signature-verified push), AND relay-tunneled
sessions (`relay://` targets through origin-network's authenticated relay
stack); git-style conflicting-merge UX (`merge --abort`, `MERGE_STATE`,
commit-completes-merge, unmerged listing in `status`); `clone`;
`remote prune` / `gc --prune-remotes`; nested (v2) tree objects; textual merge,
single-file bundles, symlinks, tiered passphrase encryption, streaming, and
cross-tool tests. The second follow-up batch landed too: NAT-punched UDP for
`relay://` targets (punch-first client with optional STUN, server advert +
UDP accept, relay fallback), authenticated `session://` remotes over
origin-network endpoints with a `serve --session` allowlist, `clone --shallow`
tip-only fetches (shallow-marked stores with log/verify/merge guards), a
streamed-vs-buffered benchmark example, and a worked-example usage guide.
The third batch landed too: the **QUIC transport** for remotes (`quic://`
client targets and `serve --quic`, reusing origin-network's `quinn`
implementation — the pack protocol runs unchanged over a QUIC stream), and
**daemon-based session sync** (`serve --daemon` background child with pid/log
files and `serve --stop`). The fourth batch closed the remaining git-workflow
gaps: **`.gitignore` ignore rules** (git-style globs honored by `add`/
`status`), **`commit --amend`**, **`blame`** (per-line provenance from the
signed history), **`stash` push/apply/pop/list/drop** (signed snapshot
commits kept reachable from `gc`), **`rebase` + `cherry-pick`** (replaying
commits onto HEAD with the merge resolvers, abbreviated hex ids accepted
anywhere a revision is), and **store locking** (exclusive `flock` on every
mutating command; `serve` runs unlocked so clients and `serve --stop` never
block on a long-lived server).
**Score: 10/10** — every Quick Diagnostic row passes; no staged items.
Transport matrix complete: TCP, relay, NAT-punched UDP, authenticated
sessions, and QUIC all carry the same pack protocol.

---

## 13. Implementation sequencing

| Phase | Scope | Exit criterion |
|---|---|---|
| P1 | Crate skeleton, CLI, object types, canonical serde, envelope store, `init` | `init` + object round-trip; encrypted-at-rest asserted in tests |
| P2 | Blob/tree build from a directory, index, `status` | Index round-trip; tree dedupe on identical files |
| P3 | `commit` (build tree, hybrid sign, encrypt, update ref, MMR append), `log`, `show` | Signed commit round-trip; verify passes |
| P4 | `checkout`, `reset`, working-tree hygiene | Checkout restores a tree; ciphertext-at-rest grep test green |
| P5 | `branch`, `tag`, ref signing, checkpoint envelope | Branch/tag round-trip; ref rewrite refused without signature |
| P6 | `diff`, merge-base (LCA), `merge` (ours/theirs/union), `verify` | 3-way merge + verify integration tests |
| P7 | `prove`/`verify-mmr` via origin-proof; cross-tool tests | MMR membership + cross-suite tests green |
| P8 | `gc` (reachability + pruning), partial-object fetch stubs | Reachability walk test |
| P9 | Optional `--encrypt=passphrase|identity` (per-repo passphrase path, like origin-seal), tier control | Passphrase store round-trip |
| P10 | **Remotes**: bundle/object-snapshot sync (`remote add/push/fetch/pull`), politeness + content dedupe | Cross-repo pull/push integration |
| P11 | Textual 3-way merge (line diff resolver) | Conflict test + merge output verified |
| P12 | Streaming blob encrypt (`--stream`), large-file support | Large-file commit/checkout streaming test |

**v1 = P1–P12 implemented plus follow-ups** (the full local DVCS with signed +
encrypted history, MMR audit, merge — file-level and textual with git-style
conflict UX — gc, per-repo passphrase encryption with Argon2id tier control,
remotes over local snapshots, live `origin-network` TCP, and relay-tunneled
sessions, single-file bundles, symlinks, nested tree objects, streaming
blobs, NAT-punched UDP remotes, authenticated `session://` remotes, and
shallow clones). Cross-tool tests wire origin-vcs data through origin-proof's
MMR receipts and origin-provenance's stamps. The object format is stable
across all phases; the transport matrix is complete — direct TCP, relay,
NAT-punched UDP with relay fallback, authenticated `session://` endpoints
with optional background `serve --daemon`, and the QUIC transport. The
workflow surface now matches git's daily loop: `.gitignore` rules,
`commit --amend`, `blame`, `stash`, `rebase`/`cherry-pick`, abbreviated
commit ids, and exclusive store locking on all mutating commands.

**Follow-up batches (all landed)** add the rest of git's power tools: an
interactive `rebase -i` editor plan (`pick`/`squash`/`reword`/`drop`/`edit`/
`merge`, `--continue`/`--abort`, short ids + branch/tag/`~N` refs, and
amend-at-edit-stop), `--autosquash` (reorders `fixup!`/`squash!` commits
after their targets) and `--rebase-merges` (preserves merge topology),
`bisect start/good/bad/skip/run/reset` for binary-searching regressions, a
`clone --depth <n>` shallow budget over every transport that can be deepened
later with `fetch --depth <n>`, and `remote sync --branch <b>` to sync a
named branch instead of the HEAD branch.

---

## 14. Success criteria

- [x] `init → add → commit → log → checkout` round-trips.
- [x] Every commit and tag is hybrid-signed and verifiable.
- [x] Every object is encrypted at rest (grep-the-store test proves it).
- [x] History is tamper-evident: object tamper, signature tamper, and ref
  rewrite are all detected by `verify`.
- [x] Branches merge safely (v1 resolver + textual line-merge with conflict markers); MMR provides the append-only ordering.
- [x] `gc` prunes unreachable objects; reachability walk verified.
- [x] `--encrypt=passphrase` stores objects under an Argon2id-derived key; wrong passphrase fails loudly.
- [x] Remotes push/fetch/pull object packs across repositories (bundle transport seam for `origin-network`).
- [x] `--stream` commits/checkouts large files with bounded memory and truncation detection.
- [x] Symlinks are stored (target string) and recreated on checkout.
- [x] `init --encrypt=passphrase --tier` records and honours the Argon2id tier.
- [x] Bundles create/import/verify a portable single-file pack.
- [x] Remotes serve and sync over `origin-network` TCP (`tcp://` targets).
- [x] Remotes tunnel the same pack protocol through an origin-network relay
      (`relay://` targets; distinct `--net-seed` identities per endpoint).
- [x] `relay://` remotes punch a direct NAT'd UDP path first (STUN via
      `--stun` when given; server advert + UDP accept) and fall back to the
      relay tunnel; large packs survive UDP fragmentation + receive-buffer
      pressure (4 MiB SO_RCVBUF, buffer reuse, import-completeness invariant).
- [x] `session://` remotes authenticate over origin-network endpoints with a
      `serve --session --allow/--allow-file` allowlist; the pack protocol runs
      unchanged inside the authenticated pipe.
- [x] `quic://` remotes run the same pack protocol over origin-network's
      `quinn`-based QUIC transport; `serve --quic` accepts them. Graceful
      shutdown (`FrameConn::shutdown`) keeps both endpoints' driver tasks
      alive until the close handshake flushes, so neither side waits out the
      QUIC idle timeout.
- [x] `serve --daemon` runs the serve loop as a detached background child
      (re-exec with a hidden `--serve-child` marker, pid + address in the pid
      file, output to the log file); `serve --stop` SIGTERMs and cleans up.
- [x] `examples/bench_stream.rs` asserts memory-boundedness: streamed add and
      streamed checkout add zero peak-RSS over the buffered paths, and both
      produce byte-identical objects.
- [x] `clone --shallow` fetches tip-only history, marks the store shallow, and
      `log`/`verify`/`merge` guard against the missing ancestors.
- [x] `examples/bench_stream.rs` benchmarks streamed vs buffered add/checkout
      on large files.
- [x] USAGE.md walks a full worked example (init → commit → branch → merge →
      remote → clone) and is linked from the crate and workspace READMEs.
- [x] `clone <target> <dir>` inits + fetches + checks out in one command.
- [x] `remote prune` / `gc --prune-remotes` drop stale tracking refs.
- [x] Conflicting merges record `MERGE_STATE`, list unmerged paths in `status`,
      are completed by `commit` (two parents) and undone by `merge --abort`.
- [x] Trees are stored as nested (v2) subtree objects; legacy flat trees still
      read; gc keeps intermediate subtree objects reachable.
- [x] Cross-tool tests: origin-proof MMR membership + origin-provenance stamp
      verification over origin-vcs data.
- [x] `.gitignore` rules exclude ignored paths from `add`/`status` (git-style
      globs, negation, anchoring); `.gitignore` itself is never tracked.
- [x] `commit --amend` rewrites the last commit's message and/or folds in a
      late stage; the MMR stays append-only.
- [x] `blame` attributes each line to the signed commit that introduced it
      (plain + `--json`).
- [x] `stash push/apply/pop/list/drop` shelve and restore working-tree +
      index changes; stash commits are gc-reachable.
- [x] `rebase <branch>` and `cherry-pick <rev>` replay commits onto HEAD with
      the `union`/`textual` resolvers; abbreviated hex ids resolve
      unambiguously.
- [x] Mutating commands take an exclusive store lock (`flock`, released on
      drop); `serve` runs unlocked so clients never block on it.
- [x] Pushes are fast-forward-only by default: a divergent branch overwrite is
      refused on every transport (and for directory targets) until
      `push --force`; the server reports the refusal as a pack error.
- [x] Sparse checkouts: `clone`/`pull`/`fetch`/`checkout --path` materialize
      only the selected subtree (SPARSE marker), the full history + objects
      stay local, and a plain `checkout` restores the whole tree.
- [x] `verify` checks annotated tags (content address + signed ref + target
      walk) and `verify --tree` asserts the working tree matches HEAD,
      reporting M/D/?? drift (sparse-aware).
- [x] All unit/integration/cross-tool tests green; clippy `-D warnings`; fmt clean.

---

## Appendix: related existing work (do not redo)

- **`origin-provenance`** — directory scan into a `Manifest` of SHA3-256 stamps;
  the seed of our `Tree` builder.
- **`origin-proof`** — MMR append/root/prove/verify; the append-only log.
- **`origin-common::Envelope / IdentityStore / atomic_write`** — the encryption-
  at-rest, identity/signing, and atomic-write layer.
- **`origin-seal`** — `key_from_identity` HKDF pattern and streamed envelope
  sequence uniquely-framing per-chunk nonces; both reused.
- **`origin-wallet` / `origin-proof`** — the MMR-history receipts pattern that
  proves the append-only log is battle-tested in this suite.

---

**Document Version:** 1.0.3
**Last Updated:** August 26, 2026
**Status:** v1 implemented (P1–P12) + follow-ups (clone, prune, git-style merge
UX, nested trees, relay remotes) + second batch (NAT-punched UDP remotes,
authenticated `session://` remotes, `clone --shallow`, benchmark, usage
guide) + third batch (QUIC transport, background `serve --daemon`) + fourth
batch (`.gitignore` ignore rules, `commit --amend`, `blame`, `stash`,
`rebase`/`cherry-pick`, abbreviated ids, store locking) + fifth batch
(fast-forward-only `push --force` policy, sparse checkouts via `--path`,
`verify --tree` working-tree audit, annotated-tag verification) + sixth batch
(`branch -m`/`tag -d`, `commit --author`/`--date` overrides, interactive
`rebase -i` with reorder/squash/reword/drop/edit + `--continue`/`--abort`,
store-less `remote ls-remote` across every transport, scheduled `remote sync`
with `--once`/`--daemon`/`--stop`, `~N` ancestor refs) + seventh batch
(amend-at-edit-stop resume, ref/ancestor specs in rebase todo files,
diverged-sync no-clobber guarantee + tests, `clone --depth <n>` bounded
shallow history over every network transport, and a `REBASING.md` guide). No
staged items.