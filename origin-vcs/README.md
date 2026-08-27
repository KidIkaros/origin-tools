# `origin-vcs`

Git-like file versioning for the origin-tools suite, with two origin-specific
properties the suite's design *insists* on (see
[`FILE_VERSIONING_DESIGN.md`](/FILE_VERSIONING_DESIGN.md)):

1. **Signed history** — every commit, tag, and branch ref is hybrid-signed
   (Ed25519 + Falcon-1024) under a domain-derived subkey of the suite identity
   (`origin-vcs`), so the entire history is an authenticated chain.
2. **Encrypted at rest** — every stored object is wrapped in an origin-common
   `Envelope` (XChaCha20-Poly1305, AAD-authenticated header) under a second
   domain-derived key (`origin-vcs::objects`). No blob, path, tree, or commit
   message ever lands plaintext on disk.

It is a full local DVCS: content-addressed blobs/trees/commits, an index
(staging area), branches, tags, three-way merge, diff, and an append-only MMR
commit log for tamper-evident total ordering (mirroring `origin-proof`).

All cryptography comes from `origin-crypto-sdk`.

See [`USAGE.md`](USAGE.md) for a complete worked example (init → commit →
branch → merge → remote → clone).

---

## Quick start

```bash
# In a directory you want to version:
origin-vcs init --seed <32-byte-hex>          # or: --identity (suite identity)

# Stage and commit
echo "hello" > a.txt
origin-vcs add a.txt
origin-vcs commit -m "first commit"

# History, status, diff, branches
origin-vcs log --oneline
origin-vcs status
origin-vcs verify                         # signs + object hashes + MMR

origin-vcs branch feature
origin-vcs checkout feature
# ...work...
origin-vcs checkout main
origin-vcs merge feature
```

Two key-mode flags control *both* signing and the storage-encryption key:

| Flag | Meaning |
|---|---|
| `--seed <hex>` | Use an explicit 32-byte seed (dev/no-identity). |
| `--identity` | Derive from `~/.origin/identity.seed` (passphrase via `-p`). |

A repo written under one key source is only readable/verifiable under the same
source.

## Commands

| Command | Description |
|---|---|
| `init` | Initialize an encrypted store (default `.origin-vcs/`) |
| `add <path…>` / `rm <path…>` | Stage / unstage paths (`.gitignore` rules honored by `add`/`status`) |
| `status [--json]` | Staged / modified / deleted / untracked |
| `commit -m <msg> [--amend] [--author <s>] [--date <epoch>]` | Build tree + signed commit, advance branch, append MMR; `--amend` rewrites the last commit (new message and/or folded-in stage); `--author`/`--date` override the recorded identity/timestamp |
| `log [--oneline] [--json]` | History |
| `show <rev> [--path <p>]` | A commit, or a file at a revision |
| `branch [<name>]` / `branch -d <name>` / `branch -m <old> <new>` | List / create / delete / rename branches |
| `checkout <branch\|commit> [--path <p>…]` | Restore the working tree from a revision; `--path` materializes only those paths (plain `checkout` restores the full tree) |
| `tag <name> [<rev>]` / `tag -d <name>` | Signed tags / delete a tag |
| `diff [<a> [<b>]]` | Tree diff (defaults: HEAD vs working tree) |
| `merge <branch> [--strategy union\|textual]` | Fast-forward, file-level, or line-diff three-way merge |
| `merge --abort` | Abort an in-progress (conflicting) merge, restoring HEAD/index/tree |
| `rebase <branch>` / `rebase -i <base> [--todo <f>] [--autosquash] [--rebase-merges] [--continue\|--abort]` | Replay a branch's commits (after the merge base) onto HEAD, one at a time; `-i` edits a todo plan (`pick`/`squash`/`reword <msg>`/`drop`/`edit`/`merge`) via `--todo` or `$EDITOR`, pausing at `edit` stops for `--continue`/`--abort`; `--autosquash` reorders `fixup!`/`squash!` commits after their targets; `--rebase-merges` replays merge commits instead of dropping them; `rebase -i <ancestor>` rewrites the current branch's commits after it (git-style) |
| `cherry-pick <rev>` | Apply a single commit's changes onto HEAD (short hex ids + `~N` ancestor refs accepted) |
| `bisect start <good> [--bad <bad>] \| good <rev> \| bad <rev> \| skip \| run <script> \| reset` | Binary-search a regression between a good and bad commit; `good`/`bad` narrow the range, `skip` marks an untestable commit, `run <script>` automates it, `reset` clears the session |
| `cherry-pick <rev>` | Apply a single commit's changes onto HEAD (short hex ids + `~N` ancestor refs accepted) |
| `stash push\|apply\|pop\|list\|drop [<n>]` | Shelve / restore / list working-tree + index changes |
| `blame <path> [--from <rev>] [--json]` | Per-line provenance (which signed commit introduced each line) |
| `clone <target> <dir> [--path <p>…]` | Init a store, register the remote, fetch + check out (git-clone style); `--path` clones sparsely (subtree on disk, full history + objects local) |
| `reset [--mode soft\|hard] <rev>` | Move / hard-reset HEAD |
| `verify [--target <rev>] [--tree]` | Verify every signature, object hash, tag object, and the MMR; `--tree` also asserts the working tree matches HEAD |
| `mmr [--root]` | Show commit count / print MMR root |
| `gc [--prune-remotes]` | Prune objects unreachable from any ref (reachability walk); optionally drop stale tracking refs |
| `remote add\|remove\|list <name> [<target>]` | Manage remotes (dir snapshot, `tcp://`, `session://`, `relay://`, or `quic://` target) |
| `remote push\|fetch\|pull <name> [--force] [--path <p>…]` | Sync object packs + refs with a remote; `--force` overwrites a non-fast-forward branch tip, `--path` switches to a sparse checkout; `fetch --depth <n>` deepens a shallow clone by fetching `<n>` more ancestor generations |
| `remote prune <name>` | Delete stale tracking refs (branches the remote no longer advertises) |
| `remote ls-remote <target>` | List branches/tags of any remote target — no local store or seed needed (works from any directory) |
| `remote sync <name> [--once] [--interval <s>] [--branch <b>] [--daemon] [--stop]` | Scheduled sync: pull + push a configured remote on an interval; `--branch <b>` syncs a named branch instead of HEAD, `--once` does a single round-trip, `--daemon` runs it in the background (pid/log files), `--stop` kills it |
| `remote serve --listen <addr>` / `--relay <url>` / `--session <addr> [--allow …]` / `--quic <addr>` | Serve a store over TCP, a relay, authenticated sessions, or QUIC |
| `remote serve … --daemon` / `--stop` | Run the serve loop as a background daemon (pid/log files) / stop it |
| `remote … --stun <host:port>` | STUN server for NAT-punched relay remotes (advert + decision tree) |
| `clone … --shallow` | Shallow clone: tip commits + trees/blobs only, store marked shallow |
| `bundle create\|import\|verify <file>` | Single-file bundle exchange (git-bundle style) |
| `init --encrypt passphrase [--tier nano\|standard\|sovereign]` | Argon2id key mode + cost tier |
| `add --stream` / `checkout --stream` | Bounded-memory blob ingest / tree restore |

Refs are `<store>/refs/{heads,tags}/<name>` (signed + encrypted envelopes);
`HEAD` holds the branch name; the MMR lives in `<store>/mmr.json` with an
explicit `<store>/commit-log.json` so membership can be replayed for `verify`.

## Security model

- **Address = SHA3-256 of `type‖canonical`** → tampering changes the address so
  lookups fail; `verify` recomputes every address.
- **Signatures cover canonical bytes incl. `tree` + `parents`** → rewriting
  history breaks the next commit's signature.
- **Refs are signed** → moving a branch requires the identity.
- **MMR append-only log** → a total order persists even across branch rewrites;
  `verify` asserts the log replays to the stored root.
- **Envelope AEAD** authenticates the envelope header; a corrupted or
  wrong-key envelope aborts loudly.

## Tests

```bash
cargo test -p origin-vcs
cargo clippy -p origin-vcs --all-targets -- -D warnings
cargo fmt -p origin-vcs -- --check
```

Integration tests assert both happy-path DVCS flows and the two security
properties: the *encrypted-at-rest* guarantee (no plaintext greps out of the
store) and *tamper detection* (corrupting a blob envelope makes `verify` fail).

### Working tree hygiene (`follow-up` batch)

- **`.gitignore` rules** — git-style ignore semantics (per-directory files,
  `!` negation, `/` anchoring, `**`/`*`/`?` globs, trailing-`/` dir-only
  patterns) are honored by `add`, `status`, and the checkout hygiene walk.
  `.gitignore` itself is never tracked.
- **`commit --amend`** — rewrite the last commit's message and/or fold in
  late stages; the MMR stays append-only (the ref moves).
- **`blame`** — walks the signed history and attributes each line to the
  commit that introduced it (`--json` for machine use).
- **`stash`** — `push` snapshots the working tree + index into a signed stash
  commit (kept reachable from `gc`) and restores the committed state;
  `apply`/`pop` three-way it back onto the current tree; `list`/`drop`
  manage the stack.
- **`rebase` / `cherry-pick`** — replay commits onto HEAD (with the same
  `--strategy union|textual` resolution as merge); short hex ids resolve
  unambiguously anywhere a revision is accepted.
- **Store locking** — every mutating command takes an exclusive `flock` on
  the store (released on drop), so concurrent `commit`/`push`/`gc` runs can't
  race the index, refs, or MMR. `remote serve` deliberately runs unlocked so
  clients (and `serve --stop`) never block on a long-lived server.
- **`push --force`** — a push may not overwrite a remote branch tip unless
  the pushed tip descends from it (fast-forward); divergent pushes are
  refused on every transport (and for directory targets) until `--force`.
  The server reports the refusal to the pusher as a pack-level error.
- **Sparse checkouts** — `clone --path <p>…`, `pull/fetch --path <p>…`, and
  `checkout --path <p>…` record a `SPARSE` marker and materialize only those
  paths (the full history + object set stay local); a plain `checkout` clears
  the marker and restores the full tree. Every later checkout/pull/merge
  respects the active set.
- **`verify --tree` + tag verification** — `verify` now also checks every
  annotated tag object (content address + signed ref) and walks its target;
  `verify --tree` asserts the working tree matches HEAD exactly (modified /
  deleted / untracked drift is reported, sparse-aware).

## Follow-up features (all implemented)

- **Argon2id tiers** — `init --encrypt passphrase --tier standard|sovereign`
  records the tier in `config.json`; passphrase keys derive with the tier's
  cost parameters (matches origin-seal).
- **Symlinks** — symlinks are stored git-style (blob = link target) with a
  `Symlink` tree mode and recreated on checkout.
- **Bundles** — `bundle create/import/verify` moves a repo as one portable
  file; `verify` proves every envelope is present and decryptable.
- **Live TCP remotes** — `remote serve` + `tcp://host:port` targets sync over
  origin-network's `TcpTransport`; pushed commits are signature-verified by
  the server before adoption.
- **Cross-tool tests** — origin-vcs data is verified through origin-proof's
  MMR receipts and origin-provenance's SHA3-256 stamps.
- **`clone`** — one command to init + register the remote + fetch + check out
  the default (or `--branch`) branch.
- **`remote prune` + `gc --prune-remotes`** — drop tracking refs whose branch
  the remote no longer advertises (or whose tip is no longer reachable).
- **Merge UX** — a conflicting merge no longer commits: it writes the
  marker-bearing tree to the index/working tree, records `MERGE_STATE`, and
  `status` lists the unmerged paths; `commit` completes the merge (two
  parents) and `merge --abort` restores the pre-merge state.
- **Nested tree objects** — trees are stored as git-style nested subtree
  objects (v2 format) on disk while every in-memory consumer keeps the flat
  path map; identical subtrees dedupe, legacy flat trees stay readable, and
  gc/push reachability walks the intermediate subtree objects.
- **Relay remotes** — `relay://host:port/<relay-fp>/<relay-pk>/<peer-fp>`
  targets tunnel the same pack protocol through origin-network's relay
  (authenticated Noise IK + AUTH, live forwarding pairs). Both ends use
  distinct network identities (`--net-seed`); the relay operator's allowlist
  must register both.
- **NAT-punched UDP** — a `relay://` server publishes its STUN/local UDP
  candidates as a relay advert; clients punch (`connect_p2p`) and run the
  same pack protocol over a direct datagram transport (fragmented
  `[type][more]` datagrams, enlarged kernel buffers), falling back to the
  relay tunnel when no advert exists or the punch fails.
- **Authenticated sessions** — `session://host:port/<peer-fp>/<peer-tpk>`
  targets dial an origin-network `Endpoint`: the Noise IK + AUTH handshake
  verifies the peer identity and the pack protocol rides a ratcheted
  `SecurePipe`. `remote serve --session` accepts only allowlisted identities
  (`--allow <seed>` repeated, or `--allow-file` of PeerKeys records).
- **QUIC transport** — `quic://host:port` targets (and `serve --quic <addr>`)
  carry the same pack protocol over origin-network's `quinn`-based QUIC
  transport: stream multiplexing + 0-RTT migration, with self-signed TLS
  used for obfuscation only (identity auth happens above the transport, via
  `session://`). Graceful teardown (`FrameConn::shutdown`) keeps both
  endpoints' driver tasks alive through the close handshake, so neither side
  waits out the QUIC idle timeout.
- **Background daemon** — `remote serve --session … --daemon` re-execs the
  binary as a detached background child: the pid file records the child pid +
  bound address, stdout/stderr go to the log file, and `remote serve --stop`
  SIGTERMs and cleans up.
- **Shallow clones** — `clone --shallow` fetches only the tip commits + tree
  closures (no ancestors) and marks the store shallow (`SHALLOW`); `log`
  stops at the boundary, `verify` passes on the truncated history, merge is
  refused until full history is fetched. `clone --depth <n>` fetches at most
  `n` ancestor generations (1 = tips only, same as `--shallow`) over any
  network transport.
- **Merge guide** — see [`MERGING.md`](MERGING.md) for the three-way merge
  model, conflict workflows, and `merge --abort` / commit-completes-merge
  resolution paths.
- **Rebase & sync guide** — see [`REBASING.md`](REBASING.md) for interactive
  rebase (reorder/squash/reword/drop/edit/merge, `--autosquash`,
  `--rebase-merges`, `--continue`/`--abort`), amend-at-edit-stop, and
  scheduled `remote sync` behavior (`--branch`, divergence never clobbers).
- **Bisect** — `bisect start/good/bad/skip/run/reset` binary-searches a
  regression between good and bad commits; the session is persisted (`run
  <script>` automates it end-to-end).

## Phase 8–12 features (all implemented)

- **`gc`** — reachability walk from branches/tags/HEAD; prunes unreachable
  envelopes; `verify` still passes afterward.
- **`--encrypt=passphrase`** — per-repo `config.json` records the key mode;
  passphrase repos derive the object key with Argon2id + a per-repo random
  salt (wrong passphrase fails loudly). Signing still uses the identity.
- **Remotes** — `remote add/push/fetch/pull` mirror the reachable object set
  + branch/tag tips as a manifest + verbatim envelopes (content-addressed, so
  key-agnostic paths). Pull fast-forwards only when the remote descends from
  local HEAD; divergent pulls refuse. The transport seam is a local directory
  today — the pack format is stable for an `origin-network` p2p address later.
- **Textual 3-way merge** — `merge --strategy textual` runs a line-diff
  (Myers/LCS) resolver: non-overlapping hunks auto-merge; identical edits
  collapse; genuine clashes emit `<<<<<<<`/`>>>>>>>` markers.
- **Streaming blobs** — `add --stream` / `checkout --stream` chunk blobs
  (unique per-chunk nonces + zero-length sentinel, mirroring origin-seal),
  bounded memory, with the blob address still the plaintext content hash.

## Benchmark (`examples/bench_stream.rs`)

Streamed vs buffered add/checkout on a 64 MiB payload
(`cargo run -p origin-vcs --example bench_stream 64`):

| path | time | MiB/s |
|---|---|---|
| add buffered | 0.90s | 70.9 |
| add streamed | 1.62s | 39.6 |
| check buffered | 0.48s | 133.9 |
| check streamed | 0.45s | 142.4 |

Streamed add pays a ~1.8× cost for bounded memory (two-pass content hashing
+ per-chunk nonces); streamed checkout is on par with (slightly faster than)
buffered. The example also **asserts memory-boundedness**: peak RSS during a
streamed add/checkout adds ~zero over the buffered path, and both paths
produce byte-identical content-addressed ids.

## License

Apache-2.0