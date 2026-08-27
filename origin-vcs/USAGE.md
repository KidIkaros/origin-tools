# origin-vcs — usage guide

`origin-vcs` is a git-style versioning tool with three properties git doesn't
give you by default: every object is **encrypted at rest**, every commit is
**hybrid-signed** (Ed25519 + Falcon-1024), and the commit log is auditable
through an **MMR** (Merkle Mountain Range) whose root you can verify end to end.

This guide walks a complete workflow. All commands assume you are inside the
working directory that owns the store (`<dir>/.origin-vcs`).

---

## 1. Initialize a repository

```sh
cd ~/projects/my-site
origin-vcs init                       # identity-mode encryption (default)
origin-vcs init --branch main
```

At-rest object keys are derived from your suite identity (or an explicit
`--seed <hex>`). For a passphrase-protected store:

```sh
origin-vcs init --encrypt passphrase --tier standard --passphrase-file ~/.vcs-pass
# tier: nano (default) | standard | sovereign  → Argon2id cost for the key
```

Every command that touches the store accepts the same identity flags
(`--identity`, `--seed`, `--passphrase-file`); the store remembers how its
keys are derived (`config.json`), so you only need to supply the matching
credential.

## 2. Stage, commit, inspect

```sh
echo 'Hello, world' > index.html
origin-vcs add index.html             # stage (add . stages everything)
origin-vcs status                     # staged / modified / deleted / untracked
origin-vcs commit -m "welcome page"
origin-vcs log --oneline              # or --json
origin-vcs show HEAD                  # metadata for a commit
origin-vcs show HEAD --path index.html   # a file at a revision
origin-vcs diff                       # working tree vs HEAD
origin-vcs verify                     # signatures, hashes, refs, MMR root
origin-vcs mmr --root                 # the audit root of your history
```

Large files can be staged with bounded memory (`--stream`, chunked
encryption); checkout can write them the same way:

```sh
origin-vcs add --stream video.mp4
origin-vcs checkout main --stream
```

## 3. Branches, tags, merges

```sh
origin-vcs branch feature             # create from HEAD
origin-vcs branch                     # list
origin-vcs branch -d feature          # delete
origin-vcs branch -m feature renamed  # rename
origin-vcs checkout feature
# ...edit and commit...
origin-vcs checkout main
origin-vcs merge feature              # union strategy (whole-file resolution)
origin-vcs merge feature --strategy textual   # line-level 3-way merge
```

A textual merge that hits genuine conflicts does **not** commit: the working
tree keeps `<<<<<<<` / `>>>>>>>` markers, `status` lists the unmerged paths,
and `commit` completes the merge (two parents) once you resolve them.
`merge --abort` restores the pre-merge state.

```sh
origin-vcs tag v1.0
origin-vcs tag                        # list
origin-vcs tag -d v1.0                # delete
```

### Ignore rules, amend, stash, blame, rebase, cherry-pick

```sh
# .gitignore — git-style rules (per-directory files, `!` negation, `/`
# anchoring, `**`/`*`/`?` globs, trailing-`/` dir-only). Honored by `add`
# and `status`; `.gitignore` itself is never tracked.
printf 'target/\n*.log\n' > .gitignore
origin-vcs add .                       # skips ignored paths

# Amend the last commit (new message and/or fold in a late stage)
origin-vcs add fix.patch
origin-vcs commit --amend -m "better message"

# Shelve / restore uncommitted work
origin-vcs stash push "WIP: experiments"
origin-vcs stash list
origin-vcs stash apply                 # keep the entry
origin-vcs stash pop                   # apply + drop
origin-vcs stash drop 0

# Who introduced each line (from the signed history)
origin-vcs blame src/main.rs
origin-vcs blame src/main.rs --json

# Replay history onto HEAD
origin-vcs rebase feature              # re-apply feature's commits onto HEAD
origin-vcs cherry-pick 43a114f5        # apply one commit (short ids accepted)

# Override the recorded identity / timestamp of a commit
origin-vcs commit -m "backfilled" --author "Alice <alice@example.com>" --date 1234567890

# Interactive rebase — edit a todo plan (pick/squash/reword/drop/edit/merge)
origin-vcs rebase -i HEAD~3                     # opens $EDITOR on the plan
origin-vcs rebase -i HEAD~3 --todo plan.txt     # or supply the plan directly
#   pick 43a114f5
#   squash 90bc22aa
#   reword 5f1e00cc "new message"
#   drop 7c2dd901
#   edit 88aa11bb          # stop here to amend, then:
origin-vcs rebase --continue                    # resume after an edit stop
origin-vcs rebase --abort                       # restore the pre-rebase tip

# Autosquash: reorder fixup!/squash! commits after their targets
origin-vcs rebase -i HEAD~5 --autosquash
# Preserve merge commits during a rebase instead of dropping them
origin-vcs rebase -i HEAD~3 --rebase-merges

# Git-style bisect — binary-search a regression
origin-vcs bisect start 3d90ff21            # known good commit (bad = HEAD)
origin-vcs bisect start good0 --bad bad50   # or name both explicitly
origin-vcs bisect good                       # current candidate passes
origin-vcs bisect bad                        # current candidate fails
origin-vcs bisect skip                       # candidate won't build
origin-vcs bisect run ./check.sh             # automate the loop with a script
origin-vcs bisect reset                      # clear the session
```

Todo specs accept short/full hex ids, branch and tag names, and `~N` ancestor
refs (`HEAD~2`). The full interactive-rebase and `remote sync` walkthroughs
(including amend-at-edit-stop and divergent-branch behavior) live in
[`REBASING.md`](REBASING.md).

### Auditing the working tree

```sh
origin-vcs verify                       # signatures, objects, tags, MMR
origin-vcs verify --tree                # also assert the working tree matches HEAD
#   (fails with a drift list — M / D / ?? — if anything changed)
```

`verify` checks every annotated tag too: the tag object's content address,
its signed ref, and the commit it points at.

## 4. Remotes — from a directory to the network

A remote is any target that can store a pack. Configure one, then
push/fetch/pull:

```sh
origin-vcs remote add origin /srv/vcs-backup/my-site   # a local directory
origin-vcs remote push origin
origin-vcs remote push --force origin # overwrite a non-fast-forward branch tip
origin-vcs remote pull origin         # fetch + fast-forward
origin-vcs remote list
origin-vcs remote prune origin        # drop tracking refs the remote dropped
origin-vcs gc --prune-remotes         # prune objects + stale tracking refs

# Inspect any remote without a local repository at all
origin-vcs remote ls-remote /srv/vcs-backup/my-site
origin-vcs remote ls-remote tcp://host:7332

# Scheduled sync: pull + push a configured remote on an interval
origin-vcs remote sync origin --once        # single round-trip, then exit
origin-vcs remote sync origin --interval 60 --daemon   # background loop
origin-vcs remote sync origin --branch feature  # sync feature, not HEAD
origin-vcs remote sync origin --stop        # stop the daemon (pid file)

# Deepen a shallow clone: fetch more ancestor generations than --depth gave
origin-vcs fetch --depth 20 origin          # pull history up to 20 generations
origin-vcs fetch --shallow origin          # fetch tips only
```

`ls-remote` needs no local store and no key: run it from any directory to
list branches/tags of a directory pack, `tcp://`, `quic://`, `session://`, or
`relay://` target. `sync` runs a pull-then-push tick per interval; `--branch
<b>` syncs a named branch instead of the HEAD branch, useful when pushing a
feature branch while working on another. As a daemon it records a pid file
(default `<store>/sync.pid`) so `--stop` can find it, and logs to
`<store>/sync.log`. A shallow clone (from `clone --shallow` or `--depth <n>`)
can be deepened with `fetch --depth <n>`, which requests the deeper pack on
the same transport and extends history past the old shallow boundary.

**Divergent branches are never clobbered.** A sync tick fast-forwards the
local branch onto the remote when possible, then pushes local commits
(fast-forward-only, like `push`). If the two sides have diverged (neither
descends from the other), the tick skips that branch — the pull and the push
are both refused and logged (`pull skipped: ... diverged` / `push skipped:`)
— and every later tick retries. Fix a divergence the same way you would
after a refused `push`: merge the other side locally, then `push --force`
(see the merge guide).

Pushes are **fast-forward-only by default**: overwriting a remote branch tip
that your pushed tip does not descend from is refused (on every transport,
and for directory targets) unless you pass `--force`.

### Sparse checkouts — keep only a subtree on disk

For a large tree, materialize only the paths you need while the full history
+ objects stay local:

```sh
origin-vcs clone --path src tcp://host:7332 ./worktree   # only src/ on disk
origin-vcs pull --path src origin          # switch an existing repo to sparse
origin-vcs fetch --path src origin         # record the sparse set for later checkouts
origin-vcs checkout main                   # clear the sparse set, full tree again
```

Every later `checkout`/`pull`/`merge` respects the active sparse set; a plain
`checkout` clears it and restores everything.

### Live transports

```sh
# Plain TCP (convenient; anyone who can reach the port can fetch ciphertext)
origin-vcs remote serve --listen 127.0.0.1:7332
origin-vcs remote add origin tcp://host:7332

# Authenticated sessions (Noise IK handshake + AUTH claim; allowlist enforced)
origin-vcs remote serve --session 0.0.0.0:7332 --allow <peer-seed-hex>
#   (or --allow-file peers.jsonl with serialized PeerKeys records)
origin-vcs remote add origin session://host:7332/<server-fp>/<server-transport-pk>

# Relay: rendezvous + NAT punching, so peers behind NATs sync directly
origin-vcs remote serve --relay relay://relay.host:7333/<relay-fp>/<relay-pk>
origin-vcs remote add origin relay://relay.host:7333/<relay-fp>/<relay-pk>/<peer-fp> \
    --net-seed <hex>          # distinct identity for the relay connection
```

Relay remotes first try a NAT-punched **direct UDP** exchange (the server
publishes its STUN/local candidates as a relay advert; the client punches and
dials). If the punch fails, the same pack protocol rides the relay tunnel.
Use `--stun <host:port>` on both sides to advertise/learn public addresses
across NATs.

### Bundles — one portable file

```sh
origin-vcs bundle create my-site.ovcsbnd
origin-vcs bundle import my-site.ovcsbnd --name archive   # into another store
origin-vcs bundle verify my-site.ovcsbnd
```

### Clone

```sh
origin-vcs clone tcp://host:7332 ./copy
origin-vcs clone relay://relay.host:7333/<fp>/<pk>/<peer-fp> ./copy --net-seed <hex>
origin-vcs clone tcp://host:7332 ./shallow-copy --shallow   # tip only
```

A shallow clone fetches only the tip commits + their trees/blobs and marks
the store shallow (`SHALLOW`): `log` stops at the boundary, `verify` passes
on the truncated history, and `gc` never prunes what's there. Merge on a
shallow clone is refused until you fetch full history.

## 5. Housekeeping

```sh
origin-vcs reset --id <commit> --mode soft   # move HEAD only
origin-vcs reset --id <commit> --mode hard   # also restore the tree
origin-vcs gc                                # prune unreachable objects
origin-vcs verify                            # full audit after any transfer
```

## Worked example — the whole loop

```sh
mkdir demo && cd demo
origin-vcs init
printf 'v1\n' > app.txt
origin-vcs add app.txt && origin-vcs commit -m "v1"

origin-vcs branch feature
origin-vcs checkout feature
printf 'v1\nfeature work\n' > app.txt
origin-vcs add app.txt && origin-vcs commit -m "feature"
origin-vcs checkout main
printf 'v1\nmain work\n' > app.txt
origin-vcs add app.txt && origin-vcs commit -m "main"

origin-vcs merge feature --strategy textual   # non-overlapping → auto-merge
origin-vcs verify                             # all signatures + MMR consistent

origin-vcs remote add origin /tmp/demo-remote
origin-vcs remote push origin
cd .. && origin-vcs clone /tmp/demo-remote demo-copy
cd demo-copy && origin-vcs log --oneline && origin-vcs verify
```

## What is verified, and how

- **Objects** are content-addressed (SHA3-256 of plaintext) and stored as
  encrypted envelopes — the store contains no plaintext.
- **Commits** carry a hybrid (Ed25519 + Falcon-1024) signature embedding its
  public keys, so `verify` needs no vault or identity.
- **History** is an append-only log committed to an MMR; `verify` replays the
  log and compares the recomputed root to the persisted one, detecting any
  tampering with the order or content of commits.
