# origin-vcs — rebase & sync guide

Two workflows that reshape or move history: **interactive rebase** rewrites
your own branch's commits (reorder, squash, reword, drop, edit), and
**scheduled sync** keeps a working copy in lockstep with a shared remote.
Both are additive to the object model — every rewritten or synced commit is a
normal signed commit — and both refuse to do anything destructive without you
saying so.

---

## 1. Non-interactive rebase

`origin-vcs rebase <branch>` replays the commits on `<branch>` (after your
merge base) onto `HEAD`, one at a time, producing a linear history:

```sh
origin-vcs checkout main
origin-vcs rebase feature        # re-apply feature's commits onto main
```

Each replayed commit is a new signed commit with the same author and message,
re-created on top of the current `HEAD`. The branch you were on moves forward
to the last replayed commit. Conflicts (both sides touched the same file)
abort the rebase with a message listing the paths — resolve, then retry with
`--strategy textual` for a line-level merge, or merge instead.

`cherry-pick` is the single-commit version: `origin-vcs cherry-pick 43a114f5`
applies one commit's diff onto `HEAD` (short hex ids and `~N` ancestor refs
like `HEAD~3` are accepted everywhere a commit is expected).

## 2. Interactive rebase — the todo plan

`origin-vcs rebase -i <base>` lets you edit a **todo plan** before anything is
replayed. Two forms:

| Form | What it rewrites |
|---|---|
| `rebase -i <ancestor>` | The current branch's commits *after* that ancestor (git-style) — the usual case |
| `rebase -i <other-branch>` | That branch's commits, replayed onto `HEAD` (same as non-interactive) |

The plan is generated with one `pick` line per commit, oldest first, and
opened in `$EDITOR` (or passed directly with `--todo <file>`):

```text
pick 43a114f5 # welcome page
pick 90bc22aa # fix typos
pick 5f1e00cc # add dark mode
# pick | squash | reword <msg> | drop | edit
```

| Action | Effect |
|---|---|
| `pick <rev>` | Replay the commit as-is |
| `squash <rev>` | Fold the commit into the *previous* pick (messages are joined) |
| `reword <rev> "new message"` | Replay with a different message |
| `drop <rev>` | Skip the commit entirely |
| `edit <rev>` | Replay, then stop so you can amend before continuing |
| `merge <rev>` | Replay a merge commit, preserving its two parents |

The plan must mention **every** commit being replayed exactly once — the
parser refuses partial or repeated plans, so a typo can never silently drop a
commit. Commit references may be full or short hex ids, branch/tag names, or
`~N` ancestor specs (`HEAD~2`).

```sh
origin-vcs rebase -i HEAD~3                     # edit $EDITOR's plan
origin-vcs rebase -i HEAD~3 --todo plan.txt     # supply the plan directly

**Autosquash** — pass `--autosquash` and commits whose subject begins with
`fixup! <subject>` or `squash! <subject>` are automatically reordered to sit
right after the pick they refer to (matched by message prefix), and
reworded to `fixup`/`squash` accordingly:

```sh
origin-vcs rebase -i HEAD~5 --autosquash
#   pick 43a114f5 # implement feature
#   fixup 90bc22aa # fixup! implement feature   ← moved here automatically
#   pick 5f1e00cc # other work
#   squash ab01d7ef # squash! other work
```

**Preserving merges** — by default merge commits are dropped from the plan
(history is linearized). Pass `--rebase-merges` to replay them via the
`merge` action instead, keeping the branch topology intact.

### Squash example

To fold the last two commits of a three-commit branch into one:

```text
pick 5f1e00cc # add dark mode
squash 90bc22aa # fix typos     ← folded into the pick above
pick 43a114f5 # welcome page
```

Result: two commits instead of three, with the squashed messages joined.

## 3. The `edit` stop — amend, then continue

`edit` pauses the rebase with the commit checked out and the state saved.
Make any change, then resume:

```sh
origin-vcs rebase -i HEAD~3     # plan: edit 43a114f5, pick 90bc22aa, ...
# ...pauses at the edit stop...
echo 'fix' >> index.html
origin-vcs add index.html
origin-vcs commit --amend -m "welcome page (fixed)"   # replace the paused commit
origin-vcs rebase --continue                           # replay the rest
```

`--continue` resumes from **whatever is at the branch tip now** — the amended
commit, or any fixup commit you made at the stop — and replays the remaining
picks on top. Nothing you commit at the stop is lost.

To bail out of a paused rebase entirely:

```sh
origin-vcs rebase --abort        # restore the pre-rebase tip, index, and tree
```

## 4. Scheduled sync — keep a copy in lockstep

`origin-vcs remote sync <name>` runs a **pull-then-push tick** against a
configured remote on an interval:

```sh
origin-vcs remote add origin /srv/vcs-backup/my-site
origin-vcs remote sync origin --once              # one round-trip, then exit
origin-vcs remote sync origin --interval 60 --daemon   # background loop
origin-vcs remote sync origin --stop              # stop the daemon (pid file)
```

Each tick:

1. **Pull** — fast-forward the local branch onto the remote branch if the
   remote has commits we don't.
2. **Push** — publish local commits the remote doesn't have
   (fast-forward-only, exactly like `remote push`).

The working tree is checked out after a pull, so run sync from the
repository's working directory (the daemon records `sync.pid`/`sync.log` in
the store).

### Divergent branches are never clobbered

If the local and remote branches have **diverged** (neither descends from the
other), the tick refuses both the pull and the push and logs why:

```text
sync: pull skipped: remote origin/main is not a fast-forward of main (diverged); merge manually
sync: push skipped: push refused: remote branch 'main' is not a fast-forward; use --force to overwrite
```

Your local commit and the remote commit are both left exactly as they were —
sync never force-overwrites on its own. Every later tick retries, so the
daemon heals automatically once the divergence is resolved. To resolve:

```sh
# pull the other side in, merge, then publish
origin-vcs merge --strategy textual   # after fetching / pulling the remote branch
origin-vcs remote push --force origin # now your tip descends from the remote's
```

See `MERGING.md` for the merge itself.

## 5. Verify after rewriting

Every rewritten commit is a fresh signed commit; the originals stay in the
object store (and the MMR) until `gc` prunes unreachable ones.

```sh
origin-vcs log --oneline           # the new linear history
origin-vcs verify                  # signatures + MMR still consistent
origin-vcs gc                      # prune the old, now-unreachable commits
```

---

## Related

- `origin-vcs/MERGING.md` — merging two branches (union/textual, conflict UX).
- `origin-vcs/README.md` — full command reference (including `bisect` for
  binary-searching a regression).
- `origin-vcs/USAGE.md` — the full workflow guide (init → commit → branches →
  remotes → clone).
- `FILE_VERSIONING_DESIGN.md` — design notes on history rewriting and remotes.
