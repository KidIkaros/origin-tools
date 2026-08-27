# origin-vcs — merging guide

`origin-vcs` merges one branch into your current branch (`HEAD`). Merges are
**three-way**: the common ancestor of both branches is found, each side's
changes are diffed against it, and the two change sets are combined. The
object model is unchanged by the merge — the result is a normal signed commit
with **two parents**.

---

## 1. The two strategies

| Strategy | Command | What it does |
|---|---|---|
| `union` (default) | `origin-vcs merge feature` | Whole-file resolution: for each file both sides changed differently, the *other* side (the branch being merged) wins; files only one side touched merge normally. Fast, deterministic, never blocks. |
| `textual` | `origin-vcs merge feature --strategy textual` | Line-level three-way merge (Myers/LCS diff): non-overlapping hunks auto-merge, identical edits collapse, and only genuine clashes produce conflict markers. |

`union` is safe for any file type (it never tries to interpret content).
`textual` is what you want for text files where both branches edited the same
lines.

```sh
origin-vcs merge feature                    # union (default)
origin-vcs merge feature --strategy textual # line-level
origin-vcs merge feature -m "merge feature" # custom commit message
```

If the merge would be a no-op (the branch is already an ancestor of `HEAD`),
origin-vcs says so and does nothing.

## 2. What a conflict looks like

With `--strategy textual`, a genuine clash (both sides changed the same
lines differently) does **not** create a commit. The working tree keeps the
merged file with conflict markers, exactly like git:

```text
<<<<<<< ours
line as it exists on our branch
=======
line as the other branch has it
>>>>>>> theirs
```

The index and working tree reflect the conflicted state, and a `MERGE_STATE`
record is written so the merge can be resumed or aborted.

## 3. Resolving a conflict

```sh
origin-vcs status          # lists unmerged paths
```

`status` prints the paths carrying `<<<<<<<`/`>>>>>>>` markers (and with
`--json`, `unmerged` + `merge_in_progress` fields). Edit each conflicted file
by hand — keep one side, combine both, or delete the markers — then:

```sh
origin-vcs add <resolved-file>     # stage the resolution
origin-vcs commit -m "merge feature"
```

A `commit` while a merge is in progress **completes the merge**: the commit
gets the two parents `[HEAD, <other-branch>]` and the `MERGE_STATE` is
cleared. `status` then shows a clean tree.

## 4. Aborting a merge

Changed your mind? Restore everything to the pre-merge state:

```sh
origin-vcs merge --abort
```

This resets `HEAD`, the index, and the working tree to exactly what they
were before the merge started — conflicted files are replaced with their
originals, and `MERGE_STATE` is removed. Nothing from the aborted merge is
committed; the objects it created are unreachable and swept by `gc`.

## 5. Merges and shallow clones

A shallow clone (`clone --shallow`) fetches only tip commits — its ancestry
is truncated, so origin-vcs cannot compute a reliable merge base across the
boundary. `merge` refuses to run on a shallow store; `remote pull` (full
history) first, then merge.

## 6. Worked example

```sh
origin-vcs init
printf 'line 1\nline 2\n' > notes.txt
origin-vcs add notes.txt && origin-vcs commit -m "base"

origin-vcs branch feature
origin-vcs checkout feature
printf 'line 1\nline 2\nfeature\n' > notes.txt
origin-vcs add notes.txt && origin-vcs commit -m "feature work"

origin-vcs checkout main
printf 'line 1\nline 2\nmain\n' > notes.txt
origin-vcs add notes.txt && origin-vcs commit -m "main work"

origin-vcs merge feature --strategy textual   # different lines → auto-merges
origin-vcs log                                # merge commit with 2 parents
origin-vcs verify                             # signatures + MMR still consistent
```

Now make both branches edit the *same* line to see a real conflict:

```sh
# both add a third line with different text on the same line boundary
origin-vcs merge feature --strategy textual   # → conflict, no commit
origin-vcs status                             # notes.txt is unmerged
# resolve: edit notes.txt, remove the markers
origin-vcs add notes.txt
origin-vcs commit -m "merge feature"          # completes the merge
```

## 7. Verify after merging

Merges produce two-parent commits exactly like any other commit: hybrid
signed, encrypted at rest, appended to the MMR. `origin-vcs verify` replays
the full history (including merge commits) and checks signatures, object
hashes, refs, and the MMR root — run it after any merge you care about.

---

## Related

- `origin-vcs/USAGE.md` — the full workflow guide (init → commit → branches →
  remotes → clone).
- `FILE_VERSIONING_DESIGN.md` — design notes on the merge resolver and the
  object format.
