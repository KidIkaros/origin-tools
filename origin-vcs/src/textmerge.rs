// SPDX-License-Identifier: Apache-2.0

//! Textual three-way merge (Phase 11) — a line-diff resolver.
//!
//! Given base/ours/theirs file bytes, produces a merged file that:
//!  - keeps lines unchanged across all three sides verbatim,
//!  - applies a side's edit where only that side changed a line,
//!  - auto-merges non-overlapping single-line edits (both sides changed
//!    different base lines),
//!  - collapses identical edits, and
//!  - where both sides changed the *same* base line differently, emits
//!    standard conflict markers for a human to resolve:
//!    `<<<<<<<` / `=======` / `>>>>>>>`.
//!
//! The diff is a line-granular Myers (LCS-backtrace) edit script; the merge is
//! a per-base-line fold. Multi-line insert/delete hunks that don't align 1:1
//! are surfaced as conflicts (safety over cleverness): this never silently
//! merges a deletion on one side with a distinct insertion on the other.

/// Per-base-line edit produced by the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Edit {
    /// Base line is unchanged.
    Keep,
    /// Base line is replaced by exactly these lines (empty vector = deletion).
    Replace(Vec<Vec<u8>>),
}

/// Returns the merged bytes and whether any conflict markers were emitted.
pub fn merge_lines(base: &[u8], ours: &[u8], theirs: &[u8]) -> (Vec<u8>, bool) {
    if base == ours {
        return (theirs.to_vec(), false);
    }
    if base == theirs {
        return (ours.to_vec(), false);
    }
    if ours == theirs {
        return (ours.to_vec(), false);
    }

    let b: Vec<Vec<u8>> = split_lines(base);
    let o: Vec<Vec<u8>> = split_lines(ours);
    let t: Vec<Vec<u8>> = split_lines(theirs);

    let ours_edit = myers(&b, &o);
    let theirs_edit = myers(&b, &t);
    fold(&b, &ours_edit, &theirs_edit)
}

fn split_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..bytes.len() {
        if bytes[i] == b'\n' {
            out.push(bytes[start..=i].to_vec());
            start = i + 1;
        }
    }
    if start < bytes.len() {
        out.push(bytes[start..].to_vec());
    }
    out
}

/// Myers edit script (LCS backtrace) of `base` → `target`, aligned one slot per
/// base line. Insertions are folded into the `Replace` of the preceding base
/// line; a base-line deletion becomes an empty `Replace`.
fn myers(base: &[Vec<u8>], target: &[Vec<u8>]) -> Vec<Edit> {
    let n = base.len();
    let m = target.len();
    if n == 0 {
        // Everything is an insertion with no base row to attach to.
        return Vec::new();
    }

    // LCS DP.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if base[i] == target[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    // Backtrace: iterate base rows, tracking the aligned target column, and
    // emit Keep for matching lines and Replace for everything else, folding any
    // skipped (inserted) target lines into the nearest preceding Replace.
    let mut edits: Vec<Edit> = Vec::with_capacity(n);
    let mut j = 0usize;
    let mut held_inserts: Vec<Vec<u8>> = Vec::new();
    let mut i = 0usize;
    while i < n {
        if j < m && base[i] == target[j] && dp[i][j] == dp[i + 1][j + 1] + 1 {
            // Match: flush held inserts (impossible here since a match means no
            // prior insert pending on this exact row) then Keep.
            edits.push(match held_inserts.is_empty() {
                true => Edit::Keep,
                false => Edit::Replace(std::mem::take(&mut held_inserts)),
            });
            i += 1;
            j += 1;
        } else {
            // Lookahead: if we can move down (delete a base line), do so; else
            // move right (keep a target line as insert) or down.
            let can_insert = j < m && (i == n || dp[i][j + 1] >= dp[i + 1][j]);
            if can_insert {
                held_inserts.push(target[j].clone());
                j += 1;
            } else {
                // Delete/replace this base line (optionally carrying held
                // inserts, e.g. when a substituted pair follows an insert).
                edits.push(Edit::Replace(std::mem::take(&mut held_inserts)));
                i += 1;
            }
        }
    }
    // Any trailing target lines are lost insertions; attach to the last Replace
    // (delete of the tail) by extending it. Represent them as a trailing
    // Replace if the last edit is Keep.
    if !held_inserts.is_empty() {
        if let Some(Edit::Replace(lines)) = edits.last_mut() {
            lines.extend(held_inserts);
        } else {
            edits.push(Edit::Replace(std::mem::take(&mut held_inserts)));
        }
    }
    edits
}

/// Fold two per-base-line edit scripts into a single merged stream.
fn fold(base: &[Vec<u8>], ours: &[Edit], theirs: &[Edit]) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::new();
    let mut conflicted = false;

    let emit = |lines: &[Vec<u8>], out: &mut Vec<u8>| {
        for l in lines {
            out.extend_from_slice(l);
        }
    };

    for (bi, base_line) in base.iter().enumerate() {
        let oe = ours.get(bi).cloned().unwrap_or(Edit::Keep);
        let te = theirs.get(bi).cloned().unwrap_or(Edit::Keep);
        match (&oe, &te) {
            (Edit::Keep, Edit::Keep) => out.extend_from_slice(base_line),
            (Edit::Replace(ov), Edit::Keep) => emit(ov, &mut out),
            (Edit::Keep, Edit::Replace(tv)) => emit(tv, &mut out),
            (Edit::Replace(ov), Edit::Replace(tv)) if *ov == *tv => emit(ov, &mut out),
            (Edit::Replace(ov), Edit::Replace(tv)) => {
                conflicted = true;
                out.extend_from_slice(b"<<<<<<< ours\n");
                emit(ov, &mut out);
                out.extend_from_slice(b"=======\n");
                emit(tv, &mut out);
                out.extend_from_slice(b">>>>>>> theirs\n");
            }
        }
    }
    (out, conflicted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_sides_are_kept() {
        let base = b"a\nb\nc\n".to_vec();
        let ours = base.clone();
        let theirs = base.clone();
        let (out, conflicted) = merge_lines(&base, &ours, &theirs);
        assert_eq!(out, base);
        assert!(!conflicted);
    }

    #[test]
    fn one_side_only_change_applies() {
        let base = b"a\nb\nc\n".to_vec();
        let ours = b"a\nB\nc\n".to_vec();
        let theirs = base.clone();
        let (out, _) = merge_lines(&base, &ours, &theirs);
        assert_eq!(out, ours);
    }

    #[test]
    fn independent_non_overlapping_changes_auto_merge() {
        let base = b"line1\nline2\nline3\nline4\n".to_vec();
        let ours = b"line1\nCHANGED\nline3\nline4\n".to_vec();
        let theirs = b"line1\nline2\nCHANGED3\nline4\n".to_vec();
        let (out, conflicted) = merge_lines(&base, &ours, &theirs);
        assert!(
            !conflicted,
            "non-overlapping hunks should auto-merge: {}",
            String::from_utf8_lossy(&out)
        );
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("CHANGED") && s.contains("CHANGED3"));
    }

    #[test]
    fn overlapping_different_changes_conflict() {
        let base = b"a\nb\nc\n".to_vec();
        let ours = b"x\nb\nc\n".to_vec();
        let theirs = b"y\nb\nc\n".to_vec();
        let (out, conflicted) = merge_lines(&base, &ours, &theirs);
        assert!(conflicted);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<<<<<<<"));
        assert!(s.contains(">>>>>>>"));
        assert!(s.contains('x') && s.contains('y'));
    }

    #[test]
    fn identical_edit_on_both_sides_collapses() {
        let base = b"a\nb\nc\n".to_vec();
        let ours = b"a\nZ\nc\n".to_vec();
        let theirs = b"a\nZ\nc\n".to_vec();
        let (out, conflicted) = merge_lines(&base, &ours, &theirs);
        assert!(!conflicted);
        assert_eq!(out, ours);
    }
}
