// SPDX-License-Identifier: Apache-2.0

//! Git-style ignore rules (`.gitignore`).
//!
//! Implements the common subset of git's ignore semantics used by the working
//! tree scanner (`collect_files`): pattern lines in `.gitignore` files, applied
//! from the repo root downward, with `!` negation, leading `/` anchoring, and
//! trailing `/` directory-only matching. `**` spans path separators; a single
//! `*` matches within one path component; `?` matches a single character.
//!
//! The working-tree walk (`collect_files`) visits directories top-down and
//! feeds each `.gitignore` into this state, so each file applies to its own
//! subtree and deeper rules override shallower ones.

use std::path::PathBuf;

/// One compiled ignore pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnorePattern {
    /// Pattern text (without leading `!`, `/` anchor, or trailing `/`).
    text: String,
    /// Whether the pattern was negated with `!`.
    pub negate: bool,
    /// Whether the pattern is anchored to the ignore file's directory.
    anchored: bool,
    /// Whether the pattern matches directories only (trailing `/`).
    dir_only: bool,
}

/// Match a single glob against a path's components.
fn glob_match(pat: &str, path: &str) -> bool {
    match_components(pat, path)
}

/// Recursively match `pat` (a glob possibly containing `**`) against `path`.
fn match_components(pat: &str, path: &str) -> bool {
    // Split both into `/`-separated tokens for clean handling of `**`.
    let p: Vec<&str> = pat.split('/').filter(|s| !s.is_empty()).collect();
    let t: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    dmatch(&p, &t)
}

fn dmatch(p: &[&str], t: &[&str]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        "**" => {
            // `**` matches zero or more components.
            for skip in 0..=t.len() {
                if dmatch(&p[1..], &t[skip..]) {
                    return true;
                }
            }
            false
        }
        seg => {
            if t.is_empty() {
                return false;
            }
            if segment_match(seg, t[0]) {
                dmatch(&p[1..], &t[1..])
            } else {
                false
            }
        }
    }
}

/// Match a single path component against a glob segment (no `/` inside).
fn segment_match(seg: &str, comp: &str) -> bool {
    let s: Vec<char> = seg.chars().collect();
    let c: Vec<char> = comp.chars().collect();
    smatch(&s, &c)
}

fn smatch(s: &[char], c: &[char]) -> bool {
    if s.is_empty() {
        return c.is_empty();
    }
    match s[0] {
        '*' => {
            for take in 0..=c.len() {
                if smatch(&s[1..], &c[take..]) {
                    return true;
                }
            }
            false
        }
        '?' => !c.is_empty() && smatch(&s[1..], &c[1..]),
        '\\' => {
            if s.len() >= 2 {
                !c.is_empty() && s[1] == c[0] && smatch(&s[2..], &c[1..])
            } else {
                false
            }
        }
        ch => !c.is_empty() && ch == c[0] && smatch(&s[1..], &c[1..]),
    }
}

impl IgnorePattern {
    /// Does this pattern match `rel_path` (components from the scope root)?
    fn matches(&self, rel_path: &[&str], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        let joined = rel_path.join("/");
        if self.anchored {
            glob_match(&self.text, &joined)
        } else {
            // Unanchored: match basename, or any path ending in this pattern.
            // git matches a plain pattern against any suffix component, but to
            // keep semantics simple and match git's common behavior, match if
            // the whole path matches, OR any directory suffix matches.
            if glob_match(&self.text, &joined) {
                return true;
            }
            // Try each trailing suffix of the path.
            for i in 0..rel_path.len() {
                if glob_match(&self.text, &rel_path[i..].join("/")) {
                    return true;
                }
            }
            false
        }
    }
}

/// Ignore state accumulated while walking the working tree.
#[derive(Debug, Default, Clone)]
pub struct IgnoreState {
    /// `(scope_dir, patterns)` for each `.gitignore` read so far, in walk
    /// order (shallower first). `scope_dir` is the ignore file's directory as
    /// path components from the walk root.
    scopes: Vec<(Vec<PathBuf>, Vec<IgnorePattern>)>,
}

impl IgnoreState {
    /// Parse `.gitignore` file bytes into patterns.
    pub fn parse(bytes: &[u8]) -> Vec<IgnorePattern> {
        let text = String::from_utf8_lossy(bytes);
        let mut out = Vec::new();
        for line in text.lines() {
            let raw = line.trim_end();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let pat = raw;
            let (negate, rest) = match pat.strip_prefix('!') {
                Some(r) => (true, r),
                None => (false, pat),
            };
            let dir_only = rest.ends_with('/');
            let (anchored, text) = match rest.strip_prefix('/') {
                Some(r) => (true, r),
                None => (false, rest),
            };
            let text = text.trim_end_matches('/').to_string();
            out.push(IgnorePattern {
                text,
                negate,
                anchored,
                dir_only,
            });
        }
        out
    }

    /// Record a `.gitignore` found at directory `scope_dir` (components from
    /// the walk root).
    pub fn push_scope(&mut self, scope_dir: &[PathBuf], bytes: &[u8]) {
        let pats = Self::parse(bytes);
        if !pats.is_empty() {
            self.scopes.push((scope_dir.to_vec(), pats));
        }
    }

    /// Whether `name` (a child of `rel_path`) is ignored.
    pub fn is_ignored(&self, rel_path: &[String], name: &str, is_dir: bool) -> bool {
        // Build the full component path.
        let mut full: Vec<&str> = rel_path.iter().map(|s| s.as_str()).collect();
        full.push(name);
        // Evaluate innermost scope first so deeper rules win.
        for (scope_dir, patterns) in self.scopes.iter().rev() {
            if full.len() < scope_dir.len() {
                continue;
            }
            // The path must reside within this scope's directory.
            let within = (0..scope_dir.len()).all(|i| {
                full.get(i)
                    .map(|&s| s == scope_dir[i].to_str().unwrap_or(""))
                    == Some(true)
            });
            if !within {
                continue;
            }
            let rel_from_scope = &full[scope_dir.len()..];
            for p in patterns {
                if p.matches(rel_from_scope, is_dir) {
                    return !p.negate;
                }
            }
        }
        false
    }
}

/// Create a fresh ignore state.
pub fn default_ignore_state() -> IgnoreState {
    IgnoreState::default()
}
