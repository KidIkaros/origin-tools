// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-vcs.
//!
//! The working tree is the directory that owns the store (by default a hidden
//! `.origin-vcs/` subdirectory). Blobs are addressed by SHA3-256 of their
//! plaintext and stored encrypted; trees/commits likewise. All writes are
//! signed with the suite identity (or an explicit seed) and committed to an
//! append-only MMR.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::cli::Commands;
use crate::cli::*;
use crate::crypto::{resolve_keysource, KeySource, Signature};
use crate::object::{commit_address, Blob, Commit, FileMode, Tree, TreeEntry};
use crate::remote::is_ancestor;
use crate::store::Store;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn default_store(cwd: &Path) -> PathBuf {
    cwd.join(".origin-vcs")
}

/// Open the store at the resolved path and derive the storage key from the
/// key source so the same seed/identity can decrypt what `init` wrote.
/// Acquires an exclusive advisory lock so concurrent commands can't race the
/// index / refs / MMR (released when the returned Store is dropped).
fn resolve_store(store: &Option<String>, cwd: &Path, ks: &KeySource) -> Result<Store, String> {
    resolve_store_with_lock(store, cwd, ks, true)
}

/// Like [resolve_store] but with configurable locking. `remote serve` is
/// long-lived (foreground accept loop or detached daemon) so it must not hold
/// the exclusive lock — it would deadlock every client command on the same
/// store, including `serve --stop` itself.
fn resolve_store_with_lock(
    store: &Option<String>,
    cwd: &Path,
    ks: &KeySource,
    lock: bool,
) -> Result<Store, String> {
    let root = match store {
        Some(s) => PathBuf::from(s),
        None => default_store(cwd),
    };
    if !root.exists() {
        return Err(format!(
            "not a repository: '{}' (run 'origin-vcs init' first)",
            root.display()
        ));
    }
    // Derive the object-encryption key from the repo's recorded encrypt mode
    // (identity-HKDF or passphrase-Argon2id), then open the store under it so
    // whatever this command does reads/writes with the correct key.
    let key = crate::store::repo_storage_key(&root, ks)?;
    let mut store = if lock {
        Store::open_locked(&root, key)?
    } else {
        Store::open(&root, key)?
    };
    store.load_meta()?;
    Ok(store)
}

/// Recursively collect `(rel_path, abs_path)` for all visible files under
/// `dir`, skipping the store directory and any hidden path.
fn collect_files(dir: &Path, store_rel: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut out = BTreeMap::new();
    let mut ignore = crate::ignore::default_ignore_state();
    walk(dir, dir, store_rel, Vec::new(), &mut ignore, &mut out)?;
    Ok(out)
}

/// Untracked-side ignore always applies to `.gitignore` itself.
/// Recursively walk `current`, honoring `.gitignore` rules (git-style ignore
/// semantics via `ignore::IgnoreState`) and always excluding the store dir and
/// hidden entries. `rel_path` is the component path from the walk root.
fn walk(
    base: &Path,
    current: &Path,
    store_rel: &Path,
    rel_path: Vec<String>,
    ignore: &mut crate::ignore::IgnoreState,
    out: &mut BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    let mut entries: Vec<(PathBuf, String)> = Vec::new();
    for entry in std::fs::read_dir(current).map_err(|e| format!("read dir {:?}: {e}", current))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
        if rel == Path::new("") || rel.starts_with(store_rel) {
            continue;
        }
        if name.starts_with('.') && name != ".gitignore" {
            // Hidden entries are never auto-tracked (except .gitignore, which
            // is read for rules and excluded from tracking below); the
            // current store dir (if non-hidden) is additionally excluded via
            // store_rel above.
            continue;
        }
        entries.push((path, name));
    }
    // Read this directory's .gitignore (if any) BEFORE deciding children, and
    // apply it to children; git applies the file to its own directory.
    let mut scope_bytes: Option<Vec<u8>> = None;
    for (path, name) in &entries {
        if name == ".gitignore" {
            if let Ok(b) = std::fs::read(path) {
                scope_bytes = Some(b);
            }
            break;
        }
    }
    if let Some(bytes) = scope_bytes {
        ignore.push_scope(
            &rel_path.iter().map(PathBuf::from).collect::<Vec<_>>(),
            &bytes,
        );
    }

    for (path, name) in entries {
        if name == ".gitignore" {
            continue; // never tracked
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let rel_str = rel_of_components(&rel_path, &name);
        if meta.is_dir() {
            if ignore.is_ignored(&rel_path, &name, true) {
                continue;
            }
            let mut child_rel = rel_path.clone();
            child_rel.push(name.clone());
            walk(base, &path, store_rel, child_rel, ignore, out)?;
        } else if !ignore.is_ignored(&rel_path, &name, false) {
            // Regular files and symlinks.
            out.insert(rel_str, path);
        }
    }
    Ok(())
}

fn rel_of_components(rel_path: &[String], name: &str) -> String {
    if rel_path.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", rel_path.join("/"), name)
    }
}

/// The blob id a working file's bytes would address to.
fn working_file_id(data: &[u8]) -> [u8; 32] {
    crate::object::blob_address(&Blob::new(data.to_vec()))
}

fn short(id: &[u8; 32]) -> String {
    hex::encode(&id[..8])
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn whoami() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "host".into());
    format!("{user} <{user}@{host}>")
}

/// Resolve a string ref: <hex commit>, abbreviated <hex prefix>, branch name,
/// tag name, or "HEAD".
fn resolve_id(store: &Store, spec: &str) -> Result<[u8; 32], String> {
    if spec == "HEAD" || spec == "@" {
        let head = store.head_branch()?.ok_or("no HEAD")?;
        return store.read_ref("heads", &head);
    }
    // `~N` ancestor syntax: HEAD~2, <ref>~N, or <short-id>~N.
    if let Some((base, n)) = spec.rsplit_once('~') {
        let n: u32 = n
            .parse()
            .map_err(|_| format!("bad ancestor depth in '{spec}'"))?;
        if n == 0 {
            return resolve_id(store, base);
        }
        let mut cur = resolve_id(store, base)?;
        for _ in 0..n {
            let c = store.read_commit(&cur)?;
            let Some(p) = c.parents.first() else {
                return Err(format!("{spec}: not enough ancestors"));
            };
            cur = *p;
        }
        return Ok(cur);
    }
    if let Ok(bytes) = hex::decode(spec) {
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            return Ok(id);
        }
        if (4..32).contains(&bytes.len()) {
            return resolve_short_id(store, spec);
        }
    }
    if store.ref_exists("heads", spec) {
        return store.read_ref("heads", spec);
    }
    if store.ref_exists("tags", spec) {
        return store.read_ref("tags", spec);
    }
    Err(format!("unknown ref: {spec}"))
}

/// Resolve an abbreviated commit id against known tips (branches, tags,
/// remotes, HEAD) plus the commit log, falling back to a fanout scan of the
/// object store. Errors when the prefix is ambiguous.
fn resolve_short_id(store: &Store, prefix: &str) -> Result<[u8; 32], String> {
    let prefix = prefix.to_lowercase();
    let mut candidates: Vec<[u8; 32]> = Vec::new();
    if let Ok(Some(b)) = store.head_branch() {
        if let Ok(id) = store.read_ref("heads", &b) {
            candidates.push(id);
        }
    }
    for id in store.meta().branches.values() {
        candidates.push(*id);
    }
    for id in store.meta().tags.values() {
        candidates.push(*id);
    }
    if let Ok(ids) = store.remote_refs() {
        candidates.extend(ids);
    }
    if let Ok(log) = store.commit_log() {
        candidates.extend(log);
    }
    candidates.sort();
    candidates.dedup();
    let mut matches: Vec<[u8; 32]> = candidates
        .iter()
        .filter(|id| hex::encode(id).starts_with(&prefix))
        .copied()
        .collect();
    // Fallback: scan object fanout for ids matching the prefix (covers commits
    // reachable only by ancestry, e.g. a parent of a shallow boundary).
    if matches.is_empty() {
        let dirs = store.root().join("objects");
        if let Ok(rd) = std::fs::read_dir(&dirs) {
            for d in rd.flatten() {
                if !d.path().is_dir() {
                    continue;
                }
                let dir = d.file_name().to_string_lossy().to_string();
                if !prefix.starts_with(&dir) {
                    continue;
                }
                if let Ok(rd2) = std::fs::read_dir(d.path()) {
                    for f in rd2.flatten() {
                        let name = f.file_name().to_string_lossy().to_string();
                        let Some(rest) = name.strip_suffix(".env") else {
                            continue;
                        };
                        let full = format!("{dir}{rest}");
                        if full.starts_with(&prefix) {
                            if let Ok(bytes) = hex::decode(&full) {
                                let mut id = [0u8; 32];
                                id.copy_from_slice(&bytes);
                                matches.push(id);
                            }
                        }
                    }
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => Err(format!("unknown ref: {prefix}")),
        1 => Ok(matches[0]),
        _ => Err(format!("ambiguous ref: {prefix}")),
    }
}

fn detect_mode(path: &Path) -> FileMode {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::symlink_metadata(path) {
            if m.file_type().is_symlink() {
                return FileMode::Symlink;
            }
            return FileMode::from_permissions(m.permissions().mode());
        }
        FileMode::File
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        FileMode::File
    }
}

/// The blob bytes a working path contributes: a symlink's link target string,
/// or the file's content. (Symlinks are stored git-style as the target path.)
fn path_blob_data(abs: &Path) -> Result<Vec<u8>, String> {
    if detect_mode(abs).is_symlink() {
        let target = std::fs::read_link(abs).map_err(|e| format!("readlink {:?}: {e}", abs))?;
        Ok(target.to_string_lossy().as_bytes().to_vec())
    } else {
        std::fs::read(abs).map_err(|e| format!("read {:?}: {e}", abs))
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

pub fn cmd_init(args: InitArgs, cwd: &Path) -> Result<(), String> {
    let root = match &args.store {
        Some(s) => PathBuf::from(s),
        None => default_store(cwd),
    };
    if root.exists() && !args.force {
        return Err(format!(
            "store already exists at '{}' (use --force to re-initialize)",
            root.display()
        ));
    }
    std::fs::create_dir_all(&root).map_err(|e| format!("create store: {e}"))?;

    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;

    // Record how at-rest object encryption keys are derived. `passphrase` mode
    // needs a per-repo random salt persisted so opens can re-derive the key.
    // The tier governs Argon2id cost for passphrase-mode key derivation.
    origin_common::tier_from_str(&args.tier)
        .map_err(|e| format!("invalid tier '{}': {e}", args.tier))?;
    let cfg = if args.encrypt == "passphrase" {
        let mut salt = [0u8; 16];
        origin_crypto_sdk::fill_random(&mut salt)
            .map_err(|e| format!("salt generation failed: {e}"))?;
        crate::store::RepoConfig {
            encrypt: "passphrase".into(),
            salt: Some(hex::encode(salt)),
            default_branch: Some(args.branch.clone()),
            tier: args.tier.clone(),
        }
    } else {
        crate::store::RepoConfig {
            encrypt: "identity".into(),
            salt: None,
            default_branch: Some(args.branch.clone()),
            tier: args.tier.clone(),
        }
    };
    crate::store::write_repo_config(&root, &cfg)?;

    let key = crate::store::repo_storage_key(&root, &ks)?;
    let mut store = Store::open(&root, key)?;
    store.set_head(Some(args.branch.clone()))?;
    store.load_meta()?;
    println!(
        "initialized encrypted repository at {} (branch: {}, encrypt: {})",
        root.display(),
        args.branch,
        cfg.encrypt
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// add / rm / status
// ---------------------------------------------------------------------------

pub fn cmd_add(args: AddArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;
    let store_rel = store
        .root()
        .strip_prefix(cwd)
        .unwrap_or(store.root())
        .to_path_buf();
    let files = collect_files(cwd, &store_rel)?;

    // Stage a file, optionally streaming it through chunked encryption.
    // Symlinks are stored as their link-target string (never streamed).
    let stage = |store: &Store, abs: &Path| -> Result<[u8; 32], String> {
        if detect_mode(abs).is_symlink() {
            let data = path_blob_data(abs)?;
            store.write_blob(&data)
        } else if args.stream {
            store.write_blob_stream(abs, args.chunk_size)
        } else {
            let data = std::fs::read(abs).map_err(|e| format!("read: {e}"))?;
            store.write_blob(&data)
        }
    };

    let mut index = store.load_index()?;
    let mut staged = 0usize;
    for arg in &args.paths {
        let p = Path::new(arg);
        let rel_s = if p.is_absolute() {
            p.strip_prefix(cwd)
                .map(|r| r.to_string_lossy().to_string())
                .unwrap_or_else(|_| arg.clone())
        } else {
            arg.trim_start_matches("./").to_string()
        };
        if files.contains_key(&rel_s) && p.is_file() {
            let id = stage(&store, &files[&rel_s])?;
            let mode = detect_mode(&files[&rel_s]);
            index.entries.insert(rel_s, TreeEntry { mode, id });
            staged += 1;
        } else if p.is_dir() {
            // Stage every collected file under this directory. A trailing
            // slash is normalized away; "." means the whole tree.
            let prefix = rel_s.trim_end_matches('/');
            let to_stage: Vec<(String, PathBuf)> = files
                .iter()
                .filter(|(r, _)| {
                    prefix == "."
                        || r.strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
                .map(|(r, a)| (r.clone(), a.clone()))
                .collect();
            for (r, abs) in to_stage {
                let id = stage(&store, &abs)?;
                let mode = detect_mode(&abs);
                index.entries.insert(r.clone(), TreeEntry { mode, id });
                staged += 1;
            }
        } else {
            return Err(format!("path not found: {arg}"));
        }
    }
    store.save_index(&index)?;
    println!("staged {staged} file(s)");
    Ok(())
}

pub fn cmd_rm(args: RmArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;
    let mut index = store.load_index()?;
    let mut removed = 0usize;
    for p in &args.paths {
        if index.entries.remove(p).is_some() {
            removed += 1;
        }
    }
    store.save_index(&index)?;
    println!("removed {removed} path(s) from index");
    Ok(())
}

pub fn cmd_status(args: StatusArgs, cwd: &Path) -> Result<(), String> {
    let dir_root = match &args.dir {
        Some(d) => PathBuf::from(d),
        None => cwd.to_path_buf(),
    };
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, &dir_root, &ks)?;
    let store_rel = store
        .root()
        .strip_prefix(&dir_root)
        .unwrap_or(store.root())
        .to_path_buf();
    let files = collect_files(&dir_root, &store_rel)?;
    let index = store.load_index()?;

    let branch = store.head_branch()?.unwrap_or_else(|| "detached".into());

    let mut staged = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut untracked = Vec::new();

    for (rel, entry) in &index.entries {
        let disk_id = match files.get(rel) {
            None => None,
            Some(abs) => match path_blob_data(abs) {
                Ok(data) => Some(working_file_id(&data)),
                Err(_) => None,
            },
        };
        match disk_id {
            None => deleted.push(rel.clone()),
            Some(id) if id == entry.id => staged.push(rel.clone()),
            Some(_) => modified.push(rel.clone()),
        }
    }
    for rel in files.keys() {
        if !index.entries.contains_key(rel) {
            untracked.push(rel.clone());
        }
    }

    // Merge-in-progress reporting: list working files carrying conflict
    // markers (the unmerged paths) while MERGE_STATE is recorded.
    let in_merge = load_merge_state(&store)?.is_some();
    let mut unmerged = Vec::new();
    if in_merge {
        for (rel, abs) in &files {
            if let Ok(data) = path_blob_data(abs) {
                if has_conflict_markers(&data) {
                    unmerged.push(rel.clone());
                }
            }
        }
    }

    if args.json {
        let out = serde_json::json!({
            "branch": branch,
            "staged": staged,
            "modified": modified,
            "deleted": deleted,
            "untracked": untracked,
            "merge_in_progress": in_merge,
            "unmerged": unmerged,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    println!("On branch {branch}");
    if in_merge {
        println!("You have unmerged paths; fix conflicts and commit, or 'merge --abort'");
    }
    for p in &unmerged {
        println!("  U {p}");
    }
    for p in &modified {
        println!("  M {p}");
    }
    for p in &deleted {
        println!("  D {p}");
    }
    for p in &staged {
        println!("  S {p}");
    }
    for p in &untracked {
        println!("  ?? {p}");
    }
    if modified.is_empty() && deleted.is_empty() && untracked.is_empty() && staged.is_empty() {
        println!("nothing to commit, working tree clean");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// commit / log / show
// ---------------------------------------------------------------------------

pub fn cmd_commit(args: CommitArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;

    // A conflicting merge leaves MERGE_STATE; the commit then completes the
    // merge with parents [head, other] instead of the linear parent (amend
    // is not allowed mid-merge).
    let merge_state = load_merge_state(&store)?;
    if args.amend && merge_state.is_some() {
        return Err("cannot amend during a merge; complete or abort the merge first".into());
    }
    let index = store.load_index()?;
    if index.entries.is_empty() && merge_state.is_none() {
        return Err("nothing to commit (index is empty; use 'add')".into());
    }

    let branch = store
        .head_branch()?
        .ok_or("no branch checked out (init first)")?;

    // Amend: reuse HEAD's parent(s) and (if -m is empty) its tree so late
    // stages fold in; otherwise take the staged index as the new tree.
    let (parent_ids, tree_id, message) = if args.amend {
        if !store.ref_exists("heads", &branch) {
            return Err("nothing to amend (no commits on this branch yet)".into());
        }
        let head_id = store.read_ref("heads", &branch)?;
        let head_commit = store.read_commit(&head_id)?;
        let new_tree = store.write_tree(&index)?;
        let msg = if args.message.is_empty() {
            head_commit.message.clone()
        } else {
            args.message.clone()
        };
        (head_commit.parents.clone(), new_tree, msg)
    } else {
        let parents = match &merge_state {
            Some(st) => vec![st.head_id, st.other_id],
            None => {
                if store.ref_exists("heads", &branch) {
                    vec![store.read_ref("heads", &branch)?]
                } else {
                    Vec::new()
                }
            }
        };
        let tree_id = store.write_tree(&index)?;
        (parents, tree_id, args.message)
    };

    let mut commit = Commit::new();
    commit.tree = tree_id;
    commit.parents = parent_ids;
    commit.message = message;
    commit.author = args.author.unwrap_or_else(whoami);
    commit.committer = commit.author.clone();
    commit.ts = args.date.unwrap_or_else(now_ts);

    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&commit));
    let id = store.write_commit(&commit, &sig)?;

    store.write_ref("heads", &branch, id, &sig)?;
    store.update_mem_ref("heads", &branch, id);
    store.append_commit_leaf(&id)?;

    if args.amend {
        println!("[{branch} {}] (amended) {}", short(&id), commit.message);
    } else if merge_state.is_some() {
        clear_merge_state(&store);
        println!(
            "[{branch} {}] merge completed: {}",
            short(&id),
            commit.message
        );
    } else {
        println!("[{branch} {}] {}", short(&id), commit.message);
    }
    Ok(())
}

pub fn cmd_log(args: LogArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;
    let start = match &args.from {
        Some(spec) => resolve_id(&store, spec)?,
        None => {
            let branch = store.head_branch()?.ok_or("no HEAD")?;
            store.read_ref("heads", &branch)?
        }
    };

    let mut cur = start;
    let mut entries: Vec<(String, Commit)> = Vec::new();
    for _ in 0..args.max.unwrap_or(usize::MAX) {
        // On a shallow clone the boundary commit's parent objects are absent;
        // that is the end of local history, not an error.
        let record = match store.read_commit_record(&cur) {
            Ok(r) => r,
            Err(_) if store.is_shallow() => break,
            Err(e) => return Err(format!("commit {} unreadable: {e}", short(&cur))),
        };
        entries.push((hex::encode(cur), record.commit.clone()));
        match record.commit.parents.first() {
            Some(p) => cur = *p,
            None => break,
        }
    }

    if args.json {
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .map(|(id, c)| {
                serde_json::json!({
                    "id": id,
                    "tree": hex::encode(c.tree),
                    "parents": c.parents.iter().map(hex::encode).collect::<Vec<_>>(),
                    "message": c.message,
                    "author": c.author,
                    "ts": c.ts,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        return Ok(());
    }

    for (id, c) in &entries {
        if args.oneline {
            println!("{} {}", &id[..8], c.message);
        } else {
            println!("commit {}", id);
            println!("    {} ({})", c.message, c.author);
            println!();
        }
    }
    Ok(())
}

pub fn cmd_show(args: ShowArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;
    let id = resolve_id(&store, &args.id)?;
    let record = store.read_commit_record(&id)?;
    let commit = record.commit;

    if let Some(path) = &args.path {
        let tree = store.read_tree(&commit.tree)?;
        let entry = tree
            .entries
            .get(path)
            .ok_or_else(|| format!("path not in tree: {path}"))?;
        let blob = store.read_blob(&entry.id)?;
        std::io::Write::write_all(&mut std::io::stdout(), &blob.data)
            .map_err(|e| format!("write stdout: {e}"))?;
        return Ok(());
    }

    println!("commit {}", hex::encode(id));
    println!("  tree:     {}", hex::encode(commit.tree));
    println!(
        "  parent(s): {}",
        commit
            .parents
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("  author:   {}", commit.author);
    println!("\n  {}", commit.message);
    Ok(())
}

// ---------------------------------------------------------------------------
// branch / tag / checkout / reset
// ---------------------------------------------------------------------------

pub fn cmd_branch(args: BranchArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;

    if let Some(del) = args.delete {
        store.delete_ref("heads", &del)?;
        println!("deleted branch {del}");
        return Ok(());
    }

    if let Some(pair) = args.mv {
        if pair.len() != 2 {
            return Err("branch --move needs <old> <new>".into());
        }
        let old = &pair[0];
        let new = &pair[1];
        if !store.ref_exists("heads", old) {
            return Err(format!("branch does not exist: {old}"));
        }
        if store.ref_exists("heads", new) {
            return Err(format!("branch exists: {new}"));
        }
        let tip = store.read_ref("heads", old)?;
        let bundle = ks.signing_bundle()?;
        let sig = crate::crypto::Signature::sign(&bundle, &tip);
        store.write_ref("heads", new, tip, &sig)?;
        store.update_mem_ref("heads", new, tip);
        store.delete_ref("heads", old)?;
        store.meta_mut().branches.remove(old);
        // HEAD follows the rename when the current branch was moved.
        if store.head_branch()?.as_deref() == Some(old.as_str()) {
            store.set_head(Some(new.clone()))?;
        }
        println!("moved branch {old} -> {new}");
        return Ok(());
    }

    match args.name {
        None => {
            let branch = store.head_branch()?.unwrap_or_else(|| "-".into());
            let mut names: Vec<String> = store.meta().branches.keys().cloned().collect();
            names.sort();
            for n in names {
                let marker = if n == branch { "*" } else { " " };
                println!("{marker} {n}");
            }
        }
        Some(name) => {
            let from = match &args.from {
                Some(spec) => resolve_id(&store, spec)?,
                None => {
                    let head = store.head_branch()?.ok_or("no HEAD to branch from")?;
                    store.read_ref("heads", &head)?
                }
            };
            if store.ref_exists("heads", &name) {
                return Err(format!("branch exists: {name}"));
            }
            let bundle = ks.signing_bundle()?;
            let sig = crate::crypto::Signature::sign(&bundle, &from);
            store.write_ref("heads", &name, from, &sig)?;
            store.update_mem_ref("heads", &name, from);
            println!("created branch {name}");
        }
    }
    Ok(())
}

pub fn cmd_tag(args: TagArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;
    if let Some(del) = args.delete {
        if !store.ref_exists("tags", &del) {
            return Err(format!("tag does not exist: {del}"));
        }
        store.delete_ref("tags", &del)?;
        store.meta_mut().tags.remove(&del);
        println!("deleted tag {del}");
        return Ok(());
    }
    match args.name {
        None => {
            let mut tags: Vec<String> = store.meta().tags.keys().cloned().collect();
            tags.sort();
            for t in tags {
                println!("{t}");
            }
            Ok(())
        }
        Some(name) => {
            let target = match &args.target {
                Some(t) => resolve_id(&store, t)?,
                None => {
                    let head = store.head_branch()?.ok_or("no HEAD")?;
                    store.read_ref("heads", &head)?
                }
            };
            let mut tag = crate::object::Tag::new(&name);
            tag.target = target;
            tag.message = args.message.unwrap_or_default();
            tag.ts = now_ts();
            let body = serde_json::to_vec(&tag).map_err(|e| format!("tag ser: {e}"))?;
            let bundle = ks.signing_bundle()?;
            let sig = Signature::sign(&bundle, &body);
            let id = store.write_tag(&tag)?;
            store.write_ref("tags", &name, id, &sig)?;
            store.update_mem_ref("tags", &name, id);
            println!("tagged <{}> as {name}", short(&target));
            Ok(())
        }
    }
}

pub(crate) fn ensure_tree_on_disk(
    store: &Store,
    tree: &Tree,
    dir_root: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(dir_root)
        .map_err(|e| format!("mkdir {:?}: {e}", dir_root.display()))?;
    let store_rel = store
        .root()
        .strip_prefix(dir_root)
        .unwrap_or(store.root())
        .to_path_buf();
    let sparse = store.sparse_paths()?;
    let existing = collect_files(dir_root, &store_rel)?;
    for rel in existing.keys() {
        if sparse_in_scope(&sparse, rel) && !tree.entries.contains_key(rel) {
            let _ = std::fs::remove_file(dir_root.join(rel));
        }
    }
    for (rel, entry) in &tree.entries {
        if !sparse_in_scope(&sparse, rel) {
            continue;
        }
        let target = dir_root.join(rel);
        write_entry_to_disk(store, entry, &target, false)?;
    }
    let _ = (store_rel, existing);
    Ok(())
}

/// Whether `rel` falls under the active sparse-checkout set (empty set =
/// everything in scope). Paths match the prefix or anything beneath it.
fn sparse_in_scope(sparse: &[String], rel: &str) -> bool {
    sparse.is_empty()
        || sparse
            .iter()
            .any(|p| rel == p || rel.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
}

/// Like [ensure_tree_on_disk], but writes each blob through the store's
/// bounded-memory path (`read_blob_to_path`), so a large streamed checkout
/// never buffers a whole file. Mode restoration is identical.
pub(crate) fn ensure_tree_on_disk_streamed(
    store: &Store,
    tree: &Tree,
    dir_root: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(dir_root)
        .map_err(|e| format!("mkdir {:?}: {e}", dir_root.display()))?;
    let store_rel = store
        .root()
        .strip_prefix(dir_root)
        .unwrap_or(store.root())
        .to_path_buf();
    let sparse = store.sparse_paths()?;
    let existing = collect_files(dir_root, &store_rel)?;
    for rel in existing.keys() {
        if sparse_in_scope(&sparse, rel) && !tree.entries.contains_key(rel) {
            let _ = std::fs::remove_file(dir_root.join(rel));
        }
    }
    for (rel, entry) in &tree.entries {
        if !sparse_in_scope(&sparse, rel) {
            continue;
        }
        let target = dir_root.join(rel);
        write_entry_to_disk(store, entry, &target, true)?;
    }
    Ok(())
}

/// Write one tree entry to disk. Symlinks are recreated from their stored
/// target string (git-style); regular/executable files are written either
/// buffered or via the store's bounded-memory path (`stream=true`).
pub(crate) fn write_entry_to_disk(
    store: &Store,
    entry: &crate::object::TreeEntry,
    target: &Path,
    stream: bool,
) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {:?}: {e}", parent.display()))?;
        }
    }

    if entry.mode.is_symlink() {
        // Symlink: content is the link target string.
        let blob = store.read_blob(&entry.id)?;
        let target_str = String::from_utf8_lossy(&blob.data).to_string();
        let _ = std::fs::remove_file(target);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target_str, target)
                .map_err(|e| format!("symlink {:?} -> {target_str}: {e}", target))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(target, &target_str)
                .map_err(|e| format!("write {:?}: {e}", target.display()))?;
        }
        return Ok(());
    }

    if stream {
        store.read_blob_to_path(&entry.id, target)?;
    } else {
        let blob = store.read_blob(&entry.id)?;
        origin_common::atomic_write(target, &blob.data)
            .map_err(|e| format!("write {:?}: {e}", target.display()))?;
    }
    if entry.mode == FileMode::Executable {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(target)
                .map_err(|e| format!("meta: {e}"))?
                .permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(target, p).map_err(|e| format!("chmod: {e}"))?;
        }
    }
    Ok(())
}

pub fn cmd_checkout(args: CheckoutArgs, cwd: &Path) -> Result<(), String> {
    let dir_root = match &args.dir {
        Some(d) => PathBuf::from(d),
        None => cwd.to_path_buf(),
    };
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, &dir_root, &ks)?;
    // `--path` switches on a sparse checkout; without it, the sparse set is
    // cleared and the full tree is restored (any later pull/merge also
    // materializes the whole tree again).
    if args.path.is_empty() {
        store.set_sparse(&[])?;
    } else {
        store.set_sparse(&args.path)?;
    }
    let id = resolve_id(&store, &args.target)?;
    let commit = store.read_commit(&id)?;
    let tree = store.read_tree(&commit.tree)?;

    let is_branch = store.ref_exists("heads", &args.target);
    let branch = if is_branch {
        args.target.clone()
    } else {
        "detached".to_string()
    };
    if is_branch {
        store.set_head(Some(branch.clone()))?;
    }

    store.save_index(&tree)?;
    if args.stream {
        ensure_tree_on_disk_streamed(&store, &tree, &dir_root)?;
    } else {
        ensure_tree_on_disk(&store, &tree, &dir_root)?;
    }
    println!("checked out {} ({})", branch, short(&id));
    Ok(())
}

pub fn cmd_reset(args: ResetArgs, cwd: &Path) -> Result<(), String> {
    let dir_root = match &args.dir {
        Some(d) => PathBuf::from(d),
        None => cwd.to_path_buf(),
    };
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, &dir_root, &ks)?;
    let id = resolve_id(&store, &args.id)?;
    let commit = store.read_commit(&id)?;

    let branch = store.head_branch()?.ok_or("no HEAD")?;
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &id);
    store.write_ref("heads", &branch, id, &sig)?;
    store.update_mem_ref("heads", &branch, id);

    if args.mode.as_deref() == Some("hard") {
        let tree = store.read_tree(&commit.tree)?;
        store.save_index(&tree)?;
        ensure_tree_on_disk(&store, &tree, &dir_root)?;
    }
    println!(
        "reset {branch} to {} ({})",
        short(&id),
        args.mode.as_deref().unwrap_or("soft")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// diff / merge / verify / mmr
// ---------------------------------------------------------------------------

fn tree_of_spec(store: &Store, spec: Option<&str>, dir_root: &Path) -> Result<Tree, String> {
    match spec {
        Some(s) => {
            let id = resolve_id(store, s)?;
            let c = store.read_commit(&id)?;
            store.read_tree(&c.tree)
        }
        None => {
            let store_rel = store
                .root()
                .strip_prefix(dir_root)
                .unwrap_or(store.root())
                .to_path_buf();
            let files = collect_files(dir_root, &store_rel)?;
            let mut tree = Tree::new();
            for (rel, abs) in &files {
                if let Ok(data) = path_blob_data(abs) {
                    let id = working_file_id(&data);
                    tree.entries.insert(
                        rel.clone(),
                        TreeEntry {
                            mode: detect_mode(abs),
                            id,
                        },
                    );
                }
            }
            Ok(tree)
        }
    }
}

pub fn cmd_diff(args: DiffArgs, cwd: &Path) -> Result<(), String> {
    let dir_root = match &args.dir {
        Some(d) => PathBuf::from(d),
        None => cwd.to_path_buf(),
    };
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, &dir_root, &ks)?;
    let a = tree_of_spec(&store, args.a.as_deref(), &dir_root)?;
    let b = tree_of_spec(&store, args.b.as_deref(), &dir_root)?;

    let paths: BTreeSet<String> = a.entries.keys().chain(b.entries.keys()).cloned().collect();
    let mut changed = 0usize;
    for p in paths {
        if let Some(only) = args.path.as_deref() {
            if p != only {
                continue;
            }
        }
        let ea = a.entries.get(&p);
        let eb = b.entries.get(&p);
        match (ea, eb) {
            (None, Some(_)) => {
                println!("+ {p}");
                changed += 1;
            }
            (Some(_), None) => {
                println!("- {p}");
                changed += 1;
            }
            (Some(x), Some(y)) if x.id != y.id => {
                println!("M {p}");
                changed += 1;
            }
            _ => {}
        }
    }
    if changed == 0 {
        println!("(no differences)");
    }
    Ok(())
}

/// Lowest common ancestor of two commits in the parent DAG. Assumes the two
/// commits are related; if not, conservatively returns the root of `b`.
fn merge_base(store: &Store, a: [u8; 32], b: [u8; 32]) -> Result<[u8; 32], String> {
    fn ancestors(store: &Store, start: [u8; 32]) -> Result<BTreeSet<[u8; 32]>, String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let c = store.read_commit(&id)?;
            for p in &c.parents {
                stack.push(*p);
            }
        }
        Ok(seen)
    }

    let anc_a = ancestors(store, a)?;
    let mut cur = b;
    loop {
        if anc_a.contains(&cur) {
            return Ok(cur);
        }
        let c = store.read_commit(&cur)?;
        let Some(p) = c.parents.first() else {
            return Ok(cur);
        };
        cur = *p;
    }
}

/// Persisted state of an in-progress merge. A merge that hits conflicts is
/// NOT committed: the merged (marker-bearing) tree is written to the index
/// and working tree and the state below is recorded so `commit` can complete
/// the merge (parents = [head, other]) or `merge --abort` can undo it.
#[derive(serde::Serialize, serde::Deserialize)]
struct MergeState {
    head_branch: String,
    head_id: [u8; 32],
    other_id: [u8; 32],
    other_name: String,
    base_id: [u8; 32],
    message: String,
}

fn merge_state_path(store: &Store) -> PathBuf {
    store.root().join("MERGE_STATE")
}

fn load_merge_state(store: &Store) -> Result<Option<MergeState>, String> {
    let path = merge_state_path(store);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("merge state parse: {e}")),
        Err(_) => Ok(None),
    }
}

fn save_merge_state(store: &Store, st: &MergeState) -> Result<(), String> {
    let body = serde_json::to_vec(st).map_err(|e| format!("merge state ser: {e}"))?;
    origin_common::atomic_write(&merge_state_path(store), &body)
        .map_err(|e| format!("write merge state: {e}"))
}

fn clear_merge_state(store: &Store) {
    let _ = std::fs::remove_file(merge_state_path(store));
}

/// Whether the bytes contain textual merge conflict markers
/// (`<<<<<<< ` / `>>>>>>> `), as emitted by textmerge.
fn has_conflict_markers(data: &[u8]) -> bool {
    for line in data.split(|b| *b == b'\n') {
        if line.starts_with(b"<<<<<<< ") || line.starts_with(b">>>>>>> ") {
            return true;
        }
    }
    false
}

/// Undo an in-progress merge: restore the head branch ref, index, and
/// working tree to the pre-merge state and drop the recorded state.
fn abort_merge(store: &mut Store, ks: &KeySource, cwd: &Path) -> Result<(), String> {
    let Some(state) = load_merge_state(store)? else {
        return Err("no merge in progress to abort".into());
    };
    let head_commit = store.read_commit(&state.head_id)?;
    let tree = store.read_tree(&head_commit.tree)?;
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&head_commit));
    store.write_ref("heads", &state.head_branch, state.head_id, &sig)?;
    store.update_mem_ref("heads", &state.head_branch, state.head_id);
    store.save_index(&tree)?;
    ensure_tree_on_disk(store, &tree, cwd)?;
    clear_merge_state(store);
    println!(
        "merge aborted; {} restored to {}",
        state.head_branch,
        short(&state.head_id)
    );
    Ok(())
}

pub fn cmd_merge(args: MergeArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;

    if store.is_shallow() {
        return Err(
            "merge on a shallow clone is not supported; fetch the full history first (re-clone without --shallow)"
                .into(),
        );
    }

    if args.abort {
        return abort_merge(&mut store, &ks, cwd);
    }

    let head_branch = store.head_branch()?.ok_or("no HEAD")?;
    let head = store.read_ref("heads", &head_branch)?;
    let other = resolve_id(&store, &args.branch)?;

    let base = merge_base(&store, head, other)?;

    // Already up to date?
    if base == other {
        println!("already up to date");
        return Ok(());
    }
    // Fast-forward when other descends from head.
    if base == head {
        let other_commit = store.read_commit(&other)?;
        let tree = store.read_tree(&other_commit.tree)?;
        let bundle = ks.signing_bundle()?;
        let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&other_commit));
        store.write_ref("heads", &head_branch, other, &sig)?;
        store.update_mem_ref("heads", &head_branch, other);
        store.save_index(&tree)?;
        ensure_tree_on_disk(&store, &tree, cwd)?;
        println!("fast-forwarded {head_branch} to {}", short(&other));
        return Ok(());
    }

    // Real 3-way merge.
    let head_commit = store.read_commit(&head)?;
    let other_commit = store.read_commit(&other)?;
    let base_commit = store.read_commit(&base)?;
    let head_tree = store.read_tree(&head_commit.tree)?;
    let other_tree = store.read_tree(&other_commit.tree)?;
    let base_tree = store.read_tree(&base_commit.tree)?;

    let (merged, conflicts) = match args.strategy.as_str() {
        "textual" => three_way_textual(&store, &base_tree, &head_tree, &other_tree)?,
        _ => three_way(&base_tree, &head_tree, &other_tree)?,
    };

    if !conflicts.is_empty() {
        // Git-style: leave the merged (marker-bearing) tree in the index and
        // working tree, record the merge state, and do NOT commit. The user
        // resolves the markers, then `commit` completes the merge.
        let state = MergeState {
            head_branch: head_branch.clone(),
            head_id: head,
            other_id: other,
            other_name: args.branch.clone(),
            base_id: base,
            message: args.message.clone(),
        };
        save_merge_state(&store, &state)?;
        store.save_index(&merged)?;
        ensure_tree_on_disk(&store, &merged, cwd)?;
        println!(
            "merge of {} into {head_branch} has conflicts in: {}",
            args.branch,
            conflicts.join(", ")
        );
        println!(
            "resolve the conflicts, then 'commit' to complete the merge, or 'merge --abort' to undo"
        );
        return Ok(());
    }

    let bundle = ks.signing_bundle()?;
    let mut mc = Commit::new();
    mc.tree = store.write_tree(&merged)?;
    mc.parents = vec![head, other];
    mc.message = args.message;
    mc.author = whoami();
    mc.committer = mc.author.clone();
    mc.ts = now_ts();
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&mc));
    let mid = store.write_commit(&mc, &sig)?;
    store.write_ref("heads", &head_branch, mid, &sig)?;
    store.update_mem_ref("heads", &head_branch, mid);
    store.append_commit_leaf(&mid)?;
    store.save_index(&merged)?;
    ensure_tree_on_disk(&store, &merged, cwd)?;

    println!(
        "merged {} into {head_branch} as {}",
        args.branch,
        short(&mid)
    );
    Ok(())
}

/// Deterministic three-way file-level combine. Returns the merged flat tree
/// plus the paths that conflicted (both sides changed a path differently;
/// v1 policy resolves those in favor of `ours`). Callers decide whether a
/// conflict means "record state and stop" (git-style) or "keep ours".
fn three_way(base: &Tree, ours: &Tree, theirs: &Tree) -> Result<(Tree, Vec<String>), String> {
    let paths: BTreeSet<String> = base
        .entries
        .keys()
        .chain(ours.entries.keys())
        .chain(theirs.entries.keys())
        .cloned()
        .collect();

    let mut merged = Tree::new();
    let mut conflicts: Vec<String> = Vec::new();

    for p in paths {
        let b = base.entries.get(&p).cloned();
        let o = ours.entries.get(&p).cloned();
        let t = theirs.entries.get(&p).cloned();

        let chosen: Option<TreeEntry> = match (&b, &o, &t) {
            // No side has it -> skip.
            (None, None, None) => None,
            // Present in base:
            (Some(be), oo, tt) => {
                let base_id = be.id;
                let o_unchanged = oo.as_ref().is_some_and(|e| e.id == base_id);
                let t_unchanged = tt.as_ref().is_some_and(|e| e.id == base_id);
                match (o_unchanged, t_unchanged) {
                    // both unchanged -> base
                    (true, true) => b.clone(),
                    // one side changed, other unchanged -> the change; if the
                    // "changed" side is actually absent/removed, take that.
                    (false, true) => o.clone().or(b.clone()),
                    (true, false) => t.clone().or(b.clone()),
                    // both changed:
                    (false, false) => match (oo, tt) {
                        // both removed -> remove
                        (None, None) => None,
                        // both changed identically -> keep
                        (Some(oe), Some(te)) if oe.id == te.id => Some(oe.clone()),
                        // one removed, other changed -> conflict (keep the change)
                        (None, Some(te)) => {
                            conflicts.push(p.clone());
                            Some(te.clone())
                        }
                        (Some(oe), None) => {
                            conflicts.push(p.clone());
                            Some(oe.clone())
                        }
                        // both changed differently -> conflict (keep ours)
                        (Some(oe), Some(_)) => {
                            conflicts.push(p.clone());
                            Some(oe.clone())
                        }
                    },
                }
            }
            // Not in base:
            (None, oo, tt) => match (oo, tt) {
                (None, None) => None,
                (Some(oe), Some(te)) if oe.id == te.id => Some(oe.clone()),
                (Some(oe), Some(_)) => {
                    conflicts.push(p.clone());
                    Some(oe.clone())
                }
                (Some(oe), None) => Some(oe.clone()),
                (None, Some(te)) => Some(te.clone()),
            },
        };

        if let Some(e) = chosen {
            merged.entries.insert(p, e);
        }
    }

    Ok((merged, conflicts))
}

/// Textual three-way merge (Phase 11). Same tree walk as [three_way], but for
/// paths both sides changed differently it reads the base/ours/theirs *blobs*
/// and runs the line diff resolver (`textmerge`), so non-overlapping edits
/// auto-merge and real clashes emit conflict markers. Returns the merged tree
/// plus the conflicted paths.
pub fn three_way_textual(
    store: &Store,
    base: &Tree,
    ours: &Tree,
    theirs: &Tree,
) -> Result<(Tree, Vec<String>), String> {
    let paths: BTreeSet<String> = base
        .entries
        .keys()
        .chain(ours.entries.keys())
        .chain(theirs.entries.keys())
        .cloned()
        .collect();

    let mut merged = Tree::new();
    let mut conflicts: Vec<String> = Vec::new();

    for p in paths {
        let b = base.entries.get(&p).cloned();
        let o = ours.entries.get(&p).cloned();
        let t = theirs.entries.get(&p).cloned();

        let chosen: Option<crate::object::TreeEntry> = match (&b, &o, &t) {
            (None, None, None) => None,
            (Some(be), oo, tt) => {
                let base_id = be.id;
                let o_unchanged = oo.as_ref().is_some_and(|e| e.id == base_id);
                let t_unchanged = tt.as_ref().is_some_and(|e| e.id == base_id);
                match (o_unchanged, t_unchanged) {
                    (true, true) => b.clone(),
                    (false, true) => o.clone().or(b.clone()),
                    (true, false) => t.clone().or(b.clone()),
                    (false, false) => match (oo, tt) {
                        (None, None) => None,
                        (Some(oe), Some(te)) if oe.id == te.id => Some(oe.clone()),
                        (None, Some(te)) => {
                            conflicts.push(p.clone());
                            Some(te.clone())
                        }
                        (Some(oe), None) => {
                            conflicts.push(p.clone());
                            Some(oe.clone())
                        }
                        // Both changed this blob differently: textual merge.
                        (Some(oe), Some(te)) => {
                            let base_bytes = store.read_blob(&base_id)?.data;
                            let ours_bytes = store.read_blob(&oe.id)?.data;
                            let theirs_bytes = store.read_blob(&te.id)?.data;
                            let (bytes, marker) = crate::textmerge::merge_lines(
                                &base_bytes,
                                &ours_bytes,
                                &theirs_bytes,
                            );
                            if marker {
                                conflicts.push(p.clone());
                            }
                            let id = store.write_blob(&bytes)?;
                            Some(crate::object::TreeEntry { mode: oe.mode, id })
                        }
                    },
                }
            }
            (None, oo, tt) => {
                let oe = oo.clone();
                let te = tt.clone();
                match (oe, te) {
                    (None, None) => None,
                    (Some(oe), Some(te)) if oe.id == te.id => Some(oe.clone()),
                    (Some(oe), Some(te)) => {
                        let base_bytes: Vec<u8> = Vec::new(); // absent in base
                        let ours_bytes = store.read_blob(&oe.id)?.data;
                        let theirs_bytes = store.read_blob(&te.id)?.data;
                        let (bytes, marker) =
                            crate::textmerge::merge_lines(&base_bytes, &ours_bytes, &theirs_bytes);
                        if marker {
                            conflicts.push(p.clone());
                        }
                        let id = store.write_blob(&bytes)?;
                        Some(crate::object::TreeEntry { mode: oe.mode, id })
                    }
                    (Some(oe), None) => Some(oe.clone()),
                    (None, Some(te)) => Some(te.clone()),
                }
            }
        };

        if let Some(e) = chosen {
            merged.entries.insert(p, e);
        }
    }

    Ok((merged, conflicts))
}

// ---------------------------------------------------------------------------
// stash / blame / rebase / cherry-pick
// ---------------------------------------------------------------------------

fn snap_working_tree(store: &Store, cwd: &Path) -> Result<Tree, String> {
    let store_rel = store
        .root()
        .strip_prefix(cwd)
        .unwrap_or(store.root())
        .to_path_buf();
    let files = collect_files(cwd, &store_rel)?;
    let mut tree = Tree::new();
    for (rel, abs) in &files {
        if let Ok(data) = path_blob_data(abs) {
            // Write the blob so the snapshot tree is fully readable back by a
            // later apply/pop checkout (write_blob is content-addressed and
            // idempotent for unchanged files).
            let id = store.write_blob(&data)?;
            tree.entries.insert(
                rel.clone(),
                TreeEntry {
                    mode: detect_mode(abs),
                    id,
                },
            );
        }
    }
    Ok(tree)
}

/// Write a synthetic commit object (used by stash) referencing the snapshot
/// tree, and return its id. `parent` is the original HEAD so a pop/apply can
/// tell which working state the stash captured.
fn write_snapshot_commit(
    store: &Store,
    ks: &KeySource,
    tree: &Tree,
    parent: Option<[u8; 32]>,
    message: &str,
) -> Result<[u8; 32], String> {
    let tree_id = store.write_tree(tree)?;
    let mut c = Commit::new();
    c.tree = tree_id;
    c.parents = parent.into_iter().collect();
    c.message = message.to_string();
    c.author = whoami();
    c.committer = c.author.clone();
    c.ts = now_ts();
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&c));
    store.write_commit(&c, &sig)
}

pub fn cmd_stash(args: StashArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;

    match args.action {
        crate::cli::StashAction::List {} => {
            let stashes = store.list_stashes()?;
            if stashes.is_empty() {
                println!("no stash entries");
                return Ok(());
            }
            for id in &stashes {
                let c = store.read_commit(id)?;
                // The stored message already embeds the "stash@{n}:" prefix.
                println!("{}", c.message);
            }
            Ok(())
        }
        crate::cli::StashAction::Push { message } => {
            // Guard: only stash if there is something to stash (working tree
            // differs from HEAD tree).
            let head_opt = store
                .head_branch()?
                .and_then(|b| store.read_ref("heads", &b).ok());
            let wtree = snap_working_tree(&store, cwd)?;
            let differs = match head_opt {
                Some(h) => {
                    let hc = store.read_commit(&h)?;
                    let htree = store.read_tree(&hc.tree)?;
                    wtree != htree
                }
                None => !wtree.entries.is_empty(),
            };
            if !differs {
                println!("no local changes to stash");
                return Ok(());
            }

            let mut stashes = store.list_stashes()?;
            let msg = format!(
                "stash@{{{}}}: {}",
                stashes.len(),
                message.unwrap_or_else(|| "WIP on stash".into())
            );
            let id = write_snapshot_commit(&store, &ks, &wtree, head_opt, &msg)?;
            stashes.insert(0, id);
            store.save_stashes(&stashes)?;

            // Reset HEAD/index/tree to the last real commit so the working
            // tree is clean of the shelved changes.
            match head_opt {
                Some(h) => {
                    let hc = store.read_commit(&h)?;
                    let htree = store.read_tree(&hc.tree)?;
                    store.save_index(&htree)?;
                    ensure_tree_on_disk(&store, &htree, cwd)?;
                }
                None => {
                    store.save_index(&Tree::new())?;
                }
            }
            println!("saved working tree and index as {msg}");
            Ok(())
        }
        crate::cli::StashAction::Apply { index } => {
            let stashes = store.list_stashes()?;
            let id = pick_stash(&stashes, index)?;
            apply_stash(&store, cwd, id)?;
            println!("applied stash@{{{}}}", index.unwrap_or(0));
            Ok(())
        }
        crate::cli::StashAction::Pop { index } => {
            let mut stashes = store.list_stashes()?;
            if stashes.is_empty() {
                return Err("nothing to pop (no stash entries)".into());
            }
            let i = index.unwrap_or(0);
            let id = pick_stash(&stashes, Some(i))?;
            apply_stash(&store, cwd, id)?;
            stashes.remove(i);
            store.save_stashes(&stashes)?;
            println!("popped stash@{{{i}}} and applied it");
            Ok(())
        }
        crate::cli::StashAction::Drop { index } => {
            let mut stashes = store.list_stashes()?;
            if stashes.is_empty() {
                return Err("nothing to drop (no stash entries)".into());
            }
            let i = index.unwrap_or(0);
            let id = pick_stash(&stashes, Some(i))?;
            stashes.remove(i);
            store.save_stashes(&stashes)?;
            println!("dropped stash@{{{i}}} ({})", short(&id));
            Ok(())
        }
    }
}

/// Resolve the nth stash (default 0) or error out of range.
fn pick_stash(stashes: &[[u8; 32]], index: Option<usize>) -> Result<[u8; 32], String> {
    let i = index.unwrap_or(0);
    stashes
        .get(i)
        .copied()
        .ok_or_else(|| format!("stash at index {i} does not exist"))
}

/// Apply a stash into the index + working tree as a four-way merge against
/// its original parent, so shelved changes merge with (not overwrite) any
/// current edits.
fn apply_stash(store: &Store, cwd: &Path, id: [u8; 32]) -> Result<(), String> {
    let sc = store.read_commit(&id)?;
    let stree = store.read_tree(&sc.tree)?;
    // Restore into the index and working tree as a whole-tree checkout; if the
    // current tree has newer changes they are already staged, so a full
    // overwrite of tracked paths could clobber them. To be safe and simple,
    // we three-way against the stash's recorded parent.
    let parent_tree = match sc.parents.first() {
        Some(p) => {
            let pc = store.read_commit(p)?;
            store.read_tree(&pc.tree)?
        }
        None => Tree::new(),
    };
    let cur = store.load_index()?;
    let (merged, _conflicts) = three_way(&parent_tree, &cur, &stree)?;
    store.save_index(&merged)?;
    ensure_tree_on_disk(store, &merged, cwd)?;
    Ok(())
}

pub fn cmd_blame(args: BlameArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;

    let start = match &args.from {
        Some(spec) => resolve_id(&store, spec)?,
        None => {
            let head = store.head_branch()?.ok_or("no HEAD")?;
            store.read_ref("heads", &head)?
        }
    };

    // Walk history from start, collecting per-line origin. We build the file's
    // lines over time: iterate commits oldest-first, and for each line that is
    // unchanged since the previous attribution, keep the original author.
    //
    // Implementation: walk ancestors once to build a chronological vec of
    // (commit, blob_id). Then diff consecutive versions to propagate
    // unchanged lines, assigning the first (oldest) commit that introduced
    // each surviving line — the standard "git blame" semantics (last change
    // wins).
    let mut history: Vec<([u8; 32], Vec<Vec<u8>>)> = Vec::new();
    let mut cur = start;
    for _ in 0..usize::MAX {
        let record = match store.read_commit_record(&cur) {
            Ok(r) => r,
            Err(_) if store.is_shallow() => break,
            Err(e) => return Err(format!("commit {} unreadable: {e}", short(&cur))),
        };
        let c = &record.commit;
        let tree = store.read_tree(&c.tree)?;
        let blob = match tree.entries.get(&args.path) {
            Some(e) => store
                .read_blob(&e.id)
                .map_err(|e| format!("blob for {}: {e}", args.path))?,
            None => {
                // File not present at this commit: treat as empty.
                Blob::new(Vec::new())
            }
        };
        let lines = split_blame_lines(&blob.data);
        history.push((cur, lines));
        match c.parents.first() {
            Some(p) => cur = *p,
            None => break,
        }
    }
    history.reverse(); // oldest first

    if history.is_empty() {
        return Err(format!("no history for {}", args.path));
    }

    // Assign each line to the last commit in the chronological walk that
    // contains it (matching git blame's "most recent change wins"). We
    // progressively move lines back in time: start from the newest file, then
    // for each older commit, lines it has that match the current pending set
    // get attributed to it.
    //
    // Simpler & robust: for each line index in the final (newest) file, scan
    // history oldest→newest and pick the *last* commit whose version contains
    // that exact line at that position — approximating blame well enough for
    // provenance.
    let newest = &history.last().unwrap().1;
    let mut out: Vec<([u8; 32], String, String)> = Vec::new(); // (id, author, line)
    for line in newest {
        // The commit that introduced this line: the *oldest* commit whose
        // version contains the exact line. A line unchanged since it was
        // introduced is present in every later commit, so the oldest holder is
        // its introducer; if a later commit modified it, the old text is no
        // longer present there and the modifier becomes the oldest holder.
        let mut owner = None;
        let mut author = String::new();
        for (cid, lines) in &history {
            if lines.iter().any(|l| l == line) {
                owner = Some(*cid);
                let c = store.read_commit(cid)?;
                author = c.author.clone();
                break;
            }
        }
        let owner = owner.unwrap_or(history[0].0);
        out.push((owner, author, String::from_utf8_lossy(line).to_string()));
    }

    if args.json {
        let arr: Vec<serde_json::Value> = out
            .iter()
            .enumerate()
            .map(|(i, (id, author, text))| {
                serde_json::json!({
                    "line": i + 1,
                    "commit": hex::encode(id),
                    "author": author,
                    "text": text,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        return Ok(());
    }

    for (id, author, text) in &out {
        println!(
            "{:>8} {} | {}",
            &hex::encode(id)[..8],
            author,
            text.trim_end()
        );
    }
    Ok(())
}

fn split_blame_lines(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..data.len() {
        if data[i] == b'\n' {
            out.push(data[start..=i].to_vec());
            start = i + 1;
        }
    }
    if start < data.len() {
        out.push(data[start..].to_vec());
    }
    out
}

/// Re-apply all commits from `branch` (after the merge base with HEAD) onto
/// HEAD, one at a time, fast-forwarding through clean applies and stopping
/// with a clear error on a conflicting replay. `-i` runs the interactive
/// variant (todo plan with pick/squash/reword/drop/edit); `--continue` and
/// `--abort` manage a paused interactive rebase.
pub fn cmd_rebase(args: RebaseArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;

    if store.is_shallow() {
        return Err("rebase on a shallow clone is not supported".into());
    }

    if args.abort {
        return abort_rebase(&mut store, &ks, cwd);
    }
    if args.cont {
        return continue_rebase(&mut store, &ks, cwd);
    }
    if args.interactive {
        return interactive_rebase(&mut store, &ks, cwd, &args);
    }

    let head_branch = store.head_branch()?.ok_or("no HEAD")?;
    let head = store.read_ref("heads", &head_branch)?;
    let branch_tip = resolve_id(&store, &args.branch)?;
    let base = merge_base(&store, head, branch_tip)?;

    // Collect commits on `branch` not in `base`'s ancestry of head (i.e. the
    // unique commits to replay), oldest-first.
    let mut to_replay: Vec<[u8; 32]> = Vec::new();
    let mut cur = branch_tip;
    while cur != base {
        to_replay.push(cur);
        let c = store.read_commit(&cur)?;
        let Some(p) = c.parents.first() else { break };
        cur = *p;
    }
    to_replay.reverse();

    if to_replay.is_empty() {
        println!("up to date; nothing to rebase");
        return Ok(());
    }
    let count = to_replay.len();
    for cid in to_replay {
        let step = replay_one(
            &mut store,
            &ks,
            cwd,
            &head_branch,
            cid,
            Some(&args.strategy),
        )?;
        println!("(on {}) replayed as {}", short(&cid), short(&step));
    }
    println!("rebase complete; {head_branch} now carries {count} rebased commit(s)");
    Ok(())
}

/// Apply the changes of one commit (diff between its first parent's tree and
/// its own tree) onto the current HEAD, producing a new signed commit.
fn replay_one(
    store: &mut Store,
    ks: &KeySource,
    cwd: &Path,
    head_branch: &str,
    cid: [u8; 32],
    strategy: Option<&str>, // default textual
) -> Result<[u8; 32], String> {
    let head_id = store.read_ref("heads", head_branch)?;
    let (c, nid, merged) = replayed_commit(store, ks, cid, head_id, None, strategy)?;
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&c));
    store.write_ref("heads", head_branch, nid, &sig)?;
    store.update_mem_ref("heads", head_branch, nid);
    store.append_commit_leaf(&nid)?;
    store.save_index(&merged)?;
    ensure_tree_on_disk(store, &merged, cwd)?;
    Ok(nid)
}

/// Compute a replayed commit: `cid`'s diff (vs its first parent) applied onto
/// `parent_id`'s tree. Returns the commit, its id, and the merged tree. Does
/// NOT touch refs / index / MMR — the caller decides when to persist.
fn replayed_commit(
    store: &Store,
    ks: &KeySource,
    cid: [u8; 32],
    parent_id: [u8; 32],
    message_override: Option<&str>,
    strategy: Option<&str>,
) -> Result<(Commit, [u8; 32], Tree), String> {
    let target_commit = store.read_commit(&cid)?;
    let target_tree = store.read_tree(&target_commit.tree)?;

    // Base for the patch = first parent tree (or empty tree for a root).
    let base_tree = match target_commit.parents.first() {
        Some(p) => {
            let pc = store.read_commit(p)?;
            store.read_tree(&pc.tree)?
        }
        None => Tree::new(),
    };
    let parent_commit = store.read_commit(&parent_id)?;
    let parent_tree = store.read_tree(&parent_commit.tree)?;

    let strat = strategy.unwrap_or("textual");
    let (merged, conflicts) = match strat {
        "union" => three_way(&base_tree, &parent_tree, &target_tree)?,
        _ => three_way_textual(store, &base_tree, &parent_tree, &target_tree)?,
    };
    if !conflicts.is_empty() {
        return Err(format!(
            "conflicts applying commit {} ({}); aborting",
            short(&cid),
            conflicts.join(", ")
        ));
    }

    let tree_id = store.write_tree(&merged)?;
    let mut c = Commit::new();
    c.tree = tree_id;
    c.parents = vec![parent_id];
    c.message = message_override
        .map(str::to_string)
        .unwrap_or_else(|| target_commit.message.clone());
    c.author = target_commit.author.clone();
    c.committer = whoami();
    c.ts = now_ts();
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&c));
    let nid = store.write_commit(&c, &sig)?;
    Ok((c, nid, merged))
}

// ---------------------------------------------------------------------------
// interactive rebase (todo plan + continue/abort)
// ---------------------------------------------------------------------------

/// Persisted rebase state for `--continue` / `--abort`.
#[derive(serde::Serialize, serde::Deserialize)]
struct RebaseState {
    branch: String,
    orig_head: [u8; 32],
    cur: [u8; 32],
    remaining: Vec<RebaseEntry>,
    strategy: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RebaseEntry {
    action: String,
    id: [u8; 32],
    message: Option<String>,
}

fn rebase_state_path(store: &Store) -> std::path::PathBuf {
    store.root().join("REBASE_STATE")
}

fn load_rebase_state(store: &Store) -> Result<RebaseState, String> {
    let bytes =
        std::fs::read(rebase_state_path(store)).map_err(|e| format!("rebase state: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("rebase state parse: {e}"))
}

fn save_rebase_state(store: &Store, st: &RebaseState) -> Result<(), String> {
    let body = serde_json::to_vec(st).map_err(|e| format!("rebase state ser: {e}"))?;
    origin_common::atomic_write(&rebase_state_path(store), &body)
        .map_err(|e| format!("write rebase state: {e}"))
}

fn clear_rebase_state(store: &Store) -> Result<(), String> {
    let p = rebase_state_path(store);
    if p.exists() {
        std::fs::remove_file(&p).map_err(|e| format!("clear rebase state: {e}"))?;
    }
    Ok(())
}

/// `rebase --abort`: restore the branch to the pre-rebase HEAD and the
/// working tree to match.
fn abort_rebase(store: &mut Store, ks: &KeySource, cwd: &Path) -> Result<(), String> {
    let st = load_rebase_state(store)?;
    let head = st.orig_head;
    let commit = store.read_commit(&head)?;
    let tree = store.read_tree(&commit.tree)?;
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &head);
    store.write_ref("heads", &st.branch, head, &sig)?;
    store.update_mem_ref("heads", &st.branch, head);
    store.save_index(&tree)?;
    ensure_tree_on_disk(store, &tree, cwd)?;
    clear_rebase_state(store)?;
    println!("rebase aborted; {} restored to {}", st.branch, short(&head));
    Ok(())
}

/// `rebase --continue`: resume a paused interactive rebase from the saved
/// plan, then finish (move the branch, update the index + working tree).
fn continue_rebase(store: &mut Store, ks: &KeySource, cwd: &Path) -> Result<(), String> {
    let mut st = load_rebase_state(store)?;
    // The user may have amended / committed on top of the paused commit
    // while `edit` stopped us. Resume from the CURRENT branch tip (what the
    // user actually has on disk), not the tip captured at pause time —
    // otherwise those fixups would be dropped by the remaining picks.
    let cur_tip = store.read_ref("heads", &st.branch)?;
    st.cur = cur_tip;
    let (branch, final_id) = apply_rebase_plan(store, ks, cwd, st)?;
    finish_rebase(store, ks, cwd, &branch, final_id)?;
    println!("rebase complete; {branch} now carries the rebased commits");
    Ok(())
}

/// Build an autosquashed todo plan: detect `fixup!` and `squash!` prefixes
/// in commit messages and reorder the plan so each fixup/squash follows its
/// target commit. Unmatched fixup/squash lines are left at the end.
fn autosquash_plan(
    _store: &Store,
    _to_replay: &[[u8; 32]],
    plan_lines: &[String],
) -> Result<String, String> {
    // Build a map of short-id -> (action, full line) for all entries.
    let mut entries: Vec<(String, String)> = plan_lines
        .iter()
        .map(|line| {
            let id = line.split_whitespace().nth(1).unwrap_or("").to_string();
            (id, line.clone())
        })
        .collect();

    // For each fixup!/squash! commit, find its target by message prefix.
    let mut reorder: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (i, (id, line)) in entries.iter().enumerate() {
        if line.starts_with("pick") {
            continue; // target commits are not moved
        }
        // The comment after # contains the original message
        let msg = line.split("# ").nth(1).unwrap_or("").trim();
        if let Some(target_msg) = msg
            .strip_prefix("fixup! ")
            .or_else(|| msg.strip_prefix("squash! "))
        {
            // Find the target commit with matching message prefix
            if let Some((j, _)) = entries.iter().enumerate().find(|(_, (id2, l))| {
                l.starts_with("pick")
                    && id2 != id
                    && l.split("# ").nth(1).unwrap_or("").trim() == target_msg
            }) {
                // Move this entry after the target
                if j + 1 < entries.len() {
                    reorder.insert(i, j + 1);
                }
            }
        }
    }

    // Apply reorderings (move entries after their targets)
    for (from, _to) in reorder.iter().rev() {
        let entry = entries.remove(*from);
        let insert_at = *_to;
        entries.insert(insert_at, entry);
    }

    Ok(entries
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n# pick | squash | reword <msg> | drop | edit\n")
}

/// `rebase -i <branch>`: build a todo plan (pick each commit), let the user
/// reorder/squash/reword/drop/edit via `--todo <file>` or $EDITOR, then apply.
fn interactive_rebase(
    store: &mut Store,
    ks: &KeySource,
    cwd: &Path,
    args: &RebaseArgs,
) -> Result<(), String> {
    let head_branch = store.head_branch()?.ok_or("no HEAD")?;
    let head = store.read_ref("heads", &head_branch)?;
    let branch_tip = resolve_id(store, &args.branch)?;

    // Two supported forms:
    //   * `rebase -i <base>` (git-style): `branch` is an ancestor of HEAD, so
    //     rewrite the current branch's commits after it, replaying them onto it.
    //   * `rebase -i <other-branch>`: replay that branch's commits onto HEAD
    //     (the same semantics as the non-interactive rebase).
    let rewrites_current = branch_tip != head && is_ancestor(store, branch_tip, head)?;
    let (start, to_replay) = if rewrites_current {
        let mut ids: Vec<[u8; 32]> = Vec::new();
        let mut cur = head;
        while cur != branch_tip {
            ids.push(cur);
            let c = store.read_commit(&cur)?;
            let Some(p) = c.parents.first() else { break };
            cur = *p;
        }
        ids.reverse();
        (branch_tip, ids)
    } else {
        let base = merge_base(store, head, branch_tip)?;
        let mut ids: Vec<[u8; 32]> = Vec::new();
        let mut cur = branch_tip;
        while cur != base {
            ids.push(cur);
            let c = store.read_commit(&cur)?;
            let Some(p) = c.parents.first() else { break };
            cur = *p;
        }
        ids.reverse();
        (head, ids)
    };
    if to_replay.is_empty() {
        println!("up to date; nothing to rebase");
        return Ok(());
    }

    // Default plan: pick every commit, oldest first.
    // When --rebase-merges is set, merge commits (>1 parent) are included;
    // otherwise they are skipped entirely (linearize).
    let mut default_plan: Vec<String> = Vec::new();
    for id in &to_replay {
        let c = store.read_commit(id).map(|c| c.message).unwrap_or_default();
        let is_merge = store
            .read_commit(id)
            .map(|c| c.parents.len() > 1)
            .unwrap_or(false);
        if is_merge && !args.rebase_merges {
            continue; // skip merge commits when not preserving merges
        }
        let action = if is_merge { "merge" } else { "pick" };
        default_plan.push(format!(
            "{action} {} # {}",
            short(id),
            c.split('\n').next().unwrap_or("")
        ));
    }

    // Autosquash: if --autosquash, detect fixup!/squash! prefixes and
    // reorder the plan so each fixup/squash follows its target commit.
    let plan_text = if args.autosquash {
        autosquash_plan(store, &to_replay, &default_plan)?
    } else {
        format!(
            "{}\n# pick | squash | reword <msg> | drop | edit\n",
            default_plan.join("\n")
        )
    };

    let edited = match &args.todo {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| format!("read todo {}: {e}", path))?
        }
        None => run_editor(&plan_text)?,
    };
    let entries = parse_rebase_todo(store, &to_replay, &edited)?;

    let st = RebaseState {
        branch: head_branch.clone(),
        orig_head: head,
        cur: start,
        remaining: entries,
        strategy: args.strategy.clone(),
    };
    save_rebase_state(store, &st)?;
    let (branch, final_id) = apply_rebase_plan(store, ks, cwd, st)?;
    finish_rebase(store, ks, cwd, &branch, final_id)?;
    println!("rebase complete; {branch} now carries the rebased commits");
    Ok(())
}

/// Spawn $VISUAL/$EDITOR on a generated todo file; returns the edited text.
fn run_editor(plan_text: &str) -> Result<String, String> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .map_err(|_| "interactive rebase needs --todo <file> or $EDITOR".to_string())?;
    let path = std::env::temp_dir().join(format!("origin-rebase-{}.todo", std::process::id()));
    std::fs::write(&path, plan_text).map_err(|e| format!("write todo: {e}"))?;
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| format!("editor {editor}: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&path);
        return Err("editor exited non-zero; rebase not started".into());
    }
    let edited = std::fs::read_to_string(&path).map_err(|e| format!("read edited todo: {e}"))?;
    let _ = std::fs::remove_file(&path);
    Ok(edited)
}

/// Parse a todo file: `pick|squash|reword|drop|edit <hash> ["new message"]`.
/// Every commit to replay must appear exactly once (prefix hashes allowed).
fn parse_rebase_todo(
    store: &Store,
    to_replay: &[[u8; 32]],
    text: &str,
) -> Result<Vec<RebaseEntry>, String> {
    let mut seen: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let action = it.next().unwrap_or("").to_string();
        let id_spec = it.next().unwrap_or("").to_string();
        if !matches!(
            action.as_str(),
            "pick" | "squash" | "fixup" | "reword" | "drop" | "edit" | "merge"
        ) {
            return Err(format!(
                "todo line {}: unknown action '{action}'",
                lineno + 1
            ));
        }
        let message = if action == "reword" {
            let rest = line
                .splitn(3, char::is_whitespace)
                .nth(2)
                .unwrap_or("")
                .trim();
            Some(rest.trim_matches('"').to_string())
        } else {
            None
        };
        let id = resolve_plan_id(store, to_replay, &id_spec)?;
        if !seen.insert(id) {
            return Err(format!(
                "todo line {}: commit {} listed twice",
                lineno + 1,
                short(&id)
            ));
        }
        out.push(RebaseEntry {
            action,
            id,
            message,
        });
    }
    if out.len() != to_replay.len() {
        let missing: Vec<String> = to_replay
            .iter()
            .filter(|id| !seen.contains(*id))
            .map(short)
            .collect();
        return Err(format!(
            "todo plan covers {} of {} commit(s); missing: {}",
            out.len(),
            to_replay.len(),
            if missing.is_empty() {
                "none".into()
            } else {
                missing.join(", ")
            }
        ));
    }
    Ok(out)
}

/// Resolve a todo hash against the set of commits being replayed (full hex or
/// unambiguous prefix).
fn resolve_plan_id(store: &Store, candidates: &[[u8; 32]], spec: &str) -> Result<[u8; 32], String> {
    let resolve = |s: &str| -> Result<[u8; 32], String> {
        // Ref names (branch/tag), HEAD, and `~N` ancestor specs resolve via
        // the store; the result must still be one of the replay candidates.
        if s != "HEAD" && !s.contains('~') && hex::decode(s).is_err() {
            if store.ref_exists("heads", s) {
                return store.read_ref("heads", s);
            }
            if store.ref_exists("tags", s) {
                return store.read_ref("tags", s);
            }
        }
        resolve_id(store, s)
    };
    let id = resolve(spec)?;
    if candidates.contains(&id) {
        return Ok(id);
    }
    if let Ok(bytes) = hex::decode(spec) {
        if bytes.len() == 32 {
            return Err(format!("unknown commit in todo: {spec}"));
        }
        if (4..32).contains(&bytes.len()) {
            let prefix = spec.to_lowercase();
            let matches: Vec<[u8; 32]> = candidates
                .iter()
                .copied()
                .filter(|id| hex::encode(id).starts_with(&prefix))
                .collect();
            return match matches.len() {
                1 => Ok(matches[0]),
                0 => Err(format!("unknown commit in todo: {spec}")),
                _ => Err(format!("ambiguous commit in todo: {spec}")),
            };
        }
    }
    Err(format!("commit {spec} is not part of this rebase"))
}

/// Apply a rebase plan onto `st.cur`. Updates `st.remaining`/`st.cur` in the
/// saved state as it goes so an `edit` stop can resume with `--continue`.
/// Returns (branch, final head id) when the whole plan applied.
fn apply_rebase_plan(
    store: &mut Store,
    ks: &KeySource,
    cwd: &Path,
    mut st: RebaseState,
) -> Result<(String, [u8; 32]), String> {
    let mut last_pick: Option<[u8; 32]> = None;
    let mut idx = 0usize;
    while idx < st.remaining.len() {
        let entry = st.remaining[idx].clone();
        match entry.action.as_str() {
            "drop" => {
                println!("dropped {}", short(&entry.id));
            }
            "pick" | "reword" | "edit" => {
                let msg = if entry.action == "reword" {
                    entry.message.as_deref()
                } else {
                    None
                };
                let (c, nid, merged) =
                    replayed_commit(store, ks, entry.id, st.cur, msg, Some(&st.strategy))?;
                println!(
                    "({}) replayed as {} ({})",
                    short(&entry.id),
                    short(&nid),
                    c.message.split('\n').next().unwrap_or("")
                );
                st.cur = nid;
                last_pick = Some(nid);
                // `edit`: stop here; the working tree reflects the commit.
                if entry.action == "edit" {
                    st.remaining = st.remaining[idx + 1..].to_vec();
                    save_rebase_state(store, &st)?;
                    store.save_index(&merged)?;
                    ensure_tree_on_disk(store, &merged, cwd)?;
                    println!(
                        "stopped at {}; edit and run 'rebase --continue' (or --abort)",
                        short(&nid)
                    );
                    return Err("rebase paused at edit; run rebase --continue".into());
                }
            }
            "squash" => {
                let prev = last_pick
                    .ok_or_else(|| format!("squash {} has no preceding pick", short(&entry.id)))?;
                let prev_commit = store.read_commit(&prev)?;
                let prev_tree = store.read_tree(&prev_commit.tree)?;
                let target = store.read_commit(&entry.id)?;
                let target_tree = store.read_tree(&target.tree)?;
                let base_tree = match target.parents.first() {
                    Some(p) => {
                        let pc = store.read_commit(p)?;
                        store.read_tree(&pc.tree)?
                    }
                    None => Tree::new(),
                };
                let strat = st.strategy.as_str();
                let (merged, conflicts) = match strat {
                    "union" => three_way(&base_tree, &prev_tree, &target_tree)?,
                    _ => three_way_textual(store, &base_tree, &prev_tree, &target_tree)?,
                };
                if !conflicts.is_empty() {
                    return Err(format!(
                        "conflicts squashing {} ({}); aborting",
                        short(&entry.id),
                        conflicts.join(", ")
                    ));
                }
                let tree_id = store.write_tree(&merged)?;
                let mut c = Commit::new();
                c.tree = tree_id;
                c.parents = prev_commit.parents.clone();
                c.message = match &entry.message {
                    Some(m) => m.clone(),
                    None => {
                        let tmsg = target.message.clone();
                        format!("{}\n\n{tmsg}", prev_commit.message)
                    }
                };
                c.author = prev_commit.author.clone();
                c.committer = whoami();
                c.ts = now_ts();
                let bundle = ks.signing_bundle()?;
                let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&c));
                let nid = store.write_commit(&c, &sig)?;
                println!("squashed {} into {}", short(&entry.id), short(&prev));
                st.cur = nid;
                last_pick = Some(nid);
            }
            "fixup" => {
                // Like squash but discards the fixup commit's message;
                // the result keeps only the preceding commit's message.
                let prev = last_pick
                    .ok_or_else(|| format!("fixup {} has no preceding pick", short(&entry.id)))?;
                let prev_commit = store.read_commit(&prev)?;
                let prev_tree = store.read_tree(&prev_commit.tree)?;
                let target = store.read_commit(&entry.id)?;
                let target_tree = store.read_tree(&target.tree)?;
                let base_tree = match target.parents.first() {
                    Some(p) => {
                        let pc = store.read_commit(p)?;
                        store.read_tree(&pc.tree)?
                    }
                    None => Tree::new(),
                };
                let strat = st.strategy.as_str();
                let (merged, conflicts) = match strat {
                    "union" => three_way(&base_tree, &prev_tree, &target_tree)?,
                    _ => three_way_textual(store, &base_tree, &prev_tree, &target_tree)?,
                };
                if !conflicts.is_empty() {
                    return Err(format!(
                        "conflicts fixup {} ({}); aborting",
                        short(&entry.id),
                        conflicts.join(", ")
                    ));
                }
                let tree_id = store.write_tree(&merged)?;
                let mut c = Commit::new();
                c.tree = tree_id;
                c.parents = prev_commit.parents.clone();
                // Keep only the previous commit's message (fixup discards its own).
                c.message = prev_commit.message.clone();
                c.author = prev_commit.author.clone();
                c.committer = whoami();
                c.ts = now_ts();
                let bundle = ks.signing_bundle()?;
                let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&c));
                let nid = store.write_commit(&c, &sig)?;
                println!("fixup {} into {}", short(&entry.id), short(&prev));
                st.cur = nid;
                last_pick = Some(nid);
            }
            "merge" => {
                // Replaying a merge commit: recreate it with its original
                // parents but rebased onto the current tip. The commit may
                // have two parents — the first is the "main" line (replayed)
                // and the second is the branch being merged.
                let original = store.read_commit(&entry.id)?;
                let msg = entry.message.as_deref();
                let (c, nid, _merged) =
                    replayed_commit(store, ks, entry.id, st.cur, msg, Some(&st.strategy))?;
                println!(
                    "({}) merge replayed as {} ({})",
                    short(&entry.id),
                    short(&nid),
                    c.message.split('\n').next().unwrap_or("")
                );
                st.cur = nid;
                last_pick = Some(nid);
                let _ = original;
            }
            other => return Err(format!("todo action '{other}' not supported")),
        }
        idx += 1;
    }
    Ok((st.branch.clone(), st.cur))
}

/// Finish a completed rebase: move the branch ref, append to the MMR, and
/// restore the index + working tree.
fn finish_rebase(
    store: &mut Store,
    ks: &KeySource,
    cwd: &Path,
    branch: &str,
    final_id: [u8; 32],
) -> Result<(), String> {
    let commit = store.read_commit(&final_id)?;
    let tree = store.read_tree(&commit.tree)?;
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&commit));
    store.write_ref("heads", branch, final_id, &sig)?;
    store.update_mem_ref("heads", branch, final_id);
    store.append_commit_leaf(&final_id)?;
    store.save_index(&tree)?;
    ensure_tree_on_disk(store, &tree, cwd)?;
    clear_rebase_state(store)?;
    Ok(())
}

/// Apply a single commit's changes onto HEAD (one cherry-pick: the diff of
/// `commit` vs its first parent, onto current HEAD).
pub fn cmd_cherry_pick(args: CherryPickArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;

    if store.is_shallow() {
        return Err("cherry-pick on a shallow clone is not supported".into());
    }
    let cid = resolve_id(&store, &args.commit)?;
    let head_branch = store.head_branch()?.ok_or("no HEAD")?;
    let nid = replay_one(
        &mut store,
        &ks,
        cwd,
        &head_branch,
        cid,
        Some(&args.strategy),
    )?;
    println!("cherry-picked {} as {}", short(&cid), short(&nid));
    Ok(())
}

pub fn cmd_verify(args: VerifyArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;

    // 1. MMR consistency: replay the commit log and compare to persisted root.
    let persisted = store.mmr_root();
    let log_root = {
        let log = store.commit_log()?;
        let mut acc = crate::mmr::MmrState::new();
        for id in &log {
            acc.append(id);
        }
        acc.root()
    };
    let mmr_ok = log_root == persisted;

    // 2. Walk every reachable commit from branch heads (+ tagged commits).
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut queue: Vec<[u8; 32]> = Vec::new();
    for id in store.meta().branches.values() {
        queue.push(*id);
    }
    // Also walk tracking refs (remote fetches / bundle imports) so imported
    // history is verifiable before any local branch exists.
    for id in store.remote_refs()? {
        queue.push(id);
    }
    if let Some(t) = args.target.as_deref() {
        queue.push(resolve_id(&store, t)?);
    }

    // Tags: verify each tag object (content address + signed ref) and walk
    // its target commit even when no branch reaches it.
    let mut tag_names: Vec<String> = store.meta().tags.keys().cloned().collect();
    tag_names.sort();
    for name in &tag_names {
        let signed = store.read_ref_signed("tags", name)?;
        let tag = store.read_tag(&signed.target)?;
        if crate::object::tag_address(&tag) != signed.target {
            return Err(format!(
                "tag '{name}' content-address mismatch (tampered object)"
            ));
        }
        let body = serde_json::to_vec(&tag).map_err(|e| format!("tag ser: {e}"))?;
        signed
            .signature
            .verify(&body)
            .map_err(|e| format!("tag '{name}' signature invalid: {e}"))?;
        queue.push(tag.target);
    }

    let mut checked = 0usize;
    while let Some(id) = queue.pop() {
        if !seen.insert(id) {
            continue;
        }
        // On a shallow clone, parents below the SHALLOW boundary are absent;
        // skip them (their history was never fetched) instead of failing.
        let record = match store.read_commit_record(&id) {
            Ok(r) => r,
            Err(_) if store.is_shallow() => continue,
            Err(e) => return Err(format!("commit {} unreadable: {e}", short(&id))),
        };
        checked += 1;
        let c = &record.commit;
        if commit_address(c) != id {
            return Err(format!(
                "commit {} content-address mismatch (tampered object)",
                hex::encode(id)
            ));
        }
        record
            .signature
            .verify(&crate::object::canonical_commit(c))
            .map_err(|e| format!("commit {} signature invalid: {e}", short(&id)))?;
        let tree = store
            .read_tree(&c.tree)
            .map_err(|e| format!("commit {} tree: {e}", short(&id)))?;
        for (rel, entry) in &tree.entries {
            if !store.object_exists(&entry.id) {
                return Err(format!(
                    "commit {} references missing blob {:?} for '{}'",
                    short(&id),
                    short(&entry.id),
                    rel
                ));
            }
        }
        for p in &c.parents {
            queue.push(*p);
        }
    }

    println!("verified {checked} commit(s); signatures and object hashes OK");
    println!(
        "mmr root: {} ({})",
        hex::encode(persisted),
        if mmr_ok { "consistent" } else { "MISMATCH" }
    );
    if !mmr_ok {
        return Err("mmr log/root mismatch — history was tampered".into());
    }
    if checked == 0 {
        return Err("no commits to verify (repository is empty)".into());
    }
    if !tag_names.is_empty() {
        println!(
            "verified {} tag(s); signatures and object hashes OK",
            tag_names.len()
        );
    }

    // Optional working-tree drift check: the tree on disk (honoring ignore
    // rules) must match the checked-out HEAD tree exactly.
    if args.tree {
        check_tree_drift(&store, &dir_root())?;
    }
    Ok(())
}

fn dir_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Assert the working tree matches HEAD: no modified, deleted, or untracked
/// files (ignoring hidden/store/ignored paths). Returns an error listing the
/// drift on the first mismatch.
fn check_tree_drift(store: &Store, dir_root: &Path) -> Result<(), String> {
    let head = store.head_branch()?.ok_or("no HEAD branch checked out")?;
    let head_id = store.read_ref("heads", &head)?;
    let head_commit = store.read_commit(&head_id)?;
    let head_tree = store.read_tree(&head_commit.tree)?;
    let store_rel = store
        .root()
        .strip_prefix(dir_root)
        .unwrap_or(store.root())
        .to_path_buf();
    let files = collect_files(dir_root, &store_rel)?;
    // Sparse checkout: only the in-scope subset is expected on disk, so
    // out-of-scope HEAD entries are not drift.
    let sparse = store.sparse_paths()?;

    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut untracked = Vec::new();
    for (rel, abs) in &files {
        if !sparse_in_scope(&sparse, rel) {
            continue;
        }
        match head_tree.entries.get(rel) {
            Some(entry) => {
                if let Ok(data) = path_blob_data(abs) {
                    if entry.id != working_file_id(&data) {
                        modified.push(rel.clone());
                    }
                }
            }
            None => untracked.push(rel.clone()),
        }
    }
    for rel in head_tree.entries.keys() {
        if sparse_in_scope(&sparse, rel) && !files.contains_key(rel) {
            deleted.push(rel.clone());
        }
    }

    if modified.is_empty() && deleted.is_empty() && untracked.is_empty() {
        println!("working tree matches HEAD ({head})");
        return Ok(());
    }
    let mut out = Vec::new();
    for rel in &modified {
        out.push(format!("  M {rel}"));
    }
    for rel in &deleted {
        out.push(format!("  D {rel}"));
    }
    for rel in &untracked {
        out.push(format!("  ?? {rel}"));
    }
    Err(format!(
        "working tree does not match HEAD ({head}):\n{}",
        out.join("\n")
    ))
}

pub fn cmd_mmr(args: MmrArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;
    if args.root {
        println!("{}", hex::encode(store.mmr_root()));
        Ok(())
    } else {
        let log = store.commit_log()?;
        println!(
            "{} commit(s), mmr root {}",
            log.len(),
            hex::encode(store.mmr_root())
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// bundle
// ---------------------------------------------------------------------------

pub fn cmd_bundle(args: BundleArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;
    match args.action {
        crate::cli::BundleAction::Create(a) => {
            let m = crate::bundle::create(&store, Path::new(&a.file))?;
            println!(
                "wrote bundle {} ({} objects, {} branch(es), {} tag(s))",
                a.file,
                m.object_ids.len(),
                m.branches.len(),
                m.tags.len()
            );
        }
        crate::cli::BundleAction::Import(a) => {
            let m = crate::bundle::import(&mut store, &ks, Path::new(&a.file), &a.name)?;
            println!(
                "imported bundle {} ({} objects, branches: {})",
                a.file,
                m.object_ids.len(),
                m.branches
                    .keys()
                    .map(|b| format!("{}/{}", a.name, b))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        crate::cli::BundleAction::Verify(a) => {
            crate::bundle::verify(&store, Path::new(&a.file))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

/// Garbage-collect unreachable objects: keep everything reachable from branch
/// and tag refs (+ HEAD) and prune every other envelope from the store.
pub fn cmd_gc(args: GcArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let store = resolve_store(&args.store, cwd, &ks)?;

    // HEAD id (only meaningful when the branch is not unborn).
    let extra: Vec<[u8; 32]> = store
        .head_branch()?
        .and_then(|b| store.read_ref("heads", &b).ok())
        .into_iter()
        .collect();
    let reachable =
        store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &extra)?;

    let had = store.all_object_ids()?.len();
    let pruned = store.prune_unreachable(&reachable)?;
    let kept = had.saturating_sub(pruned);
    println!("gc: {had} objects -> kept {kept}, pruned {pruned} unreachable");

    // Optionally drop tracking refs whose tip is no longer reachable from any
    // local branch/tag (e.g. a remote branch that was force-pushed away).
    if args.prune_remotes {
        let remotes = crate::remote::list(store.root())?;
        let mut pruned_refs = 0usize;
        for r in &remotes {
            for b in crate::remote::tracking_refs(&store, &r.name)? {
                let name = format!("{}/{b}", r.name);
                if let Ok(tip) = store.read_ref("remotes", &name) {
                    if !reachable.contains(&tip) {
                        store.delete_ref("remotes", &name)?;
                        pruned_refs += 1;
                    }
                }
            }
        }
        println!("gc: pruned {pruned_refs} stale tracking ref(s)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// remote
// ---------------------------------------------------------------------------

pub fn cmd_remote(args: RemoteArgs, cwd: &Path) -> Result<(), String> {
    let net_seed = parse_net_seed(args.net_seed.as_deref())?;
    let stun = args.stun.as_deref();
    let args_all = args.clone();

    // `ls-remote` needs no local store and no repo seed: it queries any
    // remote target directly. A key source is only consulted for session/
    // relay targets that derive a network identity from it (or from
    // --net-seed), so resolve it lazily instead of requiring a repo.
    if let crate::cli::RemoteAction::LsRemote(a) = &args.action {
        let r = crate::remote::Remote {
            name: "ls-remote".into(),
            target: a.target.clone(),
        };
        let manifest = if crate::remote::is_tcp_target(&r.target) {
            crate::remote::net_ls(&r)?
        } else if crate::remote::is_quic_target(&r.target) {
            crate::remote::quic_ls(&r)?
        } else if crate::remote::is_session_target(&r.target) {
            let ks = resolve_keysource(
                args.identity,
                args.seed.as_deref(),
                args.passphrase_file.as_deref(),
            )?;
            crate::remote::session_ls(&r, crate::remote::net_seed_or_default(&ks, net_seed))?
        } else if crate::remote::is_relay_target(&r.target) {
            let ks = resolve_keysource(
                args.identity,
                args.seed.as_deref(),
                args.passphrase_file.as_deref(),
            )?;
            crate::remote::relay_ls(&r, crate::remote::net_seed_or_default(&ks, net_seed), stun)?
        } else {
            crate::remote::read_manifest(std::path::Path::new(&r.target))?
        };
        if manifest.branches.is_empty() && manifest.tags.is_empty() {
            println!("(remote has no branches or tags)");
        }
        for (b, id) in &manifest.branches {
            println!("{} branch {b}", hex::encode(&id[..8]));
        }
        for (t, id) in &manifest.tags {
            println!("{} tag    {t}", hex::encode(&id[..8]));
        }
        return Ok(());
    }

    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    // Serve / sync are long-lived (accept loop / daemon / interval loop), so
    // they must not hold the exclusive store lock — otherwise clients (and
    // `serve --stop`) would block forever waiting on it. All other remote
    // actions are short-lived and lock normally.
    let lock = !matches!(
        args.action,
        crate::cli::RemoteAction::Serve(_) | crate::cli::RemoteAction::Sync(_)
    );
    let mut store = resolve_store_with_lock(&args.store, cwd, &ks, lock)?;
    let store_root = store.root().to_path_buf();

    match args.action {
        crate::cli::RemoteAction::Add(a) => {
            let r = crate::remote::add(&store_root, &a.name, &a.target)?;
            println!("added remote {} -> {}", r.name, r.target);
        }
        crate::cli::RemoteAction::Remove(a) => {
            crate::remote::remove(&store_root, &a.name)?;
            println!("removed remote {}", a.name);
        }
        crate::cli::RemoteAction::List(_) => {
            let remotes = crate::remote::list(&store_root)?;
            if remotes.is_empty() {
                println!("(no remotes configured)");
            }
            for r in &remotes {
                println!("{}    {}", r.name, r.target);
            }
        }
        crate::cli::RemoteAction::Push(a) => {
            let r = crate::remote::get(&store_root, &a.name)?;
            let m = crate::remote::push(&store, &ks, &r, net_seed, stun, a.force)?;
            println!(
                "pushed {} branch(es) and {} object(s) to {}",
                m.branches.len(),
                m.object_ids.len(),
                r.name
            );
        }
        crate::cli::RemoteAction::Fetch(a) => {
            let r = crate::remote::get(&store_root, &a.name)?;
            if !a.path.is_empty() {
                // Record the sparse set so the next checkout is subtree-only.
                store.set_sparse(&a.path)?;
            }
            let m = crate::remote::fetch(&mut store, &ks, &r, true, net_seed, stun, a.depth)?;
            println!(
                "fetched {} branch(es)/tag(s) from {} ({}/... tracking refs set)",
                m.branches.len() + m.tags.len(),
                r.name,
                r.name
            );
        }
        crate::cli::RemoteAction::Pull(a) => {
            let r = crate::remote::get(&store_root, &a.name)?;
            let branch = match &a.branch {
                Some(b) => b.clone(),
                None => store.head_branch()?.ok_or("no HEAD branch to pull")?,
            };
            if !a.path.is_empty() {
                store.set_sparse(&a.path)?;
            }
            crate::remote::pull(&mut store, &ks, &r, &branch, cwd, net_seed, stun)?;
        }
        crate::cli::RemoteAction::Prune(a) => {
            let r = crate::remote::get(&store_root, &a.name)?;
            let pruned = crate::remote::prune(&mut store, &ks, &r, net_seed, stun)?;
            println!("pruned {pruned} stale tracking ref(s) for {}", r.name);
        }
        // Handled by the early return above (no local store needed).
        crate::cli::RemoteAction::LsRemote(_) => unreachable!("ls-remote handled earlier"),
        crate::cli::RemoteAction::Sync(a) => {
            let pid_file = a
                .pid_file
                .clone()
                .unwrap_or_else(|| store_root.join("sync.pid").display().to_string());
            let log_file = a
                .log_file
                .clone()
                .unwrap_or_else(|| store_root.join("sync.log").display().to_string());
            // Stop a sync daemon started with --daemon (no remote work
            // needed — the pid file has everything).
            if a.stop {
                return daemon_stop(&pid_file, "sync");
            }
            if a.daemon && !a.serve_child {
                return sync_daemon_spawn(&args_all, &a, &pid_file, &log_file);
            }
            let r = crate::remote::get(&store_root, &a.name)?;
            loop {
                let branch = match &a.branch {
                    Some(b) => b.clone(),
                    None => match store.head_branch() {
                        Ok(Some(b)) => b,
                        _ => {
                            println!("sync: no HEAD branch; skipping tick");
                            return Err("no HEAD branch to sync".into());
                        }
                    },
                };
                // Fast-forward local onto remote, then push local changes.
                match crate::remote::pull(&mut store, &ks, &r, &branch, cwd, net_seed, stun) {
                    Ok(()) => println!("sync: pulled {branch}"),
                    Err(e) => println!("sync: pull skipped: {e}"),
                }
                match crate::remote::push(&store, &ks, &r, net_seed, stun, false) {
                    Ok(m) => println!("sync: pushed {} branch(es)", m.branches.len()),
                    Err(e) => println!("sync: push skipped: {e}"),
                }
                if a.once {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(a.interval));
            }
        }
        crate::cli::RemoteAction::Serve(a) => {
            let pid_file = a
                .pid_file
                .clone()
                .unwrap_or_else(|| store_root.join("serve.pid").display().to_string());
            let log_file = a
                .log_file
                .clone()
                .unwrap_or_else(|| store_root.join("serve.log").display().to_string());

            // Daemon lifecycle: --stop terminates a daemon started with
            // --daemon (no store/identity work needed — the pid file has
            // everything).
            if a.stop {
                return daemon_stop(&pid_file, "serve");
            }
            // --daemon: re-exec this binary as a detached background child
            // that runs the same serve command (the child never re-spawns:
            // it carries the hidden --serve-child marker).
            if a.daemon && !a.serve_child {
                return daemon_spawn(&args_all, &a, &pid_file, &log_file);
            }

            // The daemon child records its pid immediately so --stop can
            // find it even if binding is slow, then reports the bound
            // address through the serve loop's on_bound callback.
            if a.serve_child {
                let body = format!("pid {}\n", std::process::id());
                let _ = std::fs::write(&pid_file, body);
            }
            let report_bound: Option<Box<dyn FnOnce(std::net::SocketAddr) + Send>> =
                if a.serve_child {
                    let pf = pid_file.clone();
                    Some(Box::new(move |bound| {
                        let body = format!("pid {}\naddr {bound}\n", std::process::id());
                        let _ = std::fs::write(&pf, body);
                    }))
                } else {
                    None
                };
            let report = std::sync::Arc::new(std::sync::Mutex::new(report_bound));

            if let Some(session_listen) = &a.session {
                let listen = session_listen
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| format!("invalid session listen '{}': {e}", session_listen))?;
                if a.relay.is_some() || a.quic.is_some() {
                    return Err("--session, --relay, and --quic are mutually exclusive".into());
                }
                // Allowlist: explicit --allow seeds + --allow-file PeerKeys.
                let mut allow: Vec<[u8; 32]> = Vec::new();
                for h in &a.allow {
                    let s = parse_net_seed(Some(h))?
                        .ok_or_else(|| format!("--allow seed must be 32 bytes hex: {h}"))?;
                    allow.push(s);
                }
                if let Some(file) = &a.allow_file {
                    let bytes = std::fs::read(file).map_err(|e| format!("allow-file: {e}"))?;
                    for line in bytes.split(|b| *b == b'\n') {
                        if line.iter().all(|b| b.is_ascii_whitespace()) {
                            continue;
                        }
                        let keys: origin_network::identity::PeerKeys = serde_json::from_slice(line)
                            .map_err(|e| {
                                format!("allow-file line is not a PeerKeys record: {e}")
                            })?;
                        allow.push(keys.fingerprint);
                    }
                }
                if allow.is_empty() {
                    return Err(
                        "--session requires at least one --allow seed or an --allow-file".into(),
                    );
                }
                return crate::remote::serve_session(
                    &mut store,
                    &ks,
                    listen,
                    &allow,
                    net_seed,
                    report.lock().unwrap().take(),
                );
            }
            if let Some(quic_listen) = &a.quic {
                let listen = quic_listen
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| format!("invalid quic listen '{}': {e}", quic_listen))?;
                println!(
                    "serving {} over QUIC on {listen} (ctrl-c to stop)",
                    store_root.display()
                );
                loop {
                    let rep = std::sync::Arc::clone(&report);
                    let bound =
                        crate::remote::serve_quic_once(&mut store, &ks, listen, move |b| {
                            if let Some(f) = rep.lock().unwrap().take() {
                                f(b);
                            }
                        })?;
                    println!("served one quic connection on {bound}");
                }
            }
            match &a.relay {
                Some(url) => {
                    return crate::remote::serve_relay_forever(
                        &mut store, &ks, url, net_seed, stun,
                    );
                }
                None => {
                    let listen = a
                        .listen
                        .parse::<std::net::SocketAddr>()
                        .map_err(|e| format!("invalid listen address '{}': {e}", a.listen))?;
                    println!(
                        "serving {} on {listen} (ctrl-c to stop)",
                        store_root.display()
                    );
                    loop {
                        let rep = std::sync::Arc::clone(&report);
                        let bound = crate::remote::serve_once(&mut store, &ks, listen, move |b| {
                            if let Some(f) = rep.lock().unwrap().take() {
                                f(b);
                            }
                        })?;
                        println!("served one connection on {bound}");
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// serve --daemon / serve --stop
// ---------------------------------------------------------------------------

/// Re-exec this binary as a background serve daemon: same command line minus
/// the daemonization flags, plus the hidden `--serve-child` marker and the
/// canonical pid/log paths. The child's stdout/stderr go to the log file;
/// the pid file records the child pid and (once bound) the listener address.
fn daemon_spawn(
    args: &RemoteArgs,
    serve: &RemoteServeArgs,
    pid_file: &str,
    log_file: &str,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let mut cmd = std::process::Command::new(&exe);
    // The `remote` args (identity/store/net) are parent-level for the
    // `serve` subcommand, so they must precede it; serve-mode flags follow.
    cmd.arg("remote");
    if let Some(s) = &args.seed {
        cmd.args(["--seed", s]);
    }
    if args.identity {
        cmd.arg("--identity");
    }
    if let Some(p) = &args.passphrase_file {
        cmd.args(["--passphrase-file", p]);
    }
    if let Some(s) = &args.store {
        cmd.args(["--store", s]);
    }
    if let Some(s) = &args.net_seed {
        cmd.args(["--net-seed", s]);
    }
    if let Some(s) = &args.stun {
        cmd.args(["--stun", s]);
    }
    cmd.arg("serve");
    // Serve-mode flags, mirrored from the parent invocation.
    if let Some(s) = &serve.session {
        cmd.args(["--session", s]);
    }
    if let Some(s) = &serve.relay {
        cmd.args(["--relay", s]);
    }
    if let Some(s) = &serve.quic {
        cmd.args(["--quic", s]);
    }
    if let Some(f) = &serve.allow_file {
        cmd.args(["--allow-file", f]);
    }
    for h in &serve.allow {
        cmd.args(["--allow", h]);
    }
    cmd.args(["--listen", &serve.listen]);
    // The child marker + canonical pid/log paths.
    cmd.args([
        "--serve-child",
        "--pid-file",
        pid_file,
        "--log-file",
        log_file,
    ]);

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .map_err(|e| format!("open log {log_file}: {e}"))?;
    let log_err = log.try_clone().map_err(|e| format!("log clone: {e}"))?;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Detach from the terminal's process group so the daemon survives
        // the controlling terminal closing.
        cmd.process_group(0);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn serve daemon: {e}"))?;
    println!(
        "serve daemon started (pid {}) — pid file: {pid_file}, log: {log_file}",
        child.id()
    );
    Ok(())
}

/// Stop a daemon started with `serve --daemon`: read the pid file, SIGTERM
/// the pid, wait for it to exit (bounded), and remove the pid file.
/// Re-exec this binary as a detached background child running `remote sync`
/// (the child carries the hidden `--serve-child` marker so it never re-spawns;
/// pid + remote go to the pid file, output to the log file).
fn sync_daemon_spawn(
    args: &RemoteArgs,
    sync: &crate::cli::RemoteSyncArgs,
    pid_file: &str,
    log_file: &str,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("remote");
    if let Some(s) = &args.seed {
        cmd.args(["--seed", s]);
    }
    if args.identity {
        cmd.arg("--identity");
    }
    if let Some(p) = &args.passphrase_file {
        cmd.args(["--passphrase-file", p]);
    }
    if let Some(s) = &args.store {
        cmd.args(["--store", s]);
    }
    if let Some(s) = &args.net_seed {
        cmd.args(["--net-seed", s]);
    }
    if let Some(s) = &args.stun {
        cmd.args(["--stun", s]);
    }
    cmd.arg("sync");
    cmd.arg(&sync.name);
    cmd.args([
        "--interval",
        &sync.interval.to_string(),
        "--serve-child",
        "--pid-file",
        pid_file,
        "--log-file",
        log_file,
    ]);
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .map_err(|e| format!("open log {:?}: {e}", log_file))?;
    let err = out.try_clone().map_err(|e| format!("clone log: {e}"))?;
    let child = cmd
        .stdout(std::process::Stdio::from(out))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .map_err(|e| format!("spawn sync daemon: {e}"))?;
    origin_common::atomic_write(
        &std::path::PathBuf::from(pid_file),
        format!("{} sync {}\n", child.id(), sync.name).as_bytes(),
    )
    .map_err(|e| format!("write pid file: {e}"))?;
    println!(
        "sync daemon started (pid {}) — pid file: {pid_file}, log: {log_file}",
        child.id()
    );
    Ok(())
}

fn daemon_stop(pid_file: &str, kind: &str) -> Result<(), String> {
    let body = std::fs::read_to_string(pid_file)
        .map_err(|e| format!("no {kind} daemon pid file {pid_file}: {e}"))?;
    // Serve writes `pid <pid>`, sync writes `<pid> sync <name>` — accept
    // the first whitespace-delimited integer on any line.
    let pid: i32 = body
        .lines()
        .find_map(|l| l.split_whitespace().find_map(|tok| tok.parse().ok()))
        .ok_or_else(|| format!("unparseable {kind} daemon pid file {pid_file}"))?;
    #[cfg(unix)]
    {
        let r = unsafe { libc::kill(pid, libc::SIGTERM) };
        if r != 0 {
            // Already gone: clean up the stale pid file.
            let _ = std::fs::remove_file(pid_file);
            println!("{kind} daemon pid {pid} already stopped");
            return Ok(());
        }
        // Wait (bounded) for the process to actually exit.
        for _ in 0..50 {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    std::fs::remove_file(pid_file).map_err(|e| format!("remove pid file {pid_file}: {e}"))?;
    println!("stopped {kind} daemon pid {pid}");
    Ok(())
}

/// Parse an optional `--net-seed` hex into a 32-byte network identity.
fn parse_net_seed(hex_s: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    match hex_s {
        None => Ok(None),
        Some(h) => {
            let bytes = hex::decode(h.trim()).map_err(|e| format!("invalid net-seed hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("net-seed must be 32 bytes, got {}", bytes.len()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(Some(seed))
        }
    }
}

// ---------------------------------------------------------------------------
// clone
// ---------------------------------------------------------------------------

/// Clone a remote repository: init a fresh store in `<dir>`, register the
/// remote, fetch, and check out the requested (or default) branch.
///
/// The destination must derive the SAME storage key as the source to decrypt
/// its envelopes — identity mode requires the same `--seed`; passphrase mode
/// requires the same passphrase and storage config.
pub fn cmd_clone(args: CloneArgs, _cwd: &Path) -> Result<(), String> {
    let dest = PathBuf::from(&args.dir);
    std::fs::create_dir_all(&dest).map_err(|e| format!("create {:?}: {e}", dest.display()))?;
    let store_root = dest.join(".origin-vcs");

    let init = InitArgs {
        store: Some(store_root.display().to_string()),
        branch: "main".into(),
        force: false,
        encrypt: args.encrypt.clone(),
        tier: args.tier.clone(),
        seed: args.seed.clone(),
        identity: args.identity,
        passphrase_file: args.passphrase_file.clone(),
    };
    cmd_init(init, &dest)?;

    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let net_seed = parse_net_seed(args.net_seed.as_deref())?;
    let mut store = resolve_store(&Some(store_root.display().to_string()), &dest, &ks)?;
    crate::remote::add(store.root(), &args.name, &args.target)?;
    let remote = crate::remote::get(store.root(), &args.name)?;
    // `--depth N` implies a shallow clone of at most N ancestor generations;
    // plain `--shallow` is depth 1 (tips only).
    let fetch_depth = args.depth.or(if args.shallow { Some(1) } else { None });
    let manifest = crate::remote::fetch(
        &mut store,
        &ks,
        &remote,
        true,
        net_seed,
        args.stun.as_deref(),
        fetch_depth,
    )?;

    // Sparse clone: record the subtree set before the first checkout so only
    // those paths are materialized (the full history + objects stay local).
    if !args.path.is_empty() {
        store.set_sparse(&args.path)?;
    }
    let branch = match &args.branch {
        Some(b) => b.clone(),
        None => {
            if manifest.branches.contains_key("main") {
                "main".into()
            } else {
                manifest
                    .branches
                    .keys()
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("remote '{}' has no branches", remote.name))?
            }
        }
    };
    let remote_ref = format!("{}/{branch}", args.name);
    let tip = store.read_ref("remotes", &remote_ref)?;
    crate::remote::attach_branch(&mut store, &ks, &branch, tip, &dest, &remote_ref)?;
    println!(
        "cloned {} (branch {branch}) into {}",
        remote.name,
        dest.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let cwd = cwd.as_path();
    match cli.command {
        Commands::Init(a) => cmd_init(a, cwd),
        Commands::Add(a) => cmd_add(a, cwd),
        Commands::Rm(a) => cmd_rm(a, cwd),
        Commands::Status(a) => cmd_status(a, cwd),
        Commands::Commit(a) => cmd_commit(a, cwd),
        Commands::Log(a) => cmd_log(a, cwd),
        Commands::Show(a) => cmd_show(a, cwd),
        Commands::Branch(a) => cmd_branch(a, cwd),
        Commands::Checkout(a) => cmd_checkout(a, cwd),
        Commands::Tag(a) => cmd_tag(a, cwd),
        Commands::Diff(a) => cmd_diff(a, cwd),
        Commands::Merge(a) => cmd_merge(a, cwd),
        Commands::Rebase(a) => cmd_rebase(a, cwd),
        Commands::CherryPick(a) => cmd_cherry_pick(a, cwd),
        Commands::Stash(a) => cmd_stash(a, cwd),
        Commands::Blame(a) => cmd_blame(a, cwd),
        Commands::Clone(a) => cmd_clone(a, cwd),
        Commands::Verify(a) => cmd_verify(a, cwd),
        Commands::Mmr(a) => cmd_mmr(a, cwd),
        Commands::Reset(a) => cmd_reset(a, cwd),
        Commands::Gc(a) => cmd_gc(a, cwd),
        Commands::Remote(a) => cmd_remote(a, cwd),
        Commands::Bundle(a) => cmd_bundle(a, cwd),
        Commands::Bisect(a) => cmd_bisect(a, cwd),
    }
}

// ---------------------------------------------------------------------------
// bisect — binary search for the regression commit
// ---------------------------------------------------------------------------

/// Persistent bisect state stored in `.origin-vcs/BISECT_STATE`.
#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug)]
struct BisectState {
    /// Known good commits (exactly one when session starts).
    goods: Vec<[u8; 32]>,
    /// Known bad commits (exactly one when session starts).
    bads: Vec<[u8; 32]>,
    /// Commits skipped because they are not buildable.
    skipped: Vec<[u8; 32]>,
}

fn bisect_state_path(store: &Store) -> std::path::PathBuf {
    store.root().join("BISECT_STATE")
}

fn load_bisect_state(store: &Store) -> Result<BisectState, String> {
    let bytes =
        std::fs::read(bisect_state_path(store)).map_err(|e| format!("bisect state: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("bisect state parse: {e}"))
}

fn save_bisect_state(store: &Store, state: &BisectState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|e| format!("bisect ser: {e}"))?;
    origin_common::atomic_write(&bisect_state_path(store), &bytes)
        .map_err(|e| format!("write bisect state: {e}"))
}

/// Walk ancestors of `tip` in commit order (newest first), skipping commits
/// in `skip` and `already_visited`, until a valid candidate is found.
/// A commit is valid if it is reachable from `tip` without passing any of
/// the `goods` commits, and is not in `skip` or `already_visited`.
fn bisect_candidates(
    store: &Store,
    tip: [u8; 32],
    goods: &BTreeSet<[u8; 32]>,
    skip: &BTreeSet<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut queue = vec![tip];
    while let Some(id) = queue.pop() {
        if !seen.insert(id) || goods.contains(&id) {
            continue;
        }
        out.push(id);
        if let Ok(c) = store.read_commit(&id) {
            for p in &c.parents {
                queue.push(*p);
            }
        }
    }
    out.retain(|id| !skip.contains(id));
    out
}

/// Find the merge-base (common ancestor) of two commits by walking both
/// parent chains and returning the first commit seen in both walks.
fn bisect_merge_base(store: &Store, a: [u8; 32], b: [u8; 32]) -> Result<[u8; 32], String> {
    let mut seen_a: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut queue_a = vec![a];
    while let Some(id) = queue_a.pop() {
        if !seen_a.insert(id) {
            continue;
        }
        if let Ok(c) = store.read_commit(&id) {
            for p in &c.parents {
                queue_a.push(*p);
            }
        }
    }
    let mut seen_b: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut queue_b = vec![b];
    while let Some(id) = queue_b.pop() {
        if !seen_b.insert(id) {
            continue;
        }
        if seen_a.contains(&id) {
            return Ok(id);
        }
        if let Ok(c) = store.read_commit(&id) {
            for p in &c.parents {
                queue_b.push(*p);
            }
        }
    }
    Err("no merge-base found between the good and bad commits".into())
}

/// Compute the bisect midpoint using the Git algorithm:
/// 1. Find all commits reachable from bad but not from good.
/// 2. Pick the commit at the halfway point by commit-graph distance.
fn bisect_next(
    store: &Store,
    goods: &BTreeSet<[u8; 32]>,
    bads: &BTreeSet<[u8; 32]>,
    skip: &BTreeSet<[u8; 32]>,
) -> Result<[u8; 32], String> {
    // Find the merge-base of any good and any bad.
    let _base = bisect_merge_base(
        store,
        *goods.iter().next().unwrap(),
        *bads.iter().next().unwrap(),
    )?;
    // Candidates: commits reachable from bad but not from any good, skipping.
    let mut candidates = Vec::new();
    for &bad in bads {
        candidates.extend(bisect_candidates(store, bad, goods, skip));
    }
    // Retain only those reachable from the bad tip.
    candidates.dedup();
    if candidates.is_empty() {
        return Err("no remaining candidates to bisect".into());
    }
    // The midpoint: Git's algorithm picks the commit in the middle of the
    // topo-sorted list (counting from base to bad).
    let mid = candidates.len() / 2;
    Ok(candidates[mid])
}

pub fn cmd_bisect(args: crate::cli::BisectArgs, cwd: &Path) -> Result<(), String> {
    let ks = resolve_keysource(
        args.identity,
        args.seed.as_deref(),
        args.passphrase_file.as_deref(),
    )?;
    let mut store = resolve_store(&args.store, cwd, &ks)?;

    match args.action {
        crate::cli::BisectAction::Start { good, bad } => {
            let good_id = resolve_id(&store, &good)?;
            let bad_id = match bad {
                Some(b) => resolve_id(&store, &b)?,
                None => {
                    let h = store.head_branch()?.ok_or("no HEAD")?;
                    store.read_ref("heads", &h)?
                }
            };
            let state = BisectState {
                goods: vec![good_id],
                bads: vec![bad_id],
                skipped: vec![],
            };
            save_bisect_state(&store, &state)?;
            // Print the first candidate
            let next = bisect_next(
                &store,
                &state.goods.iter().copied().collect(),
                &state.bads.iter().copied().collect(),
                &state.skipped.iter().copied().collect(),
            )?;
            let c = store.read_commit(&next)?;
            println!(
                "bisect: next is {} ({})",
                short(&next),
                c.message.split('\n').next().unwrap_or("")
            );
        }
        crate::cli::BisectAction::Good { commit } => {
            let mut state = load_bisect_state(&store)?;
            let id = resolve_id(&store, &commit)?;
            state.goods.push(id);
            save_bisect_state(&store, &state)?;
            let next = bisect_next(
                &store,
                &state.goods.iter().copied().collect(),
                &state.bads.iter().copied().collect(),
                &state.skipped.iter().copied().collect(),
            )?;
            let c = store.read_commit(&next)?;
            println!(
                "bisect: next is {} ({})",
                short(&next),
                c.message.split('\n').next().unwrap_or("")
            );
        }
        crate::cli::BisectAction::Bad { commit } => {
            let mut state = load_bisect_state(&store)?;
            let id = resolve_id(&store, &commit)?;
            state.bads.push(id);
            save_bisect_state(&store, &state)?;
            let next = bisect_next(
                &store,
                &state.goods.iter().copied().collect(),
                &state.bads.iter().copied().collect(),
                &state.skipped.iter().copied().collect(),
            )?;
            let c = store.read_commit(&next)?;
            println!(
                "bisect: next is {} ({})",
                short(&next),
                c.message.split('\n').next().unwrap_or("")
            );
        }
        crate::cli::BisectAction::Skip => {
            let mut state = load_bisect_state(&store)?;
            // Skip the current HEAD
            let head = store.head_branch()?.ok_or("no HEAD")?;
            let head_id = store.read_ref("heads", &head)?;
            state.skipped.push(head_id);
            save_bisect_state(&store, &state)?;
            let next = bisect_next(
                &store,
                &state.goods.iter().copied().collect(),
                &state.bads.iter().copied().collect(),
                &state.skipped.iter().copied().collect(),
            )?;
            let c = store.read_commit(&next)?;
            println!(
                "bisect: next is {} ({})",
                short(&next),
                c.message.split('\n').next().unwrap_or("")
            );
        }
        crate::cli::BisectAction::Reset => {
            let path = bisect_state_path(&store);
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| format!("remove bisect state: {e}"))?;
            }
            println!("bisect: session reset");
        }
        crate::cli::BisectAction::Run { script } => {
            let mut state = load_bisect_state(&store)?;
            // Maintain a single good/bad window. `lo` is the newest commit we
            // know is good (or the original good boundary) and `hi` the newest
            // known-bad boundary; every classification shrinks the window so
            // the midpoint moves each iteration and the search terminates.
            let mut lo: [u8; 32] = *state
                .goods
                .last()
                .unwrap_or(state.bads.first().expect("bisect has no state"));
            let mut hi: [u8; 32] = *state.bads.last().expect("bisect has no bad");
            let mut skipped: BTreeSet<[u8; 32]> = state.skipped.iter().copied().collect();
            loop {
                // Interior commits strictly between the good (lo) and bad (hi)
                // boundaries. `bisect_candidates` walks hi's ancestors but
                // stops at lo; we drop hi itself (already classified) and lo so
                // the midpoint always picks a fresh, untested commit.
                let mut candidates: Vec<[u8; 32]> =
                    bisect_candidates(&store, hi, &BTreeSet::from([lo]), &skipped)
                        .into_iter()
                        .filter(|id| *id != hi)
                        .collect();
                if candidates.is_empty() {
                    break;
                }
                candidates.reverse(); // oldest-first
                let mid = candidates[candidates.len() / 2];
                // Checkout mid
                let head_branch = store.head_branch()?.ok_or("no HEAD")?;
                let bundle = ks.signing_bundle()?;
                let sig = Signature::sign(&bundle, &mid);
                store.write_ref("heads", &head_branch, mid, &sig)?;
                store.update_mem_ref("heads", &head_branch, mid);
                let mid_c = store.read_commit(&mid)?;
                let mid_tree = store.read_tree(&mid_c.tree)?;
                store.save_index(&mid_tree)?;
                ensure_tree_on_disk(&store, &mid_tree, cwd)?;
                // Run the script
                let status = std::process::Command::new("sh")
                    .args(["-c", &script])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        lo = mid;
                        state.goods.push(mid);
                        println!("bisect: {} is GOOD", short(&mid));
                    }
                    Ok(s) => {
                        hi = mid;
                        state.bads.push(mid);
                        println!(
                            "bisect: {} is BAD (exit {})",
                            short(&mid),
                            s.code().unwrap_or(-1)
                        );
                    }
                    Err(e) => {
                        skipped.insert(mid);
                        state.skipped.push(mid);
                        println!("bisect: {} skipped (script error: {e})", short(&mid));
                    }
                }
            }
            save_bisect_state(&store, &state)?;
            println!("bisect: first bad commit is {}", short(&hi));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_way_ours_wins_on_conflict() {
        let mut base = Tree::new();
        base.entries.insert(
            "x".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [1u8; 32],
            },
        );
        let mut ours = base.clone();
        ours.entries.get_mut("x").unwrap().id = [2u8; 32];
        let mut theirs = base.clone();
        theirs.entries.get_mut("x").unwrap().id = [3u8; 32];
        let (m, conflicts) = three_way(&base, &ours, &theirs).unwrap();
        assert_eq!(m.entries["x"].id, [2u8; 32]);
        assert_eq!(conflicts, vec!["x"]);
    }

    #[test]
    fn three_way_added_on_both_identical() {
        let base = Tree::new();
        let mut ours = base.clone();
        let mut theirs = base.clone();
        ours.entries.insert(
            "n".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [9u8; 32],
            },
        );
        theirs.entries.insert(
            "n".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [9u8; 32],
            },
        );
        let (m, conflicts) = three_way(&base, &ours, &theirs).unwrap();
        assert!(m.entries.contains_key("n"));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn three_way_one_side_change_wins() {
        let mut base = Tree::new();
        base.entries.insert(
            "f".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [1u8; 32],
            },
        );
        let mut ours = base.clone();
        ours.entries.get_mut("f").unwrap().id = [7u8; 32]; // ours changed
        let theirs = base.clone(); // theirs unchanged
        let (m, _) = three_way(&base, &ours, &theirs).unwrap();
        assert_eq!(m.entries["f"].id, [7u8; 32]);
    }

    #[test]
    fn conflict_marker_detection() {
        assert!(has_conflict_markers(
            b"a\n<<<<<<< ours\nx\n>>>>>>> theirs\n"
        ));
        assert!(has_conflict_markers(b">>>>>>> theirs\n"));
        assert!(!has_conflict_markers(b"clean file\n<<< not a marker\n"));
        assert!(!has_conflict_markers(b""));
    }

    #[test]
    fn three_way_removed_both_gone() {
        let mut base = Tree::new();
        base.entries.insert(
            "r".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [5u8; 32],
            },
        );
        let ours = Tree::new();
        let theirs = Tree::new();
        let (m, _) = three_way(&base, &ours, &theirs).unwrap();
        assert!(!m.entries.contains_key("r"));
    }
}
