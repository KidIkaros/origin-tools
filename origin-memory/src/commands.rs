// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-memory.
//!
//! Identity model: the graph's master seed is derived from the suite's
//! unified origin identity (`~/.origin/identity.seed`) via
//! `IdentityStore::derive_key(domain, 32)`. One seed, domain-separated —
//! no separate key material for the memory graph.

use std::path::PathBuf;

use origin_common::{
    resolve_passphrase, resolve_passphrase_confirm, tier_from_str, IdentityStore, MemoryTier,
    OriginHome,
};

use crate::{Evidence, Memory, MemoryNode, ZoomQuery};

use crate::cli::{
    AddArgs, Commands, EndorseArgs, GraphArgs, RevokeArgs, TreeArgs, TrustArgs, VerifyArgs,
    ZoomArgs,
};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Init(args) => cmd_init(args),
        Commands::Add(args) => cmd_add(args),
        Commands::Revoke(args) => cmd_revoke(args),
        Commands::Zoom(args) => cmd_zoom(args),
        Commands::Tree(args) => cmd_tree(args),
        Commands::Chart(args) => cmd_chart(args),
        Commands::Verify(args) => cmd_verify(args),
        Commands::Endorse(args) => cmd_endorse(args),
        Commands::Trust(args) => cmd_trust(args),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Shared open-graph plumbing
// ──────────────────────────────────────────────────────────────────────

/// Derive the graph's master seed from the suite identity.
///
/// With `bootstrap = true` (only `init`), a missing suite identity is created
/// on first use, so `origin memory init` is a self-contained bootstrap. All
/// other commands only load — they never create key material silently.
fn master_seed(graph: &GraphArgs, bootstrap: bool) -> Result<[u8; 32], String> {
    let home = OriginHome::load()?;
    let seed_path = home.identity_seed_path();
    let identity = if !seed_path.exists() && bootstrap {
        let passphrase = resolve_passphrase_confirm(graph.passphrase_file.as_deref())?;
        let store = IdentityStore::create(&home, &passphrase, MemoryTier::Standard)
            .map_err(|e| format!("cannot create suite identity: {e}"))?;
        eprintln!(
            "Created suite identity at {} (passphrase-protected).",
            seed_path.display()
        );
        store
    } else {
        let passphrase = resolve_passphrase(graph.passphrase_file.as_deref())?;
        IdentityStore::load(&home, &passphrase).map_err(|e| {
            format!("cannot load origin identity: {e}. Run `origin memory init` to bootstrap it.")
        })?
    };
    let key = identity.derive_key(&graph.domain, 32)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key);
    Ok(seed)
}

fn graph_root(graph: &GraphArgs) -> Result<PathBuf, String> {
    match &graph.root {
        Some(r) => {
            let expanded = if let Some(stripped) = r.strip_prefix("~/") {
                match std::env::var_os("HOME") {
                    Some(h) => PathBuf::from(h).join(stripped),
                    None => PathBuf::from(r),
                }
            } else {
                PathBuf::from(r)
            };
            Ok(expanded)
        }
        None => Ok(OriginHome::load()?.root().join("memory")),
    }
}

fn open_memory(graph: &GraphArgs, bootstrap: bool) -> Result<(Memory, PathBuf), String> {
    let seed = master_seed(graph, bootstrap)?;
    let root = graph_root(graph)?;
    let mem = Memory::open(&root, &seed, &graph.domain)
        .map_err(|e| format!("open graph at {}: {e}", root.display()))?;
    Ok((mem, root))
}

/// Surface integrity warnings that `open` collects — never fatal, never silent.
fn print_integrity_warnings(mem: &Memory) {
    for id in mem.tampered() {
        eprintln!("warning: node '{id}' failed signature verification on load");
    }
    for problem in mem.journal_tampered() {
        eprintln!("warning: {problem}");
    }
}

// ──────────────────────────────────────────────────────────────────────
// Commands
// ──────────────────────────────────────────────────────────────────────

fn cmd_init(graph: GraphArgs) -> Result<(), String> {
    let (mem, root) = open_memory(&graph, true)?;
    print_integrity_warnings(&mem);
    let schema = mem
        .schema_version()
        .map_err(|e| format!("schema version: {e}"))?;
    println!("Memory graph: {}", root.display());
    println!("  fingerprint:    {}", mem.fingerprint());
    println!("  schema version: {schema}");
    println!("  nodes:          {}", mem.len());
    Ok(())
}

fn cmd_add(args: AddArgs) -> Result<(), String> {
    let (mut mem, root) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);

    let node = if let Some(file) = &args.file {
        MemoryNode::from_markdown_file(std::path::Path::new(file))?
    } else {
        let id = args
            .id
            .as_deref()
            .ok_or("--id required (or use --file)")?
            .to_string();
        let title = args.title.as_deref().unwrap_or(&id).to_string();
        let time = args.time.as_deref().ok_or("--time required (YYYY-MM-DD)")?;
        if args.topics.is_empty() {
            return Err("--topics required (comma-separated)".to_string());
        }
        let body = match &args.body {
            Some(b) => b.clone(),
            None => {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .map_err(|e| format!("read stdin: {e}"))?;
                buf
            }
        };
        let md = format!(
            "---\ntitle: {title}\ntime: {time}\ntopic: [{}]\nevidence: {}\n---\n{body}",
            args.topics.join(", "),
            args.evidence
        );
        MemoryNode::from_markdown(&id, &md)?
    };

    let id = node.id.clone();
    if args.secret {
        mem.add_secret(node)
    } else {
        mem.add(node)
    }
    .map_err(|e| format!("add: {e}"))?;

    println!(
        "Added '{id}' ({}) to {}",
        if args.secret { "secret" } else { "signed" },
        root.display()
    );
    Ok(())
}

fn cmd_revoke(args: RevokeArgs) -> Result<(), String> {
    let (mut mem, _) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);
    if mem.node(&args.id).is_none() {
        return Err(format!("node '{}' not found", args.id));
    }
    mem.revoke(&args.id, &args.reason)
        .map_err(|e| format!("revoke: {e}"))?;
    println!(
        "Revoked '{}' (reason: {}). The journal entry is signed and hash-chained.",
        args.id, args.reason
    );
    Ok(())
}

fn cmd_zoom(args: ZoomArgs) -> Result<(), String> {
    let (mem, _) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);

    let time = match &args.date {
        Some(d) => {
            let center = chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
                .map_err(|e| format!("bad --date '{d}': {e}"))?;
            Some((center, args.window))
        }
        None => None,
    };
    let evidence = args.evidence.as_deref().map(Evidence::from_label);
    let tier = match &args.tier {
        Some(t) => Some(tier_from_str(t)?),
        None => None,
    };
    let q = ZoomQuery {
        time,
        topics: if args.topic.is_empty() {
            None
        } else {
            Some(args.topic.clone())
        },
        evidence,
        tier,
        min_trust: args.min_trust,
        trust_domain: args.trust_domain.clone(),
    };

    if args.scored {
        let results = mem.zoom_scored(&q);
        for r in results {
            let trust = r
                .signer_trust
                .map(|t| format!(" trust={t:.2}"))
                .unwrap_or_default();
            println!("{:.4}  {}{trust}", r.score, r.id);
        }
    } else {
        for id in mem.zoom(&q) {
            println!("{id}");
        }
    }
    Ok(())
}

fn cmd_tree(args: TreeArgs) -> Result<(), String> {
    let (mem, _) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);
    if mem.node(&args.id).is_none() {
        return Err(format!("node '{}' not found", args.id));
    }
    print!("{}", mem.render_tree(&args.id));
    Ok(())
}

fn cmd_chart(graph: GraphArgs) -> Result<(), String> {
    let (mem, _) = open_memory(&graph, false)?;
    print_integrity_warnings(&mem);
    print!("{}", mem.render_star_chart());
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let (mut mem, _) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);

    if let Some(id) = &args.id {
        let ok = mem.verify(id);
        println!(
            "{}: {}",
            id,
            if ok {
                "signature OK"
            } else {
                "signature FAILED"
            }
        );
        return if ok {
            Ok(())
        } else {
            Err(format!("verify failed for '{id}'"))
        };
    }

    let report = mem.verify_all();
    println!(
        "Graph integrity: {} valid, {} revoked, {} failed",
        report.valid.len(),
        report.revoked.len(),
        report.failed.len()
    );
    if !report.revoked.is_empty() {
        println!("  revoked: {}", report.revoked.join(", "));
    }
    if !report.failed.is_empty() {
        println!("  FAILED:  {}", report.failed.join(", "));
    }

    let rev_ok = mem.revocations_verified();
    let end_ok = mem.store_endorsements_verified();
    println!(
        "Journals: revocations {} | endorsements {}",
        if rev_ok { "OK" } else { "BROKEN" },
        if end_ok { "OK" } else { "BROKEN" }
    );

    if args.layer {
        let summary_ids: Vec<String> = mem
            .node_ids()
            .into_iter()
            .filter(|id| {
                mem.node(id)
                    .is_some_and(|n| n.evidence == Evidence::Summary)
            })
            .collect();
        let mut checked = 0usize;
        let mut failed = 0usize;
        for sid in &summary_ids {
            if let Some(summary) = mem.node(sid) {
                let links: Vec<String> = summary.links.iter().cloned().collect();
                for lid in links {
                    checked += 1;
                    if !mem.verify_layer(sid, &lid) {
                        failed += 1;
                        println!("  layer proof FAILED: {lid} in {sid}");
                    }
                }
            }
        }
        println!("Layer proofs: {} checked, {} failed", checked, failed);
        if failed > 0 {
            return Err("layer membership proofs failed".to_string());
        }
    }

    if report.all_sound() && rev_ok && end_ok {
        Ok(())
    } else {
        Err("integrity check failed".to_string())
    }
}

fn cmd_endorse(args: EndorseArgs) -> Result<(), String> {
    let (mut mem, _) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);
    if args.target.len() != 64 || !args.target.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("--target must be a 64-char hex fingerprint".to_string());
    }
    if !(0.0..=1.0).contains(&args.confidence) {
        return Err("--confidence must be in [0,1]".to_string());
    }
    mem.endorse(&args.target, &args.capability, args.confidence);
    println!(
        "Endorsed {} in domain '{}' (confidence {:.2}). Signed + chained into endorsements.json.",
        &args.target[..12],
        args.capability,
        args.confidence
    );
    Ok(())
}

fn cmd_trust(args: TrustArgs) -> Result<(), String> {
    let (mem, _) = open_memory(&args.graph, false)?;
    print_integrity_warnings(&mem);
    let score = mem.trust_score(&args.target, &args.capability);
    println!(
        "trust({} | {}) = {:.4}",
        &args.target, args.capability, score
    );
    Ok(())
}
