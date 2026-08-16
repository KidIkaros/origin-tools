// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2026 Origin Contributors

//! Origin Canary Embedder — CLI entry point.

use origin_canary::manifest::CanaryManifest;
use origin_canary::{embed, verify};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "origin-canary",
    about = "Origin Canary Embedder — steganographic canary token embedding + hybrid-PQC provenance",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Embed canary tokens into a source tree, build a BLAKE3 Merkle commitment.
    Embed(EmbedArgs),
    /// Verify canary tokens in a suspect codebase against a manifest.
    Verify(VerifyArgs),
    /// Sign a manifest with the creator's hybrid Ed25519+Falcon-1024 identity.
    Sign(SignArgs),
    /// Verify a signed commitment (both signatures must pass).
    VerifyCommitment(VerifyCommitmentArgs),
    /// Fingerprint a release archive and bind it to a signed commitment.
    Fingerprint(FingerprintArgs),
    /// Verify a signed fingerprint (optionally vs. archive and commitment).
    VerifyFingerprint(VerifyFingerprintArgs),
    /// Append a fingerprint to a local JSONL ledger.
    Publish(PublishArgs),
    /// Assemble a litigation evidence package from a suspect codebase.
    Evidence(EvidenceArgs),
    /// CI gate: scan a tree, exit non-zero if canaries are missing/invalid.
    Ci(CiArgs),
}

#[derive(Parser, Debug)]
struct EmbedArgs {
    /// Source directory to embed canaries into.
    #[arg(short = 'S', long)]
    source: PathBuf,

    /// Arbitrary project identifier chosen by the creator.
    #[arg(short = 'p', long)]
    project_id: u64,

    /// Distribution identifier (e.g. release tag, version string).
    #[arg(short = 'd', long)]
    distribution_id: String,

    /// Per-distribution salt (hex-encoded). Keep offline.
    #[arg(short = 's', long)]
    salt: String,

    /// Number of canary tokens to embed.
    #[arg(short = 'n', long, default_value = "10")]
    num_canaries: usize,

    /// Output path for the manifest JSON.
    #[arg(long, default_value = "canary_manifest.json")]
    manifest_out: PathBuf,

    /// Strategies to use, in order (cycling through them for each token).
    /// Comma-separated: variable.python,variable.javascript,watermark,deadcode.python
    #[arg(
        long,
        default_value = "variable.python,variable.javascript,watermark,deadcode.python"
    )]
    strategies: String,
}

#[derive(Parser, Debug)]
struct VerifyArgs {
    /// Source directory to scan for canary tokens.
    #[arg(short, long)]
    source: PathBuf,

    /// Path to the canary manifest JSON.
    #[arg(short = 'm', long)]
    manifest: PathBuf,

    /// Print results as a single JSON line (machine-readable).
    #[arg(long)]
    json: bool,
}

#[derive(Parser, Debug)]
struct SignArgs {
    /// Path to the canary manifest JSON to sign.
    #[arg(short = 'm', long)]
    manifest: PathBuf,

    /// Encrypted identity blob (from `origin identity keygen`).
    #[arg(short = 'i', long)]
    identity: PathBuf,

    /// Passphrase file for the identity blob (prompts if omitted).
    #[arg(short = 'P', long)]
    passphrase_file: Option<PathBuf>,

    /// Memory tier used when the identity was created (nano|standard|sovereign).
    #[arg(short = 't', long, default_value = "standard")]
    tier: String,

    /// Output path for the signed commitment JSON.
    #[arg(short = 'o', long, default_value = "canary_commitment.json")]
    out: PathBuf,
}

#[derive(Parser, Debug)]
struct VerifyCommitmentArgs {
    /// Path to the signed commitment JSON.
    #[arg(short = 'c', long)]
    commitment: PathBuf,
}

#[derive(Parser, Debug)]
struct FingerprintArgs {
    /// Path to the canary manifest JSON.
    #[arg(short = 'm', long)]
    manifest: PathBuf,

    /// Path to the signed commitment JSON (must match the manifest).
    #[arg(short = 'c', long)]
    commitment: PathBuf,

    /// The distributed archive file to fingerprint (tar/zip/etc.).
    #[arg(short = 'a', long)]
    archive: PathBuf,

    /// Encrypted identity blob (from `origin identity keygen`).
    #[arg(short = 'i', long)]
    identity: PathBuf,

    /// Passphrase file for the identity blob (prompts if omitted).
    #[arg(short = 'P', long)]
    passphrase_file: Option<PathBuf>,

    /// Memory tier used when the identity was created (nano|standard|sovereign).
    #[arg(short = 't', long, default_value = "standard")]
    tier: String,

    /// Output path for the signed fingerprint JSON.
    #[arg(short = 'o', long, default_value = "canary_fingerprint.json")]
    out: PathBuf,
}

#[derive(Parser, Debug)]
struct VerifyFingerprintArgs {
    /// Path to the signed fingerprint JSON.
    #[arg(short = 'f', long)]
    fingerprint: PathBuf,

    /// Optional: re-hash this archive and compare against the record.
    #[arg(short = 'a', long)]
    archive: Option<PathBuf>,

    /// Optional: check the fingerprint against this commitment.
    #[arg(short = 'c', long)]
    commitment: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct PublishArgs {
    /// Path to the signed fingerprint JSON.
    #[arg(short = 'f', long)]
    fingerprint: PathBuf,

    /// Ledger file to append to (created if missing; JSONL).
    #[arg(short = 'l', long, default_value = "canary_ledger.jsonl")]
    ledger: PathBuf,
}

#[derive(Parser, Debug)]
struct EvidenceArgs {
    /// Suspect source directory to scan.
    #[arg(short = 'S', long)]
    source: PathBuf,

    /// Path to the canary manifest JSON.
    #[arg(short = 'm', long)]
    manifest: PathBuf,

    /// Path to the signed commitment JSON.
    #[arg(short = 'c', long)]
    commitment: PathBuf,

    /// Optional: signed fingerprint JSON to include in the chain.
    #[arg(short = 'f', long)]
    fingerprint: Option<PathBuf>,

    /// Optional: JSONL ledger to confirm the fingerprint was published.
    #[arg(short = 'l', long)]
    ledger: Option<PathBuf>,

    /// Output path for the evidence package JSON.
    #[arg(short = 'o', long, default_value = "evidence.json")]
    out: PathBuf,
}

#[derive(Parser, Debug)]
struct CiArgs {
    /// Suspect source directory to scan.
    #[arg(short = 'S', long)]
    source: PathBuf,

    /// Path to the canary manifest JSON.
    #[arg(short = 'm', long)]
    manifest: PathBuf,

    /// Optional: signed commitment JSON (verifies the signature chain too).
    #[arg(short = 'c', long)]
    commitment: Option<PathBuf>,

    /// File threshold: exit 3 if fewer than N canary matches are found.
    #[arg(short = 'n', long, default_value = "1")]
    min_matches: usize,

    /// Print machine-readable JSON lines instead of human output.
    #[arg(long)]
    json: bool,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unlock an identity blob → master seed. Shared by sign + fingerprint.
fn unlock_seed(
    identity: &std::path::Path,
    passphrase_file: &Option<PathBuf>,
    tier: &str,
) -> Result<[u8; 32], String> {
    let blob = std::fs::read(identity)
        .map_err(|e| format!("cannot read identity blob {}: {e}", identity.display()))?;

    let passphrase = match passphrase_file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read passphrase file: {e}"))?
            .trim()
            .to_string(),
        None => rpassword::prompt_password("Identity passphrase: ")
            .map_err(|e| format!("passphrase prompt failed: {e}"))?,
    };

    let tier = match tier {
        "nano" => origin_crypto_sdk::tier::MemoryTier::Nano,
        "sovereign" => origin_crypto_sdk::tier::MemoryTier::Sovereign,
        "standard" => origin_crypto_sdk::tier::MemoryTier::Standard,
        other => return Err(format!("unknown tier '{other}'")),
    };

    eprintln!("Unlocking identity (Argon2id)...");
    origin_crypto_sdk::blob::recover_seed(&blob, passphrase.as_bytes(), tier)
        .map_err(|e| format!("decryption failed (wrong passphrase or corrupted blob): {e}"))
}

fn die(msg: String) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

/// Load and parse a JSON file, exiting 1 with a clear message on any failure.
fn load_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read {}: {e}", path.display())));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| die(format!("cannot parse {}: {e}", path.display())))
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Embed(args) => {
            let strategy_names: Vec<String> = args
                .strategies
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if strategy_names.is_empty() {
                eprintln!("error: at least one strategy must be specified");
                process::exit(1);
            }

            let config = embed::EmbedConfig {
                source_dir: args.source,
                project_id: args.project_id,
                distribution_id: args.distribution_id,
                salt: args.salt,
                num_canaries: args.num_canaries,
                manifest_out: Some(args.manifest_out.clone()),
                strategy_names,
            };

            match embed::run_embed(config) {
                Ok(result) => {
                    println!("Embedding complete.");
                    println!("  Project ID:       {}", result.manifest.project_id);
                    println!("  Distribution:     {}", result.manifest.distribution_id);
                    println!("  Tokens embedded:  {}", result.manifest.token_count);
                    println!("  Merkle root:      {}", result.merkle_root);
                    println!("  Files modified:   {}", result.modified_files.len());
                    println!("  Manifest:         {}", args.manifest_out.display());
                    println!();
                    println!("To verify a suspect codebase:");
                    println!(
                        "  origin-canary verify --source <suspect-dir> -m {}",
                        args.manifest_out.display()
                    );
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Verify(args) => {
            let manifest_json = match std::fs::read_to_string(&args.manifest) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("error: cannot read manifest: {}", e);
                    process::exit(1);
                }
            };

            let manifest: CanaryManifest = match serde_json::from_str(&manifest_json) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("error: cannot parse manifest: {}", e);
                    process::exit(1);
                }
            };

            if manifest.is_empty() {
                eprintln!("error: manifest contains no canary tokens");
                process::exit(1);
            }

            let matches = verify::verify_source(&args.source, &manifest);

            if args.json {
                let obj = serde_json::json!({
                    "tool": "origin-canary",
                    "mode": "verify",
                    "matches": matches.len(),
                    "match_details": matches.iter().map(|m| serde_json::json!({
                        "token_id": m.token_id,
                        "file_path": m.file_path,
                        "line_number": m.line_number,
                        "secret": m.secret,
                    })).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string(&obj).unwrap());
            } else {
                verify::print_verification_results(&matches, &manifest);
            }

            // Exit 0 even with no matches — the scan completed successfully.
            // A non-zero exit would be reserved for actual errors.
            process::exit(0);
        }
        Commands::Sign(args) => {
            let manifest_json = match std::fs::read_to_string(&args.manifest) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("error: cannot read manifest: {}", e);
                    process::exit(1);
                }
            };
            let manifest: CanaryManifest = match serde_json::from_str(&manifest_json) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("error: cannot parse manifest: {}", e);
                    process::exit(1);
                }
            };

            let blob = match std::fs::read(&args.identity) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: cannot read identity blob: {}", e);
                    process::exit(1);
                }
            };

            // Passphrase: file or interactive prompt (never echoed).
            let passphrase = match &args.passphrase_file {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(p) => p.trim().to_string(),
                    Err(e) => {
                        eprintln!("error: cannot read passphrase file: {}", e);
                        process::exit(1);
                    }
                },
                None => match rpassword::prompt_password("Identity passphrase: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: passphrase prompt failed: {}", e);
                        process::exit(1);
                    }
                },
            };

            let tier = match args.tier.as_str() {
                "nano" => origin_crypto_sdk::tier::MemoryTier::Nano,
                "sovereign" => origin_crypto_sdk::tier::MemoryTier::Sovereign,
                "standard" => origin_crypto_sdk::tier::MemoryTier::Standard,
                other => {
                    eprintln!("error: unknown tier '{}'", other);
                    process::exit(1);
                }
            };

            eprintln!("Unlocking identity (Argon2id)...");
            let seed =
                match origin_crypto_sdk::blob::recover_seed(&blob, passphrase.as_bytes(), tier) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "error: decryption failed (wrong passphrase or corrupted blob): {}",
                            e
                        );
                        process::exit(1);
                    }
                };

            eprintln!("Deriving hybrid signing keys (Ed25519 + Falcon-1024)...");
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            match origin_canary::commitment::sign_commitment(&manifest, &seed, timestamp) {
                Ok(commitment) => {
                    let json = match serde_json::to_string_pretty(&commitment) {
                        Ok(j) => j,
                        Err(e) => {
                            eprintln!("error: cannot serialize commitment: {}", e);
                            process::exit(1);
                        }
                    };
                    if let Err(e) = std::fs::write(&args.out, json) {
                        eprintln!("error: cannot write {}: {}", args.out.display(), e);
                        process::exit(1);
                    }
                    println!("Commitment signed.");
                    println!("  Project:          {}", commitment.payload.project_id);
                    println!("  Distribution:     {}", commitment.payload.distribution_id);
                    println!("  Merkle root:      {}", commitment.payload.merkle_root);
                    println!("  Structure digest: {}", commitment.payload.structure);
                    println!("  Timestamp:        {}", commitment.payload.timestamp);
                    println!("  Output:           {}", args.out.display());
                    println!();
                    println!("To verify the commitment:");
                    println!(
                        "  origin-canary verify-commitment -c {}",
                        args.out.display()
                    );
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::VerifyCommitment(args) => {
            let commitment_json = match std::fs::read_to_string(&args.commitment) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("error: cannot read commitment: {}", e);
                    process::exit(1);
                }
            };
            let commitment: origin_canary::commitment::SignedCommitment =
                match serde_json::from_str(&commitment_json) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("error: cannot parse commitment: {}", e);
                        process::exit(1);
                    }
                };

            match commitment.verify() {
                Ok(origin_canary::commitment::Verification::Valid) => {
                    println!("Commitment is VALID.");
                    println!("  Version:      {}", commitment.payload.version);
                    println!("  Project:      {}", commitment.payload.project_id);
                    println!("  Distribution: {}", commitment.payload.distribution_id);
                    println!("  Merkle root:  {}", commitment.payload.merkle_root);
                    println!("  Timestamp:    {}", commitment.payload.timestamp);
                    println!("  Domain:       {}", commitment.domain);
                    println!("  Ed25519:      valid");
                    println!("  Falcon-1024:  valid");
                    process::exit(0);
                }
                Ok(origin_canary::commitment::Verification::Invalid(reason)) => {
                    println!("Commitment is INVALID.");
                    println!("  Reason: {}", reason);
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("error: malformed commitment: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Fingerprint(args) => {
            let manifest: CanaryManifest = load_json(&args.manifest);
            let commitment: origin_canary::commitment::SignedCommitment =
                load_json(&args.commitment);

            let seed = unlock_seed(&args.identity, &args.passphrase_file, &args.tier)
                .unwrap_or_else(|e| die(e));

            eprintln!("Deriving hybrid signing keys (Ed25519 + Falcon-1024)...");
            match origin_canary::fingerprint::sign_fingerprint(
                &manifest,
                &commitment,
                &args.archive,
                &seed,
                now_unix(),
            ) {
                Ok(fp) => {
                    let json = serde_json::to_string_pretty(&fp)
                        .unwrap_or_else(|e| die(format!("cannot serialize fingerprint: {e}")));
                    std::fs::write(&args.out, json).unwrap_or_else(|e| {
                        die(format!("cannot write {}: {e}", args.out.display()))
                    });
                    println!("Fingerprint signed.");
                    println!("  Archive:            {}", fp.payload.archive_name);
                    println!("  Archive hash:       {}", fp.payload.archive_hash);
                    println!("  Archive size:       {} bytes", fp.payload.archive_size);
                    println!("  Source tree hash:   {}", fp.payload.source_tree_hash);
                    println!("  Merkle root:        {}", fp.payload.merkle_root);
                    println!("  Commitment digest:  {}", fp.payload.commitment_digest);
                    println!(
                        "  Project / Dist:     {} / {}",
                        fp.payload.project_id, fp.payload.distribution_id
                    );
                    println!("  Output:             {}", args.out.display());
                    println!();
                    println!("To verify the fingerprint:");
                    println!(
                        "  origin-canary verify-fingerprint -f {}",
                        args.out.display()
                    );
                }
                Err(e) => die(e),
            }
        }
        Commands::VerifyFingerprint(args) => {
            let fp: origin_canary::fingerprint::SignedFingerprint = load_json(&args.fingerprint);

            let mut checks: Vec<(&str, bool)> = vec![];
            let mut hard_fail = false;

            match fp.verify() {
                Ok(origin_canary::commitment::Verification::Valid) => {
                    checks.push(("signatures (Ed25519 + Falcon-1024)", true))
                }
                Ok(origin_canary::commitment::Verification::Invalid(reason)) => {
                    checks.push(("signatures (Ed25519 + Falcon-1024)", false));
                    println!("  signature failure: {reason}");
                    hard_fail = true;
                }
                Err(e) => die(format!("malformed fingerprint: {e}")),
            }

            if let Some(archive) = &args.archive {
                match fp.matches_archive(archive) {
                    Ok(true) => checks.push(("archive hash + size", true)),
                    Ok(false) => {
                        checks.push(("archive hash + size", false));
                        hard_fail = true;
                    }
                    Err(e) => die(e),
                }
            }

            if let Some(commitment_path) = &args.commitment {
                let commitment: origin_canary::commitment::SignedCommitment =
                    load_json(commitment_path);
                match fp.matches_commitment(&commitment) {
                    Ok(true) => checks.push(("commitment binding", true)),
                    Ok(false) => {
                        checks.push(("commitment binding", false));
                        hard_fail = true;
                    }
                    Err(e) => die(e),
                }
            }

            println!("Fingerprint verification:");
            for (name, ok) in &checks {
                println!("  [{}] {}", if *ok { "PASS" } else { "FAIL" }, name);
            }
            if hard_fail {
                println!("Fingerprint is INVALID.");
                process::exit(2);
            }
            println!("Fingerprint is VALID.");
        }
        Commands::Publish(args) => {
            let fp: origin_canary::fingerprint::SignedFingerprint = load_json(&args.fingerprint);

            match origin_canary::fingerprint::publish(&args.ledger, &fp) {
                Ok(index) => {
                    println!("Published record #{index} to {}", args.ledger.display());
                    println!(
                        "  Project / Dist: {} / {}",
                        fp.payload.project_id, fp.payload.distribution_id
                    );
                    println!(
                        "  Archive:         {} ({})",
                        fp.payload.archive_name, fp.payload.archive_hash
                    );
                }
                Err(e) => die(e),
            }
        }
        Commands::Evidence(args) => {
            let manifest: CanaryManifest = load_json(&args.manifest);
            let commitment: origin_canary::commitment::SignedCommitment =
                load_json(&args.commitment);

            let fingerprint = args.fingerprint.as_ref().map(|p| {
                serde_json::from_str::<origin_canary::fingerprint::SignedFingerprint>(
                    &std::fs::read_to_string(p)
                        .unwrap_or_else(|e| die(format!("cannot read fingerprint: {e}"))),
                )
                .unwrap_or_else(|e| die(format!("cannot parse fingerprint: {e}")))
            });

            match origin_canary::evidence::assemble(
                &args.source,
                &manifest,
                &commitment,
                fingerprint.as_ref(),
                args.ledger.as_deref(),
                now_unix(),
            ) {
                Ok(package) => {
                    let json = serde_json::to_string_pretty(&package)
                        .unwrap_or_else(|e| die(format!("cannot serialize evidence: {e}")));
                    std::fs::write(&args.out, json).unwrap_or_else(|e| {
                        die(format!("cannot write {}: {e}", args.out.display()))
                    });
                    println!("Evidence package assembled.");
                    println!("  Matches:       {}", package.matches.len());
                    println!(
                        "  Merkle root:   {}",
                        &package.merkle_root[..16.min(package.merkle_root.len())]
                    );
                    let checks = package.all_checks();
                    for (name, ok) in &checks {
                        println!("  [{}] {}", if *ok { "PASS" } else { "FAIL" }, name);
                    }
                    println!("  Output:        {}", args.out.display());
                    if package.is_sound() {
                        println!("Evidence package is SOUND.");
                    } else {
                        println!("Evidence package has FAILED checks.");
                        process::exit(2);
                    }
                }
                Err(e) => die(e),
            }
        }
        Commands::Ci(args) => {
            let manifest: CanaryManifest = load_json(&args.manifest);

            let matches = origin_canary::verify::verify_source(&args.source, &manifest);

            let mut checks: Vec<(String, bool)> = vec![];
            checks.push((
                format!(
                    "canary matches ≥ {} (found {})",
                    args.min_matches,
                    matches.len()
                ),
                matches.len() >= args.min_matches,
            ));

            // Optional commitment chain verification.
            let mut commitment_valid = true;
            if let Some(c_path) = &args.commitment {
                let commitment: origin_canary::commitment::SignedCommitment = load_json(c_path);
                let sig_ok = matches!(
                    commitment.verify(),
                    Ok(origin_canary::commitment::Verification::Valid)
                );
                let root_ok = manifest.merkle_root.as_deref()
                    == Some(commitment.payload.merkle_root.as_str());
                commitment_valid = sig_ok && root_ok;
                checks.push((
                    format!(
                        "commitment valid + bound to manifest (sig={}, root={})",
                        sig_ok, root_ok
                    ),
                    commitment_valid,
                ));
            }

            if args.json {
                let mut obj = serde_json::json!({
                    "tool": "origin-canary",
                    "mode": "ci",
                    "matches": matches.len(),
                    "min_matches": args.min_matches,
                    "pass": matches.len() >= args.min_matches && commitment_valid,
                    "match_details": matches.iter().map(|m| serde_json::json!({
                        "token_id": m.token_id,
                        "file_path": m.file_path,
                        "line_number": m.line_number,
                    })).collect::<Vec<_>>(),
                });
                if args.commitment.is_some() {
                    obj["commitment_valid"] = serde_json::json!(commitment_valid);
                }
                println!("{}", serde_json::to_string(&obj).unwrap());
                if obj["pass"].as_bool().unwrap_or(false) {
                    process::exit(0);
                } else {
                    process::exit(3);
                }
            }

            println!("origin-canary CI gate:");
            for (name, ok) in &checks {
                println!("  [{}] {}", if *ok { "PASS" } else { "FAIL" }, name);
            }
            if matches.len() >= args.min_matches && commitment_valid {
                println!("CI gate PASSED.");
            } else {
                println!("CI gate FAILED.");
                process::exit(3);
            }
        }
    }
}
