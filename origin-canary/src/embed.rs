// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! Canary embedding logic — core embed flow.

use crate::manifest::{CanaryManifest, CanaryToken};
use crate::merkle::{build_merkle_tree, get_merkle_proof};
use crate::strategies::{impls::*, traits::EmbedStrategy, traits::SeededRng};
use origin_crypto_sdk::blake3;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for an embedding run.
#[derive(Debug)]
pub struct EmbedConfig {
    /// Source directory to embed canaries into.
    pub source_dir: PathBuf,
    /// Arbitrary project identifier chosen by the creator.
    pub project_id: u64,
    /// Distribution identifier (e.g. release tag, version string).
    pub distribution_id: String,
    /// Per-distribution salt (hex-encoded). Keep offline.
    pub salt: String,
    /// Number of canary tokens to embed.
    pub num_canaries: usize,
    /// Output path for the manifest JSON.
    pub manifest_out: Option<PathBuf>,
    /// Strategies to use, in order (cycling through them for each token).
    pub strategy_names: Vec<String>,
}

/// Result of an embedding run.
#[derive(Debug)]
pub struct EmbedResult {
    /// The generated manifest.
    pub manifest: CanaryManifest,
    /// Files that were modified.
    pub modified_files: Vec<String>,
    /// The Merkle root (hex).
    pub merkle_root: String,
}

/// Generate a single canary token secret.
///
/// Deterministic from `(project_id, distribution_id, index, salt)` using BLAKE3.
/// Format: `canary_<blake3(project_id | distribution_id | index | salt)[:12]>`.
pub fn generate_canary_token(
    project_id: u64,
    distribution_id: &str,
    index: usize,
    salt: &str,
) -> String {
    let data = format!(
        "{}{}{}{}{}",
        project_id, distribution_id, index, salt, "canary-v1"
    );
    let hash = blake3::hash(data.as_bytes());
    let hex_hash = hex::encode(hash.as_bytes()).to_lowercase();
    format!("canary_{}", &hex_hash[..12.min(hex_hash.len())])
}

/// Build the list of embedding strategies from the workspace.
///
/// Returns a map from strategy name to boxed strategy. The first match for a
/// given file extension is used.
pub fn build_strategies() -> HashMap<String, Box<dyn EmbedStrategy>> {
    let mut map: HashMap<String, Box<dyn EmbedStrategy>> = HashMap::new();

    // Variable injection strategies per language.
    map.insert("variable.python".into(), Box::new(VariableInjectPython));
    map.insert(
        "variable.javascript".into(),
        Box::new(VariableInjectJavaScript),
    );
    map.insert("variable.rust".into(), Box::new(VariableInjectRust));
    map.insert("variable.solidity".into(), Box::new(VariableInjectSolidity));

    // Watermark strategies (applies to any text file with comments).
    map.insert("watermark".into(), Box::new(WatermarkStrategy));

    // Dead code strategy (Python-only for now).
    map.insert("deadcode.python".into(), Box::new(DeadCodePython));

    map
}

/// Scan the source tree for files matching the given extensions, excluding
/// directories in the exclusion set.
pub fn scan_files(source_dir: &Path, extensions: &[(impl AsRef<Path>, &[&str])]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let exclusions: Vec<&str> = vec![
        "test",
        "tests",
        "__test__",
        "__tests__",
        "__pycache__",
        "node_modules",
        ".git",
        "venv",
        ".venv",
        ".env",
        "build",
        "dist",
        "target",
        ".tox",
        ".nox",
        ".eggs",
        "tools",
    ];

    for (dir, exts) in extensions {
        let dir_path = source_dir.join(dir);
        if !dir_path.exists() {
            continue;
        }
        scan_dir(&dir_path, exts, &exclusions, &mut files);
    }

    files.sort();
    files
}

fn scan_dir(dir: &Path, exts: &[&str], exclusions: &[&str], files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if exclusions.contains(&dir_name.as_str()) {
                    continue;
                }
                scan_dir(&path, exts, exclusions, files);
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_string();
                    if exts.contains(&ext_str.as_str()) {
                        // Skip very large files.
                        if let Ok(meta) = path.metadata() {
                            if meta.len() < 500_000 {
                                files.push(path);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Run the embedding flow.
pub fn run_embed(config: EmbedConfig) -> Result<EmbedResult, String> {
    let source_dir = &config.source_dir;

    if !source_dir.is_dir() {
        return Err(format!(
            "source directory does not exist: {}",
            source_dir.display()
        ));
    }

    if config.num_canaries == 0 {
        return Err("num_canaries must be at least 1".to_string());
    }

    if config.strategy_names.is_empty() {
        return Err("at least one strategy must be specified".to_string());
    }

    let strategies = build_strategies();
    for name in &config.strategy_names {
        if !strategies.contains_key(name) {
            return Err(format!("unknown strategy '{}'", name));
        }
    }

    // Generate canary tokens.
    let seed = config
        .project_id
        .wrapping_mul(6364136223846793005)
        .wrapping_add(config.distribution_id.len() as u64)
        .wrapping_add(config.salt.len() as u64);
    let mut rng = SeededRng::new(seed);

    // Generate canary tokens.
    let mut tokens: Vec<CanaryToken> = Vec::with_capacity(config.num_canaries);
    for i in 0..config.num_canaries {
        let secret =
            generate_canary_token(config.project_id, &config.distribution_id, i, &config.salt);
        let strategy_name = config.strategy_names[i % config.strategy_names.len()].clone();
        tokens.push(CanaryToken {
            token_id: i,
            secret,
            embedding_type: strategy_name,
            target_file: String::new(),
            line_number: 0,
            merkle_leaf: None,
            merkle_proof: Vec::new(),
        });
    }

    // Embed each token using its assigned strategy.
    let mut modified_files = Vec::new();
    let mut used_files: HashSet<PathBuf> = HashSet::new();

    for token in &mut tokens {
        let Some(strategy) = strategies.get(&token.embedding_type) else {
            eprintln!(
                "warning: unknown strategy '{}' — skipping token {}",
                token.embedding_type, token.token_id
            );
            continue;
        };

        if let Some(relative) = strategy.embed(source_dir, token, &mut rng, &mut used_files) {
            token.target_file = relative.clone();
            modified_files.push(relative);
        } else {
            eprintln!(
                "warning: could not embed token {} (strategy '{}' found no suitable file)",
                token.token_id, token.embedding_type
            );
        }
    }

    // Only tokens that were actually embedded belong in the manifest.
    let mut tokens: Vec<CanaryToken> = tokens
        .into_iter()
        .filter(|t| !t.target_file.is_empty())
        .collect();

    // Honest coverage: if we couldn't place every requested token, say so
    // explicitly rather than silently under-embedding (a forensic tool must
    // not misreport coverage density).
    if tokens.len() < config.num_canaries {
        return Err(format!(
            "only embedded {} of {} requested tokens — not enough eligible source files \
             for the selected strategies (need more files, more languages, or fewer tokens)",
            tokens.len(),
            config.num_canaries
        ));
    }

    if tokens.is_empty() {
        return Err(
            "no canary tokens were embedded — no embeddable files found for the given strategies"
                .to_string(),
        );
    }

    // Record where each token landed: the first line containing the secret
    // in the file we just wrote.
    for token in &mut tokens {
        let path = source_dir.join(&token.target_file);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(idx) = content.lines().position(|l| l.contains(&token.secret)) {
                token.line_number = idx + 1;
            }
        }
    }

    // Compute source tree hash.
    let source_tree_hash = hash_source_tree(source_dir)?;

    // Build Merkle tree.
    let leaf_hashes: Vec<String> = tokens
        .iter()
        .enumerate()
        .map(|(i, token)| {
            let leaf_data = format!(
                "{}|{}|{}|{}",
                token.secret, config.project_id, config.distribution_id, i
            );
            let hash = blake3::hash(leaf_data.as_bytes());
            hex::encode(hash.as_bytes()).to_lowercase()
        })
        .collect();

    let merkle_tree = build_merkle_tree(leaf_hashes);
    let merkle_root = merkle_tree.root.clone();

    // Attach Merkle proofs to tokens.
    for (i, token) in tokens.iter_mut().enumerate() {
        token.merkle_leaf = Some(merkle_tree.leaves[i].clone());
        token.merkle_proof = get_merkle_proof(&merkle_tree, i);
    }

    let manifest = CanaryManifest {
        project_id: config.project_id,
        distribution_id: config.distribution_id.clone(),
        salt: config.salt.clone(),
        source_tree_hash,
        token_count: tokens.len(),
        canary_tokens: tokens,
        merkle_root: Some(merkle_root.clone()),
    };

    // Write manifest.
    if let Some(out_path) = config.manifest_out {
        let json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
        fs::write(&out_path, json).map_err(|e| e.to_string())?;
        eprintln!("manifest written to: {}", out_path.display());
    }

    Ok(EmbedResult {
        manifest,
        modified_files,
        merkle_root,
    })
}

/// Compute a BLAKE3 hash of the source tree (sorted file list + contents).
fn hash_source_tree(source_dir: &Path) -> Result<String, String> {
    let mut hasher = blake3::Hasher::new();

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(source_dir, &mut files)?;

    files.sort();

    for file in &files {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        hasher.update(name.as_bytes());
        if let Ok(content) = fs::read(file) {
            hasher.update(&content);
        }
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash.as_bytes()).to_lowercase())
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            // Skip excluded dirs.
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let exclusions = [
                "test",
                "tests",
                "__pycache__",
                "node_modules",
                ".git",
                "venv",
                ".venv",
                "build",
                "dist",
                "target",
                ".tox",
                ".nox",
                ".eggs",
            ];
            if !exclusions.contains(&name.as_str()) {
                collect_files(&path, files)?;
            }
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_string();
                if [
                    "py", "js", "jsx", "ts", "tsx", "rs", "sol", "c", "cpp", "h", "hpp", "go",
                    "java", "kt",
                ]
                .contains(&ext_str.as_str())
                {
                    files.push(path);
                }
            }
        }
    }
    Ok(())
}
