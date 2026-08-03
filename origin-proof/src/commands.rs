// SPDX-License-Identifier: Apache-2.0

//! commands — CLI dispatch for origin-proof (MMR membership proofs).
//!
//! The MMR implementation itself lives in `crate::mmr` so it can be reused as a
//! library (e.g. by origin-memory for per-layer tamper-evident proofs). This
//! module only handles CLI argument parsing, state file I/O, and proof output.

use std::path::Path;

use crate::cli::{AppendArgs, Commands, ProveArgs, RootArgs, VerifyArgs};
use crate::mmr::{decode_hash, parent_hash, MembershipProof, MmrState};

// ---------------------------------------------------------------------------
// State I/O
// ---------------------------------------------------------------------------

fn load_state(path: &str) -> Result<MmrState, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let state: MmrState =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse state: {e}"))?;
    if state.version != 2 {
        return Err(format!(
            "unsupported state version {} (expected 2)",
            state.version
        ));
    }
    Ok(state)
}

fn save_state(state: &MmrState, path: Option<&str>) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(state).map_err(|e| format!("cannot serialize state: {e}"))?;
    match path {
        Some(p) => std::fs::write(p, &json).map_err(|e| format!("cannot write '{p}': {e}")),
        None => {
            println!("{json}");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Append(args) => cmd_append(args),
        Commands::Root(args) => cmd_root(args),
        Commands::Prove(args) => cmd_prove(args),
        Commands::Verify(args) => cmd_verify(args),
    }
}

fn cmd_append(args: AppendArgs) -> Result<(), String> {
    let mut state = match &args.state {
        Some(p) if Path::new(p).exists() => load_state(p)?,
        _ => MmrState::new(),
    };

    let data = hex::decode(args.data.trim()).map_err(|e| format!("invalid data hex: {e}"))?;
    if data.is_empty() {
        return Err("data must not be empty".to_string());
    }
    let leaf_hash = *origin_crypto_sdk::blake3::hash(&data).as_bytes();
    state.append_hash(leaf_hash);

    save_state(&state, args.output.as_deref())?;
    eprintln!(
        "appended leaf #{} (root: {})",
        state.leaf_count - 1,
        hex::encode(state.root())
    );
    Ok(())
}

fn cmd_root(args: RootArgs) -> Result<(), String> {
    let state = load_state(&args.state)?;
    println!("{}", hex::encode(state.root()));
    eprintln!(
        "{} leaves, {} mountains",
        state.leaf_count,
        state.mountains.len()
    );
    Ok(())
}

fn cmd_prove(args: ProveArgs) -> Result<(), String> {
    let state = load_state(&args.state)?;
    let proof = state.prove(args.index)?;
    let json = serde_json::to_string_pretty(&proof).map_err(|e| format!("serialize proof: {e}"))?;
    println!("{json}");
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let content = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("cannot read '{}': {e}", args.proof))?;
    let proof: MembershipProof =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse proof: {e}"))?;

    let expected_root =
        hex::decode(args.root.trim()).map_err(|e| format!("invalid root hex: {e}"))?;
    if expected_root.len() != 32 {
        return Err(format!(
            "root must be 32 bytes, got {}",
            expected_root.len()
        ));
    }

    // Walk the auth path from leaf to peak, then reconstruct root from peaks.
    let mut current = decode_hash(&proof.leaf_hash);
    for step in &proof.auth_path {
        let sibling = decode_hash(&step.hash);
        current = if step.is_left {
            parent_hash(current, sibling)
        } else {
            parent_hash(sibling, current)
        };
    }

    if proof.peak_index >= proof.peaks.len() {
        return Err(format!(
            "peak_index {} out of range ({} peaks)",
            proof.peak_index,
            proof.peaks.len()
        ));
    }
    let mut peaks: Vec<[u8; 32]> = proof.peaks.iter().map(|p| decode_hash(p)).collect();
    peaks[proof.peak_index] = current;

    let computed_root = if peaks.is_empty() {
        [0u8; 32]
    } else {
        peaks
            .iter()
            .skip(1)
            .fold(peaks[0], |acc, &p| parent_hash(acc, p))
    };

    if computed_root == expected_root[..] {
        println!("OK");
        eprintln!(
            "leaf {} verified against root ({} peaks, auth path length {})",
            proof.leaf_index,
            peaks.len(),
            proof.auth_path.len()
        );
        Ok(())
    } else {
        Err(format!(
            "computed root {} != expected {}",
            hex::encode(computed_root),
            hex::encode(&expected_root)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(data: &[u8]) -> [u8; 32] {
        *origin_crypto_sdk::blake3::hash(data).as_bytes()
    }

    fn build_mmr(n: u64) -> MmrState {
        let mut state = MmrState::new();
        for i in 0..n {
            state.append_hash(h(&i.to_le_bytes()));
        }
        state
    }

    #[test]
    fn cli_prove_verify_round_trip() {
        let state = build_mmr(50);
        let root = state.root();
        for i in 0..50 {
            let proof = state.prove(i).unwrap();
            // Verify via the library path used by cmd_verify's reconstruction.
            let mut current = decode_hash(&proof.leaf_hash);
            for step in &proof.auth_path {
                let sibling = decode_hash(&step.hash);
                current = if step.is_left {
                    parent_hash(current, sibling)
                } else {
                    parent_hash(sibling, current)
                };
            }
            let mut peaks: Vec<[u8; 32]> = proof.peaks.iter().map(|p| decode_hash(p)).collect();
            peaks[proof.peak_index] = current;
            let computed = if peaks.is_empty() {
                [0u8; 32]
            } else {
                peaks
                    .iter()
                    .skip(1)
                    .fold(peaks[0], |acc, &p| parent_hash(acc, p))
            };
            assert_eq!(computed, root, "leaf {i}");
        }
    }
}
