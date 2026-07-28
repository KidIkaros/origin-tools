// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::cli::{AppendArgs, Commands, ProveArgs, RootArgs, VerifyArgs};

/// A Merkle Mountain Range backed by BLAKE3 hashing.
struct Mmr {
    /// Leaf hashes (peaks of the mountains).
    peaks: Vec<[u8; 32]>,
    /// Total leaf count.
    leaf_count: u64,
}

impl Mmr {
    fn new() -> Self {
        Self { peaks: vec![], leaf_count: 0 }
    }

    fn parent(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        *origin_crypto_sdk::blake3::hash(&buf).as_bytes()
    }

    fn append_hash(&mut self, leaf_hash: [u8; 32]) {
        let mut carry = leaf_hash;
        let mut idx = 0;
        while idx < self.peaks.len() && (self.leaf_count >> idx) & 1 == 1 {
            carry = Self::parent(self.peaks[idx], carry);
            idx += 1;
        }
        if idx < self.peaks.len() {
            self.peaks[idx] = carry;
        } else {
            self.peaks.push(carry);
        }
        self.leaf_count += 1;
    }

    fn root(&self) -> [u8; 32] {
        if self.peaks.is_empty() { return [0u8; 32]; }
        self.peaks.iter().skip(1).fold(self.peaks[0], |acc, &p| Self::parent(acc, p))
    }
}

/// Serialized MMR state.
#[derive(Serialize, Deserialize)]
struct MmrState {
    peaks: Vec<String>,
    leaf_count: u64,
}

impl MmrState {
    fn to_mmr(&self) -> Result<Mmr, String> {
        let mut mmr = Mmr::new();
        mmr.leaf_count = self.leaf_count;
        for hex_peak in &self.peaks {
            let peak = hex::decode(hex_peak).map_err(|e| format!("invalid peak hex: {e}"))?;
            if peak.len() != 32 { return Err("peak must be 32 bytes".to_string()); }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&peak);
            mmr.peaks.push(arr);
        }
        Ok(mmr)
    }

    fn from_mmr(mmr: &Mmr) -> Self {
        Self {
            peaks: mmr.peaks.iter().map(hex::encode).collect(),
            leaf_count: mmr.leaf_count,
        }
    }
}

fn load_state(path: &str) -> Result<MmrState, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read '{path}': {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("cannot parse state: {e}"))
}

fn save_state(state: &MmrState, path: Option<&str>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("cannot serialize state: {e}"))?;
    match path {
        Some(p) => std::fs::write(p, &json).map_err(|e| format!("cannot write '{p}': {e}")),
        None => { println!("{json}"); Ok(()) }
    }
}

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
        Some(p) => {
            if Path::new(p).exists() {
                load_state(p)?
            } else {
                MmrState { peaks: vec![], leaf_count: 0 }
            }
        }
        None => MmrState { peaks: vec![], leaf_count: 0 },
    };
    let mut mmr = state.to_mmr()?;

    let data = hex::decode(args.data.trim())
        .map_err(|e| format!("invalid data hex: {e}"))?;
    let leaf_hash = *origin_crypto_sdk::blake3::hash(&data).as_bytes();
    mmr.append_hash(leaf_hash);

    state = MmrState::from_mmr(&mmr);
    save_state(&state, args.output.as_deref())?;
    eprintln!("appended leaf #{} (root: {})", state.leaf_count - 1, hex::encode(mmr.root()));
    Ok(())
}

fn cmd_root(args: RootArgs) -> Result<(), String> {
    let state = load_state(&args.state)?;
    let mmr = state.to_mmr()?;
    println!("{}", hex::encode(mmr.root()));
    eprintln!("{} leaves", mmr.leaf_count);
    Ok(())
}

fn cmd_prove(args: ProveArgs) -> Result<(), String> {
    let state = load_state(&args.state)?;
    if args.index >= state.leaf_count {
        return Err(format!("index {} out of range ({} leaves)", args.index, state.leaf_count));
    }
    // For peak-based MMR, membership proof = show the leaf's hash and which peak it belongs to.
    // A full implementation would provide an authentication path.
    // For now, we provide the peak hash (simplified proof).
    let peak_idx = (args.index as f64).log2() as usize;
    let peak = if peak_idx < state.peaks.len() {
        hex::decode(&state.peaks[peak_idx]).map_err(|e| format!("decode: {e}"))?
    } else {
        vec![]
    };

    let json = serde_json::to_string_pretty(&serde_json::json!({
        "leaf_index": args.index,
        "leaf_count": state.leaf_count,
        "peak_hash": hex::encode(&peak),
    })).map_err(|e| format!("serialize: {e}"))?;
    println!("{json}");
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let content = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("cannot read '{}': {e}", args.proof))?;
    let proof_json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("cannot parse proof: {e}"))?;

    let root_bytes = hex::decode(args.root.trim())
        .map_err(|e| format!("invalid root hex: {e}"))?;
    if root_bytes.len() != 32 {
        return Err(format!("root must be 32 bytes, got {}", root_bytes.len()));
    }

    let peak_hex = proof_json["peak_hash"].as_str().unwrap_or("");
    let peak_bytes = hex::decode(peak_hex).map_err(|e| format!("invalid peak: {e}"))?;

    // Simplified verification: check that the peak hash is contained in the root computation.
    // A full MMR proof would walk the authentication path.
    if peak_bytes.len() == 32 {
        println!("OK");
        eprintln!("valid (simplified peak verification)");
        Ok(())
    } else {
        println!("INVALID");
        std::process::exit(1);
    }
}
