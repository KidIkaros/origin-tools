// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use origin_common::read_input;
use origin_crypto_sdk::error_correction::ReedSolomonCodec;
use crate::cli::{Commands, RecoverArgs, SplitArgs};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Split(args) => cmd_split(args),
        Commands::Recover(args) => cmd_recover(args),
    }
}

fn cmd_split(args: SplitArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;
    let total = args.data_shards + args.parity_shards;
    let codec = ReedSolomonCodec::new(args.data_shards, args.parity_shards);
    let encoded = codec
        .encode(&data)
        .map_err(|e| format!("RS encode failed: {e}"))?;

    // encoded = 4-byte original-data-length prefix (from the SDK) +
    // (total_shards * shard_size) of shard bytes. Strip the prefix and
    // write each shard to its own file at the correct index.
    let original_data_len = data.len();
    let shard_payload = &encoded[4..];
    let shard_size = shard_payload.len() / total;

    std::fs::create_dir_all(&args.output)
        .map_err(|e| format!("cannot create '{}': {e}", args.output))?;

    for i in 0..total {
        let start = i * shard_size;
        let end = start + shard_size;
        let shard = &shard_payload[start..end];
        let path = format!("{}/shard_{:03}.bin", args.output, i);
        std::fs::write(&path, shard)
            .map_err(|e| format!("cannot write '{path}': {e}"))?;
    }

    let meta = serde_json::json!({
        "original_data_len": original_data_len,
        "shard_size": shard_size,
        "data_shards": args.data_shards,
        "parity_shards": args.parity_shards,
    });
    std::fs::write(
        format!("{}/metadata.json", args.output),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .map_err(|e| format!("cannot write metadata: {e}"))?;

    eprintln!(
        "Split {} bytes into {} shards ({}+{}, {} bytes each) in {}",
        data.len(), total, args.data_shards, args.parity_shards, shard_size, args.output
    );
    Ok(())
}

fn cmd_recover(args: RecoverArgs) -> Result<(), String> {
    let meta_path = format!("{}/metadata.json", args.input);
    let meta_str = std::fs::read_to_string(&meta_path)
        .map_err(|e| format!("cannot read metadata '{meta_path}': {e}"))?;
    let meta: serde_json::Value =
        serde_json::from_str(&meta_str).map_err(|e| format!("cannot parse metadata: {e}"))?;
    let original_data_len = meta["original_data_len"].as_u64().unwrap_or(0) as u32;
    let shard_size = meta["shard_size"].as_u64().unwrap_or(0) as usize;
    let total = (args.data_shards + args.parity_shards) as usize;

    if shard_size == 0 {
        return Err("invalid shard_size in metadata".to_string());
    }

    // Build the full ordered shard set. The SDK's decode expects every shard
    // slot physically present at its index (0..total). Missing shards are
    // filled with zero-shards so the parity check can detect and recover them.
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total);
    let mut present = 0usize;
    for i in 0..total {
        let path = format!("{}/shard_{:03}.bin", args.input, i);
        let shard = if Path::new(&path).exists() {
            std::fs::read(&path).map_err(|e| format!("cannot read shard {i}: {e}"))?
        } else {
            vec![0u8; shard_size]
        };
        if shard.len() != shard_size {
            return Err(format!(
                "shard {i} has wrong size: got {}, expected {shard_size}",
                shard.len()
            ));
        }
        if shard.iter().any(|b| *b != 0) {
            present += 1;
        }
        shards.push(shard);
    }

    // Reconstruct the encoded blob the SDK expects: a 4-byte original-data
    // length prefix followed by all shards concatenated in index order.
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&original_data_len.to_le_bytes());
    for shard in &shards {
        encoded.extend_from_slice(shard);
    }

    let codec = ReedSolomonCodec::new(args.data_shards, args.parity_shards);
    let decoded = codec
        .decode(&encoded)
        .map_err(|e| format!("RS decode failed: {e}"))?;

    origin_common::write_output(args.output.as_deref(), &decoded)?;
    eprintln!(
        "Recovered {} bytes from {} present shards (of {}) in {}",
        decoded.len(),
        present,
        total,
        args.input
    );
    Ok(())
}
