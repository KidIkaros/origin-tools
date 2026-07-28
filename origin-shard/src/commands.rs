// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::cli::{Commands, RecoverArgs, SplitArgs};
use origin_common::read_input;
use origin_crypto_sdk::error_correction::ReedSolomonCodec;

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Split(args) => cmd_split(args),
        Commands::Recover(args) => cmd_recover(args),
    }
}

fn cmd_split(args: SplitArgs) -> Result<(), String> {
    if args.data_shards == 0 {
        return Err("data_shards must be >= 1".to_string());
    }
    if args.parity_shards == 0 {
        return Err("parity_shards must be >= 1".to_string());
    }

    let data = read_input(args.input.as_deref())?;
    if data.is_empty() {
        return Err("input data must not be empty".to_string());
    }

    let total = args.data_shards + args.parity_shards;
    let codec = ReedSolomonCodec::new(args.data_shards, args.parity_shards);
    let shards = codec
        .encode_shards(&data)
        .map_err(|e| format!("RS encode failed: {e}"))?;

    std::fs::create_dir_all(&args.output)
        .map_err(|e| format!("cannot create '{}': {e}", args.output))?;

    let shard_size = shards[0].len();
    for (i, shard) in shards.iter().enumerate() {
        let path = format!("{}/shard_{:03}.bin", args.output, i);
        std::fs::write(&path, shard).map_err(|e| format!("cannot write '{path}': {e}"))?;
    }

    let meta = serde_json::json!({
        "original_data_len": data.len(),
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
        data.len(),
        total,
        args.data_shards,
        args.parity_shards,
        shard_size,
        args.output
    );
    Ok(())
}

fn cmd_recover(args: RecoverArgs) -> Result<(), String> {
    if args.data_shards == 0 {
        return Err("data_shards must be >= 1".to_string());
    }
    if args.parity_shards == 0 {
        return Err("parity_shards must be >= 1".to_string());
    }

    let meta_path = format!("{}/metadata.json", args.input);
    let meta_str = std::fs::read_to_string(&meta_path)
        .map_err(|e| format!("cannot read metadata '{meta_path}': {e}"))?;
    let meta: serde_json::Value =
        serde_json::from_str(&meta_str).map_err(|e| format!("cannot parse metadata: {e}"))?;
    let original_data_len = meta["original_data_len"].as_u64().unwrap_or(0) as usize;
    let shard_size = meta["shard_size"].as_u64().unwrap_or(0) as usize;
    let total = args.data_shards + args.parity_shards;

    if shard_size == 0 {
        return Err("invalid shard_size in metadata".to_string());
    }
    if original_data_len == 0 {
        return Err("invalid original_data_len in metadata".to_string());
    }

    // Load shards as Option<Vec<u8>> — None for missing files.
    // This enables true erasure recovery via decode_shards().
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
    let mut present = 0usize;
    let mut missing = Vec::new();
    for i in 0..total {
        let path = format!("{}/shard_{:03}.bin", args.input, i);
        if Path::new(&path).exists() {
            let shard = std::fs::read(&path).map_err(|e| format!("cannot read shard {i}: {e}"))?;
            if shard.len() != shard_size {
                return Err(format!(
                    "shard {i} has wrong size: got {}, expected {shard_size}",
                    shard.len()
                ));
            }
            present += 1;
            shards.push(Some(shard));
        } else {
            missing.push(i);
            shards.push(None);
        }
    }

    if present < args.data_shards {
        return Err(format!(
            "not enough shards: have {present}, need at least {} (missing: {:?})",
            args.data_shards, missing
        ));
    }

    let codec = ReedSolomonCodec::new(args.data_shards, args.parity_shards);
    let decoded = codec
        .decode_shards(&shards, original_data_len)
        .map_err(|e| format!("RS decode failed: {e}"))?;

    origin_common::write_output(args.output.as_deref(), &decoded)?;
    eprintln!(
        "Recovered {} bytes from {} present shards (of {}, {} missing) in {}",
        decoded.len(),
        present,
        total,
        missing.len(),
        args.input
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use origin_crypto_sdk::error_correction::ReedSolomonCodec;

    /// Split data into shards via the SDK, write to a temp dir, and recover.
    fn split_and_recover(
        data: &[u8],
        data_shards: usize,
        parity_shards: usize,
        remove_indices: &[usize],
    ) -> Result<Vec<u8>, String> {
        let _total = data_shards + parity_shards;
        let codec = ReedSolomonCodec::new(data_shards, parity_shards);
        let shards = codec
            .encode_shards(data)
            .map_err(|e| format!("encode: {e}"))?;
        let _shard_size = shards[0].len();

        // Build Option list, removing specified indices
        let mut opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for &idx in remove_indices {
            opts[idx] = None;
        }

        codec
            .decode_shards(&opts, data.len())
            .map_err(|e| format!("decode: {e}"))
    }

    #[test]
    fn roundtrip_no_loss() {
        let data = b"hello world, this is a test of reed-solomon sharding";
        let recovered = split_and_recover(data, 3, 2, &[]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn recover_one_missing_data_shard() {
        let data = b"the quick brown fox jumps over the lazy dog";
        // Remove data shard 0
        let recovered = split_and_recover(data, 3, 2, &[0]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn recover_one_missing_parity_shard() {
        let data = b"parity shard loss should be transparent";
        // Remove parity shard (index 3 = first parity in 3+2 config)
        let recovered = split_and_recover(data, 3, 2, &[3]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn recover_max_erasures() {
        let data = b"maximum erasure recovery test with exactly parity_shards missing";
        // Remove 2 shards (= parity_shards) — one data, one parity
        let recovered = split_and_recover(data, 3, 2, &[0, 4]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn too_many_missing_fails() {
        let data = b"this should fail because too many shards are missing";
        // Remove 3 shards (> parity_shards=2)
        let result = split_and_recover(data, 3, 2, &[0, 1, 3]);
        assert!(result.is_err(), "should fail with too many missing shards");
    }

    #[test]
    fn single_byte_data() {
        let data = b"X";
        let recovered = split_and_recover(data, 2, 1, &[]).unwrap();
        assert_eq!(recovered, data);
        // With one shard missing
        let recovered = split_and_recover(data, 2, 1, &[0]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn odd_shard_count_1_plus_1() {
        let data = b"minimal config: 1 data + 1 parity";
        let recovered = split_and_recover(data, 1, 1, &[]).unwrap();
        assert_eq!(recovered, data);
        // Lose the data shard, recover from parity alone
        let recovered = split_and_recover(data, 1, 1, &[0]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn high_parity_config() {
        let data = b"high redundancy: 2 data + 4 parity shards for robust storage";
        // Can lose up to 4 shards
        let recovered = split_and_recover(data, 2, 4, &[0, 1, 3, 5]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn large_data_64kb() {
        let data: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let recovered = split_and_recover(&data, 4, 2, &[]).unwrap();
        assert_eq!(recovered, data);
        // With one shard missing
        let recovered = split_and_recover(&data, 4, 2, &[2]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn large_data_1mb() {
        let data: Vec<u8> = (0..1_048_576).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let recovered = split_and_recover(&data, 5, 3, &[1, 4]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn data_not_divisible_by_shards() {
        // 10 bytes / 3 data shards = shard_size 4, last shard padded
        let data = b"0123456789";
        let recovered = split_and_recover(data, 3, 2, &[]).unwrap();
        assert_eq!(recovered, data);
        let recovered = split_and_recover(data, 3, 2, &[1]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn all_zeros_data() {
        let data = vec![0u8; 100];
        let recovered = split_and_recover(&data, 3, 2, &[0]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn all_0xff_data() {
        let data = vec![0xFFu8; 100];
        let recovered = split_and_recover(&data, 3, 2, &[2]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn deterministic_encoding() {
        let data = b"determinism check";
        let codec = ReedSolomonCodec::new(3, 2);
        let a = codec.encode_shards(data).unwrap();
        let b = codec.encode_shards(data).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_data_different_shards() {
        let codec = ReedSolomonCodec::new(3, 2);
        let a = codec.encode_shards(b"aaa").unwrap();
        let b = codec.encode_shards(b"bbb").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn shard_sizes_are_equal() {
        let data = b"uneven length data for shard size check!!";
        let codec = ReedSolomonCodec::new(4, 3);
        let shards = codec.encode_shards(data).unwrap();
        let size = shards[0].len();
        for (i, s) in shards.iter().enumerate() {
            assert_eq!(s.len(), size, "shard {i} has different size");
        }
    }

    #[test]
    fn wrong_shard_count_in_decode_fails() {
        let codec = ReedSolomonCodec::new(3, 2);
        let shards = codec.encode_shards(b"test").unwrap();
        // Pass wrong number of shards (3 instead of 5)
        let opts: Vec<Option<Vec<u8>>> = shards[..3].iter().cloned().map(Some).collect();
        let result = codec.decode_shards(&opts, 4);
        assert!(result.is_err());
    }

    #[test]
    fn inconsistent_shard_sizes_fail() {
        let codec = ReedSolomonCodec::new(2, 1);
        let shards: Vec<Option<Vec<u8>>> = vec![
            Some(vec![1, 2, 3]),
            Some(vec![4, 5]), // wrong size
            Some(vec![7, 8, 9]),
        ];
        let result = codec.decode_shards(&shards, 3);
        assert!(result.is_err());
    }
}
