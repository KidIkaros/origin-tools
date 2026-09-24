// SPDX-License-Identifier: Apache-2.0

//! api — the typed library surface for origin-shard.
//!
//! Reed-Solomon split and recover as plain function calls over in-memory
//! data. File/directory handling stays in the CLI layer; these functions
//! operate on bytes so any application can plug in its own storage.
//!
//! Design rules (see ARCHITECTURE.md):
//! - One crypto provider: erasure coding goes through the SDK's
//!   `ReedSolomonCodec` — nothing is re-implemented here.
//! - Errors are typed (`ShardError`), never `String`.

use origin_crypto_sdk::error_correction::ReedSolomonCodec;

use crate::error::{Result, ShardError};

/// Split `data` into `data_shards` data shards + `parity_shards` parity
/// shards (Reed-Solomon). Returns the shards in order; any application can
/// persist them however it wants (files, object storage, network).
pub fn split(data: &[u8], data_shards: usize, parity_shards: usize) -> Result<Vec<Vec<u8>>> {
    if data_shards == 0 || parity_shards == 0 {
        return Err(ShardError::InvalidConfig(
            "data_shards and parity_shards must both be >= 1".into(),
        ));
    }
    if data.is_empty() {
        return Err(ShardError::InvalidConfig(
            "input data must not be empty".into(),
        ));
    }

    let codec = ReedSolomonCodec::new(data_shards, parity_shards);
    let shards = codec
        .encode_shards(data)
        .map_err(|e| ShardError::Codec(format!("encode failed: {e}")))?;
    Ok(shards)
}

/// Recover the original data from a set of shards (any order; missing
/// shards passed as `None`).
///
/// `data_shards` must be >= 1 and `parity_shards` >= 1. Shard sizes must
/// match the size recorded in metadata.
pub fn recover(
    shards: &[Option<Vec<u8>>],
    data_shards: usize,
    parity_shards: usize,
    original_data_len: usize,
) -> Result<Vec<u8>> {
    if data_shards == 0 || parity_shards == 0 {
        return Err(ShardError::InvalidConfig(
            "data_shards and parity_shards must both be >= 1".into(),
        ));
    }
    if original_data_len == 0 {
        return Err(ShardError::InvalidConfig(
            "original_data_len must be > 0".into(),
        ));
    }

    let total = data_shards + parity_shards;
    if shards.len() != total {
        return Err(ShardError::InvalidConfig(format!(
            "expected {total} shards, got {}",
            shards.len()
        )));
    }

    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < data_shards {
        let missing: Vec<usize> = shards
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_none())
            .map(|(i, _)| i)
            .collect();
        return Err(ShardError::NotEnoughShards(format!(
            "have {present}, need at least {data_shards} (missing: {missing:?})"
        )));
    }

    let codec = ReedSolomonCodec::new(data_shards, parity_shards);
    codec
        .decode_shards(shards, original_data_len)
        .map_err(|e| ShardError::Codec(format!("decode failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_and_recover(
        data: &[u8],
        data_shards: usize,
        parity_shards: usize,
        remove_indices: &[usize],
    ) -> Result<Vec<u8>> {
        let codec = ReedSolomonCodec::new(data_shards, parity_shards);
        let shards = codec
            .encode_shards(data)
            .map_err(|e| ShardError::Codec(format!("encode: {e}")))?;

        let mut opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for &idx in remove_indices {
            opts[idx] = None;
        }

        recover(&opts, data_shards, parity_shards, data.len())
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
        let recovered = split_and_recover(data, 3, 2, &[0]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn recover_one_missing_parity_shard() {
        let data = b"parity shard loss should be transparent";
        let recovered = split_and_recover(data, 3, 2, &[3]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn recover_max_erasures() {
        let data = b"maximum erasure recovery test with exactly parity_shards missing";
        let recovered = split_and_recover(data, 3, 2, &[0, 4]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn too_many_missing_fails() {
        let data = b"this should fail because too many shards are missing";
        let result = split_and_recover(data, 3, 2, &[0, 1, 3]);
        assert!(result.is_err(), "should fail with too many missing shards");
    }

    #[test]
    fn single_byte_data() {
        let data = b"X";
        let recovered = split_and_recover(data, 2, 1, &[]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn large_data_64kb() {
        let data: Vec<u8> = (0..65536).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let recovered = split_and_recover(&data, 4, 2, &[2]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn zero_config_rejected() {
        let data = b"anything";
        assert!(split(data, 0, 2).is_err());
        assert!(split(data, 3, 0).is_err());
        assert!(split(b"", 3, 2).is_err());
    }
}
