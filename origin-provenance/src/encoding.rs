// SPDX-License-Identifier: Apache-2.0

//! Canonical byte recipes for the OPM manifest (spec §4).
//!
//! Every hash recipe in the provenance trust path lives here, byte-locked
//! with golden vectors. Content hashing is BLAKE3; identity/commitment
//! hashing is SHA3-256. Digest inputs are assembled by `*_input` builders so
//! tests (and the Python cross-check) can pin the exact bytes, not just the
//! digest.
//!
//! Domain tags (byte counts verified mechanically, 2026-09-21):
//! asset=26, edit=25, checkpoint=31, attestation=32, manifest=29,
//! signer-fp=30.

use origin_crypto_sdk::{blake3, sha3_256};

/// Default chunk size for the content-commitment chunk tree (design D2).
pub const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;

/// Domain for `HybridSigningKeyBundle::from_seed` (spec §3).
pub const SIGNER_DOMAIN: &str = "origin-provenance:signer:v1";

pub const TAG_ASSET: &[u8] = b"origin-provenance:asset:v1";
pub const TAG_EDIT: &[u8] = b"origin-provenance:edit:v1";
pub const TAG_CHECKPOINT: &[u8] = b"origin-provenance:checkpoint:v1";
pub const TAG_ATTESTATION: &[u8] = b"origin-provenance:attestation:v1";
pub const TAG_MANIFEST: &[u8] = b"origin-provenance:manifest:v1";
pub const TAG_SIGNER_FP: &[u8] = b"origin-provenance:signer-fp:v1";
pub const TAG_ANCHOR: &[u8] = b"origin-provenance:anchor:v1";

/// Content-binding action byte (spec S3). Unknown values reject downstream.
/// JSON form is the lowercase string ("capture"/"edit"/"publish"/"annotate");
/// the byte form enters `edit_leaf` via `From<Action> for u8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Action {
    Capture = 0,
    Edit = 1,
    Publish = 2,
    Annotate = 3,
}

impl TryFrom<u8> for Action {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, u8> {
        match v {
            0 => Ok(Action::Capture),
            1 => Ok(Action::Edit),
            2 => Ok(Action::Publish),
            3 => Ok(Action::Annotate),
            other => Err(other),
        }
    }
}

impl From<Action> for u8 {
    fn from(a: Action) -> u8 {
        a as u8
    }
}

/// `asset_id = SHA3-256(TAG_ASSET || whole_file_hash_at_first_edit)` (spec S1).
pub fn asset_id(whole_file_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(TAG_ASSET.len() + 32);
    buf.extend_from_slice(TAG_ASSET);
    buf.extend_from_slice(whole_file_hash);
    sha3_256(&buf)
}

/// Exact input bytes of the edit leaf digest (spec §4).
pub fn edit_leaf_input(
    index: u64,
    action_u8: u8,
    chunk_tree_root: &[u8; 32],
    whole_file_hash: &[u8; 32],
    asset_id: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TAG_EDIT.len() + 32 + 8 + 1 + 32 + 32);
    buf.extend_from_slice(TAG_EDIT);
    buf.extend_from_slice(asset_id);
    buf.extend_from_slice(&index.to_be_bytes());
    buf.extend_from_slice(&[action_u8]);
    buf.extend_from_slice(chunk_tree_root);
    buf.extend_from_slice(whole_file_hash);
    buf
}

/// `edit_leaf = BLAKE3(edit_leaf_input(..))` (unkeyed).
pub fn edit_leaf(
    index: u64,
    action_u8: u8,
    chunk_tree_root: &[u8; 32],
    whole_file_hash: &[u8; 32],
    asset_id: &[u8; 32],
) -> [u8; 32] {
    blake3::hash(&edit_leaf_input(
        index,
        action_u8,
        chunk_tree_root,
        whole_file_hash,
        asset_id,
    ))
    .into()
}

/// Exact input bytes of the checkpoint payload (spec §4).
pub fn checkpoint_payload_input(
    leaf_count: u64,
    mmr_root: &[u8; 32],
    timestamp: i64,
    signer_fingerprint_raw: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TAG_CHECKPOINT.len() + 8 + 32 + 8 + 32);
    buf.extend_from_slice(TAG_CHECKPOINT);
    buf.extend_from_slice(&leaf_count.to_be_bytes());
    buf.extend_from_slice(mmr_root);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(signer_fingerprint_raw);
    buf
}

/// Exact input bytes of the attestation payload (spec §4).
pub fn attestation_payload_input(
    manifest_id: &[u8; 32],
    leaf_count: u64,
    mmr_root: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TAG_ATTESTATION.len() + 32 + 8 + 32);
    buf.extend_from_slice(TAG_ATTESTATION);
    buf.extend_from_slice(manifest_id);
    buf.extend_from_slice(&leaf_count.to_be_bytes());
    buf.extend_from_slice(mmr_root);
    buf
}

/// Exact input bytes of the head-anchor payload (ticket T-RT1): the
/// publisher's signed announcement of a manifest head. Binds the
/// announced head (`manifest_id`) to its edit count and the asset.
pub fn anchor_payload_input(
    edit_count: u64,
    manifest_id: &[u8; 32],
    asset_id: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TAG_ANCHOR.len() + 8 + 32 + 32);
    buf.extend_from_slice(TAG_ANCHOR);
    buf.extend_from_slice(&edit_count.to_be_bytes());
    buf.extend_from_slice(manifest_id);
    buf.extend_from_slice(asset_id);
    buf
}

/// One checkpoint's contribution to the manifest signable bytes.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointBasis {
    pub leaf_count: u64,
    pub mmr_root: [u8; 32],
    pub timestamp: i64,
    pub signer_fingerprint_raw: [u8; 32],
}

/// Exact input bytes of `manifest_id` (spec §4). `leaf_hashes` are the
/// BLAKE3 edit-leaf outputs in canonical order (index 0..n-1).
pub fn manifest_signable_bytes(
    version: u8,
    asset_id: &[u8; 32],
    chunk_size: u32,
    leaf_hashes: &[[u8; 32]],
    checkpoints: &[CheckpointBasis],
    threshold: Option<u32>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(TAG_MANIFEST);
    buf.push(version);
    buf.extend_from_slice(asset_id);
    buf.extend_from_slice(&chunk_size.to_be_bytes());
    buf.extend_from_slice(&(leaf_hashes.len() as u64).to_be_bytes());
    for leaf in leaf_hashes {
        buf.extend_from_slice(leaf);
    }
    buf.extend_from_slice(&(checkpoints.len() as u64).to_be_bytes());
    for cp in checkpoints {
        buf.extend_from_slice(&cp.leaf_count.to_be_bytes());
        buf.extend_from_slice(&cp.mmr_root);
        buf.extend_from_slice(&cp.timestamp.to_be_bytes());
        buf.extend_from_slice(&cp.signer_fingerprint_raw);
    }
    if let Some(k) = threshold {
        buf.extend_from_slice(&k.to_be_bytes());
    }
    buf
}

/// `manifest_id = SHA3-256(manifest_signable_bytes(..))`.
pub fn manifest_id(
    version: u8,
    asset_id: &[u8; 32],
    chunk_size: u32,
    leaf_hashes: &[[u8; 32]],
    checkpoints: &[CheckpointBasis],
    threshold: Option<u32>,
) -> [u8; 32] {
    sha3_256(&manifest_signable_bytes(
        version,
        asset_id,
        chunk_size,
        leaf_hashes,
        checkpoints,
        threshold,
    ))
}
/// `signer_fingerprint = SHA3-256(TAG_SIGNER_FP || ed25519_pk(32) ||
/// u32_be(len) || falcon_pk)` (spec §3; length-prefixed, injective).
///
/// Errors if `falcon_pk` exceeds `u32::MAX` bytes (impossible for a real
/// Falcon-1024 key at 1793 bytes; totality instead of a panic path).
pub fn signer_fingerprint(
    ed25519_pk: &[u8; 32],
    falcon_pk: &[u8],
) -> origin_crypto_sdk::Result<[u8; 32]> {
    let len = u32::try_from(falcon_pk.len())
        .map_err(|_| origin_crypto_sdk::Error::Serialization("falcon pk length overflow".into()))?;
    let mut buf = Vec::with_capacity(TAG_SIGNER_FP.len() + 32 + 4 + falcon_pk.len());
    buf.extend_from_slice(TAG_SIGNER_FP);
    buf.extend_from_slice(ed25519_pk);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(falcon_pk);
    Ok(sha3_256(&buf))
}

/// Chunk tree root (spec S2): per-chunk unkeyed BLAKE3, pairwise
/// `BLAKE3(left || right)`, odd node carried up unchanged; a lone node is
/// its own root; empty input roots to `BLAKE3(b"")`.
pub fn chunk_tree_root(data: &[u8], chunk_size: u32) -> [u8; 32] {
    let chunk_size = chunk_size.max(1) as usize;
    let leaves: Vec<[u8; 32]> = if data.is_empty() {
        vec![]
    } else {
        data.chunks(chunk_size)
            .map(|c| *blake3::hash(c).as_bytes())
            .collect()
    };
    merkle_root_from_leaf_hashes(&leaves)
}

/// Collapse leaf hashes to the S2 Merkle root (pairwise BLAKE3, odd node
/// carried up; empty list ⇒ `BLAKE3("")`, matching empty input). Exposed so
/// the verifier can rebind a manifest's per-chunk hash list to its root.
pub fn merkle_root_from_leaf_hashes(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return *blake3::hash(b"").as_bytes();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 == level.len() {
                next.push(level[i]); // odd node carried up
            } else {
                let mut pair = Vec::with_capacity(64);
                pair.extend_from_slice(&level[i]);
                pair.extend_from_slice(&level[i + 1]);
                next.push(*blake3::hash(&pair).as_bytes());
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture constants shared by the goldens and the Python cross-check.
    /// whole_file_hash/chunk_tree_root/mmr_root/fp = zero bytes unless noted;
    /// edit_leaf placeholder = 0xFF*32 (documented fixture, P1-a scoping:
    /// BLAKE3 recipes pin as Rust goldens, SHA3 recipes live-cross-check).
    mod fixture {
        pub const TIMESTAMP: i64 = 1_726_900_000;
        pub const ZERO32: [u8; 32] = [0u8; 32];
        pub const LEAF_PLACEHOLDER: [u8; 32] = [0xff; 32];
        /// Python: sha3_256(b"origin-provenance:asset:v1" || b"\x00"*32)
        pub const ASSET_ID_ZEROS: &str =
            "4fe594c4967062aeb63c8ecd8059aa652c1cc13fa2f17622f56de33fb6998261";
        /// Python: sha3_256 over the §4 signable layout with leaf=0xFF*32,
        /// 1 edit (leaf digest only, NOT the leaf input), 1 checkpoint
        /// (ts=1726900000), no threshold. (First Python fixture wrongly
        /// embedded the edit-leaf input; length pin caught it.)
        pub const MANIFEST_ID_FIXTURE: &str =
            "96a31ac5caf1cd7a9216e291a2b1d97d81992345444432dc76f9b0899e084770";
        /// Total signable length for the fixture (Python-measured).
        pub const MANIFEST_SIGNABLE_LEN: usize = 194;
    }

    #[test]
    fn domain_tag_byte_counts() {
        // Mechanical counts (Python-verified); compile-time drift alarm.
        assert_eq!(TAG_ASSET.len(), 26);
        assert_eq!(TAG_EDIT.len(), 25);
        assert_eq!(TAG_CHECKPOINT.len(), 31);
        assert_eq!(TAG_ATTESTATION.len(), 32);
        assert_eq!(TAG_MANIFEST.len(), 29);
        assert_eq!(TAG_SIGNER_FP.len(), 30);
        assert_eq!(TAG_ANCHOR.len(), 27);
    }

    #[test]
    fn anchor_payload_layout() {
        // Tag(27) || edit_count(8) || manifest_id(32) || asset_id(32)
        let input = anchor_payload_input(3, &fixture::ZERO32, &fixture::ZERO32);
        assert_eq!(input.len(), 27 + 8 + 32 + 32);
        assert_eq!(&input[..27], TAG_ANCHOR);
        assert_eq!(&input[27..35], &3u64.to_be_bytes());
    }

    #[test]
    fn asset_id_matches_python_sha3() {
        let id = asset_id(&fixture::ZERO32);
        assert_eq!(hex::encode(id), fixture::ASSET_ID_ZEROS);
    }

    #[test]
    fn action_mapping_s3() {
        assert_eq!(u8::from(Action::Capture), 0);
        assert_eq!(u8::from(Action::Edit), 1);
        assert_eq!(u8::from(Action::Publish), 2);
        assert_eq!(u8::from(Action::Annotate), 3);
        assert_eq!(Action::try_from(4), Err(4));
        assert_eq!(Action::try_from(255), Err(255));
    }

    #[test]
    fn edit_leaf_input_layout() {
        // Tag(25) || asset(32) || index(8) || action(1) || ctr(32) || wfh(32)
        let input = edit_leaf_input(7, 1, &fixture::ZERO32, &fixture::ZERO32, &fixture::ZERO32);
        assert_eq!(input.len(), 25 + 32 + 8 + 1 + 32 + 32);
        assert_eq!(&input[..25], TAG_EDIT);
        assert_eq!(input[25 + 32 + 8], 1); // action byte position
        assert_eq!(input[25 + 32 + 8 + 1 + 62], 0); // inside wfh tail
        assert_eq!(&input[input.len() - 64..input.len() - 32], &[0u8; 32]);
    }

    #[test]
    fn edit_leaf_golden_blake3() {
        // Frozen golden: pins the recipe wiring over the SDK's BLAKE3
        // (P1-a scoping: no second BLAKE3 implementation; provenance note).
        let leaf = edit_leaf(0, 0, &fixture::ZERO32, &fixture::ZERO32, &fixture::ZERO32);
        let expected_input = {
            let mut b = Vec::new();
            b.extend_from_slice(TAG_EDIT);
            b.extend_from_slice(&fixture::ZERO32);
            b.extend_from_slice(&0u64.to_be_bytes());
            b.push(0);
            b.extend_from_slice(&fixture::ZERO32);
            b.extend_from_slice(&fixture::ZERO32);
            b
        };
        let h = blake3::hash(&expected_input);
        let expected: [u8; 32] = h.as_bytes()[..].try_into().unwrap();
        assert_eq!(leaf, expected);
        // Distinct inputs → distinct leaves (sanity against constant wiring).
        let leaf1 = edit_leaf(1, 0, &fixture::ZERO32, &fixture::ZERO32, &fixture::ZERO32);
        assert_ne!(leaf, leaf1);
    }

    #[test]
    fn manifest_id_matches_python_sha3() {
        let leaves = [fixture::LEAF_PLACEHOLDER];
        let checkpoints = [CheckpointBasis {
            leaf_count: 1,
            mmr_root: fixture::ZERO32,
            timestamp: fixture::TIMESTAMP,
            signer_fingerprint_raw: fixture::ZERO32,
        }];
        let bytes = manifest_signable_bytes(
            1,
            &bytes_of(fixture::ASSET_ID_ZEROS),
            1_048_576,
            &leaves,
            &checkpoints,
            None,
        );
        assert_eq!(bytes.len(), fixture::MANIFEST_SIGNABLE_LEN);
        let id = manifest_id(
            1,
            &bytes_of(fixture::ASSET_ID_ZEROS),
            1_048_576,
            &leaves,
            &checkpoints,
            None,
        );
        assert_eq!(hex::encode(id), fixture::MANIFEST_ID_FIXTURE);
    }

    #[test]
    fn manifest_threshold_changes_signable_bytes() {
        let leaves = [fixture::LEAF_PLACEHOLDER];
        let checkpoints = [CheckpointBasis {
            leaf_count: 1,
            mmr_root: fixture::ZERO32,
            timestamp: fixture::TIMESTAMP,
            signer_fingerprint_raw: fixture::ZERO32,
        }];
        let without =
            manifest_signable_bytes(1, &fixture::ZERO32, 1024, &leaves, &checkpoints, None);
        let with =
            manifest_signable_bytes(1, &fixture::ZERO32, 1024, &leaves, &checkpoints, Some(2));
        assert_eq!(with.len(), without.len() + 4);
        assert_eq!(&with[without.len()..], &2u32.to_be_bytes());
    }

    #[test]
    fn chunk_tree_shapes() {
        let cs = 64usize;
        // Empty input ⇒ BLAKE3(b"") as root.
        let empty: [u8; 32] = blake3::hash(b"").into();
        assert_eq!(chunk_tree_root(b"", cs as u32), empty);
        // Single chunk ⇒ root = chunk hash (lone node is its own root).
        let one = chunk_tree_root(&[7u8; 10], cs as u32);
        assert_eq!(one, *blake3::hash(&[7u8; 10]).as_bytes());
        // Two chunks ⇒ root = BLAKE3(h0 || h1); NOT equal to either chunk hash.
        let two_data = vec![1u8; cs * 2];
        let h0 = blake3::hash(&two_data[..cs]);
        let h1 = blake3::hash(&two_data[cs..]);
        let mut pair = Vec::with_capacity(64);
        pair.extend_from_slice(h0.as_bytes());
        pair.extend_from_slice(h1.as_bytes());
        assert_eq!(
            chunk_tree_root(&two_data, cs as u32),
            *blake3::hash(&pair).as_bytes()
        );
        // Three chunks ⇒ odd node carried up: root = B3(h01 || h2); B3(h01) != h01.
        let three_data = vec![2u8; cs * 3];
        let t0 = *blake3::hash(&three_data[..cs]).as_bytes();
        let t1 = *blake3::hash(&three_data[cs..2 * cs]).as_bytes();
        let t2 = *blake3::hash(&three_data[2 * cs..]).as_bytes();
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(&t0);
        pt.extend_from_slice(&t1);
        let ht = *blake3::hash(&pt).as_bytes();
        let mut p = Vec::with_capacity(64);
        p.extend_from_slice(&ht);
        p.extend_from_slice(&t2);
        assert_eq!(
            chunk_tree_root(&three_data, cs as u32),
            *blake3::hash(&p).as_bytes()
        );
        let _ = two_data.len(); // silence unused in release
    }

    #[test]
    fn chunk_tree_five_chunks_golden() {
        // 5 chunks: level0=[a,b,c,d,e] → [ab,cd,e] → [abcd,e] → root
        // Structure pinned by hand-assembly; byte-golden frozen in Rust.
        let cs = 16usize;
        let data: Vec<u8> = (0u8..=79).collect();
        let ch = |i: usize| *blake3::hash(&data[i * cs..(i + 1) * cs]).as_bytes();
        let hash2 = |l: [u8; 32], r: [u8; 32]| {
            let mut p = Vec::with_capacity(64);
            p.extend_from_slice(&l);
            p.extend_from_slice(&r);
            *blake3::hash(&p).as_bytes()
        };
        let ab: [u8; 32] = hash2(ch(0), ch(1));
        let cd: [u8; 32] = hash2(ch(2), ch(3));
        let e: [u8; 32] = ch(4);
        let abcd: [u8; 32] = hash2(ab, cd);
        let expected = hash2(abcd, e);
        assert_eq!(chunk_tree_root(&data, cs as u32), expected);
    }

    fn bytes_of(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }
}
