// SPDX-License-Identifier: Apache-2.0

//! Cross-tool integration tests for origin-tools.
//!
//! These tests verify that the 9 tools compose correctly end-to-end,
//! exercising real workflows that span multiple crates.

use origin_crypto_sdk::{
    blake3,
    blob::{create_blob, recover_seed},
    ec_schnorr::{self, EcSchnorrProof},
    error_correction::ReedSolomonCodec,
    seed::gen::{generate, SeedVariant},
    stealth::pow as stealth_pow,
    tier::MemoryTier,
};

// ─── Workflow 1: seed → shard → lose shard → recover → schnorr sign/verify ───

#[test]
fn seed_shard_recover_schnorr_roundtrip() {
    // 1. Generate a seed
    let generated = generate(SeedVariant::Blake2bShake256);
    let seed_bytes = generated.seed.clone();
    assert_eq!(seed_bytes.len(), 32);

    // 2. Shard it with RS (4 data + 2 parity = 6 shards)
    let codec = ReedSolomonCodec::new(4, 2);
    let shards = codec.encode_shards(&seed_bytes).expect("encode shards");
    assert_eq!(shards.len(), 6);

    // 3. Lose 2 shards (simulate disaster)
    let mut recovered_slots: Vec<Option<Vec<u8>>> =
        shards.iter().map(|s| Some(s.clone())).collect();
    recovered_slots[1] = None; // lose shard 1
    recovered_slots[4] = None; // lose shard 4

    // 4. Recover via erasure decoding
    let recovered = codec
        .decode_shards(&recovered_slots, seed_bytes.len())
        .expect("decode shards");
    assert_eq!(recovered, seed_bytes, "recovered seed must match original");

    // 5. Use recovered seed as Schnorr keypair material
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&recovered);
    let (secret, public) = ec_schnorr::generate_keypair(&sk);

    // 6. Sign and verify
    let msg = b"cross-tool composability test";
    let proof = ec_schnorr::prove(&secret, &public, msg).expect("prove");
    assert!(ec_schnorr::verify(&proof, &public, msg).expect("verify"));

    // 7. Wrong message must fail
    assert!(!ec_schnorr::verify(&proof, &public, b"wrong").expect("verify wrong msg"));
}

// ─── Workflow 2: seed → encrypted blob → recover → schnorr sign/verify ───

#[test]
fn seed_blob_recover_schnorr_sign_verify() {
    // 1. Generate a seed
    let generated = generate(SeedVariant::Blake2bSha3_256);
    let seed_bytes = generated.seed.clone();

    // 2. Encrypt into a blob (simulates origin-seed blob-create / origin-identity keygen)
    let passphrase = b"test-passphrase-for-cross-tool";
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_bytes);
    let blob = create_blob(passphrase, MemoryTier::Nano, Some(&seed_arr)).expect("create blob");
    assert!(blob.len() > 40, "blob must have salt+nonce+ct");

    // 3. Recover the seed from the blob
    let recovered = recover_seed(&blob, passphrase, MemoryTier::Nano).expect("recover seed");
    assert_eq!(
        recovered.as_slice(),
        seed_bytes.as_slice(),
        "recovered seed must match"
    );

    // 4. Wrong passphrase must fail
    let bad = recover_seed(&blob, b"wrong-pass", MemoryTier::Nano);
    assert!(bad.is_err(), "wrong passphrase must fail");

    // 5. Use recovered seed to derive a signing key and sign
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&recovered);
    let (secret, public) = ec_schnorr::generate_keypair(&sk);
    let msg = b"identity-bound message";
    let proof = ec_schnorr::prove(&secret, &public, msg).expect("prove");
    assert!(ec_schnorr::verify(&proof, &public, msg).expect("verify"));
}

// ─── Workflow 3: seed → stealth PoW solve → verify ───

#[test]
fn seed_stealth_pow_solve_verify() {
    // 1. Generate identity seed
    let generated = generate(SeedVariant::Shake256Sha3_256);
    let identity_pk = generated.seed.clone();

    // 2. Solve PoW (simulates origin-stealth solve)
    let destination_hint = b"cross-tool-destination";
    let difficulty = 8u32; // low difficulty for test speed
    let (proof, _counter) =
        stealth_pow::solve(&identity_pk, destination_hint, difficulty).expect("solve PoW");

    // 3. Verify the proof (simulates origin-stealth verify)
    let valid = stealth_pow::verify(&proof, &identity_pk, destination_hint).expect("verify");
    assert!(valid, "PoW proof must verify");

    // 4. Wrong identity must fail
    let other = generate(SeedVariant::Blake2bShake256);
    let bad = stealth_pow::verify(&proof, &other.seed, destination_hint).expect("verify wrong id");
    assert!(!bad, "wrong identity must fail");

    // 5. Wrong destination must fail
    let bad2 = stealth_pow::verify(&proof, &identity_pk, b"wrong-dest").expect("verify wrong dest");
    assert!(!bad2, "wrong destination must fail");

    // 6. Tampered nonce must fail
    let mut tampered = proof.clone();
    tampered.nonce[0] ^= 0xFF;
    let bad3 =
        stealth_pow::verify(&tampered, &identity_pk, destination_hint).expect("verify tampered");
    assert!(!bad3, "tampered nonce must fail");
}

// ─── Workflow 4: shard → MMR proof → verify ───

#[test]
fn shard_mmr_proof_verify() {
    // 1. Generate data and shard it
    let data = b"important document to prove inclusion of";
    let codec = ReedSolomonCodec::new(3, 2);
    let shards = codec.encode_shards(data).expect("encode");

    // 2. Build MMR from shard hashes (simulates origin-proof append)
    let leaf_hashes: Vec<[u8; 32]> = shards.iter().map(|s| blake3::hash(s).into()).collect();

    // 3. Compute MMR root
    let root = compute_mmr_root(&leaf_hashes);

    // 4. Generate authentication path for leaf 2
    let proof = generate_mmr_proof(&leaf_hashes, 2);

    // 5. Verify the proof
    let valid = verify_mmr_proof(&root, &leaf_hashes[2], &proof);
    assert!(valid, "MMR proof must verify");

    // 6. Wrong leaf must fail
    let wrong_leaf: [u8; 32] = blake3::hash(b"wrong data").into();
    let bad = verify_mmr_proof(&root, &wrong_leaf, &proof);
    assert!(!bad, "wrong leaf must fail verification");
}

// ─── Workflow 5: entropy quality gate → seed generation → schnorr ───

#[test]
fn entropy_quality_gate_then_schnorr() {
    // 1. Generate high-quality entropy (simulates origin-entropy generate)
    let generated = generate(SeedVariant::Blake2bSha512);
    let entropy = generated.seed.clone();
    assert_eq!(entropy.len(), 32);

    // 2. Check entropy quality (simulates origin-entropy check)
    let quality = check_entropy_quality(&entropy);
    assert!(quality.passed, "CSPRNG output must pass quality gate");
    assert!(
        quality.shannon_entropy > 3.5,
        "Shannon entropy must be high"
    );

    // 3. Use quality-checked entropy as seed for Schnorr
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&entropy);
    let (secret, public) = ec_schnorr::generate_keypair(&sk);
    let msg = b"quality-gated message";
    let proof = ec_schnorr::prove(&secret, &public, msg).expect("prove");
    assert!(ec_schnorr::verify(&proof, &public, msg).expect("verify"));
}

// ─── Workflow 6: multi-tool pipeline (seed → blob → shard → recover → sign) ───

#[test]
fn full_pipeline_seed_blob_shard_recover_sign() {
    // 1. Generate seed
    let generated = generate(SeedVariant::Blake2bShake256);
    let seed_bytes = generated.seed.clone();

    // 2. Encrypt to blob
    let passphrase = b"pipeline-passphrase";
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_bytes);
    let blob = create_blob(passphrase, MemoryTier::Nano, Some(&seed_arr)).expect("blob");

    // 3. Shard the blob (not the seed — shard the encrypted blob for distributed storage)
    let codec = ReedSolomonCodec::new(4, 2);
    let shards = codec.encode_shards(&blob).expect("shard blob");

    // 4. Lose 2 shards
    let mut slots: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.clone())).collect();
    slots[0] = None;
    slots[3] = None;

    // 5. Recover blob
    let recovered_blob = codec
        .decode_shards(&slots, blob.len())
        .expect("recover blob");
    assert_eq!(recovered_blob, blob, "recovered blob must match");

    // 6. Recover seed from blob
    let recovered_seed =
        recover_seed(&recovered_blob, passphrase, MemoryTier::Nano).expect("recover seed");
    assert_eq!(
        recovered_seed.as_slice(),
        seed_bytes.as_slice(),
        "recovered seed must match original"
    );

    // 7. Sign with recovered seed
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&recovered_seed);
    let (secret, public) = ec_schnorr::generate_keypair(&sk);
    let msg = b"full pipeline message";
    let proof = ec_schnorr::prove(&secret, &public, msg).expect("prove");
    assert!(ec_schnorr::verify(&proof, &public, msg).expect("verify"));
}

// ─── Workflow 7: batch Schnorr verification across multiple identities ───

#[test]
fn batch_schnorr_multi_identity() {
    // 1. Generate 5 different seeds (simulates 5 users)
    let variants = [
        SeedVariant::Blake2bShake256,
        SeedVariant::Blake2bSha3_256,
        SeedVariant::Blake2bSha512,
        SeedVariant::Shake256Sha3_256,
        SeedVariant::Blake2bShake256,
    ];

    let keypairs: Vec<([u8; 32], Vec<u8>)> = variants
        .iter()
        .map(|v| {
            let g = generate(*v);
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&g.seed);
            ec_schnorr::generate_keypair(&sk)
        })
        .collect();

    // 2. Each user signs a different message
    let messages: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("message from user {i}").into_bytes())
        .collect();

    let proofs: Vec<EcSchnorrProof> = keypairs
        .iter()
        .zip(messages.iter())
        .map(|((sk, pk), msg)| ec_schnorr::prove(sk, pk, msg).expect("prove"))
        .collect();

    let pks: Vec<Vec<u8>> = keypairs.iter().map(|(_, pk)| pk.clone()).collect();

    // 3. Batch verify all 5
    let valid = ec_schnorr::batch_verify(&proofs, &pks, &messages).expect("batch verify");
    assert!(valid, "all 5 signatures must verify");

    // 4. Tamper with one message → batch must fail
    let mut bad_messages = messages.clone();
    bad_messages[2] = b"tampered message".to_vec();
    let bad = ec_schnorr::batch_verify(&proofs, &pks, &bad_messages).expect("batch verify bad");
    assert!(!bad, "tampered message must fail batch verify");
}

// ─── Helper: MMR root computation ───

fn compute_mmr_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                next.push(blake3::hash(&combined).into());
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

// ─── Helper: MMR authentication path ───

fn generate_mmr_proof(leaves: &[[u8; 32]], index: usize) -> Vec<([u8; 32], bool)> {
    let mut proof = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            let is_left = idx % 2 == 1; // sibling is on the left
            proof.push((level[sibling_idx], is_left));
        }
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                next.push(blake3::hash(&combined).into());
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
        idx /= 2;
    }
    proof
}

// ─── Helper: MMR proof verification ───

fn verify_mmr_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &[([u8; 32], bool)]) -> bool {
    let mut current = *leaf;
    for (sibling, sibling_is_left) in proof {
        let mut combined = Vec::with_capacity(64);
        if *sibling_is_left {
            combined.extend_from_slice(sibling);
            combined.extend_from_slice(&current);
        } else {
            combined.extend_from_slice(&current);
            combined.extend_from_slice(sibling);
        }
        current = blake3::hash(&combined).into();
    }
    current == *root
}

// ─── Helper: entropy quality check ───

struct EntropyQuality {
    shannon_entropy: f64,
    passed: bool,
}

fn check_entropy_quality(data: &[u8]) -> EntropyQuality {
    if data.is_empty() {
        return EntropyQuality {
            shannon_entropy: 0.0,
            passed: false,
        };
    }

    // Byte frequency histogram
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    // Shannon entropy
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }

    // Min-entropy: -log2(max_probability)
    let max_freq = *freq.iter().max().unwrap_or(&0) as f64;
    let min_entropy = if max_freq > 0.0 {
        -(max_freq / n).log2()
    } else {
        8.0
    };

    let passed = entropy > 3.0 && min_entropy > 2.0;

    EntropyQuality {
        shannon_entropy: entropy,
        passed,
    }
}
