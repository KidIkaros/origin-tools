// SPDX-License-Identifier: Apache-2.0

//! sign — hybrid Ed25519 + Falcon-1024 provenance for memory nodes.
//!
//! Every node's canonical payload is signed with the origin-crypto-sdk hybrid
//! bundle. The signature is stored as hex; verification reconstructs the
//! `Ed25519Falcon1024` and checks both components (both MUST be valid).

use crate::node::MemoryNode;
use ed25519_dalek::Signature as Ed25519Signature;
use origin_crypto_sdk::pqc::falcon1024::FalconSignature;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct NodeSignature {
    pub signer_fingerprint: String,
    pub ed25519_hex: String,
    pub falcon_hex: String,
}

/// Derive a hybrid signing bundle from a 32-byte master seed + domain.
/// Uses the process-wide cache so Falcon keygen (~4s) runs once per (seed, domain).
pub fn derive_bundle(master_seed: &[u8; 32], domain: &str) -> Arc<HybridSigningKeyBundle> {
    HybridSigningKeyBundle::from_seed_cached(master_seed, domain).expect("hybrid bundle derivation")
}

/// Sign a node's canonical payload. Returns the attestation to store alongside it.
pub fn sign_node(node: &MemoryNode, bundle: &HybridSigningKeyBundle) -> NodeSignature {
    let sig = bundle.sign_hybrid(&node.signing_payload());
    NodeSignature {
        signer_fingerprint: hex::encode(bundle.ed25519_pk().as_bytes()),
        ed25519_hex: hex::encode(sig.ed25519_sig.to_bytes()),
        falcon_hex: hex::encode(sig.falcon_sig.as_bytes()),
    }
}

/// Verify a stored signature against the node's current payload.
pub fn verify_node(
    node: &MemoryNode,
    sig: &NodeSignature,
    bundle: &HybridSigningKeyBundle,
) -> bool {
    let ed_bytes = match hex::decode(&sig.ed25519_hex) {
        Ok(b) if b.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };
    let fal_bytes = match hex::decode(&sig.falcon_hex) {
        Ok(b) => b,
        _ => return false,
    };
    let ed25519_sig = Ed25519Signature::from_bytes(&ed_bytes);
    let falcon_sig = match FalconSignature::from_bytes(&fal_bytes) {
        Ok(s) => s,
        _ => return false,
    };
    let reconstructed = Ed25519Falcon1024 {
        ed25519_sig,
        falcon_sig,
    };
    Ed25519Falcon1024::verify(
        bundle.ed25519_pk(),
        bundle.falcon1024_pk(),
        &node.signing_payload(),
        &reconstructed,
    )
    .is_ok()
}
