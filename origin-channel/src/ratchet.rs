// SPDX-License-Identifier: Apache-2.0

//! Symmetric double-ratchet for forward-secret messaging.
//!
//! After the Noise handshake establishes a shared secret, both sides
//! derive root + chain keys. Each message advances the sending chain
//! (HKDF ratchet). Each DH ratchet step (new ephemeral key) advances
//! the root key, providing forward secrecy and break-in recovery.
//!
//! Key schedule:
//! ```text
//! root_key, send_chain, recv_chain = HKDF(shared_secret, "origin-channel:ratchet:v1")
//! message_key = HKDF(chain_key, "origin-channel:message:v1")
//! next_chain  = HKDF(chain_key, "origin-channel:chain:v1")
//! ```

use origin_crypto_sdk::hkdf_sha3_256;

use crate::error::{ChannelError, Result};
use crate::types::RatchetKeys;

/// Domain labels for HKDF key derivation.
const RATCHET_INIT_LABEL: &str = "origin-channel:ratchet:v1";
const MESSAGE_KEY_LABEL: &str = "origin-channel:message:v1";
const CHAIN_ADVANCE_LABEL: &str = "origin-channel:chain:v1";
const DH_RATCHET_LABEL: &str = "origin-channel:dh-ratchet:v1";

/// Derive initial ratchet keys from the handshake shared secret.
/// The `is_initiator` flag crosses the chains: the initiator's send_chain
/// becomes the responder's recv_chain and vice versa.
pub fn init_ratchet(shared_secret: &[u8; 32], is_initiator: bool) -> Result<RatchetKeys> {
    let mut okm = [0u8; 96];
    hkdf_sha3_256(shared_secret, None, RATCHET_INIT_LABEL.as_bytes(), &mut okm)
        .map_err(|e| ChannelError::Key(format!("ratchet init HKDF failed: {e}")))?;

    let mut root = [0u8; 32];
    let mut chain_a = [0u8; 32];
    let mut chain_b = [0u8; 32];
    root.copy_from_slice(&okm[0..32]);
    chain_a.copy_from_slice(&okm[32..64]);
    chain_b.copy_from_slice(&okm[64..96]);

    // Cross chains: initiator sends on A, receives on B; responder is reversed.
    let (send_chain, recv_chain) = if is_initiator {
        (chain_a, chain_b)
    } else {
        (chain_b, chain_a)
    };

    Ok(RatchetKeys {
        root,
        send_chain,
        recv_chain,
    })
}

/// Derive a one-time message key from a chain key.
/// Returns (message_key, next_chain_key).
pub fn derive_message_key(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let mut msg_key = [0u8; 32];
    hkdf_sha3_256(chain_key, None, MESSAGE_KEY_LABEL.as_bytes(), &mut msg_key)
        .map_err(|e| ChannelError::Key(format!("message key HKDF failed: {e}")))?;

    let mut next_chain = [0u8; 32];
    hkdf_sha3_256(chain_key, None, CHAIN_ADVANCE_LABEL.as_bytes(), &mut next_chain)
        .map_err(|e| ChannelError::Key(format!("chain advance HKDF failed: {e}")))?;

    Ok((msg_key, next_chain))
}

/// Perform a DH ratchet step: mix a new DH shared secret into the root key,
/// then derive fresh send and receive chain keys.
pub fn dh_ratchet(root_key: &[u8; 32], dh_shared_secret: &[u8; 32]) -> Result<RatchetKeys> {
    let mut okm = [0u8; 96];
    hkdf_sha3_256(root_key, Some(dh_shared_secret), DH_RATCHET_LABEL.as_bytes(), &mut okm)
        .map_err(|e| ChannelError::Key(format!("DH ratchet HKDF failed: {e}")))?;

    let mut new_root = [0u8; 32];
    let mut send_chain = [0u8; 32];
    let mut recv_chain = [0u8; 32];
    new_root.copy_from_slice(&okm[0..32]);
    send_chain.copy_from_slice(&okm[32..64]);
    recv_chain.copy_from_slice(&okm[64..96]);

    Ok(RatchetKeys {
        root: new_root,
        send_chain,
        recv_chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_produces_distinct_keys() {
        let secret = [0x42u8; 32];
        let keys = init_ratchet(&secret, true).unwrap();
        assert_ne!(keys.root, keys.send_chain);
        assert_ne!(keys.send_chain, keys.recv_chain);
        assert_ne!(keys.root, keys.recv_chain);
    }

    #[test]
    fn deterministic_init() {
        let secret = [0xABu8; 32];
        let a = init_ratchet(&secret, true).unwrap();
        let b = init_ratchet(&secret, true).unwrap();
        assert_eq!(a.root, b.root);
        assert_eq!(a.send_chain, b.send_chain);
        assert_eq!(a.recv_chain, b.recv_chain);
    }

    #[test]
    fn message_key_advances_chain() {
        let chain = [0x11u8; 32];
        let (msg_key, next_chain) = derive_message_key(&chain).unwrap();
        assert_ne!(msg_key, chain);
        assert_ne!(next_chain, chain);
        assert_ne!(msg_key, next_chain);

        // Second derivation from the advanced chain gives different keys
        let (msg_key2, _) = derive_message_key(&next_chain).unwrap();
        assert_ne!(msg_key, msg_key2);
    }

    #[test]
    fn dh_ratchet_changes_all_keys() {
        let root = [0x01u8; 32];
        let dh_ss = [0x02u8; 32];
        let keys = dh_ratchet(&root, &dh_ss).unwrap();
        assert_ne!(keys.root, root);
        assert_ne!(keys.send_chain, keys.recv_chain);
    }

    #[test]
    fn different_dh_secrets_different_keys() {
        let root = [0x01u8; 32];
        let a = dh_ratchet(&root, &[0x02u8; 32]).unwrap();
        let b = dh_ratchet(&root, &[0x03u8; 32]).unwrap();
        assert_ne!(a.root, b.root);
    }
}
