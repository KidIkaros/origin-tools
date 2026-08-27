// SPDX-License-Identifier: Apache-2.0

//! Signature helpers.
//!
//! A serde-friendly hybrid (Ed25519 + Falcon-1024) signature type that embeds
//! both public keys so verification is **fully offline and stateless**, plus
//! signing/verifying wrappers over the SDK — the same construction
//! `origin-seal`/`origin-secrets` use. All crypto goes through
//! `origin-crypto-sdk`; nothing external here.

use ed25519_dalek::Signature as Ed25519Signature;
use origin_crypto_sdk::pqc::falcon1024;
use origin_crypto_sdk::signing::classical::Ed25519Signer;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Signature domain for the repo's signing identity. Any change invalidates all
/// prior signatures under the old domain for the same master seed.
pub const SIGN_DOMAIN: &str = "origin-vcs";

/// Serialized hybrid signature with embedded verifier keys (JSON-persistable).
///
/// Both public keys are stored alongside the signature so `verify` needs no
/// vault and no identity: it can check the Ed25519 half and the Falcon half
/// against the embedded keys, and (via the embedded ed25519 pk) confirm the
/// signer matched the `--identity` the repo was opened under.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
pub struct Signature {
    pub ed25519: Vec<u8>,
    pub falcon1024: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub falcon1024_pk: Vec<u8>,
}

impl Signature {
    pub fn from_sdk(sig: &Ed25519Falcon1024, bundle: &HybridSigningKeyBundle) -> Self {
        Signature {
            ed25519: sig.ed25519_sig.to_bytes().to_vec(),
            falcon1024: sig.falcon_sig.as_bytes().to_vec(),
            ed25519_pk: bundle.ed25519_pk().to_bytes().to_vec(),
            falcon1024_pk: bundle.falcon1024_pk().as_bytes().to_vec(),
        }
    }

    pub fn to_sdk(&self) -> Result<Ed25519Falcon1024, String> {
        let ed_bytes: [u8; 64] = self
            .ed25519
            .as_slice()
            .try_into()
            .map_err(|_| "bad ed25519 signature length (need 64)".to_string())?;
        let ed_sig = Ed25519Signature::from_bytes(&ed_bytes);
        let falcon_sig = falcon1024::FalconSignature::from_bytes(&self.falcon1024)
            .map_err(|e| format!("bad falcon signature: {e}"))?;
        Ok(Ed25519Falcon1024 {
            ed25519_sig: ed_sig,
            falcon_sig,
        })
    }

    pub fn ed25519_pk(&self) -> Result<[u8; 32], String> {
        let b: [u8; 32] = self
            .ed25519_pk
            .as_slice()
            .try_into()
            .map_err(|_| "bad ed25519 pubkey length".to_string())?;
        Ok(b)
    }

    pub fn falcon_pk(&self) -> Result<falcon1024::FalconPublicKey, String> {
        falcon1024::FalconPublicKey::from_bytes(&self.falcon1024_pk)
            .map_err(|e| format!("bad falcon pubkey: {e}"))
    }

    pub fn sign(bundle: &HybridSigningKeyBundle, msg: &[u8]) -> Self {
        let sdk = bundle.sign_hybrid(msg);
        Self::from_sdk(&sdk, bundle)
    }

    /// Verify both halves against `msg` using the embedded public keys.
    /// Fully offline; requires no seed, vault, or identity load.
    pub fn verify(&self, msg: &[u8]) -> Result<(), String> {
        let sdk = self.to_sdk()?;
        let ed_pk = self.ed25519_pk()?;
        let falcon_pk = self.falcon_pk()?;
        let ed_sig = sdk.ed25519_sig.to_bytes();
        let ed_ok = Ed25519Signer::verify_with_pubkey(&ed_pk, msg, &ed_sig);
        let falcon_ok = falcon1024::verify(msg, &sdk.falcon_sig, &falcon_pk).is_ok();
        if ed_ok && falcon_ok {
            Ok(())
        } else {
            Err(format!(
                "hybrid signature verification FAILED (ed25519={}, falcon1024={})",
                if ed_ok { "ok" } else { "bad" },
                if falcon_ok { "ok" } else { "bad" }
            ))
        }
    }
}

/// A concrete 32-byte master seed resolved from the CLI (suite identity or an
/// explicit `--seed`). From it we derive BOTH the storage-encryption key and the
/// hybrid signing bundle, so a repo opened under one source is readable and
/// verifiable only under the same source.
#[derive(Clone)]
pub struct KeySource {
    seed: [u8; 32],
    /// Optional resolved passphrase. Needed to re-derive the object-encryption
    /// key for `encrypt = "passphrase"` repos. Carried here so `resolve_store`
    /// can reproduce the storage key without threading a passphrase through
    /// every command signature.
    passphrase: Option<String>,
}

impl KeySource {
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn passphrase(&self) -> Option<&str> {
        self.passphrase.as_deref()
    }

    /// Storage-encryption key (HKDF-BLAKE3 domain separated).
    pub fn storage_key(&self) -> Result<[u8; 32], String> {
        let mut okm = [0u8; 32];
        origin_crypto_sdk::hkdf_blake3(
            self.seed(),
            None,
            crate::store::KEY_DOMAIN.as_bytes(),
            &mut okm,
        )
        .map_err(|e| format!("HKDF key derivation failed: {e}"))?;
        Ok(okm)
    }

    /// Hybrid signing bundle for the vcs domain.
    pub fn signing_bundle(&self) -> Result<HybridSigningKeyBundle, String> {
        HybridSigningKeyBundle::from_seed(self.seed(), SIGN_DOMAIN)
            .map_err(|e| format!("key derivation failed: {e}"))
    }
}

impl Drop for KeySource {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Resolve a [KeySource] from CLI arguments.
///
/// `--identity` uses `~/.origin/identity.seed` (passphrase via
/// `resolve_passphrase`); `--seed <hex>` uses an explicit 32-byte seed.
pub fn resolve_keysource(
    identity: bool,
    seed_hex: Option<&str>,
    passphrase_file: Option<&str>,
) -> Result<KeySource, String> {
    if identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = origin_common::resolve_passphrase(passphrase_file)?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        return Ok(KeySource {
            seed: *store.seed_bytes(),
            passphrase: Some(passphrase),
        });
    }
    if let Some(h) = seed_hex {
        let bytes = hex::decode(h.trim()).map_err(|e| format!("invalid seed hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        // Capture the passphrase if the caller supplies one (needed for
        // `encrypt = "passphrase"` repos); otherwise leave it unset rather than
        // prompting for a pure `--seed` workflow.
        let passphrase = passphrase_file
            .map(|f| origin_common::resolve_passphrase(Some(f)))
            .transpose()?;
        return Ok(KeySource { seed, passphrase });
    }
    Err("a key source is required (--identity or --seed <hex>)".to_string())
}

/// Load the signing bundle for the vcs domain from a [KeySource].
pub fn load_signing_keys(
    identity: bool,
    seed_hex: Option<&str>,
    passphrase_file: Option<&str>,
) -> Result<HybridSigningKeyBundle, String> {
    resolve_keysource(identity, seed_hex, passphrase_file)?.signing_bundle()
}

/// Derive the object-encryption key from a seed. Shared with [crate::store::Store].
pub fn derive_storage_key(seed: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut okm = [0u8; 32];
    origin_crypto_sdk::hkdf_blake3(seed, None, crate::store::KEY_DOMAIN.as_bytes(), &mut okm)
        .map_err(|e| format!("HKDF key derivation failed: {e}"))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [7u8; 32];
        let bundle = HybridSigningKeyBundle::from_seed(&seed, SIGN_DOMAIN).unwrap();
        let msg = b"hello vcs";
        let sig = Signature::sign(&bundle, msg);
        assert!(sig.verify(msg).is_ok());
        assert!(sig.verify(b"tampered").is_err());
    }

    #[test]
    fn signature_serde_roundtrip() {
        let seed = [9u8; 32];
        let bundle = HybridSigningKeyBundle::from_seed(&seed, SIGN_DOMAIN).unwrap();
        let sig = Signature::sign(&bundle, b"data");
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
        assert!(back.verify(b"data").is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];
        let bundle_a = HybridSigningKeyBundle::from_seed(&seed_a, SIGN_DOMAIN).unwrap();
        let _bundle_b = HybridSigningKeyBundle::from_seed(&seed_b, SIGN_DOMAIN).unwrap();
        let sig = Signature::sign(&bundle_a, b"msg");
        assert!(sig.verify(b"msg").is_ok());
    }
}
