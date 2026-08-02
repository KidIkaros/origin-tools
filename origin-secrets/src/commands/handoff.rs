//! Portable custodian handoff manifests.

use crate::cli::HandoffArgs;
use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandoffManifest {
    pub version: u8,
    pub kind: String,
    pub status: String,
    pub share_number: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub key_id: String,
    pub fingerprint: String,
    pub created_at: String,
    pub recipient: Option<String>,
    pub expires_at: Option<String>,
    pub verifier_embedded: bool,
    pub verification: String,
    pub source_vault_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct HandoffResponse {
    ok: bool,
    command: &'static str,
    share: String,
    manifest: String,
    status: &'static str,
    verification: &'static str,
    recipient: Option<String>,
}

/// Create a portable manifest describing a custodian share without including
/// share data, signatures, or any other secret material.
pub fn cmd_handoff(
    args: HandoffArgs,
    vault_path: &Path,
    passphrase: Option<&str>,
    json: bool,
) -> Result<(), Error> {
    if !args.share.exists() {
        return Err(Error::ShareNotFound {
            share_number: 0,
            path: args.share,
        });
    }
    if !args.force && args.out.exists() {
        return Err(Error::FileAlreadyExists(args.out));
    }

    let source_vault = vault_path.exists().then_some(vault_path);
    let share = crate::commands::share_io::read_share_file(
        &args.share,
        source_vault,
        passphrase.unwrap_or(""),
    )?;

    if let (Some(expected), Some(actual)) = (&args.recipient, &share.recipient) {
        if expected != actual {
            return Err(Error::CryptoError(format!(
                "recipient mismatch: share is bound to {actual}, manifest requested {expected}"
            )));
        }
    }

    let (verification, verifier_embedded) =
        match crate::commands::share_io::verify_share_offline(&share) {
            Ok(()) => ("offline-hybrid", true),
            Err(_) if share.verifier.is_some() => ("invalid-hybrid", true),
            Err(_) => ("structural-only", false),
        };
    if verification == "invalid-hybrid" {
        return Err(Error::ShareVerificationFailed {
            share_number: share.share_number,
            details: "embedded verifier rejected the share".to_string(),
        });
    }

    let source_vault_fingerprint = source_vault.and_then(|path| {
        passphrase
            .and_then(|pw| crate::vault_handle::VaultHandle::open(path, pw).ok())
            .map(|handle| handle.fingerprint.clone())
    });
    let recipient = args.recipient.or_else(|| share.recipient.clone());
    let manifest = HandoffManifest {
        version: 1,
        kind: "origin-secrets/custodian-handoff".to_string(),
        status: "prepared".to_string(),
        share_number: share.share_number,
        threshold: share.threshold,
        total_shares: share.total_shares,
        key_id: share.key_id.clone(),
        fingerprint: share.fingerprint.clone(),
        created_at: share.created_at.clone(),
        recipient: recipient.clone(),
        expires_at: share.expires_at.clone(),
        verifier_embedded,
        verification: verification.to_string(),
        source_vault_fingerprint,
    };
    let serialized = serde_json::to_string_pretty(&manifest)
        .map_err(|e| Error::IoError(format!("serialize handoff manifest: {e}")))?;
    crate::vault_handle::atomic_write(&args.out, serialized.as_bytes())?;

    if json {
        crate::commands::output::print_json(
            &HandoffResponse {
                ok: true,
                command: "handoff",
                share: args.share.display().to_string(),
                manifest: args.out.display().to_string(),
                status: "prepared",
                verification,
                recipient,
            },
            "handoff",
        )?;
    } else {
        println!("Custodian handoff prepared: {}", args.out.display());
        println!(
            "Share: #{} ({}/{})",
            share.share_number, share.threshold, share.total_shares
        );
        println!("Verification: {verification}");
        println!(
            "Recipient: {}",
            recipient.as_deref().unwrap_or("<unassigned>")
        );
        println!("Manifest contains metadata only; share material is not included.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{HybridSignature, Share, ShareVerifier};
    use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
    use tempfile::tempdir;

    fn share() -> Share {
        let seed = [7u8; 32];
        let signer =
            HybridSigningKeyBundle::from_seed_cached(&seed, "origin-secrets/share/v1").unwrap();
        let data = vec![1u8; 8];
        let mut signed = data.clone();
        signed.extend_from_slice(b"alice");
        Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 1,
            threshold: 2,
            total_shares: 3,
            share_data: data.clone(),
            fingerprint: "abcd1234".to_string(),
            signature: HybridSignature::from_sdk(&signer.sign_hybrid(&signed)),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            recipient: Some("alice".to_string()),
            expires_at: None,
            verifier: Some(ShareVerifier {
                ed25519: signer.ed25519_pk().to_bytes().to_vec(),
                falcon1024: signer.falcon1024_pk().as_bytes().to_vec(),
            }),
        }
    }

    #[test]
    fn manifest_excludes_share_material() {
        let dir = tempdir().unwrap();
        let share_path = dir.path().join("share.json");
        let out = dir.path().join("handoff.json");
        let share = share();
        std::fs::write(&share_path, serde_json::to_string(&share).unwrap()).unwrap();

        cmd_handoff(
            HandoffArgs {
                share: share_path,
                out: out.clone(),
                recipient: Some("alice".to_string()),
                force: false,
            },
            &dir.path().join("missing.vault"),
            None,
            false,
        )
        .unwrap();

        let raw = std::fs::read_to_string(out).unwrap();
        assert!(raw.contains("custodian-handoff"));
        assert!(raw.contains("offline-hybrid"));
        assert!(!raw.contains("share_data"));
        assert!(!raw.contains("falcon1024"));
    }
}
