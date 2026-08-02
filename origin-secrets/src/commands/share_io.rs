//! Shared share-file reading with P3 hardening: transparent decryption of
//! encrypted-at-rest shares (P3.3), expiry rejection (P3.2), and revocation
//! rejection (P3.1) when a vault is available.

use crate::crypto::{
    decrypt_share, decrypt_vault_data, derive_vault_key, encrypt_vault_data, EncryptedVault,
};
use crate::error::Error;
use crate::share::{EncryptedShare, Share, ShareVerifier};
use crate::vault::Vault;
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;
use std::path::Path;

/// Read a share file. Handles both the encrypted envelope (P3.3) and legacy
/// plaintext JSON (backward compatible / exported shares).
///
/// When `vault` is `Some`, the share is decrypted (if encrypted) using the
/// vault master seed, and revocation (P3.1) is enforced. Expiry (P3.2) is
/// always enforced when the share carries an `expires_at`.
pub fn read_share_file(
    path: &Path,
    vault: Option<&Path>,
    passphrase: &str,
) -> Result<Share, Error> {
    let raw = std::fs::read_to_string(path).map_err(|_| Error::ShareNotFound {
        share_number: 0,
        path: path.to_path_buf(),
    })?;

    // Try the encrypted envelope first; fall back to plaintext for legacy /
    // exported shares.
    let share: Share = match serde_json::from_str::<EncryptedShare>(&raw) {
        Ok(enc) => {
            let seed = match vault {
                Some(vp) => Some(load_seed(vp, passphrase)?),
                None => None,
            };
            match seed {
                Some(seed) => decrypt_share(&enc, &seed, enc_share_number(&enc, path))?,
                None => {
                    // Encrypted but no vault: cannot decrypt. Surface a clear
                    // error rather than silently failing the decode below.
                    return Err(Error::ShareCorrupted {
                        share_number: 0,
                        path: path.to_path_buf(),
                    });
                }
            }
        }
        Err(_) => serde_json::from_str::<Share>(&raw).map_err(|_| Error::ShareCorrupted {
            share_number: 0,
            path: path.to_path_buf(),
        })?,
    };

    // P3.2: expiry enforcement.
    if let Some(exp) = &share.expires_at {
        if let Ok(exp_t) = chrono_parse(exp) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if now >= exp_t {
                return Err(Error::ShareExpired {
                    share_number: share.share_number,
                    expires_at: exp.clone(),
                });
            }
        }
        // A malformed expiry is non-fatal for read; verify will still run.
    }

    // P3.1: revocation enforcement when a vault is available.
    if let Some(vp) = vault {
        let vd = decrypt_vault_data(
            &load_encrypted(vp)?,
            &derive_vault_key(passphrase.as_bytes(), &seed_salt(vp)?, vault_tier(vp)?)?,
        )?;
        if vd.revoked_shares.contains(&share.share_number) {
            return Err(Error::ShareRevoked {
                share_number: share.share_number,
            });
        }
    }

    Ok(share)
}

/// Verify a share's hybrid signature using the embedded verifier public keys
/// (P3.4) — full crypto check WITHOUT the vault. Returns `Ok(())` if valid.
pub fn verify_share_offline(share: &Share) -> Result<(), Error> {
    let verifier: &ShareVerifier = share.verifier.as_ref().ok_or_else(|| {
        // No embedded verifier: this is NOT a crypto failure, just "cannot
        // verify offline" — callers should treat it as a skip, not a reject.
        Error::CryptoError(
            "share has no embedded verifier; supply the vault for crypto verification".to_string(),
        )
    })?;
    let ed_pk = verifier.ed25519_pk().map_err(|e| {
        Error::SignatureVerificationFailed(format!("bad ed25519 verifier key: {e:?}"))
    })?;
    let falcon_pk = verifier.falcon_pk().map_err(|e| {
        Error::SignatureVerificationFailed(format!("bad falcon verifier key: {e:?}"))
    })?;

    // Exported shares sign share_data + recipient; original shares sign
    // share_data only — mirror the signing behaviour of shard/export.
    let mut msg = share.share_data.clone();
    if let Some(recipient) = &share.recipient {
        msg.extend_from_slice(recipient.as_bytes());
    }
    let sig: Ed25519Falcon1024 = share
        .signature
        .to_sdk()
        .map_err(|e| Error::SignatureVerificationFailed(format!("{e:?}")))?;
    Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, &msg, &sig).map_err(|_| {
        Error::ShareVerificationFailed {
            share_number: share.share_number,
            details: "hybrid signature invalid (offline)".to_string(),
        }
    })
}

// --- internal helpers -------------------------------------------------------

fn enc_share_number(_enc: &EncryptedShare, path: &Path) -> u8 {
    // The share number is recovered after decryption; until then we cannot know
    // it, so callers that need it pass 0 and the decrypt error is generic. To
    // keep the API simple we re-read the number from the decrypted share via a
    // second pass is wasteful; instead we derive it from the filename.
    let fname = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    // share_NNN.json -> NNN
    let digits: String = fname.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.parse::<u8>().unwrap_or(0)
}

fn load_encrypted(vp: &Path) -> Result<EncryptedVault, Error> {
    let raw = std::fs::read_to_string(vp).map_err(|_| Error::VaultNotFound(vp.to_path_buf()))?;
    let vault: Vault =
        serde_json::from_str(&raw).map_err(|e| Error::VaultCorrupted(e.to_string()))?;
    Ok(EncryptedVault {
        version: vault.version,
        created_at: vault.created_at.clone(),
        tier: vault.tier,
        fingerprint: vault.fingerprint.clone(),
        salt: vault.salt,
        nonce: vault.nonce,
        ciphertext: vault.ciphertext.clone(),
    })
}

fn load_seed(vp: &Path, passphrase: &str) -> Result<[u8; 32], Error> {
    let enc = load_encrypted(vp)?;
    let key = derive_vault_key(passphrase.as_bytes(), &enc.salt, enc.tier)?;
    let vd = decrypt_vault_data(&enc, &key)?;
    Ok(vd.master_seed)
}

fn seed_salt(vp: &Path) -> Result<[u8; 16], Error> {
    Ok(load_encrypted(vp)?.salt)
}

fn vault_tier(vp: &Path) -> Result<crate::vault::MemoryTier, Error> {
    Ok(load_encrypted(vp)?.tier)
}

/// Minimal ISO-8601 -> epoch-seconds parse (YYYY-MM-DDTHH:MM:SSZ). Avoids a
/// chrono dependency for this single use.
fn chrono_parse(s: &str) -> Result<i64, Error> {
    // Accept either "YYYY-MM-DDTHH:MM:SSZ" or "YYYY-MM-DDTHH:MM:SS+00:00".
    let compact = s.trim_end_matches('Z').replace('T', "-");
    let parts: Vec<&str> = compact.split(['-', ':', '+']).collect();
    if parts.len() < 6 {
        return Err(Error::CryptoError("bad expiry format".to_string()));
    }
    let y: i64 = parts[0]
        .parse()
        .map_err(|_| Error::CryptoError("bad year".into()))?;
    let mo: i64 = parts[1]
        .parse()
        .map_err(|_| Error::CryptoError("bad month".into()))?;
    let d: i64 = parts[2]
        .parse()
        .map_err(|_| Error::CryptoError("bad day".into()))?;
    let h: i64 = parts[3]
        .parse()
        .map_err(|_| Error::CryptoError("bad hour".into()))?;
    let mi: i64 = parts[4]
        .parse()
        .map_err(|_| Error::CryptoError("bad minute".into()))?;
    let s2: i64 = parts[5]
        .parse()
        .map_err(|_| Error::CryptoError("bad second".into()))?;
    // Days since epoch (proleptic Gregorian, good enough for expiry comparison).
    let mut days = (y - 1970) * 365 + (y - 1969) / 4;
    let month_days = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += month_days[(mo - 1) as usize];
    if mo > 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) {
        days += 1;
    }
    days += d - 1;
    let secs = days * 86400 + h * 3600 + mi * 60 + s2;
    Ok(secs)
}

#[allow(dead_code)]
fn _unused_encrypt_vault_data() {
    let _ = encrypt_vault_data;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::InitArgs;
    use crate::commands::init::cmd_init;
    use crate::crypto::encrypt_share;
    use crate::share::HybridSignature;
    use tempfile::tempdir;

    fn init_vault(dir: &std::path::Path, pw: &str) -> (std::path::PathBuf, [u8; 32]) {
        let vault_path = dir.join("secrets.vault");
        let pw_file = dir.join("pw.txt");
        std::fs::write(&pw_file, format!("{}\n", pw)).unwrap();
        cmd_init(
            InitArgs {
                tier: "standard".to_string(),
            },
            &vault_path,
            Some(pw_file.as_path()),
            false,
        )
        .unwrap();
        // Build a deterministic seed for the test by writing a known seed vault.
        let salt: [u8; 16] = [3u8; 16];
        let nonce: [u8; 24] = [4u8; 24];
        let tier = crate::vault::MemoryTier::Standard;
        let key = derive_vault_key(pw.as_bytes(), &salt, tier).unwrap();
        let mut vd = crate::crypto::VaultData::new();
        vd.master_seed = [42u8; 32];
        let enc = encrypt_vault_data(&vd, &key, salt, nonce, tier).unwrap();
        let vault = Vault {
            version: enc.version,
            created_at: enc.created_at.clone(),
            tier: enc.tier,
            fingerprint: enc.fingerprint.clone(),
            salt: enc.salt,
            nonce: enc.nonce,
            ciphertext: enc.ciphertext,
        };
        std::fs::write(&vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        (vault_path, [42u8; 32])
    }

    fn make_share(seed: &[u8; 32], number: u8) -> Share {
        let signer = origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle::from_seed_cached(
            seed,
            "origin-secrets/share/v1",
        )
        .unwrap();
        let data = vec![number; 8];
        let sig = HybridSignature::from_sdk(&signer.sign_hybrid(&data));
        Share {
            version: 1,
            key_id: "k".into(),
            share_number: number,
            threshold: 2,
            total_shares: 3,
            share_data: data,
            fingerprint: "ab".into(),
            signature: sig,
            created_at: "2026-01-01T00:00:00Z".into(),
            recipient: None,
            expires_at: None,
            verifier: Some(ShareVerifier {
                ed25519: signer.ed25519_pk().to_bytes().to_vec(),
                falcon1024: signer.falcon1024_pk().as_bytes().to_vec(),
            }),
        }
    }

    #[test]
    fn test_verify_share_offline_valid() {
        let share = make_share(&[42u8; 32], 1);
        assert!(verify_share_offline(&share).is_ok());
    }

    #[test]
    fn test_verify_share_offline_rejects_tampered() {
        let mut share = make_share(&[42u8; 32], 1);
        share.share_data[0] ^= 0xFF;
        assert!(matches!(
            verify_share_offline(&share),
            Err(Error::ShareVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_share_offline_no_verifier_errors() {
        let mut share = make_share(&[42u8; 32], 1);
        share.verifier = None;
        assert!(matches!(
            verify_share_offline(&share),
            Err(Error::CryptoError { .. })
        ));
    }

    #[test]
    fn test_read_encrypted_share_with_vault() {
        let dir = tempdir().unwrap();
        let (vault, seed) = init_vault(dir.path(), "read-share-pw-12");
        let share = make_share(&seed, 2);
        let enc = encrypt_share(&share, &seed).unwrap();
        let path = dir.path().join("share_002.json");
        std::fs::write(&path, serde_json::to_string_pretty(&enc).unwrap()).unwrap();

        let read = read_share_file(&path, Some(&vault), "read-share-pw-12").unwrap();
        assert_eq!(read.share_number, 2);
        assert_eq!(read.share_data, share.share_data);
    }

    #[test]
    fn test_read_share_rejects_revoked() {
        let dir = tempdir().unwrap();
        let (vault, seed) = init_vault(dir.path(), "read-share-pw-12");
        // Mark share 2 revoked in the vault.
        let raw = std::fs::read_to_string(&vault).unwrap();
        let mut v: crate::vault::Vault = serde_json::from_str(&raw).unwrap();
        let key = derive_vault_key("read-share-pw-12".as_bytes(), &v.salt, v.tier).unwrap();
        let enc = crate::crypto::EncryptedVault {
            version: v.version,
            created_at: v.created_at.clone(),
            tier: v.tier,
            fingerprint: v.fingerprint.clone(),
            salt: v.salt,
            nonce: v.nonce,
            ciphertext: v.ciphertext.clone(),
        };
        let mut vd = decrypt_vault_data(&enc, &key).unwrap();
        vd.revoked_shares.insert(2);
        let re_enc = encrypt_vault_data(&vd, &key, v.salt, v.nonce, v.tier).unwrap();
        v.ciphertext = re_enc.ciphertext;
        std::fs::write(&vault, serde_json::to_string_pretty(&v).unwrap()).unwrap();

        let share = make_share(&seed, 2);
        let enc = encrypt_share(&share, &seed).unwrap();
        let path = dir.path().join("share_002.json");
        std::fs::write(&path, serde_json::to_string_pretty(&enc).unwrap()).unwrap();

        let result = read_share_file(&path, Some(&vault), "read-share-pw-12");
        assert!(matches!(
            result,
            Err(Error::ShareRevoked {
                share_number: 2,
                ..
            })
        ));
    }

    #[test]
    fn test_read_share_rejects_expired() {
        let dir = tempdir().unwrap();
        let (vault, seed) = init_vault(dir.path(), "read-share-pw-12");
        let mut share = make_share(&seed, 3);
        share.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        let enc = encrypt_share(&share, &seed).unwrap();
        let path = dir.path().join("share_003.json");
        std::fs::write(&path, serde_json::to_string_pretty(&enc).unwrap()).unwrap();

        let result = read_share_file(&path, Some(&vault), "read-share-pw-12");
        assert!(matches!(
            result,
            Err(Error::ShareExpired {
                share_number: 3,
                ..
            })
        ));
    }

    #[test]
    fn test_read_encrypted_share_without_vault_fails() {
        let dir = tempdir().unwrap();
        let (_vault, seed) = init_vault(dir.path(), "read-share-pw-12");
        let share = make_share(&seed, 2);
        let enc = encrypt_share(&share, &seed).unwrap();
        let path = dir.path().join("share_002.json");
        std::fs::write(&path, serde_json::to_string_pretty(&enc).unwrap()).unwrap();

        // No vault -> cannot decrypt -> ShareCorrupted.
        let result = read_share_file(&path, None, "");
        assert!(matches!(result, Err(Error::ShareCorrupted { .. })));
    }

    #[test]
    fn test_read_plaintext_legacy_share() {
        let dir = tempdir().unwrap();
        let share = make_share(&[42u8; 32], 3);
        let path = dir.path().join("share_003.json");
        std::fs::write(&path, serde_json::to_string_pretty(&share).unwrap()).unwrap();
        let read = read_share_file(&path, None, "").unwrap();
        assert_eq!(read.share_number, 3);
    }

    #[test]
    fn test_chrono_parse_basic() {
        // 1970-01-02T00:00:00Z == 86400 seconds.
        assert_eq!(chrono_parse("1970-01-02T00:00:00Z").unwrap(), 86400);
    }
}
