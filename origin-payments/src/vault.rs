// SPDX-License-Identifier: Apache-2.0

//! Credential vault (design §3, §6 `psp configure`).
//!
//! PSP credentials (x402 facilitator API keys, card ACP API secrets) are
//! stored under `<root>/psp_vault/<rail>.secret`, owner-only (0600),
//! behind the TOTP admin gate. For the x402 rail the stored secret is
//! the facilitator API key, and the facilitator base URL is persisted in
//! a sibling file so the executor can build the [`FacilitatorConfig`] at
//! settle time. A full `origin-pass` vault (Argon2id + AEAD,
//! tier-selected) for these credentials is the documented follow-up; the
//! file layout keeps the rail→secret mapping stable in the meantime.

use std::path::Path;

use crate::error::{Error, Result};

/// Store a PSP credential for a rail (0600, owner-only).
pub fn store_secret(root: &Path, rail: &str, secret: &[u8]) -> Result<()> {
    if secret.is_empty() {
        return Err(Error::StoreCorrupted {
            details: "empty credential".to_string(),
        });
    }
    let dir = root.join("psp_vault");
    std::fs::create_dir_all(&dir).map_err(|e| Error::IoError {
        details: format!("creating {}: {e}", dir.display()),
    })?;
    let path = dir.join(format!("{rail}.secret"));
    std::fs::write(&path, secret).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", path.display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Read a stored PSP credential (returns an error when absent).
pub fn load_secret(root: &Path, rail: &str) -> Result<Vec<u8>> {
    let path = root.join("psp_vault").join(format!("{rail}.secret"));
    if !path.exists() {
        return Err(Error::OrderNotFound {
            payment_order_id: format!("psp credential for rail {rail}"),
        });
    }
    std::fs::read(&path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })
}

/// Persist the facilitator base URL for a rail (0600), separate from the
/// API key so the two are never conflated.
pub fn store_facilitator_url(root: &Path, rail: &str, url: &str) -> Result<()> {
    if url.trim().is_empty() {
        return Err(Error::StoreCorrupted {
            details: "empty facilitator URL".to_string(),
        });
    }
    let dir = root.join("psp_vault");
    std::fs::create_dir_all(&dir).map_err(|e| Error::IoError {
        details: format!("creating {}: {e}", dir.display()),
    })?;
    let path = dir.join(format!("{rail}.facilitator"));
    std::fs::write(&path, url.as_bytes()).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", path.display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Read the facilitator base URL for a rail.
pub fn load_facilitator_url(root: &Path, rail: &str) -> Result<String> {
    let path = root.join("psp_vault").join(format!("{rail}.facilitator"));
    if !path.exists() {
        return Err(Error::OrderNotFound {
            payment_order_id: format!("facilitator URL for rail {rail}"),
        });
    }
    std::fs::read_to_string(&path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })
}

/// Build the x402 [`FacilitatorConfig`] for a rail from the vault: the
/// facilitator URL plus the API key (the stored secret). `Ok(None)` when
/// the rail is not configured in the vault.
pub fn load_facilitator_config(
    root: &Path,
    rail: &str,
) -> Result<Option<crate::x402::FacilitatorConfig>> {
    // Both the URL and the key must be present for a usable config; if
    // only one exists, treat the rail as not-configured rather than
    // silently half-wired.
    let (url, key) = match (load_facilitator_url(root, rail), load_secret(root, rail)) {
        (Ok(u), Ok(k)) => (u, String::from_utf8_lossy(&k).trim().to_string()),
        _ => return Ok(None),
    };
    if url.trim().is_empty() || key.is_empty() {
        return Ok(None);
    }
    Ok(Some(crate::x402::FacilitatorConfig {
        url: url.trim().to_string(),
        api_key: key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_store_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        store_secret(dir.path(), "http402", b"super-secret-key").unwrap();
        assert_eq!(
            load_secret(dir.path(), "http402").unwrap(),
            b"super-secret-key"
        );
        assert!(load_secret(dir.path(), "card").is_err());
    }

    #[test]
    fn empty_secret_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store_secret(dir.path(), "card", b"").is_err());
    }

    #[test]
    fn facilitator_config_roundtrip_via_vault() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing configured yet.
        assert_eq!(
            load_facilitator_config(dir.path(), "http402").unwrap(),
            None
        );
        // Both sides configured → a usable config.
        store_facilitator_url(dir.path(), "http402", "http://127.0.0.1:9999").unwrap();
        store_secret(dir.path(), "http402", b"api-key-123").unwrap();
        let cfg = load_facilitator_config(dir.path(), "http402")
            .unwrap()
            .expect("configured");
        assert_eq!(cfg.url, "http://127.0.0.1:9999");
        assert_eq!(cfg.api_key, "api-key-123");
        // Half-configured (URL only) is treated as not-configured.
        let dir2 = tempfile::tempdir().unwrap();
        store_facilitator_url(dir2.path(), "http402", "http://127.0.0.1:9999").unwrap();
        assert_eq!(
            load_facilitator_config(dir2.path(), "http402").unwrap(),
            None
        );
    }
}
