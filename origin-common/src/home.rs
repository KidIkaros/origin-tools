//! OriginHome — shared home directory and configuration.
//!
//! The suite uses a single home directory (~/.origin by default) for identity,
//! config, and data. This module resolves paths and loads config.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::tier_ext::tier_from_str;

/// Configuration stored in ~/.origin/config.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default memory tier for Argon2id ("nano", "standard", "sovereign").
    #[serde(default = "default_tier")]
    pub tier: String,
    /// Default output format (hex, base64, raw).
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_tier() -> String {
    "standard".to_string()
}

fn default_format() -> String {
    "hex".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tier: default_tier(),
            format: default_format(),
        }
    }
}

impl Config {
    /// Resolve the tier string to a MemoryTier enum.
    pub fn tier(&self) -> origin_crypto_sdk::tier::MemoryTier {
        tier_from_str(&self.tier).unwrap_or(origin_crypto_sdk::tier::MemoryTier::Standard)
    }
}

/// The shared origin-tools home directory.
///
/// Resolves paths for identity, config, vault, and other shared data.
pub struct OriginHome {
    root: PathBuf,
    config: Config,
}

impl OriginHome {
    /// Load the default home directory.
    ///
    /// Respects the `ORIGIN_HOME` environment variable for testing / multi-profile.
    /// Falls back to `~/.origin`. Creates the directory and default config if needed.
    pub fn load() -> Result<Self, String> {
        let root = if let Ok(custom) = std::env::var("ORIGIN_HOME") {
            PathBuf::from(custom)
        } else {
            dirs::home_dir()
                .ok_or("cannot determine home directory")?
                .join(".origin")
        };
        Self::with_root(root)
    }

    /// Load a home directory at a specific path (for testing or multi-profile).
    pub fn with_root(root: PathBuf) -> Result<Self, String> {
        if !root.exists() {
            std::fs::create_dir_all(&root)
                .map_err(|e| format!("cannot create '{}': {e}", root.display()))?;
        }

        let config_path = root.join("config.toml");
        let config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("cannot read '{}': {e}", config_path.display()))?;
            toml::from_str(&content)
                .map_err(|e| format!("cannot parse '{}': {e}", config_path.display()))?
        } else {
            let config = Config::default();
            let content = toml::to_string_pretty(&config)
                .map_err(|e| format!("cannot serialize config: {e}"))?;
            std::fs::write(&config_path, content)
                .map_err(|e| format!("cannot write '{}': {e}", config_path.display()))?;
            config
        };

        Ok(Self { root, config })
    }

    /// Get the root directory path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the loaded configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Path to the encrypted identity seed file.
    pub fn identity_seed_path(&self) -> PathBuf {
        self.root.join("identity.seed")
    }

    /// Path to the origin-pass vault file.
    pub fn vault_path(&self) -> PathBuf {
        self.root.join("vault.opass")
    }

    /// Path to the config file.
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// Path to the keys directory (for exported public keys).
    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    /// Path to the backups directory.
    pub fn backups_dir(&self) -> PathBuf {
        self.root.join("backups")
    }
}
