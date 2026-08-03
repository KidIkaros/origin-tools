//! origin-common — Shared infrastructure for the origin-tools suite.
//!
//! Provides the foundation that all origin-tools crates depend on:
//! - `OriginHome` — resolves the shared home directory (~/.origin)
//! - `IdentityStore` — loads and manages the master identity seed
//! - `Envelope` — unified binary format for encrypted/signed data
//! - `MemoryTier` — re-exported from origin-crypto-sdk
//! - `resolve_passphrase` — shared passphrase resolution
//! - IO helpers — stdin/stdout/file abstraction

pub mod envelope;
pub mod home;
pub mod identity;
pub mod io;
pub mod passphrase;
pub mod random;
pub mod tier;
pub mod tier_ext;

// Re-export MemoryTier from SDK to avoid type conflicts
pub use origin_crypto_sdk::tier::MemoryTier;
pub use tier::argon2_builder;
pub use tier_ext::{tier_from_byte, tier_from_str, tier_to_byte};

pub use envelope::{Envelope, EnvelopeType, PayloadType};
pub use home::{Config, OriginHome};
pub use identity::IdentityStore;
pub use io::{atomic_write, read_input, write_output};
pub use passphrase::{resolve_passphrase, resolve_passphrase_confirm};
pub use random::{random_array, random_bytes};
