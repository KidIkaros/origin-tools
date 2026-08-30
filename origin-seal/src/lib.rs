// SPDX-License-Identifier: Apache-2.0

//! origin-seal — data operations: encrypt, decrypt, sign, verify, hash, MAC, KDF.
//!
//! Two surfaces, one implementation:
//!
//! - **`api`** — the typed library surface. Applications call
//!   [`api::encrypt`], [`api::decrypt`], [`api::sign`], [`api::verify`],
//!   [`api::hash`], [`api::mac`], [`api::kdf`] directly and get typed
//!   results back (no clap structs, no stdout parsing, `SealError` not
//!   `String`). This is the "foundational crate" surface.
//! - **`cli` + `commands`** — the clap shell for the `origin-seal` binary,
//!   a thin mapping onto `api`. Kept for interactive/scripted use.
//!
//! Design rules (see ARCHITECTURE.md):
//! - One crypto provider: every primitive goes through `origin-crypto-sdk`.
//! - Errors are typed (`SealError`), never `String`.

pub mod api;
pub mod cli;
pub mod commands;
pub mod error;

pub use api::{
    decrypt, encrypt, hash, kdf, mac, parse_envelope, sign, verify, EnvelopeHeader, HashKind,
    HybridSignature,
};
pub use error::{Result, SealError};
// Re-exported for downstream consumers of the typed API.
pub use origin_common::MemoryTier;
