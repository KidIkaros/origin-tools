// SPDX-License-Identifier: Apache-2.0

//! origin-seed — seed lifecycle: generate, derive, encode, encrypted blobs.
//!
//! Two surfaces, one implementation:
//!
//! - **`api`** — the typed library surface. Applications call
//!   [`api::generate`], [`api::derive`], [`api::seal_blob`],
//!   [`api::recover_blob`] directly and get typed results back
//!   (`SeedError` not `String`).
//! - **`cli` + `commands`** — the clap shell for the `origin-seed` binary.

pub mod api;
pub mod cli;
pub mod commands;
pub mod error;

pub use api::{derive, from_hex, generate, parse_tier, recover_blob, seal_blob, to_hex};
pub use error::{Result, SeedError};
