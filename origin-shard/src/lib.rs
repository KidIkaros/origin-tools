// SPDX-License-Identifier: Apache-2.0

//! origin-shard — secret sharing via Reed-Solomon erasure coding.
//!
//! Two surfaces, one implementation:
//!
//! - **`api`** — the typed library surface: `split` and `recover` operate
//!   on in-memory bytes so any application can plug in its own storage.
//! - **`cli` + `commands`** — the clap shell for the `origin-shard` binary.

pub mod api;
pub mod cli;
pub mod commands;
pub mod error;

pub use api::{recover, split};
pub use error::{Result, ShardError};
