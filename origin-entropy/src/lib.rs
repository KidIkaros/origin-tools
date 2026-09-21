// SPDX-License-Identifier: Apache-2.0

//! origin-entropy — entropy auditing: Shannon, chi-squared, min-entropy, quality gates.
//!
//! Two surfaces, one implementation:
//!
//! - **`api`** — the typed library surface: `EntropyStats::analyze`,
//!   `quality_check`, and the raw statistics functions operate on
//!   in-memory bytes so any application can plug in its own I/O.
//! - **`cli` + `commands`** — the clap shell for the `origin-entropy` binary.

pub mod api;
pub mod cli;
pub mod commands;
pub mod error;

pub use api::{chi_squared, min_entropy, quality_check, shannon_entropy, EntropyStats, QualityReport};
pub use error::{EntropyError, Result};
// SDK entropy types (for access to full metrics beyond the backward-compatible subset)
pub use origin_crypto_sdk::entropy::{analyze, check_quality, EntropyMetrics, QualityRequirements};
