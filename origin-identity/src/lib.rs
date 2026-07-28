// SPDX-License-Identifier: Apache-2.0

//! origin-identity library surface.
//!
//! Re-exports the CLI definitions and command implementations so other
//! crates (e.g. the unified `origin` binary) can dispatch programmatically.

pub mod cli;
pub mod commands;
