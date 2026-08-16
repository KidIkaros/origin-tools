// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! Origin Canary Embedder — steganographic canary token embedding for
//! source-available / fair-source projects.
//!
//! Embeds unique, per-distribution canary tokens into source code using
//! multiple steganographic strategies (variable injection, watermark
//! comments, dead code), builds a BLAKE3 Merkle tree commitment, and
//! produces a signed, publishable fingerprint record.
//!
//! # Quickstart
//!
//! ```bash
//! # Embed canaries into a source tree
//! origin canary embed \
//!   --source ./myproject/src \
//!   --project-id 42 \
//!   --distribution-id v1.3.0 \
//!   --salt <random-32-byte-hex> \
//!   --num-canaries 20 \
//!   --manifest-out ./canary-manifest.json
//!
//! # Verify canaries in suspect code
//! origin canary verify --source ./suspect --manifest ./canary-manifest.json
//! ```
//!
//! # Design
//!
//! - **No chain, no server, no external service.** The commitment is a static
//!   artifact (signed Merkle root) published however the creator chooses
//!   (signed Git tag, release notes, standalone JSON file).
//! - **Steganographic embedding.** Canary tokens are hidden in plain sight
//!   as valid-looking source code (config constants, comment references,
//!   dead validation helpers). They survive casual inspection and common
//!   transformations (minification, transpilation) where the injected
//!   constructs are preserved.
//! - **Per-distribution uniqueness.** Each distribution gets its own salt +
//!   distribution_id; tokens are deterministic from
//!   `(project_id, distribution_id, index, salt)`. A different distribution
//!   gets different tokens — you know which distribution leaked.
//! - **Honest survivability.** The tool documents what survives and what
//!   doesn't. Overclaiming undermines credibility.
//!
//! # Subcommands
//!
//! | Command | Purpose |
//! |---------|---------|
//! | `embed` | Embed canary tokens into a source tree, build Merkle commitment |
//! | `verify` | Scan a suspect codebase for canary tokens |
//! | `sign` | Sign the Merkle commitment with a hybrid PQC identity |
//! | `verify-commitment` | Verify a signed commitment against a public key |
//! | `fingerprint` | Hash a release archive + source tree + signed commitment |
//! | `evidence` | Assemble a litigation-ready evidence package

#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod commitment;
pub mod embed;
pub mod evidence;
pub mod fingerprint;
pub mod manifest;
pub mod merkle;
pub mod strategies;
pub mod verify;
