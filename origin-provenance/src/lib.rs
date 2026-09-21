// SPDX-License-Identifier: Apache-2.0

//! origin-provenance — File integrity stamps, watermarks, and verification.
//!
//! Provides cryptographic provenance for files and directories:
//! - **Stamps**: SHA3-256 content hash + timestamp + optional Ed25519 signature
//! - **Watermarks**: Invisible provenance markers embedded in file metadata
//! - **Scan**: Recursively hash a directory tree into a manifest
//! - **Verify**: Check files against a manifest, report tampering

pub mod cli;
pub mod commands;
pub mod encoding;
pub mod error;
pub mod identity;
pub mod manifest;
pub mod opm;
pub mod stamp;
pub mod watermark;
