// SPDX-License-Identifier: Apache-2.0

//! Vault primitives for `origin-pass`.
//!
//! Wire format: see `origin-crypto-sdk/docs/tools/DESIGN.md` §4 (OVLT
//! header, ChaCha20-BLAKE3 committing AEAD, per-entry nonces, encrypted
//! entry index inside the header).
//!
//! This module is a placeholder for the v0.1.0 scaffold; real primitives
//! land in step 2 of `origin-tools/DESIGN.md` §6.
