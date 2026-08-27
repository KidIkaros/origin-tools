// SPDX-License-Identifier: Apache-2.0

//! origin-vcs — Git-like file versioning with signed commits and
//! encrypted-at-rest objects.
//!
//! Modules:
//! - [`object`] — blob/tree/commit/tag types, canonical serialization, and
//!   SHA3-256 content addressing.
//! - [`store`] — encrypted-at-rest object store, refs, index, MMR persistence.
//! - [`crypto`] — hybrid (Ed25519 + Falcon-1024) signatures + identity keys.
//! - [`mmr`] — append-only Merkle Mountain Range for the commit log.
//! - [`cli`] / [`commands`] — subcommand definitions and dispatch.
//!
//! All cryptography is provided by `origin-crypto-sdk`; this crate only
//! composes it.

pub mod bundle;
pub mod cli;
pub mod commands;
pub mod crypto;
pub mod ignore;
pub mod mmr;
pub mod object;
pub mod remote;
pub mod store;
pub mod stream;
pub mod textmerge;
