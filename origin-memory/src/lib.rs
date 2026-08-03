// SPDX-License-Identifier: Apache-2.0

//! origin-memory — Provenance-tagged, temporally-aware, orthogonally-layered
//! memory graph for humans and AI.
//!
//! The thesis this crate implements:
//!
//! 1. **Leaf layer** — atomic facts stored as Obsidian-shaped markdown nodes
//!    (`[[wikilinks]]` + YAML frontmatter). No fork of any app needed; we reuse
//!    the format every PKM tool already agrees on.
//! 2. **Provenance** — every node and edge is signed with the origin-crypto-sdk
//!    hybrid Ed25519 + Falcon-1024 signature, so a fact is attributable and
//!    tamper-evident 22 years later. This is memory hygiene, not "security."
//! 3. **Orthogonal axes** — each node carries `time`, `topic`, `evidence` in
//!    frontmatter. The indexer projects these into *separate* queryable
//!    structures (not one flat graph), so an AI can zoom along one axis without
//!    the others polluting context.
//! 4. **Temporal zoom** — retrieve "what happened around t" by walking the time
//!    axis, descending only where the question points.
//!
//! This prototype proves layers 1–3 and the temporal-zoom query. The coarse
//! index (GraphRAG-style community hierarchy) and the full zoom algorithm are
//! the next frontier, intentionally left as `todo!()` markers.

pub mod axis;
pub mod crypto;
pub mod index;
pub mod layer;
pub mod memory;
pub mod node;
pub mod persist;
pub mod render;
pub mod revoke;
pub mod sign;
pub mod trust;

pub use axis::{Axis, AxisKind, ZoomQuery};
pub use crypto::BodyCipher;
pub use index::MemoryIndex;
pub use layer::LayerMmr;
pub use memory::{Memory, VerifyReport, ZoomResult};
pub use node::MemoryNode;
pub use persist::MemoryStore;
pub use revoke::RevocationStore;
pub use sign::{sign_node, verify_node, NodeSignature};
pub use trust::TrustStore;
