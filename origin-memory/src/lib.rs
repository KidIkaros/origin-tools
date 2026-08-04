// SPDX-License-Identifier: Apache-2.0

//! origin-memory — Provenance-tagged, temporally-aware, orthogonally-layered
//! memory graph for humans and AI.
//!
//! ## Design
//!
//! 1. **Leaf layer** — atomic facts stored as Obsidian-shaped markdown nodes
//!    (`[[wikilinks]]` + YAML frontmatter). Reuses the format every PKM tool
//!    agrees on; no fork needed.
//! 2. **Provenance** — every node is signed with the origin-crypto-sdk hybrid
//!    Ed25519 + Falcon-1024 signature, so a fact is attributable and
//!    tamper-evident. Retraction uses origin-attest's append-only, hash-chained
//!    revocation journal (not deletion — provenance is preserved).
//! 3. **Orthogonal axes** — each node carries `time`, `topic`, `evidence`,
//!    `tier` as *separate* queryable index structures (not one flat graph), so
//!    a query zooms along one axis without the others polluting context.
//! 4. **Temporal + semantic zoom** — `zoom()` intersects axes; `zoom_scored()`
//!    ranks by temporal proximity, topic overlap, evidence weight, and tier.
//! 5. **Recursive coarse hierarchy** — summaries-of-summaries; each level's
//!    `LayerMmr` commits its children, so membership is provable at every depth
//!    (GraphRAG-style, but verifiable via MMR not trust).
//! 6. **Encryption at rest** — secret nodes encrypt their body with SDK
//!    XChaCha20-Poly1305 (never AES-GCM); key from master seed via BLAKE3.
//! 7. **Multi-agent attribution** — every node records its signer fingerprint;
//!    trust between signers propagates via origin-attest's personalized-PageRank
//!    TrustGraph (capability-domain-specific, anti-monopoly balanced).
//! 8. **Visualization** — `render_tree` / `render_star_chart` for the
//!    star-chart / conspiracy-map view.
//!
//! ## Security caveat
//!
//! Provenance here means **attributability + tamper-evidence**, not a formal
//! security proof. The origin-crypto-sdk hybrid (Ed25519 + Falcon-1024) gives
//! strong post-quantum *signing*, but:
//!
//! - The SDK has **no formal proof of cryptographic soundness** — it is
//!   reviewed-source, not audited. Treat signatures as "this key signed this
//!   bytes," not "this person is who they claim."
//! - Key custody is the user's responsibility. The master seed derives both
//!   signing and encryption keys; losing it loses everything; leaking it
//!   compromises everything.
//! - Revocation is a hash-chained journal, not a revocation *protocol* — it
//!   proves a revocation happened, not that all parties have seen it.
//!
//! This crate is a **prototype** of the memory layer. It is not a substitute
//! for a hardened secrets manager or a formal PKI.

pub mod axis;
pub mod crypto;
pub mod endorse;
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
pub use node::{Evidence, MemoryNode};
pub use persist::MemoryStore;
pub use revoke::RevocationStore;
pub use sign::{sign_node, verify_node, NodeSignature};
pub use trust::TrustStore;
