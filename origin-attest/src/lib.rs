//! # origin-attest
//!
//! General-purpose attestation primitives: signed claims, endorsement
//! chains, revocation journals, trust graphs, audit logs, and anti-DoS
//! cookies.
//!
//! Grab this crate when you need:
//! - **Signed claims**: an agent asserts capabilities, signs with Falcon-1024
//! - **Endorsement chains**: hash-chained vouches between agents
//! - **Revocation journals**: append-only revocation records
//! - **Trust graphs**: personalized PageRank with anti-monopoly balancing
//! - **Audit logs**: hash-chained session interaction records
//! - **Anti-DoS cookies**: WireGuard-style handshake protection
//!
//! # Design
//!
//! All types are SDK-native: signing is injected (caller provides signature
//! bytes), verification uses `origin-crypto-sdk` directly. No dependency on
//! any identity crate — fingerprints and keys are hex strings.
//!
//! The trust graph operates on an abstract `EndorsementEdge` trait, so any
//! endorsement-like type can feed into it without coupling to a specific struct.

pub mod audit;
pub mod cookie;
pub mod error;
pub mod registry;
pub mod revocation;
pub mod trust;
pub mod types;

pub use audit::{AuditEntry, AuditLog};
pub use cookie::{Cookie, CookieSecret};
pub use error::{AttestError, Result};
pub use registry::{AgentRecord, AgentRegistry};
pub use revocation::{RevocationJournal, RevocationRecord};
pub use trust::{EndorsementEdge, TrustGraph, TrustGraphConfig, TrustNode};
pub use types::{CapabilityClaim, Endorsement, EndorsementChain, EndorsementTier};
