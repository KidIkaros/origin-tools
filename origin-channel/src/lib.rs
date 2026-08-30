// SPDX-License-Identifier: Apache-2.0

//! origin-channel — Encrypted sessions built on origin-crypto-sdk.
//!
//! Provides a Noise IK handshake over X25519, a symmetric double-ratchet
//! for forward-secret messaging, AEAD encryption via XChaCha20-Poly1305,
//! length-prefixed wire framing, replay protection, and cipher-suite
//! negotiation with downgrade resistance.

pub mod cli;
pub mod codec;
pub mod commands;
pub mod dh;
pub mod error;
pub mod handshake;
pub mod message;
pub mod negotiation;
pub mod nonce_tracker;
pub mod ratchet;
pub mod replay;
pub mod session;
pub mod types;
pub mod usage_limit;

pub use error::{ChannelError, Result};
pub use session::RatchetedSession;
pub use types::{ChannelState, SessionId};
pub use usage_limit::{AeadLimits, AeadUsageTracker};
