// SPDX-License-Identifier: Apache-2.0

//! origin-network — Universal transport substrate for the Origin stack.
//!
//! Design: `tgui-lab/docs/ORIGIN-NETWORK-SPEC.md` (REV 3).
//!
//! Carries authenticated, bounded byte streams between Origin identities —
//! direct when possible, relayed when not — while never touching plaintext.
//! Sits BELOW origin-channel (session crypto) in the stack.
//!
//! # Substrate contract
//! 1. Address by identity, not location: `origin:<fp>[/<device>][/<service>][/<session>]`
//! 2. End-to-end zero trust: relays carry ciphertext only
//! 3. Auth by handshake: Noise IK to identity-derived key IS the authentication
//! 4. Datagram-pure core: reliability/file semantics are layers above
//! 5. Policy over assumption: topology, buffering, trust are axes apps set

pub mod address;
pub mod error;
pub mod gate;
pub mod identity;
pub mod relay;
pub mod relay_server;
pub mod replay;
pub mod session;
pub mod transport;
pub mod wire;

pub use address::{Fingerprint, OriginAddress, ServicePort};
pub use error::{NetworkError, Result};
pub use gate::{CookieChallenge, CookieGate, IngressGate, PowGate, PowProof, TokenBucket};
pub use identity::{
    derive_transport_secret, sign_auth_claim, transport_public_key, verify_auth_claim, PeerKeys,
    PROTOCOL_VERSION, TRANSPORT_KEY_DOMAIN,
};
pub use relay::{EvictionSet, ForwardOutcome, ForwardPair, RelayState};
pub use relay_server::RelayServer;
pub use replay::HandshakeReplayTracker;
pub use session::{Endpoint, PeerResolver, SecurePipe, StaticResolver};
pub use transport::{FrameConn, TcpTransport, Transport, TransportAddr};
pub use wire::{WireError, WireType};
