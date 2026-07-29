// SPDX-License-Identifier: Apache-2.0

//! Capability sets for least-privilege access control.
//!
//! `CapabilitySet` is a bitflag-based permission model. Each bit represents
//! a discrete permission; multiple capabilities combine via bitwise OR.
//! Capabilities narrow **monotonically** down delegation chains — a child
//! can never hold more than its parent delegated.

use serde::{Deserialize, Serialize};

/// Bitflag-based capability set for least-privilege access control.
///
/// Stored as a raw `u64` for serialization. Use the associated constants
/// and helper methods to construct and inspect sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(pub u64);

impl CapabilitySet {
    // ── Individual capabilities ────────────────────────────────────

    /// No capabilities.
    pub const NONE: Self = Self(0);
    /// Sign messages / stamps / endorsements.
    pub const SIGN: Self = Self(1 << 0);
    /// Delegate authority to another identity.
    pub const DELEGATE: Self = Self(1 << 1);
    /// Revoke a previously granted delegation.
    pub const REVOKE: Self = Self(1 << 2);
    /// Stamp files with provenance metadata.
    pub const STAMP: Self = Self(1 << 3);
    /// Encrypt channel messages.
    pub const CHANNEL_ENCRYPT: Self = Self(1 << 4);
    /// Initiate handshakes.
    pub const HANDSHAKE_INITIATE: Self = Self(1 << 5);
    /// Respond to handshakes.
    pub const HANDSHAKE_RESPOND: Self = Self(1 << 6);
    /// Agent-to-agent communication.
    pub const AGENT_COMMUNICATION: Self = Self(1 << 7);
    /// Delegating tasks to other agents.
    pub const TASK_DELEGATION: Self = Self(1 << 8);
    /// Issuing attestations / endorsements.
    pub const ATTESTATION: Self = Self(1 << 9);
    /// Rotating cryptographic keys.
    pub const KEY_ROTATION: Self = Self(1 << 10);
    /// Administrative operations.
    pub const ADMIN: Self = Self(1 << 11);
    /// Proving identity to a peer.
    pub const IDENTITY_PROOF: Self = Self(1 << 12);
    /// Acting on behalf of another entity via a delegation chain.
    pub const ACT_ON_BEHALF: Self = Self(1 << 13);
    /// Operations requiring explicit human approval before execution.
    pub const HUMAN_APPROVAL_REQUIRED: Self = Self(1 << 14);

    // ── Presets ────────────────────────────────────────────────────

    /// Default human capabilities: identity proof, attestation, delegation, signing.
    pub fn human() -> Self {
        Self::IDENTITY_PROOF | Self::ATTESTATION | Self::DELEGATE | Self::SIGN
    }

    /// Default agent capabilities: communication + task delegation.
    pub fn agent() -> Self {
        Self::AGENT_COMMUNICATION | Self::TASK_DELEGATION
    }

    /// Default service capabilities: communication + channel encryption.
    pub fn service() -> Self {
        Self::AGENT_COMMUNICATION | Self::CHANNEL_ENCRYPT
    }

    /// All capabilities.
    pub fn all() -> Self {
        Self((1 << 15) - 1)
    }

    // ── Operations ─────────────────────────────────────────────────

    /// Check whether a specific capability is present.
    pub fn has(self, cap: Self) -> bool {
        self.0 & cap.0 == cap.0
    }

    /// Intersection — capabilities present in both sets.
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Union — capabilities present in either set.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether this set is a subset of `other` (monotonic narrowing check).
    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// Raw bits.
    pub fn bits(self) -> u64 {
        self.0
    }

    /// Truncate from raw bits (clears any bits beyond the defined range).
    pub fn from_bits_truncate(bits: u64) -> Self {
        Self(bits & Self::all().0)
    }
}

impl std::ops::BitOr for CapabilitySet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for CapabilitySet {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = [
            (Self::SIGN, "sign"),
            (Self::DELEGATE, "delegate"),
            (Self::REVOKE, "revoke"),
            (Self::STAMP, "stamp"),
            (Self::CHANNEL_ENCRYPT, "channel_encrypt"),
            (Self::HANDSHAKE_INITIATE, "handshake_initiate"),
            (Self::HANDSHAKE_RESPOND, "handshake_respond"),
            (Self::AGENT_COMMUNICATION, "agent_communication"),
            (Self::TASK_DELEGATION, "task_delegation"),
            (Self::ATTESTATION, "attestation"),
            (Self::KEY_ROTATION, "key_rotation"),
            (Self::ADMIN, "admin"),
            (Self::IDENTITY_PROOF, "identity_proof"),
            (Self::ACT_ON_BEHALF, "act_on_behalf"),
            (Self::HUMAN_APPROVAL_REQUIRED, "human_approval"),
        ]
        .iter()
        .filter(|(cap, _)| self.has(*cap))
        .map(|(_, name)| *name)
        .collect();
        if names.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", names.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_has_nothing() {
        let c = CapabilitySet::NONE;
        assert!(!c.has(CapabilitySet::SIGN));
        assert!(!c.has(CapabilitySet::ADMIN));
    }

    #[test]
    fn all_has_everything() {
        let c = CapabilitySet::all();
        assert!(c.has(CapabilitySet::SIGN));
        assert!(c.has(CapabilitySet::DELEGATE));
        assert!(c.has(CapabilitySet::ADMIN));
        assert!(c.has(CapabilitySet::HUMAN_APPROVAL_REQUIRED));
    }

    #[test]
    fn human_preset() {
        let c = CapabilitySet::human();
        assert!(c.has(CapabilitySet::IDENTITY_PROOF));
        assert!(c.has(CapabilitySet::DELEGATE));
        assert!(c.has(CapabilitySet::ATTESTATION));
        assert!(c.has(CapabilitySet::SIGN));
        assert!(!c.has(CapabilitySet::ADMIN));
    }

    #[test]
    fn agent_preset() {
        let c = CapabilitySet::agent();
        assert!(c.has(CapabilitySet::AGENT_COMMUNICATION));
        assert!(c.has(CapabilitySet::TASK_DELEGATION));
        assert!(!c.has(CapabilitySet::DELEGATE));
    }

    #[test]
    fn monotonic_narrowing() {
        let parent = CapabilitySet::human();
        let child = CapabilitySet::SIGN | CapabilitySet::DELEGATE;
        assert!(child.is_subset_of(parent));
        assert!(!parent.is_subset_of(child));
    }

    #[test]
    fn intersection_narrows() {
        let a = CapabilitySet::SIGN | CapabilitySet::DELEGATE | CapabilitySet::ADMIN;
        let b = CapabilitySet::SIGN | CapabilitySet::STAMP;
        let c = a.intersect(b);
        assert!(c.has(CapabilitySet::SIGN));
        assert!(!c.has(CapabilitySet::DELEGATE));
        assert!(!c.has(CapabilitySet::ADMIN));
        assert!(!c.has(CapabilitySet::STAMP));
    }

    #[test]
    fn from_bits_truncate_clears_unknown() {
        let c = CapabilitySet::from_bits_truncate(0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(c, CapabilitySet::all());
    }

    #[test]
    fn display_format() {
        let c = CapabilitySet::SIGN | CapabilitySet::DELEGATE;
        assert_eq!(format!("{c}"), "sign,delegate");
        assert_eq!(format!("{}", CapabilitySet::NONE), "none");
    }

    #[test]
    fn serde_roundtrip() {
        let c = CapabilitySet::human();
        let json = serde_json::to_string(&c).unwrap();
        let back: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
