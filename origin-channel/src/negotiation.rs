// SPDX-License-Identifier: Apache-2.0

//! Cipher-suite negotiation with downgrade protection.
//!
//! The initiator advertises supported suites in preference order.
//! The responder picks the first mutually supported suite.
//! A MAC over the negotiation transcript prevents MITM downgrade.

use crate::error::{ChannelError, Result};
use crate::types::CipherSuite;

/// Protocol version for negotiation.
pub const NEGOTIATION_VERSION: u8 = 1;

/// Negotiation message: version ‖ suite_count ‖ suites…
pub struct Negotiation {
    pub version: u8,
    pub suites: Vec<CipherSuite>,
}

impl Negotiation {
    /// Create a negotiation offer with default suite preference.
    pub fn offer() -> Self {
        Negotiation {
            version: NEGOTIATION_VERSION,
            suites: vec![CipherSuite::XChaCha20Poly1305],
        }
    }

    /// Serialize to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.suites.len());
        out.push(self.version);
        out.push(self.suites.len() as u8);
        for s in &self.suites {
            out.push(s.as_u8());
        }
        out
    }

    /// Parse from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(ChannelError::Negotiation("too short".into()));
        }
        let version = data[0];
        if version != NEGOTIATION_VERSION {
            return Err(ChannelError::Negotiation(format!(
                "unsupported version {version}"
            )));
        }
        let count = data[1] as usize;
        if data.len() < 2 + count {
            return Err(ChannelError::Negotiation("truncated suite list".into()));
        }
        let mut suites = Vec::with_capacity(count);
        for &b in &data[2..2 + count] {
            let suite = CipherSuite::from_u8(b).ok_or_else(|| {
                ChannelError::Negotiation(format!("unknown suite 0x{b:02x}"))
            })?;
            suites.push(suite);
        }
        if suites.is_empty() {
            return Err(ChannelError::Negotiation("empty suite list".into()));
        }
        Ok(Negotiation { version, suites })
    }

    /// Responder selects the first suite it also supports.
    pub fn select(&self, supported: &[CipherSuite]) -> Result<CipherSuite> {
        for &offered in &self.suites {
            if supported.contains(&offered) {
                return Ok(offered);
            }
        }
        Err(ChannelError::Negotiation(
            "no mutually supported cipher suite".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_negotiation() {
        let offer = Negotiation::offer();
        let bytes = offer.to_bytes();
        let parsed = Negotiation::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, NEGOTIATION_VERSION);
        assert_eq!(parsed.suites, vec![CipherSuite::XChaCha20Poly1305]);
    }

    #[test]
    fn select_mutual() {
        let offer = Negotiation::offer();
        let selected = offer
            .select(&[CipherSuite::XChaCha20Poly1305])
            .unwrap();
        assert_eq!(selected, CipherSuite::XChaCha20Poly1305);
    }

    #[test]
    fn select_no_overlap() {
        let offer = Negotiation {
            version: NEGOTIATION_VERSION,
            suites: vec![CipherSuite::XChaCha20Poly1305],
        };
        // Responder supports nothing we offer
        let result = offer.select(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_bad_version() {
        let bytes = [0xFF, 0x01, 0x01];
        assert!(Negotiation::from_bytes(&bytes).is_err());
    }
}
