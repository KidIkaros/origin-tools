// SPDX-License-Identifier: Apache-2.0

//! Addressing — identity-keyed hierarchical addresses (spec REV 3 §3.1).
//!
//! ```text
//! origin:<identity-fp>[/<device-id>][/<service>][/<session>]
//! ```
//!
//! * `identity-fp` — 32-byte `SeedHandle::fingerprint()` (SHA3-256 of seed).
//! * `device-id`   — u32 device index under one identity.
//! * `service`     — 4-byte registered service port (dispatch inside AEAD).
//! * `session`     — app-scoped stream id within a service.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{NetworkError, Result};

/// Address scheme prefix.
pub const SCHEME: &str = "origin";

/// An Origin identity fingerprint: SHA3-256 of the identity seed.
///
/// Hex `Display` gives zero-conversion interop with origin-attest's
/// trust graph (which keys on hex strings).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// Fingerprint of raw seed bytes — matches `SeedHandle::fingerprint()`.
    pub fn from_seed_bytes(seed: &[u8]) -> Self {
        Self(origin_crypto_sdk::sha3_256(seed))
    }

    /// Parse from a 64-char lowercase-hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| NetworkError::Address(format!("bad hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(NetworkError::Address(format!(
                "fingerprint is 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Lowercase hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form for debug output — never leak full key material paths.
        let h = self.to_hex();
        write!(f, "fp({}..{})", &h[..8], &h[56..])
    }
}

impl FromStr for Fingerprint {
    type Err = NetworkError;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

/// A 4-byte service port — dispatch happens inside the AEAD envelope
/// (FIPS FSP pattern, spec §6.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ServicePort(pub u32);

impl ServicePort {
    /// Well-known reserved port: the IPv6-style catch-all adapter slot.
    pub const ADAPTER: ServicePort = ServicePort(256);

    /// Control / relay-terminated messages.
    pub const CONTROL: ServicePort = ServicePort(1);

    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn from_be_bytes(b: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(b))
    }
}

impl fmt::Display for ServicePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A full Origin address: identity, optional device, service, session.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct OriginAddress {
    pub identity: Fingerprint,
    pub device: Option<u32>,
    pub service: Option<ServicePort>,
    pub session: Option<u64>,
}

impl OriginAddress {
    /// Address an identity only (any device, no service).
    pub fn new(identity: Fingerprint) -> Self {
        Self {
            identity,
            device: None,
            service: None,
            session: None,
        }
    }

    pub fn with_device(mut self, device: u32) -> Self {
        self.device = Some(device);
        self
    }

    pub fn with_service(mut self, service: ServicePort) -> Self {
        self.service = Some(service);
        self
    }

    pub fn with_session(mut self, session: u64) -> Self {
        self.session = Some(session);
        self
    }

    /// The identity-only base of this address.
    pub fn identity_address(&self) -> OriginAddress {
        OriginAddress::new(self.identity)
    }

    /// Parse an `origin:<fp>[/<device>][/<service>][/<session>]` URI.
    pub fn parse(s: &str) -> Result<Self> {
        let Some(rest) = s.strip_prefix(&format!("{SCHEME}:")) else {
            return Err(NetworkError::Address(format!(
                "missing '{SCHEME}:' scheme prefix"
            )));
        };
        if rest.is_empty() {
            return Err(NetworkError::Address("empty address body".into()));
        }
        let mut parts = rest.split('/');
        let identity = Fingerprint::from_hex(parts.next().unwrap())?;
        let mut addr = Self::new(identity);
        for part in parts {
            match (addr.device, addr.service, addr.session) {
                (None, _, _) => {
                    let d: u32 = part
                        .parse()
                        .map_err(|_| NetworkError::Address(format!("bad device id '{part}'")))?;
                    addr.device = Some(d);
                }
                (_, None, _) => {
                    let p: u32 = part
                        .parse()
                        .map_err(|_| NetworkError::Address(format!("bad service port '{part}'")))?;
                    addr.service = Some(ServicePort(p));
                }
                (_, _, None) => {
                    let s: u64 = part
                        .parse()
                        .map_err(|_| NetworkError::Address(format!("bad session id '{part}'")))?;
                    addr.session = Some(s);
                }
                (Some(_), Some(_), Some(_)) => {
                    return Err(NetworkError::Address(format!(
                        "too many address components: '{part}'"
                    )));
                }
            }
        }
        Ok(addr)
    }
}

impl fmt::Display for OriginAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}:{}", self.identity)?;
        if let Some(d) = self.device {
            write!(f, "/{d}")?;
        }
        if let Some(s) = self.service {
            write!(f, "/{}", s.0)?;
        }
        if let Some(s) = self.session {
            write!(f, "/{s}")?;
        }
        Ok(())
    }
}

impl FromStr for OriginAddress {
    type Err = NetworkError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> Fingerprint {
        Fingerprint([0xAB; 32])
    }

    #[test]
    fn fingerprint_from_seed_matches_sdk() {
        let seed = [7u8; 32];
        let fp = Fingerprint::from_seed_bytes(&seed);
        let expected = origin_crypto_sdk::sha3_256(&seed);
        assert_eq!(fp.0, expected);
    }

    #[test]
    fn fingerprint_hex_roundtrip() {
        let f = fp();
        assert_eq!(f.to_hex().len(), 64);
        assert_eq!(Fingerprint::from_hex(&f.to_hex()).unwrap(), f);
    }

    #[test]
    fn fingerprint_display_is_hex() {
        assert_eq!(fp().to_string(), fp().to_hex());
    }

    #[test]
    fn fingerprint_rejects_bad_hex() {
        assert!(Fingerprint::from_hex("zz").is_err());
        assert!(Fingerprint::from_hex(&"ab".repeat(31)).is_err());
        assert!(Fingerprint::from_hex(&"ab".repeat(33)).is_err());
        assert!(Fingerprint::from_hex("").is_err());
    }

    #[test]
    fn fingerprint_debug_is_short() {
        let d = format!("{:?}", fp());
        assert!(d.starts_with("fp(abababab.."));
        assert!(d.len() < 30);
    }

    #[test]
    fn fingerprint_str_roundtrip() {
        let f = fp();
        let s: Fingerprint = f.to_string().parse().unwrap();
        assert_eq!(s, f);
    }

    #[test]
    fn service_port_bytes_roundtrip() {
        let p = ServicePort(0xDEAD_BEEF);
        assert_eq!(ServicePort::from_be_bytes(p.to_be_bytes()), p);
        assert_eq!(ServicePort::CONTROL.0, 1);
        assert_eq!(ServicePort::ADAPTER.0, 256);
    }

    #[test]
    fn address_identity_only() {
        let a = OriginAddress::new(fp());
        assert_eq!(a.to_string(), format!("origin:{}", fp().to_hex()));
        assert_eq!(a.device, None);
        assert_eq!(a.service, None);
        assert_eq!(a.session, None);
    }

    #[test]
    fn address_full_hierarchy() {
        let a = OriginAddress::new(fp())
            .with_device(3)
            .with_service(ServicePort(42))
            .with_session(99);
        let s = a.to_string();
        assert!(s.starts_with("origin:"));
        assert!(s.ends_with("/3/42/99"));
    }

    #[test]
    fn address_parse_roundtrip() {
        let a = OriginAddress::new(fp())
            .with_device(1)
            .with_service(ServicePort(7))
            .with_session(13);
        assert_eq!(OriginAddress::parse(&a.to_string()).unwrap(), a);
        assert_eq!(
            OriginAddress::parse(&OriginAddress::new(fp()).to_string()).unwrap(),
            OriginAddress::new(fp())
        );
    }

    #[test]
    fn address_parse_identity_only() {
        let a = OriginAddress::parse(&format!("origin:{}", fp().to_hex())).unwrap();
        assert_eq!(a.identity, fp());
    }

    #[test]
    fn address_parse_partial() {
        let a = OriginAddress::parse(&format!("origin:{}/5", fp().to_hex())).unwrap();
        assert_eq!(a.device, Some(5));
        assert_eq!(a.service, None);
    }

    #[test]
    fn address_rejects_missing_scheme() {
        assert!(OriginAddress::parse(&fp().to_hex()).is_err());
        assert!(OriginAddress::parse("nostr:abc").is_err());
        assert!(OriginAddress::parse("origin:").is_err());
    }

    #[test]
    fn address_rejects_bad_components() {
        assert!(OriginAddress::parse("origin:zz/1").is_err());
        assert!(OriginAddress::parse(&format!("origin:{}/x", fp().to_hex())).is_err());
        assert!(OriginAddress::parse(&format!("origin:{}/1/2/3/4", fp().to_hex())).is_err());
    }

    #[test]
    fn identity_address_strips_components() {
        let a = OriginAddress::new(fp())
            .with_device(1)
            .with_service(ServicePort(2));
        assert_eq!(a.identity_address(), OriginAddress::new(fp()));
    }

    #[test]
    fn address_str_roundtrip() {
        let a = OriginAddress::new(fp()).with_device(2);
        let b: OriginAddress = a.to_string().parse().unwrap();
        assert_eq!(a, b);
    }
}
