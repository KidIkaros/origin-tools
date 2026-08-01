// SPDX-License-Identifier: Apache-2.0

//! Error types for origin-channel.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ChannelError>;

#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("replay detected: seq {0}")]
    Replay(u64),

    #[error("negotiation failed: {0}")]
    Negotiation(String),

    #[error("codec error: {0}")]
    Codec(String),

    #[error("session not established")]
    NoSession,

    #[error("key error: {0}")]
    Key(String),

    #[error("AEAD usage limit exceeded: {0}")]
    UsageLimitExceeded(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<String> for ChannelError {
    fn from(s: String) -> Self {
        ChannelError::Other(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_conversion() {
        let err: ChannelError = "something broke".to_string().into();
        assert!(matches!(err, ChannelError::Other(_)));
        assert_eq!(err.to_string(), "something broke");
    }

    #[test]
    fn display_all_variants() {
        assert!(ChannelError::Handshake("hs".into())
            .to_string()
            .contains("hs"));
        assert!(ChannelError::InvalidMessage("bad".into())
            .to_string()
            .contains("bad"));
        assert!(ChannelError::Decryption("dec".into())
            .to_string()
            .contains("dec"));
        assert!(ChannelError::Replay(42).to_string().contains("42"));
        assert!(ChannelError::Negotiation("neg".into())
            .to_string()
            .contains("neg"));
        assert!(ChannelError::Codec("cd".into()).to_string().contains("cd"));
        assert!(ChannelError::NoSession
            .to_string()
            .contains("not established"));
        assert!(ChannelError::Key("k".into()).to_string().contains("k"));
        assert!(ChannelError::UsageLimitExceeded("lim".into())
            .to_string()
            .contains("lim"));
    }
}
