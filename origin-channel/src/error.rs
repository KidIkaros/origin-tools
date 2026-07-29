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
