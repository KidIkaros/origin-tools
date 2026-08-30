pub mod api;
pub mod cli;
pub mod commands;
pub mod error;

pub use api::{batch_verify, keypair, proof_from_json, prove, verify};
pub use error::{Result, SchnorrError};
