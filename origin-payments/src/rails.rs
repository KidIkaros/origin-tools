// SPDX-License-Identifier: Apache-2.0

//! Rail abstraction (design §3; Stoa SPEC §10.2 shape).
//!
//! One interface, many rails. The executor routes orders over enabled
//! rails cheapest-first (wired in P4) via `origin-wallet`'s pay surface.

use serde::{Deserialize, Serialize};

/// x402 payment schemes (sibling `payments` repo contracts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentScheme {
    X402,
}

/// The rails a payment order may ride.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rail {
    /// Stoa evidence-based channel (§10.1) — signed ledger entries, no
    /// on-chain anything.
    NativeChannel,
    /// x402-style HTTP pay rail; EIP-712-style signed receipts.
    Http402 { url: String, scheme: PaymentScheme },
    /// Tokenized card rail (ACP-style); last4 only, never the PAN.
    CardAcp { network: String, last4: String },
}

impl std::fmt::Display for Rail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Rail::NativeChannel => "native",
            Rail::Http402 { .. } => "http402",
            Rail::CardAcp { .. } => "card",
        })
    }
}

/// A coarse rail hint on an order; `None` means smart routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailHint {
    Native,
    Http402,
    Card,
    /// Fiat rail via an ACH/SEPA-style facilitator — same verify/settle
    /// split as http402, but the facilitator settles on a traditional
    /// payment network (ACH, SEPA, wire) instead of on-chain.
    /// x402 V2 explicitly supports legacy-rail facilitators.
    Ach,
}

impl std::fmt::Display for RailHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RailHint {
    pub fn as_str(self) -> &'static str {
        match self {
            RailHint::Native => "native",
            RailHint::Http402 => "http402",
            RailHint::Card => "card",
            RailHint::Ach => "ach",
        }
    }
}

impl std::str::FromStr for RailHint {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native" => Ok(RailHint::Native),
            "http402" => Ok(RailHint::Http402),
            "card" => Ok(RailHint::Card),
            "ach" => Ok(RailHint::Ach),
            other => Err(format!(
                "unknown rail hint: {other} (expected native|http402|card|ach)"
            )),
        }
    }
}

/// The rail evidence — versioned, rail-discriminated, verifiable forever
/// (design §5; Stoa §10.2 receipt envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum RailReceipt {
    /// Encoded `ENTRY_RECEIPT` ledger entry — verifies against the
    /// gossiped ledger (Stoa §10.1).
    Native { ledger_entry: Vec<u8> },
    /// EIP-712-style signed receipt (SDK `ec_schnorr`).
    Http402 { receipt: Vec<u8> },
    /// ACP token authorization result.
    CardAcp {
        network: String,
        last4: String,
        auth: Vec<u8>,
    },
    /// ACH/SEPA facilitator authorization — the PSP settles on a
    /// traditional payment network; the receipt is the facilitator's
    /// response bytes.
    Ach {
        /// Settlement reference from the facilitator (e.g. ACH trace id,
        /// SEPA end-to-end id).
        settlement_ref: String,
        auth: Vec<u8>,
    },
}

impl RailReceipt {
    /// One-line summary for human output.
    pub fn summary(&self) -> String {
        match self {
            RailReceipt::Native { ledger_entry } => {
                format!("native (ledger entry, {} bytes)", ledger_entry.len())
            }
            RailReceipt::Http402 { receipt } => {
                format!("http402 (receipt, {} bytes)", receipt.len())
            }
            RailReceipt::CardAcp { network, last4, .. } => {
                format!("card {network} •••• {last4}")
            }
            RailReceipt::Ach { settlement_ref, .. } => {
                format!("ach (ref: {settlement_ref})")
            }
        }
    }
}
