// SPDX-License-Identifier: Apache-2.0

//! The **native rail seam** (INTEGRATION.md §4).
//!
//! Originally the wallet's native pay rail was the embedded `stoa` mesh:
//! `pay_native_with_credit` dialed the payee's node, opened a channel,
//! streamed a payment, and gossiped a signed ledger entry. That surface
//! now lives in the separate **stoa** project (which *uses* these
//! foundational crates), so `origin-wallet` no longer embeds or depends
//! on it.
//!
//! To let downstream origin-suite crates (notably `origin-payments`) keep
//! a native settlement rail without reaching into the external stoa
//! crate, this module defines a small **trait seam**:
//!
//! - [`NativeRail`] — the interface a downstream/offline consumer codes
//!   against. The external stoa project is expected to implement it for
//!   the real mesh rail later.
//! - [`LocalNativeRail`] — a **local, offline default**: enforces the
//!   spend cap + spend policy, debits the payer account, records an MMR
//!   transaction, and returns a self-contained [`NativeReceipt`]. No
//!   network, no peer address, no mesh.
//!
//! A payer/payee pair that reaches the same [receipt bytes][`NativeReceipt`]
//! can reconcile offline; a future mesh implementation carries the same
//! receipt shape.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressType, Network};
use crate::transaction::Transaction;
use crate::wallet::Wallet;
use crate::{Result, WalletError};

/// A boxed future returned by [`NativeRail::pay`] (keeps the trait
/// object-safe so down/offline crates can hold `&dyn NativeRail`).
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Parameters for one native-rail payment.
#[derive(Debug, Clone)]
pub struct NativePayParams {
    /// Counterparty node id (64 hex chars; a `MeshId`-shaped identifier).
    pub to: String,
    /// Amount in the smallest unit.
    pub amount: u64,
    /// Optional memo bytes (recorded on the receipt).
    pub memo: Vec<u8>,
    /// Optional per-transaction spend cap; refuse when `amount` exceeds it.
    pub spend_cap: Option<u64>,
    /// Optional standing credit toward the counterparty. The offline
    /// default ignores credit (there is no channel to size), but the seam
    /// keeps it for the mesh implementation.
    pub credit: Option<u64>,
}

/// A self-contained, serializable receipt of a native-rail payment.
///
/// The bytes of a receipt are the reconciliation evidence a payee (or an
/// offline observer) can verify against — the equivalence of the wire
/// `Vec<u8>` stored in a payment receipt (e.g. `RailReceipt::Native`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeReceipt {
    /// Counterparty node id the payment was addressed to.
    pub to: String,
    /// Amount paid, in the smallest unit.
    pub amount: u64,
    /// Hex-encoded memo.
    #[serde(default)]
    pub memo_hex: String,
    /// Transaction id (the MMR leaf hash hex).
    pub tx_id: String,
    /// RFC3339 timestamp when the payment was recorded.
    pub timestamp: String,
}

impl NativeReceipt {
    /// Serialize to the wire bytes carried by a payment receipt.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| WalletError::Transaction(e.to_string()))
    }

    /// Deserialize from wire bytes produced by [`NativeReceipt::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| WalletError::Transaction(format!("invalid native receipt bytes: {e}")))
    }
}

/// The native rail seam.
///
/// Downstream crates (`origin-payments`) settle against this trait; the
/// external **stoa** project implements it for the real mesh rail, and a
/// local default ([`LocalNativeRail`]) provides an offline, no-network
/// implementation today.
pub trait NativeRail {
    /// Pay `params.to` `params.amount` from `wallet`, returning a receipt.
    fn pay<'a>(
        &'a self,
        wallet: &'a mut Wallet,
        params: NativePayParams,
    ) -> BoxFuture<'a, Result<NativeReceipt>>;
}

/// A `MeshId`-shaped counterparty id → recipient `Address`.
fn recipient_address(to: &str) -> Address {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(to.as_bytes());
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&digest[..20]);
    Address::from_hash(hash, AddressType::Bech32, Network::Mainnet)
}

/// The offline default native rail: enforce caps + spend policy, debit
/// the payer's first account, record an MMR transaction, and return a
/// local receipt. No network, no peer address, no mesh.
#[derive(Debug, Default)]
pub struct LocalNativeRail;

impl LocalNativeRail {
    /// Pay through the offline rail synchronously-wrapped as the trait's
    /// boxed future.
    fn pay_sync(&self, wallet: &mut Wallet, params: NativePayParams) -> Result<NativeReceipt> {
        // Per-transaction spend cap (mirrors the original rail check).
        if let Some(cap) = params.spend_cap {
            if params.amount > cap {
                return Err(WalletError::Transaction(format!(
                    "amount {} exceeds spend cap {} (policy refusal)",
                    params.amount, cap
                )));
            }
        }
        // Standing wallet spend policy (day/month/per-tx).
        wallet.check_spend(params.amount)?;

        // Debit the payer's first account.
        let bal = wallet.get_balance(0)?;
        if bal < params.amount {
            return Err(WalletError::Transaction(format!(
                "insufficient funds: account 0 has {bal}, need {}",
                params.amount
            )));
        }
        wallet.update_balance(0, bal - params.amount)?;

        // Record an MMR transaction from the payer's address to a
        // deterministic address of the counterparty id.
        let from = wallet
            .accounts()
            .get(0)
            .map(|a| a.address().clone())
            .ok_or_else(|| WalletError::AccountNotFound("account 0 for native rail".into()))?;
        let to = recipient_address(&params.to);
        let tx = Transaction::new(&from, &to, params.amount, 0, wallet.transaction_count());
        wallet.add_transaction(&tx)?;
        // Count against the day/month spend buckets.
        wallet.record_spend(params.amount);

        // The MMR leaf hash is the transaction id on the receipt.
        let tx_id = {
            use sha2::{Digest, Sha256};
            let bytes =
                bincode::serialize(&tx).map_err(|e| WalletError::Transaction(e.to_string()))?;
            hex::encode(Sha256::digest(&bytes))
        };
        let receipt = NativeReceipt {
            to: params.to.clone(),
            amount: params.amount,
            memo_hex: hex::encode(&params.memo),
            tx_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        Ok(receipt)
    }
}

impl NativeRail for LocalNativeRail {
    fn pay<'a>(
        &'a self,
        wallet: &'a mut Wallet,
        params: NativePayParams,
    ) -> BoxFuture<'a, Result<NativeReceipt>> {
        Box::pin(async move { self.pay_sync(wallet, params) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Wallet;

    #[test]
    fn local_rail_records_payment_and_receipt_roundtrips() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        wallet.derive_account(0).unwrap();
        wallet.update_balance(0, 1_000).unwrap();

        let rail = LocalNativeRail;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let receipt = rt
            .block_on(rail.pay(
                &mut wallet,
                NativePayParams {
                    to: hex::encode([0xAB; 32]),
                    amount: 420,
                    memo: b"hello".to_vec(),
                    spend_cap: Some(1_000),
                    credit: None,
                },
            ))
            .unwrap();

        // The wallet moved value + recorded an MMR leaf + counted spend.
        assert_eq!(wallet.get_balance(0).unwrap(), 580);
        assert_eq!(wallet.transaction_count(), 1);
        assert_eq!(receipt.amount, 420);
        assert_eq!(receipt.memo_hex, hex::encode(b"hello"));

        // Receipt bytes round-trip.
        let bytes = receipt.to_bytes().unwrap();
        let back = NativeReceipt::from_bytes(&bytes).unwrap();
        assert_eq!(back, receipt);
    }

    #[test]
    fn local_rail_enforces_cap_and_insufficient_funds() {
        let mut wallet = Wallet::create("p").unwrap();
        wallet.derive_account(0).unwrap();
        wallet.update_balance(0, 100).unwrap();

        let rail = LocalNativeRail;
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Cap refusal.
        let cap_err = rt
            .block_on(rail.pay(
                &mut wallet,
                NativePayParams {
                    to: hex::encode([0xAA; 32]),
                    amount: 200,
                    memo: vec![],
                    spend_cap: Some(100),
                    credit: None,
                },
            ))
            .unwrap_err();
        assert!(cap_err.to_string().contains("spend cap"));

        // Insufficient funds.
        let funds_err = rt
            .block_on(rail.pay(
                &mut wallet,
                NativePayParams {
                    to: hex::encode([0xBB; 32]),
                    amount: 150,
                    memo: vec![],
                    spend_cap: None,
                    credit: None,
                },
            ))
            .unwrap_err();
        assert!(funds_err.to_string().contains("insufficient funds"));
    }
}
