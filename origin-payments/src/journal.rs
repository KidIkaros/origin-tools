// SPDX-License-Identifier: Apache-2.0

//! Double-entry journal (design §4, §5).
//!
//! Every settled order posts a batch of ≥ 2 rows (debit + credit) whose
//! signed sum is exactly zero. Postings are hash-chained (each commits to
//! its predecessor) so the journal is append-only and tamper-evident; a
//! per-day root lands in the MMR via reconciliation (P5).
//!
//! Amounts are decimal strings and are only ever parsed to **integer
//! minor units** — never floats (Chapter 26 rule).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::PaymentStore;

/// Minor-unit scale for amounts: 2 decimals (cent-like).
pub const AMOUNT_SCALE: u8 = 2;

/// Scale for FX rates: 6 decimals (a rate like "0.9" = 900_000).
pub const RATE_SCALE: u8 = 6;

/// A declared FX rate: 1 unit of `from` = `rate` units of `to`.
/// The rate is a decimal string, parsed to [`RATE_SCALE`] minor units.
/// Recorded on every posting of an FX batch so the conversion is part of
/// the signed canonical bytes (audit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FxRate {
    pub from: String,
    pub to: String,
    pub rate: String,
    /// FX markup in basis points (1 bp = 0.01%). A markup of 50 means
    /// the merchant charges 0.50% above the mid-market rate. Signed as
    /// part of the order so the margin is auditable and non-repudiable.
    #[serde(default)]
    pub markup_bps: u32,
}

/// One leg of a possibly multi-currency (FX) batch: an account, an amount
/// in a specific currency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyLeg {
    pub account: Account,
    pub amount: String,
    pub currency: String,
}

/// Genesis hash for the first posting in the journal.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Debit or credit leg of a double-entry posting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Account {
    Debit,
    Credit,
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Account::Debit => "debit",
            Account::Credit => "credit",
        })
    }
}

impl std::str::FromStr for Account {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "debit" => Ok(Account::Debit),
            "credit" => Ok(Account::Credit),
            _ => Err(format!("unknown account: {s} (expected debit|credit)")),
        }
    }
}

/// One double-entry row. A batch always sums to zero and chains to the
/// previous posting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPosting {
    pub posting_id: String,
    pub batch_id: String,
    pub payment_order_id: String,
    pub account: Account,
    pub amount: String,
    pub currency: String,
    pub ts: String,
    /// Hash of the previous posting's canonical bytes (genesis = zeros).
    pub prev_hash: [u8; 32],
    /// Hybrid (Ed25519 + Falcon-1024) signature in the SDK `HybridSig` wire format.
    /// wire format, over [`posting_canonical`] — the canonical bytes
    /// never include the signature or signer fields themselves, so the
    /// chain hash is stable whether or not a posting is signed.
    pub signature: Option<Vec<u8>>,
    /// Signer public keys, embedded for offline verification (the
    /// origin-secrets pattern, same as orders/events).
    pub signer: Option<crate::identity::OrderSigner>,
    /// Declared FX rate for a multi-currency batch — part of the signed
    /// canonical bytes (the conversion is auditable). `None` for
    /// single-currency batches.
    #[serde(default)]
    pub fx_rate: Option<FxRate>,
}

/// Parse a decimal string into integer units at `scale` decimals (never a
/// float). Accepts "3", "3.1", "3.15"; rejects more than `scale` decimals
/// and empty or malformed input.
pub fn parse_decimal(s: &str, scale: u8) -> Result<i128> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::InvalidAmount(s.to_string()));
    }
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let mut parts = digits.split('.');
    let whole = parts.next().unwrap_or("");
    let frac = parts.next();
    if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidAmount(s.to_string()));
    }
    let frac = match frac {
        None => "",
        Some(f) => {
            if f.is_empty() || f.len() > scale as usize || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidAmount(s.to_string()));
            }
            f
        }
    };
    let whole_val = whole
        .parse::<i128>()
        .map_err(|_| Error::InvalidAmount(s.to_string()))?;
    let frac_val = if frac.is_empty() {
        0
    } else {
        frac.parse::<i128>()
            .map_err(|_| Error::InvalidAmount(s.to_string()))?
    };
    let padded = frac_val * 10i128.pow(scale as u32 - frac.len() as u32);
    let minor = whole_val * 10i128.pow(scale as u32) + padded;
    Ok(if neg { -minor } else { minor })
}

/// Parse a decimal string into integer minor units (never a float).
/// Accepts "3", "3.1", "3.15"; rejects more than [`AMOUNT_SCALE`]
/// decimals and empty or malformed input.
pub fn parse_amount(s: &str) -> Result<i128> {
    parse_decimal(s, AMOUNT_SCALE)
}

/// Parse an FX rate decimal string at [`RATE_SCALE`] decimals, e.g.
/// "0.9" -> 900_000.
pub fn parse_rate(s: &str) -> Result<i128> {
    parse_decimal(s, RATE_SCALE)
}

/// Format integer minor units back to a decimal string.
pub fn fmt_amount(minor: i128) -> String {
    let neg = minor < 0;
    let abs = minor.unsigned_abs();
    format!(
        "{}{}.{:02}",
        if neg { "-" } else { "" },
        abs / 100,
        abs % 100
    )
}

/// Append a balanced batch of postings for one order. The batch must have
/// ≥ 2 legs and its signed sum (debit +, credit −) must be zero; postings
/// are chained to the journal head. When `signer` is supplied, every
/// posting is hybrid-signed over its canonical bytes and the signer's
/// public keys are embedded for offline verification. Returns the batch id.
pub fn append_batch(
    store: &PaymentStore,
    payment_order_id: &str,
    currency: &str,
    legs: &[(Account, &str)],
    signer: Option<&crate::identity::OperatorKeys>,
) -> Result<String> {
    if legs.len() < 2 {
        return Err(Error::JournalNotBalanced {
            details: "a batch must have at least 2 legs".to_string(),
        });
    }
    // Signed sum: debit adds, credit subtracts. Must be exactly zero.
    let mut sum: i128 = 0;
    for (account, amount) in legs {
        let minor = parse_amount(amount)?;
        sum += match account {
            Account::Debit => minor,
            Account::Credit => -minor,
        };
    }
    if sum != 0 {
        return Err(Error::JournalNotBalanced {
            details: format!("sum = {}", fmt_amount(sum)),
        });
    }

    let batch_id = uuid::Uuid::new_v4().to_string();
    let ts = crate::now_rfc3339();
    let mut prev = store.journal_head()?;
    for (account, amount) in legs {
        let mut posting = LedgerPosting {
            posting_id: uuid::Uuid::new_v4().to_string(),
            batch_id: batch_id.clone(),
            payment_order_id: payment_order_id.to_string(),
            account: *account,
            amount: (*amount).to_string(),
            currency: currency.to_string(),
            ts: ts.clone(),
            prev_hash: prev,
            signature: None,
            signer: None,
            fx_rate: None,
        };
        sign_posting(&mut posting, signer)?;
        store.append_posting(&posting)?;
        prev = posting_hash(&posting);
    }
    Ok(batch_id)
}

/// Post an order's journal batch, dispatching on whether it carries an FX
/// conversion: plain single-currency [`append_batch`] when `fx` is `None`,
/// multi-currency [`append_fx_batch`] (two legs, converted at `fx.rate`)
/// when set. Returns the batch id.
pub fn append_order_batch(
    store: &PaymentStore,
    payment_order_id: &str,
    amount: &str,
    currency: &str,
    fx: Option<&FxRate>,
    signer: Option<&crate::identity::OperatorKeys>,
) -> Result<String> {
    match fx {
        Some(rate) => {
            // Debit the quoted currency, credit the settlement currency at
            // the declared rate (1 `from` = `rate` `to`). The fee/markup is
            // the operator-owned spread already embedded in `rate`. The
            // credit leg is the debit leg CONVERTED at the rate, so the
            // FX batch balances (as `append_fx_batch` requires).
            let from_minor = parse_amount(amount)?;
            let rate_minor = parse_rate(&rate.rate)?;
            let to_minor = from_minor * rate_minor / 10i128.pow(RATE_SCALE as u32);
            let to_amount = fmt_amount(to_minor);
            append_fx_batch(
                store,
                payment_order_id,
                &[
                    CurrencyLeg {
                        account: Account::Debit,
                        amount: amount.to_string(),
                        currency: rate.from.to_string(),
                    },
                    CurrencyLeg {
                        account: Account::Credit,
                        amount: to_amount,
                        currency: rate.to.to_string(),
                    },
                ],
                rate,
                signer,
            )
        }
        None => append_batch(
            store,
            payment_order_id,
            currency,
            &[(Account::Debit, amount), (Account::Credit, amount)],
            signer,
        ),
    }
}

/// Append a balanced **multi-currency** batch (FX conversion) for one
/// order. Legs may be denominated in `rate.from` or `rate.to`; the batch
/// is balanced when the two per-currency nets move in opposite directions
/// and the `to` net equals the `from` net converted at the declared rate
/// (within 1 minor unit of rounding). The rate is recorded on every
/// posting, so the conversion is part of the signed canonical bytes.
/// When `signer` is supplied, postings are hybrid-signed.
pub fn append_fx_batch(
    store: &PaymentStore,
    payment_order_id: &str,
    legs: &[CurrencyLeg],
    rate: &FxRate,
    signer: Option<&crate::identity::OperatorKeys>,
) -> Result<String> {
    if legs.len() < 2 {
        return Err(Error::JournalNotBalanced {
            details: "an FX batch must have at least 2 legs".to_string(),
        });
    }
    let mut from_net: i128 = 0;
    let mut to_net: i128 = 0;
    for leg in legs {
        let minor = parse_amount(&leg.amount)?;
        let signed = match leg.account {
            Account::Debit => minor,
            Account::Credit => -minor,
        };
        if leg.currency == rate.from {
            from_net += signed;
        } else if leg.currency == rate.to {
            to_net += signed;
        } else {
            return Err(Error::JournalNotBalanced {
                details: format!(
                    "leg in unexpected currency {} (batch is {} -> {})",
                    leg.currency, rate.from, rate.to
                ),
            });
        }
    }
    if from_net == 0 || to_net == 0 {
        return Err(Error::JournalNotBalanced {
            details: "FX batch must move money in both currencies".to_string(),
        });
    }
    if (from_net > 0) == (to_net > 0) {
        return Err(Error::JournalNotBalanced {
            details: "FX legs must move in opposite directions (from -> to)".to_string(),
        });
    }
    // The `to` net must equal the `from` net converted at the declared
    // rate, within 1 minor unit of rounding.
    let rate_minor = parse_rate(&rate.rate)?;
    if rate_minor <= 0 {
        return Err(Error::JournalNotBalanced {
            details: "FX rate must be positive".to_string(),
        });
    }
    let converted = (from_net.unsigned_abs() as i128) * rate_minor / 10i128.pow(RATE_SCALE as u32);
    let expected = to_net.unsigned_abs() as i128;
    if converted.abs_diff(expected) > 1 {
        return Err(Error::JournalNotBalanced {
            details: format!(
                "FX rate {}/{} does not balance the batch (converted {converted} vs {expected})",
                rate.from, rate.to
            ),
        });
    }

    let batch_id = uuid::Uuid::new_v4().to_string();
    let ts = crate::now_rfc3339();
    let mut prev = store.journal_head()?;
    for leg in legs {
        let mut posting = LedgerPosting {
            posting_id: uuid::Uuid::new_v4().to_string(),
            batch_id: batch_id.clone(),
            payment_order_id: payment_order_id.to_string(),
            account: leg.account,
            amount: leg.amount.clone(),
            currency: leg.currency.clone(),
            ts: ts.clone(),
            prev_hash: prev,
            signature: None,
            signer: None,
            fx_rate: Some(rate.clone()),
        };
        sign_posting(&mut posting, signer)?;
        store.append_posting(&posting)?;
        prev = posting_hash(&posting);
    }
    Ok(batch_id)
}

/// Hybrid-sign a posting over its canonical bytes and embed the signer's
/// public keys (canonical is computed before signing, so the signature
/// never covers itself and the chain hash is identical either way).
fn sign_posting(
    posting: &mut LedgerPosting,
    signer: Option<&crate::identity::OperatorKeys>,
) -> Result<()> {
    let Some(keys) = signer else {
        return Ok(());
    };
    let canonical = posting_canonical(posting);
    let sig = keys
        .bundle
        .try_sign_hybrid(&canonical)
        .map_err(|e| Error::CryptoError {
            details: e.to_string(),
        })?;
    let hybrid = origin_crypto_sdk::signing::wire::HybridSig::from_sig(&sig);
    let mut encoded = Vec::new();
    hybrid
        .encode(&mut encoded)
        .map_err(|e| Error::CryptoError {
            details: e.to_string(),
        })?;
    posting.signature = Some(encoded);
    posting.signer = Some(crate::identity::OrderSigner {
        ed_pk: keys.bundle.ed25519_pk().to_bytes(),
        falcon_pk: keys.bundle.falcon1024_pk().as_bytes().to_vec(),
        domain: crate::identity::PAYMENTS_DOMAIN.to_string(),
    });
    Ok(())
}

/// Verify a posting's hybrid signature against its embedded signer keys.
///
/// - `Ok(true)` — signature valid (or the posting is unsigned, in which
///   case the hash chain is the integrity guarantee);
/// - `Ok(false)` — signature invalid (tampered or wrong keys);
/// - `Err` — malformed signature blob.
pub fn verify_posting_signature(p: &LedgerPosting) -> Result<bool> {
    let (Some(sig_bytes), Some(signer)) = (&p.signature, &p.signer) else {
        return Ok(true);
    };
    let sig =
        origin_crypto_sdk::signing::wire::HybridSig::decode(sig_bytes, &mut 0).map_err(|e| {
            Error::CryptoError {
                details: format!("decoding posting signature: {e}"),
            }
        })?;
    Ok(sig
        .verify(&signer.ed_pk, &signer.falcon_pk, &posting_canonical(p))
        .is_ok())
}

/// Canonical bytes of a posting — the exact payload a hybrid signature
/// covers and the chain hashes. Explicit field list: the `signature` and
/// `signer` fields are NEVER part of the canonical bytes (a signature
/// must not cover itself, and the chain hash must be stable whether or
/// not a posting is signed).
pub fn posting_canonical(p: &LedgerPosting) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        p.posting_id,
        p.batch_id,
        p.payment_order_id,
        p.account,
        p.amount,
        p.currency,
        p.ts,
        p.prev_hash,
        p.fx_rate,
    ]))
    .unwrap_or_default()
}

/// The chain hash of a posting: SHA3-256 over its canonical bytes (SDK).
pub fn posting_hash(p: &LedgerPosting) -> [u8; 32] {
    origin_crypto_sdk::sha3_256(&posting_canonical(p))
}

/// Net per currency over a slice of postings: debits add, credits
/// subtract. Exposed for the status dashboard and `balance`.
pub fn net_by_currency(postings: &[LedgerPosting]) -> Vec<(String, i128)> {
    let mut nets: std::collections::BTreeMap<String, i128> = std::collections::BTreeMap::new();
    for p in postings {
        let Ok(minor) = parse_amount(&p.amount) else {
            continue;
        };
        let signed = match p.account {
            Account::Debit => minor,
            Account::Credit => -minor,
        };
        *nets.entry(p.currency.clone()).or_insert(0) += signed;
    }
    nets.into_iter().collect()
}

/// Net balance per currency from the journal: debits add, credits
/// subtract. With `account` set, only that leg is netted.
pub fn balance(store: &PaymentStore, account: Option<Account>) -> Result<Vec<(String, i128)>> {
    let postings = store.postings()?;
    let nets = match account {
        None => net_by_currency(&postings),
        Some(want) => {
            let filtered: Vec<LedgerPosting> =
                postings.into_iter().filter(|p| p.account == want).collect();
            net_by_currency(&filtered)
        }
    };
    Ok(nets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> PaymentStore {
        let dir = tempfile::tempdir().unwrap();
        PaymentStore::open(&dir.keep()).unwrap()
    }

    #[test]
    fn parse_amount_roundtrip() {
        assert_eq!(parse_amount("3.15").unwrap(), 315);
        assert_eq!(parse_amount("3").unwrap(), 300);
        assert_eq!(parse_amount("3.1").unwrap(), 310);
        assert_eq!(parse_amount("0.05").unwrap(), 5);
        assert_eq!(parse_amount("-3.15").unwrap(), -315);
        assert_eq!(fmt_amount(315), "3.15");
        assert_eq!(fmt_amount(-315), "-3.15");
        assert_eq!(fmt_amount(300), "3.00");
        assert_eq!(fmt_amount(5), "0.05");
    }

    #[test]
    fn parse_amount_rejects_bad_input() {
        for bad in ["", "abc", "3.155", "3..1", ".5", "-", "3.1.2", "1e3"] {
            assert!(parse_amount(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn unbalanced_batch_rejected_and_nothing_written() {
        let s = tmp_store();
        let err = append_batch(
            &s,
            "o1",
            "USD",
            &[(Account::Debit, "3.00"), (Account::Credit, "2.50")],
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::JournalNotBalanced { .. }));
        assert!(
            s.postings().unwrap().is_empty(),
            "nothing written on imbalance"
        );
    }

    #[test]
    fn single_leg_batch_rejected() {
        let s = tmp_store();
        let err = append_batch(&s, "o1", "USD", &[(Account::Debit, "3.00")], None).unwrap_err();
        assert!(matches!(err, Error::JournalNotBalanced { .. }));
    }

    #[test]
    fn balanced_batches_chain_and_net_to_zero() {
        let s = tmp_store();
        let batch = append_batch(
            &s,
            "o1",
            "USD",
            &[(Account::Debit, "3.15"), (Account::Credit, "3.15")],
            None,
        )
        .unwrap();
        let postings = s.postings().unwrap();
        assert_eq!(postings.len(), 2);
        assert_eq!(postings[0].prev_hash, GENESIS_HASH);
        assert_eq!(postings[1].prev_hash, posting_hash(&postings[0]));
        assert_eq!(postings[0].batch_id, batch);
        assert_eq!(postings[1].batch_id, batch);

        // A second batch chains to the first batch's last posting.
        append_batch(
            &s,
            "o2",
            "USD",
            &[(Account::Debit, "1.00"), (Account::Credit, "1.00")],
            None,
        )
        .unwrap();
        let postings = s.postings().unwrap();
        assert_eq!(postings.len(), 4);
        assert_eq!(postings[2].prev_hash, posting_hash(&postings[1]));

        let nets = balance(&s, None).unwrap();
        assert_eq!(nets, vec![("USD".to_string(), 0)]);
    }

    #[test]
    fn balance_nets_debits_minus_credits() {
        let s = tmp_store();
        append_batch(
            &s,
            "o1",
            "USD",
            &[(Account::Debit, "5.00"), (Account::Credit, "5.00")],
            None,
        )
        .unwrap();
        append_batch(
            &s,
            "o2",
            "USD",
            &[(Account::Debit, "0.50"), (Account::Credit, "0.50")],
            None,
        )
        .unwrap();

        let nets = balance(&s, None).unwrap();
        assert_eq!(nets, vec![("USD".to_string(), 0)]);

        let d = balance(&s, Some(Account::Debit)).unwrap();
        assert_eq!(d, vec![("USD".to_string(), 550)]);
        let c = balance(&s, Some(Account::Credit)).unwrap();
        assert_eq!(c, vec![("USD".to_string(), -550)]);
    }

    #[test]
    fn multi_currency_balance_groups_by_currency() {
        let s = tmp_store();
        append_batch(
            &s,
            "o1",
            "USD",
            &[(Account::Debit, "1.00"), (Account::Credit, "1.00")],
            None,
        )
        .unwrap();
        append_batch(
            &s,
            "o2",
            "EUR",
            &[(Account::Debit, "2.00"), (Account::Credit, "2.00")],
            None,
        )
        .unwrap();
        let nets = balance(&s, None).unwrap();
        assert_eq!(nets.len(), 2);
    }

    #[test]
    fn signed_postings_verify_and_tamper_breaks() {
        let s = tmp_store();
        // A throwaway identity (origin-secrets pattern): signing never
        // touches the real ~/.origin home.
        let dir = tempfile::tempdir().unwrap();
        let home = origin_common::OriginHome::with_root(dir.path().join("home")).unwrap();
        let _store = origin_common::IdentityStore::create(
            &home,
            "test-pass",
            origin_common::MemoryTier::Nano,
        )
        .unwrap();
        let keys = crate::identity::load_operator_keys_from(&home, "test-pass").unwrap();

        append_batch(
            &s,
            "o1",
            "USD",
            &[(Account::Debit, "3.15"), (Account::Credit, "3.15")],
            Some(&keys),
        )
        .unwrap();

        let postings = s.postings().unwrap();
        assert_eq!(postings.len(), 2);
        assert!(postings[0].signature.is_some(), "posting hybrid-signed");
        assert!(postings[0].signer.is_some());
        for p in &postings {
            assert!(verify_posting_signature(p).unwrap(), "signature valid");
        }

        // Tampering with the amount breaks the signature AND the chain.
        let mut tampered = postings[0].clone();
        tampered.amount = "9.99".to_string();
        assert_eq!(verify_posting_signature(&tampered).unwrap(), false);
        assert_ne!(posting_hash(&tampered), posting_hash(&postings[0]));

        // The canonical bytes never include the signature itself.
        let signed_canonical = posting_canonical(&postings[0]);
        let mut unsigned = postings[0].clone();
        unsigned.signature = None;
        unsigned.signer = None;
        assert_eq!(signed_canonical, posting_canonical(&unsigned));

        // Unsigned postings verify trivially (chain is the guarantee).
        assert!(verify_posting_signature(&unsigned).unwrap());
    }

    fn fx_rate() -> FxRate {
        FxRate {
            from: "USD".to_string(),
            to: "EUR".to_string(),
            rate: "0.9".to_string(),
            markup_bps: 0,
        }
    }

    #[test]
    fn fx_batch_balances_two_currencies_with_rate_on_postings() {
        let s = tmp_store();
        let rate = fx_rate();
        let batch = append_fx_batch(
            &s,
            "fx-1",
            &[
                CurrencyLeg {
                    account: Account::Credit,
                    amount: "100.00".into(),
                    currency: "USD".into(),
                },
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "90.00".into(),
                    currency: "EUR".into(),
                },
            ],
            &rate,
            None,
        )
        .unwrap();

        let postings = s.postings().unwrap();
        assert_eq!(postings.len(), 2);
        assert_eq!(postings[0].batch_id, batch);
        assert_eq!(postings[0].fx_rate, Some(rate.clone()));
        assert_eq!(postings[1].fx_rate, Some(rate));
        // Chain intact.
        assert_eq!(postings[1].prev_hash, posting_hash(&postings[0]));
        // Per-currency nets are meaningful (this IS the conversion).
        let nets = balance(&s, None).unwrap();
        assert_eq!(
            nets,
            vec![("EUR".to_string(), 9000), ("USD".to_string(), -10000)]
        );
    }

    #[test]
    fn fx_batch_rejects_rate_that_does_not_balance() {
        let s = tmp_store();
        let err = append_fx_batch(
            &s,
            "fx-1",
            &[
                CurrencyLeg {
                    account: Account::Credit,
                    amount: "100.00".into(),
                    currency: "USD".into(),
                },
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "95.00".into(),
                    currency: "EUR".into(),
                },
            ],
            &fx_rate(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::JournalNotBalanced { .. }));
        assert!(s.postings().unwrap().is_empty(), "nothing written");
    }

    #[test]
    fn fx_batch_rejects_third_currency_and_same_direction() {
        let s = tmp_store();
        // A leg in a currency outside the declared pair.
        let err = append_fx_batch(
            &s,
            "fx-1",
            &[
                CurrencyLeg {
                    account: Account::Credit,
                    amount: "100.00".into(),
                    currency: "USD".into(),
                },
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "90.00".into(),
                    currency: "EUR".into(),
                },
                CurrencyLeg {
                    account: Account::Credit,
                    amount: "1.00".into(),
                    currency: "GBP".into(),
                },
            ],
            &fx_rate(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::JournalNotBalanced { .. }));

        // Same-direction legs (no actual conversion).
        let err = append_fx_batch(
            &s,
            "fx-1",
            &[
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "100.00".into(),
                    currency: "USD".into(),
                },
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "90.00".into(),
                    currency: "EUR".into(),
                },
            ],
            &fx_rate(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::JournalNotBalanced { .. }));
        assert!(s.postings().unwrap().is_empty());
    }

    #[test]
    fn fx_batch_allows_fee_pair_in_one_currency() {
        let s = tmp_store();
        // Conversion plus a self-balancing FX fee pair in the from currency.
        let batch = append_fx_batch(
            &s,
            "fx-1",
            &[
                CurrencyLeg {
                    account: Account::Credit,
                    amount: "100.00".into(),
                    currency: "USD".into(),
                },
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "90.00".into(),
                    currency: "EUR".into(),
                },
                CurrencyLeg {
                    account: Account::Debit,
                    amount: "2.00".into(),
                    currency: "USD".into(),
                },
                CurrencyLeg {
                    account: Account::Credit,
                    amount: "2.00".into(),
                    currency: "USD".into(),
                },
            ],
            &fx_rate(),
            None,
        )
        .unwrap();
        assert_eq!(s.postings().unwrap().len(), 4);
        // The from-net is unchanged by the fee pair, so conversion still holds.
        assert_eq!(batch.len(), 36);
    }

    #[test]
    fn fx_rate_is_part_of_the_canonical_bytes() {
        let s = tmp_store();
        let mut rate = fx_rate();
        let legs = [
            CurrencyLeg {
                account: Account::Credit,
                amount: "100.00".into(),
                currency: "USD".into(),
            },
            CurrencyLeg {
                account: Account::Debit,
                amount: "90.00".into(),
                currency: "EUR".into(),
            },
        ];
        append_fx_batch(&s, "fx-1", &legs, &rate, None).unwrap();
        rate.rate = "0.91".to_string();
        // A different rate must produce different canonical bytes (audit).
        let mut other = s.postings().unwrap()[0].clone();
        other.fx_rate = Some(rate);
        assert_ne!(
            posting_canonical(&other),
            posting_canonical(&s.postings().unwrap()[0])
        );
        assert_ne!(
            posting_hash(&other),
            posting_hash(&s.postings().unwrap()[0])
        );
    }

    #[test]
    fn append_order_batch_dispatches_fx_vs_plain() {
        let s = tmp_store();
        // Plain: single-currency, balanced to zero.
        append_order_batch(&s, "o-plain", "10.00", "USD", None, None).unwrap();
        assert_eq!(balance(&s, None).unwrap(), vec![("USD".to_string(), 0)]);
        let postings = s.postings().unwrap();
        assert_eq!(postings.len(), 2);
        assert_eq!(postings[0].fx_rate, None);
        assert_eq!(postings[0].currency, "USD");

        // FX: credit leg is the debit leg converted at the rate, so the
        // two-currency batch balances inside `append_fx_batch`.
        let rate = fx_rate(); // USD -> EUR @ 0.9
        append_order_batch(&s, "o-fx", "10.00", "USD", Some(&rate), None).unwrap();

        let fx_postings = s
            .postings()
            .unwrap()
            .into_iter()
            .skip(2)
            .collect::<Vec<_>>();
        assert_eq!(fx_postings.len(), 2);
        assert_eq!(fx_postings[0].currency, "USD");
        assert_eq!(fx_postings[1].currency, "EUR");
        // 10.00 USD @ 0.9 -> 9.00 EUR
        assert_eq!(fx_postings[1].amount, "9.00");
        assert_eq!(fx_postings[0].fx_rate, Some(rate));
        // Per-currency nets (Debit=+): USD +1000, EUR -900.
        let nets = balance(&s, None).unwrap();
        assert_eq!(
            nets,
            vec![("EUR".to_string(), -900), ("USD".to_string(), 1000)]
        );
    }

    #[test]
    fn parse_rate_handles_six_decimals() {
        assert_eq!(parse_rate("0.9").unwrap(), 900_000);
        assert_eq!(parse_rate("1").unwrap(), 1_000_000);
        assert_eq!(parse_rate("0.123456").unwrap(), 123_456);
        assert!(
            parse_rate("0.1234567").is_err(),
            "more than 6 decimals rejected"
        );
        assert!(
            parse_rate("-1").is_ok(),
            "negative parsed (validated elsewhere)"
        );
    }
}
