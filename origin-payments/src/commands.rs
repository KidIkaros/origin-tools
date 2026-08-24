// SPDX-License-Identifier: Apache-2.0

//! CLI command handlers: wire clap args to the store, status machine,
//! identity signing, executor, reconciliation, custody, and audit.

use std::path::Path;

use serde_json::json;

use crate::cli::{
    AuditExportArgs, Cli, Commands, CompletionsArgs, DeferredCommitArgs, DeferredInspectArgs,
    DeferredListArgs, ExecutorRunArgs, InitArgs, KeysBackupArgs, KeysRecoverArgs, OrderCreateArgs,
    PspConfigureArgs, ReconcileExportArgs, ReconcilePullArgs, SettlementExportArgs,
    WebhookListenArgs,
};
use crate::error::{Error, Result};
use crate::event::{OrderDirection, OrderStatus, PaymentEvent, PaymentOrder};
use crate::identity;
use crate::journal::{self, Account};
use crate::rails::RailHint;
use crate::store::{InsertOutcome, PaymentStore, PaymentsConfig};
use crate::{audit, custody, executor, reconcile, twofa, vault};

/// Dispatch a parsed CLI to the matching handler.
pub fn dispatch(cli: Cli, root: &Path) -> Result<()> {
    let store = PaymentStore::open(root)?;
    let json = cli.json;
    let passphrase_file = cli.passphrase_file.as_deref().and_then(|p| p.to_str());
    match cli.command {
        Commands::Init(args) => cmd_init(&store, &args, json),
        Commands::OrderCreate(args) => cmd_order_create(&store, &args, passphrase_file, json),
        Commands::OrderStatus(args) => cmd_order_status(&store, &args.payment_order_id, json),
        Commands::OrderRetry(args) => cmd_order_retry(&store, &args.payment_order_id, json),
        Commands::VerifyOrder(args) => cmd_verify_order(&store, &args.payment_order_id, json),
        Commands::OrderResume(args) => cmd_order_resume(&store, &args.payment_order_id, json),
        Commands::ExecutorRun(args) => cmd_executor_run(&store, &args, passphrase_file, json),
        Commands::JournalBalance(args) => {
            cmd_journal_balance(&store, args.account.as_deref(), json)
        }
        Commands::JournalExport(args) => cmd_journal_export(&store, args.from.as_deref(), json),
        Commands::SettlementExport(args) => cmd_settlement_export(&store, &args, json),
        Commands::ReconcilePull(args) => cmd_reconcile_pull(&store, &args, json),
        Commands::ReconcileRun(args) => cmd_reconcile_run(&store, args.date.as_deref(), json),
        Commands::ReconcileExport(args) => cmd_reconcile_export(&store, &args, json),
        Commands::ReconcileList(_) => cmd_reconcile_list(&store, json),
        Commands::DlqList(_) => cmd_dlq_list(&store, json),
        Commands::DlqRequeue(args) => cmd_order_retry(&store, &args.payment_order_id, json),
        Commands::NotificationsList(_) => cmd_notifications_list(&store, json),
        Commands::PspConfigure(args) => cmd_psp_configure(&store, &args, json),
        Commands::KeysBackup(args) => cmd_keys_backup(&store, &args, passphrase_file, json),
        Commands::KeysRecover(args) => cmd_keys_recover(&store, &args, passphrase_file, json),
        Commands::Admin2faInit(_) => cmd_admin_2fa_init(&store, json),
        Commands::AuditShow(args) => cmd_audit_show(&store, args.filter_key.as_deref(), json),
        Commands::AuditVerify(_) => cmd_audit_verify(&store, json),
        Commands::AuditExport(args) => cmd_audit_export(&store, &args, json),
        Commands::DeferredList(args) => cmd_deferred_list(&store, &args, json),
        Commands::DeferredCommit(args) => cmd_deferred_commit(&store, &args, json),
        Commands::DeferredInspect(args) => cmd_deferred_inspect(&store, &args, json),
        Commands::WebhookListen(args) => cmd_webhook_listen(&store, &args),
        Commands::Status(_) => cmd_status(&store, json),
        Commands::Completions(args) => cmd_completions(&args),
    }
}

/// One-glance ops dashboard (P7 QoL).
fn cmd_status(store: &PaymentStore, json: bool) -> Result<()> {
    let report = crate::status::build(store);
    if json {
        return emit(
            json,
            serde_json::to_value(&report).map_err(|e| Error::IoError {
                details: format!("serializing status: {e}"),
            })?,
        );
    }
    println!("payments root : {}", report.root);
    if !report.initialized {
        println!("state        : NOT INITIALIZED (run `init` first)");
        return Ok(());
    }
    if let Some(c) = &report.config {
        println!("currency      : {}", c.currency);
        println!("rails         : {}", c.enabled_rails.join(", "));
        match &c.per_tx_cap {
            Some(cap) => println!("per-tx cap    : {cap}"),
            None => println!("per-tx cap    : (unset)"),
        }
    }
    let o = &report.orders;
    println!(
        "orders        : {} total ({} NOT_STARTED, {} EXECUTING, {} SUCCESS, {} FAILED, {} REQUIRES_ACTION)",
        o.not_started + o.executing + o.success + o.failed + o.requires_action,
        o.not_started,
        o.executing,
        o.success,
        o.failed,
        o.requires_action
    );
    println!(
        "retries       : {} due of {} jobs; DLQ {} records",
        report.retries_due, report.retry_jobs, report.dlq
    );
    let nets: Vec<String> = report
        .journal_net
        .iter()
        .map(|(c, n)| format!("{c}: {}", journal::fmt_amount(*n)))
        .collect();
    println!(
        "journal       : {} postings, net {}",
        report.journal_postings,
        if nets.is_empty() {
            "(empty)".to_string()
        } else {
            nets.join(", ")
        }
    );
    match &report.last_reconcile {
        Some(r) => println!(
            "reconcile     : last {} ({}) — {} matches / {} mismatches ({:?})",
            r.date, r.run_id, r.matches, r.mismatches, r.status
        ),
        None => println!("reconcile     : (none yet)"),
    }
    match report.audit_chain_valid {
        Some(true) => println!(
            "audit         : {} entries, chain VALID",
            report.audit_entries
        ),
        Some(false) => println!(
            "audit         : {} entries, chain BROKEN",
            report.audit_entries
        ),
        None => println!("audit         : (none)"),
    }
    println!("notifications : {}", report.notifications);
    println!(
        "admin         : 2FA {}{}",
        if report.twofa_configured {
            "configured"
        } else {
            "not configured"
        },
        if report.custody_vault {
            ", custody vault present"
        } else {
            ", custody vault absent"
        }
    );
    Ok(())
}

// ── deferred settlement (P10) ─────────────────────────────────────────

/// List pending deferred-settlement commitments.
fn cmd_deferred_list(store: &PaymentStore, args: &DeferredListArgs, json: bool) -> Result<()> {
    let items = store.deferred_commitments()?;
    let filtered: Vec<_> = match &args.date {
        Some(date) => items
            .into_iter()
            .filter(|i| i.resource_url.contains(date))
            .collect(),
        None => items,
    };
    if json {
        return emit(
            json,
            serde_json::to_value(&filtered).map_err(|e| Error::IoError {
                details: format!("serializing deferred commitments: {e}"),
            })?,
        );
    }
    if filtered.is_empty() {
        println!("No pending deferred commitments.");
    } else {
        println!("{} pending deferred commitment(s):", filtered.len());
        for item in &filtered {
            println!(
                "  {} {} {} (resource: {})",
                item.payment_order_id, item.amount, item.currency, item.resource_url
            );
        }
    }
    Ok(())
}

/// Commit pending deferred commitments into a daily batch.
fn cmd_deferred_commit(store: &PaymentStore, args: &DeferredCommitArgs, json: bool) -> Result<()> {
    let date_owned = args
        .date
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let batch = crate::settle::commit_deferred_batch(store, &date_owned)?;
    if json {
        return emit(
            json,
            serde_json::to_value(&batch).map_err(|e| Error::IoError {
                details: format!("serializing deferred batch: {e}"),
            })?,
        );
    }
    if batch.items.is_empty() {
        println!("No pending commitments to commit for {date_owned}.");
    } else {
        println!(
            "Committed {} item(s) into batch {} (total: {} minor units, hash: {})",
            batch.items.len(),
            batch.batch_id,
            batch.total_minor,
            hex::encode(batch.content_hash),
        );
    }
    Ok(())
}

/// Inspect a committed deferred batch.
fn cmd_deferred_inspect(
    store: &PaymentStore,
    args: &DeferredInspectArgs,
    json: bool,
) -> Result<()> {
    let path = store.root().join(crate::settle::batch_path(&args.batch_id));
    if !path.exists() {
        return Err(Error::OrderNotFound {
            payment_order_id: args.batch_id.clone(),
        });
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })?;
    let batch: crate::settle::DeferredBatch =
        serde_json::from_str(&raw).map_err(|e| Error::StoreCorrupted {
            details: format!("parsing deferred batch: {e}"),
        })?;
    if json {
        return emit(
            json,
            serde_json::to_value(&batch).map_err(|e| Error::IoError {
                details: format!("serializing deferred batch: {e}"),
            })?,
        );
    }
    println!("Batch: {}", batch.batch_id);
    println!("Date: {}", batch.date);
    println!("Created: {}", batch.created_at);
    println!("Total: {} minor units", batch.total_minor);
    println!("Content hash: {}", hex::encode(batch.content_hash));
    println!("Items ({}):", batch.items.len());
    for item in &batch.items {
        println!(
            "  {} {} {} (resource: {})",
            item.payment_order_id, item.amount, item.currency, item.resource_url
        );
    }
    // Verify the content hash.
    let expected = crate::settle::batch_content_hash(&batch.items, &batch.date);
    if expected == batch.content_hash {
        println!("\nContent hash: VALID");
    } else {
        println!(
            "\nContent hash: MISMATCH (expected {})",
            hex::encode(expected)
        );
    }
    Ok(())
}

// ── webhook listener ───────────────────────────────────────────────────

/// Start the webhook listener for async settlement callbacks.
fn cmd_webhook_listen(store: &PaymentStore, args: &WebhookListenArgs) -> Result<()> {
    crate::webhook::listen(&args.addr, store)
}

/// Shell completions (matches origin-secrets).
fn cmd_completions(args: &CompletionsArgs) -> Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(())
}

/// Print the JSON success payload when `--json` is set.
fn emit(json: bool, value: serde_json::Value) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| Error::IoError {
                details: format!("serializing output: {e}")
            })?
        );
    }
    Ok(())
}

/// Resolve the passphrase when a source is available: `-p` file, or an
/// interactive TTY prompt. Non-interactive runs without `-p` get `None`
/// (orders stay unsigned rather than blocking).
fn maybe_passphrase(passphrase_file: Option<&str>) -> Result<Option<String>> {
    use std::io::IsTerminal;
    match passphrase_file {
        Some(p) => origin_common::resolve_passphrase(Some(p))
            .map(Some)
            .map_err(|e| Error::WalletError {
                details: format!("passphrase: {e}"),
            }),
        None if std::io::stdin().is_terminal() => origin_common::resolve_passphrase(None)
            .map(Some)
            .map_err(|e| Error::WalletError {
                details: format!("passphrase: {e}"),
            }),
        None => Ok(None),
    }
}

/// Gate an admin command behind TOTP 2FA (P7).
fn require_totp(store: &PaymentStore, code: Option<&str>) -> Result<()> {
    let code = code.ok_or(Error::TwofaRequired)?;
    if !twofa::verify(store.root(), code)? {
        return Err(Error::TwofaInvalid);
    }
    Ok(())
}

// ── init ──────────────────────────────────────────────────────────────

fn cmd_init(store: &PaymentStore, args: &InitArgs, json: bool) -> Result<()> {
    if store.config_path().exists() {
        if !args.force {
            return Err(Error::AlreadyInitialized(store.config_path()));
        }
        std::fs::remove_file(store.config_path()).map_err(|e| Error::IoError {
            details: format!("removing {}: {e}", store.config_path().display()),
        })?;
    }
    if let Some(cap) = &args.per_tx_cap {
        journal::parse_amount(cap)?; // validate early
    }
    let config = PaymentsConfig {
        currency: args.currency.clone(),
        per_tx_cap: args.per_tx_cap.clone(),
        executing_ttl_secs: args.executing_ttl,
        ..PaymentsConfig::default()
    };
    store.write_config(&config)?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "init",
                "root": store.root().display().to_string(),
                "currency": config.currency,
                "per_tx_cap": config.per_tx_cap,
                "executing_ttl_secs": config.executing_ttl_secs
            }),
        )
    } else {
        println!("Payments root initialized: {}", store.root().display());
        println!("Currency: {}", config.currency);
        if let Some(cap) = &config.per_tx_cap {
            println!("Per-tx cap: {cap}");
        }
        println!("EXECUTING TTL: {}s", config.executing_ttl_secs);
        Ok(())
    }
}

// ── order create (signed + encrypted when an identity is available) ───

fn cmd_order_create(
    store: &PaymentStore,
    args: &OrderCreateArgs,
    passphrase_file: Option<&str>,
    json: bool,
) -> Result<()> {
    // Validate the amount early — strings, never floats (Chapter 26).
    let amount_minor = journal::parse_amount(&args.amount)?;
    if amount_minor <= 0 {
        return Err(Error::InvalidAmount(format!(
            "amount must be positive, got {}",
            args.amount
        )));
    }

    let rail = match args.rail.as_deref() {
        None => None,
        Some(r) => Some(
            r.parse::<RailHint>()
                .map_err(|e| Error::IoError { details: e })?,
        ),
    };
    // FX conversion: all three of --fx-from/--fx-to/--fx-rate must be
    // given together, and the rate must parse (P9).
    let fx = match (&args.fx_from, &args.fx_to, &args.fx_rate) {
        (Some(from), Some(to), Some(rate)) => {
            if from == to {
                return Err(Error::IoError {
                    details: "--fx-from and --fx-to must differ".to_string(),
                });
            }
            journal::parse_rate(rate)?;
            Some(journal::FxRate {
                from: from.clone(),
                to: to.clone(),
                rate: rate.clone(),
                markup_bps: args.fx_markup,
            })
        }
        (None, None, None) => None,
        _ => {
            return Err(Error::IoError {
                details: "--fx-from, --fx-to, and --fx-rate must be given together".to_string(),
            })
        }
    };
    // Card tokenization: all three --card-* args or none. Providing them
    // implies the card rail (a token has no other rail).
    let card = match (&args.card_token, &args.card_network, &args.card_last4) {
        (Some(token), Some(network), Some(last4)) => {
            if let Some(r) = &rail {
                if *r != RailHint::Card {
                    return Err(Error::IoError {
                        details: "--card-* requires --rail card (or omit --rail)".to_string(),
                    });
                }
            }
            Some((token.clone(), network.clone(), last4.clone()))
        }
        (None, None, None) => None,
        _ => {
            return Err(Error::IoError {
                details: "--card-token, --card-network, and --card-last4 must be given together"
                    .to_string(),
            })
        }
    };
    let mut order = PaymentOrder::new(&args.checkout, &args.to, &args.amount, &args.currency);
    order.fx = fx;
    order.rail = if card.is_some() {
        Some(RailHint::Card)
    } else {
        rail
    };
    if let Some((token, network, last4)) = card {
        order.card_token = Some(token);
        order.card_network = Some(network);
        order.card_last4 = Some(last4);
    }
    if args.payout {
        order.direction = OrderDirection::Payout;
    }

    // P2: hybrid-sign with the operator identity when a passphrase is
    // available. No identity = unsigned order (warned below).
    let mut identity = None;
    if let Some(passphrase) = maybe_passphrase(passphrase_file)? {
        match identity::load_operator_keys(&passphrase) {
            Ok(keys) => identity = Some(keys),
            Err(Error::IdentityNotFound) => { /* warned below */ }
            Err(e) => return Err(e),
        }
    }
    let signed = identity.is_some();
    if let Some(keys) = &identity {
        identity::sign_order(&mut order, keys)?;
    }

    match store.insert_order(&order)? {
        InsertOutcome::Inserted => {
            let buyer = args.buyer.clone().unwrap_or_else(|| "buyer".to_string());
            let seller = args
                .seller
                .clone()
                .unwrap_or_else(|| "merchant".to_string());
            let mut event = PaymentEvent::new(&args.checkout, &buyer, &seller, vec![order.clone()]);
            if let Some(keys) = &identity {
                identity::sign_event(&mut event, keys)?;
                let envelope = identity::encrypt_event(&event, keys)?;
                event.envelope = Some(envelope);
            }
            store.append_event(&event)?;
            audit::record(
                store,
                audit::AT_ORDER_CREATED,
                json!({
                    "order": order.payment_order_id,
                    "checkout": order.checkout_id,
                    "amount": order.amount,
                    "currency": order.currency,
                    "direction": order.direction.to_string(),
                    "signed": signed,
                }),
                identity.as_ref(),
            )?;
            if json {
                emit(
                    json,
                    json!({
                        "ok": true,
                        "command": "order_create",
                        "payment_order_id": order.payment_order_id,
                        "event_id": event.event_id,
                        "checkout_id": order.checkout_id,
                        "status": order.status.to_string(),
                        "direction": order.direction.to_string(),
                        "signed": signed,
                        "encrypted": event.envelope.is_some()
                    }),
                )
            } else {
                println!("Order created: {}", order.payment_order_id);
                println!("  event    : {}", event.event_id);
                println!("  checkout : {}", order.checkout_id);
                println!("  to       : {}", order.to);
                println!("  amount   : {} {}", order.amount, order.currency);
                println!("  status   : {}", order.status);
                println!("  direction: {}", order.direction);
                if signed {
                    println!("  signed   : Ed25519 + Falcon-1024 (operator identity)");
                } else {
                    println!("  warning  : order unsigned (no operator identity / passphrase)");
                }
                Ok(())
            }
        }
        InsertOutcome::Replay(existing) => {
            if json {
                emit(
                    json,
                    json!({
                        "ok": true,
                        "command": "order_create",
                        "replay": true,
                        "payment_order_id": existing.payment_order_id,
                        "status": existing.status.to_string()
                    }),
                )
            } else {
                println!(
                    "Order already exists (idempotent replay): {}",
                    existing.payment_order_id
                );
                println!("  status   : {}", existing.status);
                Ok(())
            }
        }
    }
}

// ── order status / verify / retry / resume ────────────────────────────

fn cmd_order_status(store: &PaymentStore, payment_order_id: &str, json: bool) -> Result<()> {
    let order = store.get_order(payment_order_id)?;
    if json {
        emit(
            json,
            serde_json::to_value(&order).map_err(|e| Error::IoError {
                details: format!("serializing order: {e}"),
            })?,
        )
    } else {
        println!("Order: {}", order.payment_order_id);
        println!("  status   : {}", order.status);
        println!("  direction: {}", order.direction);
        println!("  to       : {}", order.to);
        println!("  amount   : {} {}", order.amount, order.currency);
        println!("  attempts : {}", order.attempts);
        println!("  created  : {}", order.created_at);
        println!("  updated  : {}", order.updated_at);
        if let Some(nra) = &order.next_retry_at {
            println!("  retry at : {nra}");
        }
        if order.signer.is_some() {
            println!("  signed   : hybrid (Ed25519 + Falcon-1024)");
        }
        if let Some(r) = &order.receipt {
            println!("  receipt  : {}", r.summary());
        }
        Ok(())
    }
}

fn cmd_verify_order(store: &PaymentStore, payment_order_id: &str, json: bool) -> Result<()> {
    let order = store.get_order(payment_order_id)?;
    match order.signer.as_ref() {
        None => {
            if json {
                emit(
                    json,
                    json!({
                        "ok": true,
                        "command": "verify_order",
                        "payment_order_id": payment_order_id,
                        "signed": false
                    }),
                )?;
            } else {
                println!(
                    "Order {} is unsigned (created without an operator identity)",
                    payment_order_id
                );
            }
            Ok(())
        }
        Some(_) => {
            let valid = identity::verify_order(&order)?;
            if !valid {
                return Err(Error::SignatureFailed {
                    details: format!(
                        "order {payment_order_id}: hybrid signature invalid or tampered"
                    ),
                });
            }
            if json {
                emit(
                    json,
                    json!({
                        "ok": true,
                        "command": "verify_order",
                        "payment_order_id": payment_order_id,
                        "signed": true,
                        "verified": true
                    }),
                )?;
            } else {
                println!(
                    "✓ Order {}: hybrid signature valid (Ed25519 + Falcon-1024)",
                    payment_order_id
                );
            }
            Ok(())
        }
    }
}

fn cmd_order_retry(store: &PaymentStore, payment_order_id: &str, json: bool) -> Result<()> {
    let mut order = store.get_order(payment_order_id)?;
    // FAILED -> NOT_STARTED: the DLQ/retry requeue path (design §4.3).
    order.transition(OrderStatus::NotStarted)?;
    order.next_retry_at = None;
    order.attempts += 1;
    store.update_order(&order)?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "order_retry",
                "payment_order_id": order.payment_order_id,
                "status": order.status.to_string(),
                "attempts": order.attempts
            }),
        )
    } else {
        println!("Order requeued: {}", order.payment_order_id);
        println!("  status   : {}", order.status);
        println!("  attempts : {}", order.attempts);
        Ok(())
    }
}

fn cmd_order_resume(store: &PaymentStore, payment_order_id: &str, json: bool) -> Result<()> {
    let mut order = store.get_order(payment_order_id)?;
    // REQUIRES_ACTION -> NOT_STARTED: the operator / rail webhook resolved
    // the pending action, so the order re-enters the ready queue and the
    // NEXT executor pass settles it. (Going to EXECUTING would strand it —
    // the executor picks up NOT_STARTED + due retries, not EXECUTING, which
    // is only returned to the queue by the crash-recovery TTL sweep.)
    order.transition(OrderStatus::NotStarted)?;
    order.next_retry_at = None;
    store.update_order(&order)?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "order_resume",
                "payment_order_id": order.payment_order_id,
                "status": order.status.to_string()
            }),
        )
    } else {
        println!(
            "Order resumed: {} (NOT_STARTED — next executor pass settles it)",
            order.payment_order_id
        );
        Ok(())
    }
}

// ── executor ──────────────────────────────────────────────────────────

fn cmd_executor_run(
    store: &PaymentStore,
    args: &ExecutorRunArgs,
    passphrase_file: Option<&str>,
    json: bool,
) -> Result<()> {
    let wallet_path = args
        .wallet
        .as_deref()
        .ok_or_else(|| Error::RailUnavailable {
            rail: "native".to_string(),
            details: "--wallet <PATH> is required for the native rail".to_string(),
        })?;
    // --peer-addr is only needed when a ready order rides the native rail
    // (the executor refuses a native settle without it); http402/card
    // passes run fine without one.
    let peer_addr = match args.peer_addr.as_deref() {
        Some(a) => Some(
            a.parse::<std::net::SocketAddr>()
                .map_err(|e| Error::RailUnavailable {
                    rail: "native".to_string(),
                    details: format!("bad --peer-addr: {e}"),
                })?,
        ),
        None => None,
    };
    // Non-interactive runs need -p/--passphrase-file: fail with a clear
    // hint instead of letting the hidden-input prompt die obscurely.
    use std::io::IsTerminal;
    let passphrase = match passphrase_file {
        Some(p) => origin_common::resolve_passphrase(Some(p)).map_err(|e| Error::WalletError {
            details: format!("passphrase: {e}"),
        })?,
        None if std::io::stdin().is_terminal() => {
            origin_common::resolve_passphrase(None).map_err(|e| Error::WalletError {
                details: format!("passphrase: {e}"),
            })?
        }
        None => {
            return Err(Error::WalletError {
                details: "no passphrase source: pass -p/--passphrase-file <FILE> when running \
                          non-interactively (stdin is not a TTY)"
                    .to_string(),
            })
        }
    };

    // Optional standing credit line toward the payee on the native rail
    // (decimal string in minor units) — pre-funds the channel so several
    // orders settle against one ENTRY_OPEN limit.
    let peer_credit = match &args.peer_credit {
        Some(s) => {
            let minor = journal::parse_amount(s).map_err(|_| Error::WalletError {
                details: format!("bad --peer-credit '{s}' (expected a decimal amount, e.g. 25.00)"),
            })?;
            if minor < 0 {
                return Err(Error::WalletError {
                    details: "--peer-credit must be non-negative".to_string(),
                });
            }
            Some(minor as u64)
        }
        None => None,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::IoError {
            details: format!("building runtime: {e}"),
        })?;
    // Parse the optional compliance rule into a scorer.
    let compliance_scorer: Option<Box<dyn crate::compliance::ComplianceScorer>> =
        match &args.compliance_rule {
            Some(json_str) => {
                let v: serde_json::Value = serde_json::from_str(json_str)
                    .map_err(|e| Error::InvalidAmount(format!("bad compliance-rule JSON: {e}")))?;
                let flag = v
                    .get("flag_threshold_minor")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::MAX) as i128;
                let reject = v
                    .get("reject_threshold_minor")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::MAX) as i128;
                let allowed = v
                    .get("allowed_counterparties")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    });
                Some(Box::new(crate::compliance::RuleBasedScorer {
                    flag_threshold_minor: flag,
                    reject_threshold_minor: reject,
                    allowed_counterparties: allowed,
                }))
            }
            None => None,
        };
    let compliance_ref: Option<&dyn crate::compliance::ComplianceScorer> =
        compliance_scorer.as_deref();
    let summary = rt.block_on(executor::run_once(
        store,
        wallet_path,
        &passphrase,
        peer_addr,
        peer_credit,
        compliance_ref,
    ))?;

    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "executor_run",
                "once": args.once,
                "ready": summary.ready,
                "executed": summary.executed,
                "retried": summary.retried,
                "recovered": summary.recovered,
                "note": summary.note
            }),
        )?;
    } else {
        println!("Executor pass complete:");
        println!("  ready    : {}", summary.ready);
        println!("  executed : {}", summary.executed);
        println!("  retried  : {}", summary.retried);
        println!("  recovered: {}", summary.recovered);
        println!("  note     : {}", summary.note);
    }
    Ok(())
}

// ── journal ───────────────────────────────────────────────────────────

fn cmd_journal_balance(store: &PaymentStore, account: Option<&str>, json: bool) -> Result<()> {
    let account = match account {
        Some(a) => Some(
            a.parse::<Account>()
                .map_err(|e| Error::IoError { details: e })?,
        ),
        None => None,
    };
    let nets = journal::balance(store, account)?;
    if json {
        let rows: Vec<_> = nets
            .iter()
            .map(|(c, n)| {
                json!({
                    "currency": c,
                    "minor_units": n,
                    "amount": journal::fmt_amount(*n)
                })
            })
            .collect();
        emit(
            json,
            json!({"ok": true, "command": "journal_balance", "balances": rows}),
        )
    } else {
        for (c, n) in &nets {
            println!("{c}: {} ({} minor units)", journal::fmt_amount(*n), n);
        }
        if nets.is_empty() {
            println!("(journal empty)");
        }
        Ok(())
    }
}

fn cmd_journal_export(store: &PaymentStore, from: Option<&str>, json: bool) -> Result<()> {
    let postings = store.postings()?;
    let filtered: Vec<_> = match from {
        Some(d) => postings
            .into_iter()
            .filter(|p| p.ts.as_str() >= d)
            .collect(),
        None => postings,
    };
    if json {
        emit(
            json,
            serde_json::to_value(&filtered).map_err(|e| Error::IoError {
                details: format!("serializing journal: {e}"),
            })?,
        )
    } else {
        for p in &filtered {
            println!(
                "{}  {:6}  {:>8} {}  batch={}  order={}",
                p.ts, p.account, p.amount, p.currency, p.batch_id, p.payment_order_id
            );
        }
        println!("{} postings", filtered.len());
        Ok(())
    }
}

// ── settlement export (P9) / reconciliation (P5) ──────────────────────

fn cmd_settlement_export(
    store: &PaymentStore,
    args: &SettlementExportArgs,
    json: bool,
) -> Result<()> {
    let date = args
        .date
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let files = reconcile::export_per_currency(store, &args.rail, &date)?;
    if json {
        let out: Vec<_> = files
            .iter()
            .map(|f| {
                json!({
                    "date": f.date,
                    "currency": f.currency,
                    "rail": f.rail,
                    "rows": f.rows.len(),
                    "content_hash": f.content_hash
                })
            })
            .collect();
        emit(
            json,
            json!({
                "ok": true,
                "command": "settlement_export",
                "date": date,
                "rail": args.rail,
                "files": out
            }),
        )
    } else if files.is_empty() {
        println!("No settled orders for {date} — no settlement files written.");
        Ok(())
    } else {
        for f in &files {
            println!(
                "{}  {}  {} rows  stamp {}",
                date,
                if f.currency.is_empty() {
                    "-".to_string()
                } else {
                    f.currency.clone()
                },
                f.rows.len(),
                &f.content_hash[..16]
            );
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct PullFile {
    rows: Vec<reconcile::SettlementRow>,
}

fn cmd_reconcile_pull(store: &PaymentStore, args: &ReconcilePullArgs, json: bool) -> Result<()> {
    let raw = std::fs::read_to_string(&args.file).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", args.file.display()),
    })?;
    let pull: PullFile = serde_json::from_str(&raw).map_err(|e| Error::StoreCorrupted {
        details: format!("parsing settlement file {}: {e}", args.file.display()),
    })?;
    let currency = args.currency.as_deref().unwrap_or("");
    let file = reconcile::pull(store, &args.rail, &args.date, currency, pull.rows)?;
    audit::record(
        store,
        audit::AT_RECONCILE,
        json!({ "action": "pull", "date": args.date, "currency": currency, "rows": file.rows.len() }),
        None,
    )?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "reconcile_pull",
                "date": args.date,
                "rows": file.rows.len(),
                "content_hash": file.content_hash
            }),
        )
    } else {
        println!(
            "Pulled settlement file for {} [{}] ({} rows, stamp {})",
            args.date,
            if currency.is_empty() {
                "-".to_string()
            } else {
                currency.to_string()
            },
            file.rows.len(),
            &file.content_hash[..16]
        );
        Ok(())
    }
}

fn cmd_reconcile_run(store: &PaymentStore, date: Option<&str>, json: bool) -> Result<()> {
    let run = reconcile::run(store, date.map(|d| d.to_string()))?;
    audit::record(
        store,
        audit::AT_RECONCILE,
        json!({
            "action": "run",
            "run_id": run.run_id,
            "date": run.date,
            "matches": run.matches,
            "mismatches": run.mismatches.len(),
            "mmr_checkpoint": hex::encode(run.mmr_checkpoint)
        }),
        None,
    )?;
    if json {
        emit(
            json,
            serde_json::to_value(&run).map_err(|e| Error::IoError {
                details: format!("serializing run: {e}"),
            })?,
        )
    } else {
        println!("Reconcile run {} ({})", run.run_id, run.date);
        println!("  matches   : {}", run.matches);
        println!("  mismatches: {}", run.mismatches.len());
        println!("  status    : {:?}", run.status);
        println!("  mmr       : {}", hex::encode(run.mmr_checkpoint));
        Ok(())
    }
}

fn cmd_reconcile_export(
    store: &PaymentStore,
    args: &ReconcileExportArgs,
    json: bool,
) -> Result<()> {
    reconcile::export(store, &args.run, &args.format, &args.out)?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "reconcile_export",
                "run": args.run,
                "format": args.format,
                "out": args.out.display().to_string()
            }),
        )
    } else {
        println!(
            "Exported run {} ({}) to {}",
            args.run,
            args.format,
            args.out.display()
        );
        Ok(())
    }
}

fn cmd_reconcile_list(store: &PaymentStore, json: bool) -> Result<()> {
    let runs = reconcile::list(store)?;
    if json {
        emit(
            json,
            serde_json::to_value(&runs).map_err(|e| Error::IoError {
                details: format!("serializing runs: {e}"),
            })?,
        )
    } else {
        for r in &runs {
            println!(
                "{}  {}  matches={}  mismatches={}  {:?}",
                r.run_id,
                r.date,
                r.matches,
                r.mismatches.len(),
                r.status
            );
        }
        println!("{} runs", runs.len());
        Ok(())
    }
}

// ── DLQ / notifications ───────────────────────────────────────────────

fn cmd_dlq_list(store: &PaymentStore, json: bool) -> Result<()> {
    let records = store.dlq_records()?;
    if json {
        emit(
            json,
            serde_json::to_value(&records).map_err(|e| Error::IoError {
                details: format!("serializing dlq: {e}"),
            })?,
        )
    } else {
        for r in &records {
            println!("{}  {}  {}", r.payment_order_id, r.reason, r.created_at);
        }
        println!("{} dead-letter records", records.len());
        Ok(())
    }
}

fn cmd_notifications_list(store: &PaymentStore, json: bool) -> Result<()> {
    let notifications = store.notifications()?;
    if json {
        emit(
            json,
            serde_json::to_value(&notifications).map_err(|e| Error::IoError {
                details: format!("serializing notifications: {e}"),
            })?,
        )
    } else {
        for n in &notifications {
            println!("{}  {}  {}", n.payment_order_id, n.event, n.created_at);
        }
        println!("{} notifications", notifications.len());
        Ok(())
    }
}

// ── admin: PSP credentials, custody, 2FA (P7) ─────────────────────────

fn cmd_psp_configure(store: &PaymentStore, args: &PspConfigureArgs, json: bool) -> Result<()> {
    require_totp(store, args.totp.as_deref())?;
    let secret = std::fs::read(&args.secret_file).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", args.secret_file.display()),
    })?;
    vault::store_secret(store.root(), &args.rail, &secret)?;
    // The http402 and card rails additionally record their facilitator
    // URL so the executor can build the authorize/verify/settle config at
    // settle time.
    if let Some(url) = &args.facilitator_url {
        if args.rail != "http402" && args.rail != "card" {
            return Err(Error::RailNotConfigured {
                rail: args.rail.clone(),
                details: "--facilitator-url applies to the http402 and card rails".to_string(),
            });
        }
        vault::store_facilitator_url(store.root(), &args.rail, url)?;
    }
    audit::record(
        store,
        audit::AT_CUSTODY,
        json!({
            "action": "psp_configure",
            "rail": args.rail,
            "facilitator_url": args.facilitator_url
        }),
        None,
    )?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "psp_configure",
                "rail": args.rail,
                "stored": format!("{}/psp_vault/{}.secret", store.root().display(), args.rail)
            }),
        )
    } else {
        println!("Stored {} credential in the PSP vault", args.rail);
        Ok(())
    }
}

fn cmd_keys_backup(
    store: &PaymentStore,
    args: &KeysBackupArgs,
    passphrase_file: Option<&str>,
    json: bool,
) -> Result<()> {
    require_totp(store, args.totp.as_deref())?;
    let passphrase =
        origin_common::resolve_passphrase(passphrase_file).map_err(|e| Error::WalletError {
            details: format!("passphrase: {e}"),
        })?;
    custody::backup(store, &passphrase, args.shards, args.threshold)?;
    audit::record(
        store,
        audit::AT_CUSTODY,
        json!({ "action": "keys_backup", "shards": args.shards, "threshold": args.threshold }),
        None,
    )?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "keys_backup",
                "shards": args.shards,
                "threshold": args.threshold
            }),
        )
    } else {
        println!(
            "Custody vault sharded {}-of-{} (keys/secrets.vault, shares in keys/shares/)",
            args.threshold, args.shards
        );
        Ok(())
    }
}

fn cmd_keys_recover(
    store: &PaymentStore,
    args: &KeysRecoverArgs,
    passphrase_file: Option<&str>,
    json: bool,
) -> Result<()> {
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| store.root().join("keys/recovered.seed"));
    // Shares are encrypted at rest (origin-secrets P3.3): recovery always
    // needs the vault passphrase — no silent unsigned fallback here.
    let passphrase =
        match maybe_passphrase(passphrase_file)? {
            Some(p) => p,
            None => return Err(Error::WalletError {
                details:
                    "keys-recover needs the custody vault passphrase (pass -p/--passphrase-file)"
                        .to_string(),
            }),
        };
    custody::recover(store, &args.shares, &out, &passphrase)?;
    audit::record(
        store,
        audit::AT_CUSTODY,
        json!({ "action": "keys_recover", "shares": args.shares.len() }),
        None,
    )?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "keys_recover",
                "shares": args.shares.len(),
                "out": out.display().to_string()
            }),
        )
    } else {
        println!("Recovered custody seed to {}", out.display());
        Ok(())
    }
}

fn cmd_admin_2fa_init(store: &PaymentStore, json: bool) -> Result<()> {
    let uri = twofa::init(store.root())?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "admin_2fa_init",
                "otpauth_uri": uri,
                "note": "scan with your authenticator app; admin commands now require --totp"
            }),
        )
    } else {
        println!("TOTP 2FA initialized. Add this to your authenticator app:");
        println!("  {uri}");
        println!("Admin commands (keys-backup, psp-configure) now require --totp <code>.");
        Ok(())
    }
}

// ── audit (P7) ────────────────────────────────────────────────────────

fn cmd_audit_show(store: &PaymentStore, filter_key: Option<&str>, json: bool) -> Result<()> {
    let records = store.audit_records()?;
    let filtered: Vec<_> = match filter_key {
        Some(key) => records
            .into_iter()
            .filter(|r| r.payload.to_string().contains(key))
            .collect(),
        None => records,
    };
    if json {
        emit(
            json,
            serde_json::to_value(&filtered).map_err(|e| Error::IoError {
                details: format!("serializing audit: {e}"),
            })?,
        )
    } else {
        for r in &filtered {
            println!(
                "seq={} type=0x{:02x} {}",
                r.seq,
                r.entry_type,
                serde_json::to_string(&r.payload).unwrap_or_default()
            );
        }
        println!("{} entries", filtered.len());
        Ok(())
    }
}

fn cmd_audit_verify(store: &PaymentStore, json: bool) -> Result<()> {
    let ok = audit::verify(store)?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "audit_verify",
                "chain_valid": ok,
                "entries": store.audit_records()?.len()
            }),
        )
    } else if ok {
        println!(
            "✓ audit chain valid ({} entries)",
            store.audit_records()?.len()
        );
        Ok(())
    } else {
        Err(Error::StoreCorrupted {
            details: "audit chain verification failed".to_string(),
        })
    }
}

fn cmd_audit_export(store: &PaymentStore, args: &AuditExportArgs, json: bool) -> Result<()> {
    audit::export(store, &args.format, &args.out)?;
    if json {
        emit(
            json,
            json!({
                "ok": true,
                "command": "audit_export",
                "format": args.format,
                "out": args.out.display().to_string()
            }),
        )
    } else {
        println!(
            "Exported audit stream ({}) to {}",
            args.format,
            args.out.display()
        );
        Ok(())
    }
}
