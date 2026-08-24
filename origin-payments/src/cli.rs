// SPDX-License-Identifier: Apache-2.0

//! clap CLI definitions (design §6, P1–P7).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "origin-payments",
    version,
    about = "Payment backend for the Origin economy: events/orders, double-entry journal, reconciliation"
)]
pub struct Cli {
    /// Payments root [default: ~/.origin/payments]
    #[arg(long, global = true)]
    pub home: Option<PathBuf>,

    /// Passphrase source (file path, '-' for stdin). Accepted before or
    /// after the subcommand (matches origin-secrets' `-p`).
    #[arg(short = 'p', long, global = true)]
    pub passphrase_file: Option<PathBuf>,

    /// Structured JSON output. Accepted before or after the subcommand.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize the payments store (config + directories).
    #[command(
        after_help = "Example:\n  origin-payments init --per-tx-cap 500.00\n  origin-payments --json init"
    )]
    Init(InitArgs),
    /// Create a payment event + one payment order (idempotent on order id).
    #[command(
        after_help = "Example:\n  origin-payments order-create --checkout c-1 --to <meshid> --amount 3.15 --currency USD --json"
    )]
    OrderCreate(Box<OrderCreateArgs>),
    /// Show an order and its receipt.
    OrderStatus(OrderStatusArgs),
    /// Re-queue a failed order from the DLQ / retry it now.
    OrderRetry(OrderRetryArgs),
    /// Verify an order's hybrid signature (P2).
    VerifyOrder(VerifyOrderArgs),
    /// Resume a REQUIRES_ACTION order back to EXECUTING.
    OrderResume(OrderResumeArgs),
    /// Run the executor one pass over the native rail.
    #[command(
        after_help = "Example:\n  origin-payments executor-run --wallet payer.wallet --peer-addr 127.0.0.1:9000"
    )]
    ExecutorRun(ExecutorRunArgs),
    /// Double-entry balance view.
    JournalBalance(JournalBalanceArgs),
    /// Export the journal (audit).
    JournalExport(JournalExportArgs),
    /// Export one provenance-stamped settlement file per currency (P9).
    SettlementExport(SettlementExportArgs),
    /// Pull a PSP settlement file for a date (P5).
    ReconcilePull(ReconcilePullArgs),
    /// Run reconciliation for a date (P5).
    ReconcileRun(ReconcileRunArgs),
    /// Export a reconcile run (plain/soc2/pcidss/hipaa).
    ReconcileExport(ReconcileExportArgs),
    /// List reconcile runs.
    ReconcileList(ReconcileListArgs),
    /// List dead-letter records.
    DlqList(DlqListArgs),
    /// Requeue a DLQ record (alias of `order retry`).
    DlqRequeue(DlqRequeueArgs),
    /// List settlement notifications (P6).
    NotificationsList(NotificationsListArgs),
    /// Configure a PSP rail's credentials (requires TOTP).
    PspConfigure(PspConfigureArgs),
    /// Back up the merchant key K-of-N via origin-secrets (requires TOTP).
    KeysBackup(KeysBackupArgs),
    /// Recover the custody seed from shares.
    KeysRecover(KeysRecoverArgs),
    /// Initialize TOTP 2FA for admin commands (P7).
    #[command(visible_alias = "admin-2fa-init")]
    Admin2faInit(Admin2faInitArgs),
    /// Show the audit stream (P7).
    AuditShow(AuditShowArgs),
    /// Verify the audit hash chain (P7).
    AuditVerify(AuditVerifyArgs),
    /// Export the audit stream (plain/soc2/pcidss/hipaa).
    AuditExport(AuditExportArgs),
    /// One-glance ops dashboard: orders by status, retries, DLQ, journal,
    /// last reconcile, audit/custody health.
    #[command(after_help = "Example:\n  origin-payments status\n  origin-payments --json status")]
    Status(StatusArgs),
    /// List pending deferred-settlement commitments (P10).
    DeferredList(DeferredListArgs),
    /// Commit pending deferred commitments into a daily batch.
    DeferredCommit(DeferredCommitArgs),
    /// Inspect a committed deferred batch.
    DeferredInspect(DeferredInspectArgs),
    /// Start the webhook listener for async settlement callbacks.
    #[command(after_help = "Example:\n  origin-payments webhook-listen --addr 0.0.0.0:8080")]
    WebhookListen(WebhookListenArgs),
    /// Generate shell completion scripts (bash/zsh/fish).
    #[command(about = "Generate shell completion scripts (bash/zsh/fish)")]
    Completions(CompletionsArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Overwrite an existing payments root.
    #[arg(long)]
    pub force: bool,
    /// Default currency.
    #[arg(long, default_value = "USD")]
    pub currency: String,
    /// Payments-layer per-transaction spend cap (decimal string, P6).
    #[arg(long)]
    pub per_tx_cap: Option<String>,
    /// Seconds an order may sit in EXECUTING before the TTL sweep
    /// re-queues it (crash recovery, design §4.3).
    #[arg(long, default_value_t = 300)]
    pub executing_ttl: u64,
}

#[derive(Args, Debug)]
pub struct OrderCreateArgs {
    /// Merchant checkout reference.
    #[arg(long)]
    pub checkout: String,
    /// Payee MeshId or stealth address.
    #[arg(long)]
    pub to: String,
    /// Amount as a decimal string (never a float), e.g. "3.15".
    #[arg(long)]
    pub amount: String,
    /// Currency.
    #[arg(long)]
    pub currency: String,
    /// Rail hint: native | http402 | card | ach. Omit for smart routing.
    #[arg(long)]
    pub rail: Option<String>,
    /// Paying party reference (default "buyer").
    #[arg(long)]
    pub buyer: Option<String>,
    /// Receiving party reference (default "merchant").
    #[arg(long)]
    pub seller: Option<String>,
    /// Mark the order as a pay-out (merchant → seller, P6).
    #[arg(long)]
    pub payout: bool,
    /// FX conversion: currency being converted FROM (the quote currency).
    /// Supply with `--fx-to` and `--fx-rate` for a multi-currency order.
    #[arg(long)]
    pub fx_from: Option<String>,
    /// FX conversion: currency the merchant settles in (TO).
    #[arg(long)]
    pub fx_to: Option<String>,
    /// FX rate: 1 `--fx-from` = `--fx-rate` of `--fx-to` (decimal string).
    #[arg(long)]
    pub fx_rate: Option<String>,
    /// FX markup in basis points (0–10000). The merchant's margin above
    /// the mid-market rate; signed as part of the order for audit.
    #[arg(long, default_value_t = 0)]
    pub fx_markup: u32,
    /// Card rail: PSP-issued token reference (never the PAN — PCI out of
    /// scope). Supply with `--card-network` and `--card-last4`; implies
    /// `--rail card`.
    #[arg(long)]
    pub card_token: Option<String>,
    /// Card rail: network (VISA | MASTERCARD | AMEX | ...) for display/audit.
    #[arg(long)]
    pub card_network: Option<String>,
    /// Card rail: last 4 digits, display/audit only.
    #[arg(long)]
    pub card_last4: Option<String>,
}

#[derive(Args, Debug)]
pub struct OrderStatusArgs {
    pub payment_order_id: String,
}

#[derive(Args, Debug)]
pub struct OrderRetryArgs {
    pub payment_order_id: String,
}

#[derive(Args, Debug)]
pub struct VerifyOrderArgs {
    pub payment_order_id: String,
}

#[derive(Args, Debug)]
pub struct OrderResumeArgs {
    pub payment_order_id: String,
}

#[derive(Args, Debug)]
pub struct ExecutorRunArgs {
    /// Single pass over ready orders.
    #[arg(long)]
    pub once: bool,
    /// Payer wallet file (required for the native rail).
    #[arg(long)]
    pub wallet: Option<PathBuf>,
    /// Counterparty's reachable address (native rail only; required when
    /// a ready order rides native, unused by http402/card passes).
    #[arg(long)]
    pub peer_addr: Option<String>,
    /// Standing credit line toward the payee on the native rail (decimal
    /// string, minor units) — pre-funds the channel so multiple orders
    /// settle against one `ENTRY_OPEN` limit instead of each re-opening a
    /// fresh (already-exhausted) line. Optional; defaults to per-order.
    #[arg(long)]
    pub peer_credit: Option<String>,
    /// Compliance rule JSON: {"flag_threshold_minor": N,
    /// "reject_threshold_minor": N, "allowed_counterparties": ["..."]}.
    /// When set, each order is scored before any rail call — Reject → DLQ,
    /// Flag → audit note + proceed. Omit for AcceptAll (no screening).
    #[arg(long)]
    pub compliance_rule: Option<String>,
}

#[derive(Args, Debug)]
pub struct JournalBalanceArgs {
    /// Restrict to one account: debit | credit.
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Args, Debug)]
pub struct JournalExportArgs {
    /// Only postings at or after this ISO 8601 timestamp.
    #[arg(long)]
    pub from: Option<String>,
}

#[derive(Args, Debug)]
pub struct SettlementExportArgs {
    /// Settlement date (ISO 8601 date); default today.
    #[arg(long)]
    pub date: Option<String>,
    /// Rail the files are for.
    #[arg(long, default_value = "native")]
    pub rail: String,
}

#[derive(Args, Debug)]
pub struct ReconcilePullArgs {
    /// Settlement date (ISO 8601 date).
    #[arg(long)]
    pub date: String,
    /// Rail the file came from.
    #[arg(long, default_value = "native")]
    pub rail: String,
    /// Settlement file path to ingest (JSON: {"rows": [{payment_order_id, amount}]}).
    #[arg(long)]
    pub file: PathBuf,
    /// Currency the file settles (e.g. EUR). Pulls persist per-currency
    /// so a multi-currency day keeps every PSP file; omit for the legacy
    /// single-file layout.
    #[arg(long)]
    pub currency: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReconcileRunArgs {
    /// Settlement date (ISO 8601 date); default today.
    #[arg(long)]
    pub date: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReconcileExportArgs {
    #[arg(long)]
    pub run: String,
    /// plain | soc2 | pcidss | hipaa.
    #[arg(long, default_value = "plain")]
    pub format: String,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ReconcileListArgs {}

#[derive(Args, Debug)]
pub struct DlqListArgs {}

#[derive(Args, Debug)]
pub struct DlqRequeueArgs {
    pub payment_order_id: String,
}

#[derive(Args, Debug)]
pub struct NotificationsListArgs {}

#[derive(Args, Debug)]
pub struct PspConfigureArgs {
    /// Rail: http402 | card.
    pub rail: String,
    /// Secret file path (the facilitator API key for the http402 rail).
    #[arg(long)]
    pub secret_file: PathBuf,
    /// Facilitator base URL (http402 | card rails), e.g. http://facilitator:8080.
    #[arg(long)]
    pub facilitator_url: Option<String>,
    /// TOTP code from the operator's authenticator.
    #[arg(long)]
    pub totp: Option<String>,
}

#[derive(Args, Debug)]
pub struct KeysBackupArgs {
    #[arg(long)]
    pub shards: u8,
    #[arg(long)]
    pub threshold: u8,
    /// TOTP code from the operator's authenticator.
    #[arg(long)]
    pub totp: Option<String>,
}

#[derive(Args, Debug)]
pub struct KeysRecoverArgs {
    /// Share files (≥ K).
    #[arg(required = true)]
    pub shares: Vec<PathBuf>,
    /// Output file for the recovered seed (hex).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Admin2faInitArgs {}

#[derive(Args, Debug)]
pub struct AuditShowArgs {
    #[arg(long)]
    pub filter_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct AuditVerifyArgs {}

#[derive(Args, Debug)]
pub struct AuditExportArgs {
    /// plain | soc2 | pcidss | hipaa.
    #[arg(long, default_value = "plain")]
    pub format: String,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct StatusArgs {}

#[derive(Args, Debug)]
pub struct DeferredListArgs {
    /// Restrict to a specific date (YYYY-MM-DD).
    #[arg(long)]
    pub date: Option<String>,
}

#[derive(Args, Debug)]
pub struct DeferredCommitArgs {
    /// The settlement date for the batch (YYYY-MM-DD).
    #[arg(long)]
    pub date: Option<String>,
}

#[derive(Args, Debug)]
pub struct DeferredInspectArgs {
    /// The batch id to inspect.
    pub batch_id: String,
}

#[derive(Args, Debug)]
pub struct WebhookListenArgs {
    /// Address to bind (e.g. 0.0.0.0:8080).
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub addr: String,
}

#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}
