# Origin Payments v1.0 Design Document

**Version:** 1.0.0
**Status:** Draft
**Date:** August 23, 2026
**Springboard:** *System Design Interview — An Insider's Guide*, ch. 26
"Payment System" (liquidslr/system-design-notes), mapped onto the
origin-tools suite and the `origin-crypto-sdk` sibling crate.

---

## Overview

Origin Payments is the payment *backend* for the Origin economy: the
coordinator that turns a checkout into settled money movement. It is a new
workspace member, `origin-payments`, composed entirely from the sibling
crates in origin-tools and the `origin-crypto-sdk` — no crypto of its own,
no new primitives, one home directory.

The design follows Chapter 26's shape — a payment service, a payment
executor, a PSP abstraction, a double-entry ledger, a wallet, and a
reconciliation engine — but *reuses what already exists* in the stack
instead of rebuilding it:

- The **PSP + rail layer** already exists in the Stoa network (embedded via
  `origin-wallet`): evidence-based channels, multi-rail `pay()` with
  cheapest-first smart routing, spend caps, time-boxed finality, and stealth
  privacy (Stoa SPEC §10).
- The **wallet** already exists (`origin-wallet`): hybrid-signed receipts,
  MMR transaction history, encrypted wallet file.
- What is **new** is the Chapter-26 coordination layer: payment events and
  orders with a status machine, idempotency and exactly-once processing,
  retry queue + dead-letter queue, the merchant-side **double-entry
  journal**, nightly **reconciliation** against PSP settlement files, the
  pay-out flow, and the compliance audit surface.

**Scope: CLI + library, same conventions as `origin-secrets`.** No web
dashboard, no hosted payment page (the x402/PSP rails provide the hosted
surface), no card data ever stored (PCI out of scope by design).

---

## 1. Chapter 26 mapping

| Chapter 26 concept | Role in Origin Payments | Existing building block |
|---|---|---|
| Payment service (coordinate, risk-check) | `PaymentService` — accepts `PaymentEvent`, splits into `PaymentOrder`s, tracks state, enforces idempotency | `origin-common` Envelope + IdentityStore; `origin-attest` trust graph for merchant risk |
| Payment executor (execute one order via PSP) | `Executor` — routes each order over enabled rails, retries with backoff | `origin-wallet` `pay_native` / `pay_service` + Stoa `Mesh::pay` (§10.2) |
| PSP / card schemes | The rail abstraction (`NativeChannel`, `Http402` x402, `CardAcp`) | Stoa SPEC §10.2 `Rail` enum; sibling `payments` repo (x402 contracts) |
| Hosted payment page | x402 HTTP rail — payment info never touches our system | `Http402 { url, scheme }` rail; V2 `PAYMENT-SIGNATURE` payload hybrid-signed with the operator bundle (`origin-crypto-sdk` Ed25519 + Falcon-1024) |
| Ledger (double-entry) | `journal` — merchant-side double-entry postings, hash-chained, MMR-checkpointed | `origin-proof` MMR; `origin-crypto-sdk` hybrid signing; Stoa `ENTRY_RECEIPT`/`ENTRY_SETTLE` as the cross-party evidence leg |
| Wallet (balances) | `origin-wallet` — buyer/merchant balances | `origin-wallet` (already shipped) |
| Reconciliation | `reconcile` — nightly comparison vs PSP settlement files, mismatch classification | `origin-network` transport; `origin-provenance` stamps on settlement files; `origin-proof` MMR checkpoint |
| Idempotency / exactly-once | `payment_order_id` as the idempotency key + unique constraint + receipt-hash cache | Stoa receipt-hash cache (replay returns cached receipt); store-level unique key |
| Retry queue / DLQ | `RetryJob` queue (exponential backoff + jitter) and `DlqRecord` dead-letter store | `origin-network` gate for rate limits; `origin-secrets`-style failure journal |
| Reconciliation/accounting records | signed, hash-chained `AuditEntry` stream | `origin-attest` audit log |
| Payment security (PCI, tokens, HTTPS) | AEAD at rest, hybrid signatures, ratcheted sessions, no card data | SDK AEAD + hybrid signing; `origin-channel` ratchet; `origin-network` gate (TokenBucket + PoW) |

---

## 2. System components

```
┌──────────────────────────────────────────────────────────────────┐
│                       origin-payments (CLI + lib)                │
├──────────────────────────────────────────────────────────────────┤
│  PaymentService        PaymentExecutor        ReconcileEngine    │
│  (events/orders,       (rail routing,         (settlement file   │
│   status machine,       retry + DLQ,           compare, mismatch │
│   idempotency)          exactly-once)          classify, MMR ckpt)│
│  ─────────────────────────────────────────────────────────────── │
│  Journal (double-entry, hash-chained, MMR-checkpointed)          │
│  Store (origin-home file store: events, orders, postings,        │
│         retry queue, DLQ, reconcile runs)                        │
│  Audit (origin-attest)   Vault (PSP credentials, origin-pass)    │
│  Custody (origin-secrets K-of-N for merchant keys)               │
└──────────────────────────────┬───────────────────────────────────┘
                               │ origin-wallet (pay surface; Stoa rail)
                               ▼
              Native channel  ·  Http402 (x402)  ·  CardAcp (ACP)
              (ledger entries,   (EIP-712-style    (tokenized card
               no on-chain)       receipts)          auth, last4 only)
```

### Crate dependency graph (new edges in bold)

```
                    origin-crypto-sdk (sole crypto provider)
                            │
                    origin-common (Envelope, IdentityStore, OriginHome)
                            │
   ┌──────────┬─────────────┼──────────────┬─────────────┬───────────┐
   │          │             │              │             │           │
origin-   origin-seal    origin-proof   origin-shard  origin-schnorr │
identity  (AEAD envs)    (MMR audit     (K-of-N key   (ZK balance/  │
(hybrid    + memos)       trail, rec.    custody)      solvency     │
 sign)                    checkpoints)                 proofs)      │
   │          │             │              │             │           │
   │          │        origin-stealth  origin-entropy  origin-seed  │
   │          │        (unlinkable     (keygen gates,  (domain      │
   │          │         pay surfaces)   DB-free rng)    subkeys)    │
   │          │             │              │             │           │
   └──────────┴─────────────┼──────────────┴─────────────┴───────────┘
                            │
            ┌───────────────┼────────────────┐
            │               │                │
     origin-pass       origin-attest    origin-channel
     (PSP creds,       (audit log,       (ratcheted
      TOTP 2FA)         trust graph,      sessions)
                        revocation)
            │               │                │
            │         origin-network   origin-provenance
            │         (transport,      (settlement-file
            │          gate/PoW)        stamps)
            │               │                │
            └───────────────┴────────────────┘
                            │
                      origin-wallet  ◄── Stoa rail (§10: channels,
                      (pay surface)      multi-rail pay, ledger
                            │            entries, spend caps)
                            │
                    ╔══════════════╗
                    ║ origin-payments ║  ← the new crate
                    ╚══════════════╝
```

---

## 3. Crate utilization map

Every sibling crate earns its place. This is the contract of the design:
**no crate is cargo-culted; each has a named responsibility.**

| Crate | Responsibility in Origin Payments |
|---|---|
| `origin-common` | `OriginHome` (`~/.origin/payments/`), `Envelope` (encrypted payment events / order payloads at rest), `IdentityStore` (the merchant/operator identity all entries are signed under), `MemoryTier` (vault tiers), `resolve_passphrase` |
| `origin-identity` | Hybrid (Ed25519 + Falcon-1024) keypair for the payment service; rotate/export of operator keys |
| `origin-seal` | AEAD-encrypt order payloads, memos, and PSP webhook payloads; integrity via SDK signing |
| `origin-seed` | Domain-derived subkeys (`payments` domain) so payment keys never equal the master identity seed |
| `origin-proof` | MMR over the journal and over daily reconciliation checkpoints — the tamper-evident append-only log; membership proofs for audit exports |
| `origin-shard` | K-of-N Reed-Solomon backup of the merchant signing key (break-glass custody) |
| `origin-secrets` | The full threshold vault for operator custody of merchant keys — reuse, do not reimplement |
| `origin-stealth` | Unlinkable pay-in surfaces: a merchant advertises a `StealthAddress`; each payment targets a fresh index (Stoa §10.4); the address is part of the signed order body |
| `origin-entropy` | Quality gates at key generation (merchant keys, PSP webhook secrets, DRBG seeds) |
| `origin-schnorr` | EC-Schnorr (secp256k1) optional balance/solvency proofs (x402 receipts are hybrid-signed with the operator identity — see P8) |
| `origin-pass` | Vault for PSP credentials (x402 facilitator keys/API secrets, ACP API secrets) — Argon2id + AEAD, TOTP/HOTP 2FA on operator admin commands |
| `origin-attest` | `AuditEntry`/`AuditLog` (hash-chained) for every money movement; `CapabilityClaim` for rail access grants; `RevocationJournal` for compromised PSP credentials; `TrustGraph` as the fraud/risk signal for merchants |
| `origin-channel` | Ratcheted, replay-protected sessions between origin-payments and wallet nodes / relay points (the "internal HTTPS"); `AeadLimits` to bound AEAD usage |
| `origin-network` | The transport for pulling PSP settlement files and webhook delivery; `TokenBucket` rate limiting + PoW/cookie gate on ingress (DDoS); relayed paths to NAT'd wallets |
| `origin-provenance` | `Stamp` on every settlement file (content hash + timestamp + signature) so reconciliation evidence is tamper-evident before it is compared |
| `origin-wallet` | The pay surface: `pay_native` / `pay_service` / `settle_channel_with` (Stoa rail); wallet MMR history as the human-facing receipt record |
| `origin-crypto-sdk` | **Everything cryptographic**: XChaCha20-Poly1305 AEAD, Argon2id KDF (tiered), HKDF-SHA3-256 subkeys, hybrid Ed25519+Falcon-1024 signatures, Reed-Solomon, MMR, stealth + PoW, EC-Schnorr (secp256k1), DRBG, entropy analysis, LZ4 compression |

---

## 4. Data flow

### 4.1 Pay-in flow (buyer → merchant)

```
1. Buyer clicks "place order" → merchant app sends a PaymentEvent to
   origin-payments: { checkout_id, buyer, payment_orders: [{ seller, amount, ... }] }
2. PaymentService validates the event, signs it with the hybrid identity,
   wraps it in an origin-common Envelope, and stores it
   (payment_events.jsonl). Splits it into PaymentOrders
   (payment_orders.jsonl); each order carries a fresh payment_order_id
   (the idempotency key; unique constraint at the store).
3. Executor picks up NOT_STARTED orders → marks EXECUTING (before any
   rail call, so a crash mid-flight is recoverable) → quotes enabled
   rails via Stoa §10.2 and routes cheapest-first.
4. The chosen rail executes:
     NativeChannel → origin-wallet pay_native (streams ENTRY_RECEIPT;
                      counterparty ingests via gossip; wallet MMR history)
     Http402       → x402 V2 flow: PAYMENT-REQUIRED challenge →
                      PAYMENT-SIGNATURE payload hybrid-signed with the
                      operator identity (Ed25519 + Falcon-1024, bound to
                      the resource URL) → facilitator verifies + settles;
                      `settlement_pending` → REQUIRES_ACTION
     CardAcp       → ACP token authorization (last4 only, never PAN)
5. On success the rail returns a Receipt (versioned, rail-discriminated,
   verifiable via Stoa verify_receipt / wallet record). Executor:
     a. posts the double-entry journal rows (merchant escrow ↔ merchant
        balance; batch sums to zero),
     b. marks the order SUCCESS, sets ledger_updated / wallet_updated,
     c. appends the receipt to the wallet's MMR history (origin-proof),
     d. writes an origin-attest AuditEntry,
     e. notifies the merchant (origin-network mail/webhook).
6. Merchant balance (origin-wallet) reflects the journal sum.
```

### 4.2 Pay-out flow (merchant → seller)

Mirror of pay-in with the money moving the other way:

```
PaymentEvent { payout } → PaymentOrders (one per seller)
→ Executor routes over enabled rails (NativeChannel to the seller's
  MeshId; CardAcp to a seller bank account via ACP; x402 for on-chain
  sellers) → journal posts the symmetric rows (merchant balance debit,
  seller payable credit) → SUCCESS + audit + notification.
```

Bookkeeping and regulatory handling are the same machinery as pay-in:
the journal and the audit export are rail-agnostic.

### 4.3 Idempotency and exactly-once

- **At-least-once delivery** with **idempotent processing** ⇒ exactly-once
  effect (Chapter 26):
  - The store rejects a second `PaymentOrder` with the same
    `payment_order_id` (unique key) and returns the existing order.
  - The rail dedupes: Stoa's receipt-hash cache returns the cached receipt
    for a replayed `pay()` (Stoa §10.1).
  - The executor marks `EXECUTING` **before** the rail call and refuses to
    re-execute an order that is already `EXECUTING` unless a crash-recovery
    scan finds it stuck past `executing_since + TTL` — then it re-queues
    with the same idempotency key, so the rail's dedupe absorbs the replay.
- **Retries**: exponential backoff + jitter (base 1 s, factor 2, cap
  5 min, default). A rail that knows better returns a `Retry-After` hint
  (honored, capped). Terminal errors (invalid amount, unknown seller,
  policy refusal, rail `Decline` with no retry) go straight to the DLQ.
- **Dead-letter queue**: `DlqRecord` holds the order, the last error, and
  the evidence (receipt/error body). Operators inspect and requeue; a
  requeued order keeps its idempotency key.
- **Slow payments** (risk review, 3DS): the order enters `REQUIRES_ACTION`;
  the executor does not retry it on a timer — it waits for the rail's
  asynchronous webhook (Stoa gossip / x402 webhook / ACP callback), the
  same "pending" pattern as Chapter 26.

### 4.4 Reconciliation

```
Every night (or on demand: reconcile run --date <d>):
1. Pull each enabled PSP's settlement file over origin-network.
2. Verify each file's origin-provenance Stamp (hash + signature).
3. Compare, per payment_order_id: PSP rows vs the journal.
4. Classify each mismatch:
     - Match                     → nothing to do
     - Adjustable (known delta)  → post a corrective journal entry with a
                                   signed rationale (standard procedure)
     - Unclassifiable            → finance queue with full evidence
5. Write ReconcileRun + ReconcileReport; checkpoint
   (settlement file hash ‖ journal root ‖ report hash) into the MMR
   (origin-proof) — the daily proof that reconciliation ran.
6. Internal consistency: journal sum vs origin-wallet balance; MMR root
   re-verification on every read path.
```

Mismatches are surfaced via `origin-payments reconcile export` (plain,
SOC2, PCI-DSS, HIPAA formats — reusing the origin-secrets compliance
pattern) for the finance team.

---

## 5. Data structures

All types are serde-serializable and versioned, consistent with the
suite's formats. Monetary amounts are **strings**, never floats
(Chapter 26's rule).

```rust
/// A checkout: one buyer action, many payment orders.
pub struct PaymentEvent {
    pub version: u8,
    pub event_id: String,          // "evt-…", generated by origin-payments
    pub checkout_id: String,       // merchant's reference
    pub buyer: String,             // MeshId or stealth-address surface
    pub seller: String,
    pub payment_orders: Vec<PaymentOrder>,
    pub status: EventStatus,       // Received | Split | AllSettled | Partial
    pub created_at: String,        // ISO 8601
    pub envelope: Envelope,        // origin-common AEAD envelope at rest
    pub signature: HybridSignature, // over the plaintext event body
}

/// One money movement. payment_order_id is THE idempotency key (unique).
pub struct PaymentOrder {
    pub version: u8,
    pub payment_order_id: String,  // uuid v4 — forwarded to the rail as nonce
    pub checkout_id: String,       // FK to PaymentEvent
    pub to: String,                // MeshId or StealthAddress (signed body)
    pub amount: String,            // decimal string, e.g. "3.15"
    pub currency: String,
    pub rail: Option<RailHint>,    // None = smart routing (cheapest-first)
    pub status: OrderStatus,       // see enum below
    pub ledger_updated: bool,      // journal posted
    pub wallet_updated: bool,      // origin-wallet balance updated
    pub attempts: u32,
    pub next_retry_at: Option<String>,
    pub executing_since: Option<String>, // crash-recovery TTL anchor
    pub receipt: Option<RailReceipt>,
    pub created_at: String,
    pub updated_at: String,
}

pub enum OrderStatus {
    NotStarted,        // "NOT_STARTED"
    Executing,         // "EXECUTING" — set before any rail call
    Success,           // "SUCCESS"  — journal + wallet updated
    Failed,            // "FAILED"   — terminal, DLQ'd
    RequiresAction,    // "REQUIRES_ACTION" — 3DS / risk review / webhook wait
}

/// The rail evidence, versioned + rail-discriminated (Stoa §10.2 shape).
pub enum RailReceipt {
    Native { ledger_entry: Vec<u8> }, // encoded ENTRY_RECEIPT; verifies vs gossip
    Http402 { receipt: Vec<u8> },     // PAYMENT-RESPONSE settlement receipt (base64 JSON)
    CardAcp { network: String, last4: String, auth: Vec<u8> },
}

/// Double-entry journal posting. A batch always sums to zero.
pub struct LedgerPosting {
    pub posting_id: String,
    pub batch_id: String,          // one batch per settled order (≥ 2 rows)
    pub payment_order_id: String,
    pub account: Account,          // Debit | Credit
    pub amount: String,            // decimal string
    pub currency: String,
    pub ts: String,
    pub prev_hash: [u8; 32],       // hash chain — append-only
    pub signature: HybridSignature,
}

pub enum Account { Debit, Credit }

/// Nightly reconciliation.
pub struct ReconcileRun {
    pub run_id: String,
    pub date: String,              // ISO 8601 date
    pub psp_files: Vec<SettlementFile>, // stamped, verified origin-provenance
    pub journal_root: [u8; 32],    // MMR root at checkpoint time
    pub matches: u64,
    pub mismatches: Vec<ReconcileMismatch>,
    pub mmr_checkpoint: [u8; 32],  // MMR leaf for this run
    pub status: ReconcileStatus,   // Clean | Mismatches | Failed
}

pub enum MismatchClass {
    Match,
    Adjustable,       // known delta, standard corrective procedure
    Unclassifiable,   // finance team investigates
}

pub struct ReconcileMismatch {
    pub run_id: String,
    pub payment_order_id: String,
    pub psp_amount: Option<String>,
    pub journal_amount: Option<String>,
    pub class: MismatchClass,
    pub evidence: Vec<String>,     // settlement row refs, receipt ids
}

/// Retry queue / DLQ records.
pub struct RetryJob {
    pub payment_order_id: String,
    pub attempt: u32,
    pub next_retry_at: String,
    pub backoff_ms: u64,
    pub last_error: String,
}

pub struct DlqRecord {
    pub payment_order_id: String,
    pub reason: String,            // terminal error, classifier
    pub evidence: serde_json::Value, // receipt / error body
    pub created_at: String,
}
```

### Store layout (`~/.origin/payments/`, `0700`)

```
~/.origin/
  payments/
    config.toml            # enabled rails, default currency, retry policy
    payment_events.jsonl   # append-only
    payment_orders.jsonl   # append-only; payment_order_id unique
    journal.jsonl          # double-entry postings (hash chain)
    retry_queue.jsonl      # RetryJob records
    dlq.jsonl              # DlqRecord records
    reconcile/*.json       # one ReconcileRun per run
    mmr.bin                # origin-proof MmrState (journal + checkpoints)
    psp_vault/             # origin-pass vault (credentials, TOTP secrets)
    keys/                  # merchant signing key (K-of-N via origin-secrets)
```

Files are written atomically (temp + rename); the ordering authority is
the hash chain + MMR, not a DB server. A SQLite backend is a v2 option
(see Open Questions); v1 deliberately stays inside the suite's one-home,
file-based convention.

---

## 6. CLI specification

Conventions mirror `origin-secrets` (flat kebab-case subcommands,
`--json` structured output, exit codes, passphrase policy — file /
stdin / interactive, never default): no card data anywhere.

```bash
origin-payments [OPTIONS] <COMMAND>

OPTIONS (all global — accepted before or after the subcommand):
    --home <PATH>            Payments root [default: ~/.origin/payments]
    -p, --passphrase-file <PATH>  Passphrase source ('-' for stdin)
    --json                   Structured output

COMMANDS:
    init [--force] [--currency <C>] [--per-tx-cap <A>]  Initialize the store
    order-create --checkout <id> --to <meshid|stealth> --amount <A>
                 [--currency <C>] [--rail native|http402|card|ach]
                 [--buyer <B>] [--seller <S>] [--payout]
                 [--card-token <T> --card-network <VISA> --card-last4 <1234>]
                                         Create a PaymentEvent + order
                                         (idempotent on payment_order_id;
                                         hybrid-signed + envelope-encrypted
                                         when an operator identity is present;
                                         --card-* set the card rail's token
                                         reference — all three or none, never
                                         the PAN)
    order-status <order-id>              Show order + receipt
    order-retry <order-id>               Re-queue FAILED from the DLQ
    order-resume <order-id>              REQUIRES_ACTION -> NOT_STARTED, so the
                                         NEXT executor pass settles it (P4)
    settlement-export [--date <D>] [--rail <R>]
                                         One provenance-stamped settlement file
                                         per currency (P9)
    executor-run --wallet <PATH> [--peer-addr <ADDR>] [--once]
                 [--peer-credit <AMOUNT>]
                                         Executor pass: NOT_STARTED + due
                                         retries, backoff + DLQ (P3/P4).
                                         --peer-credit pre-funds one standing
                                         Stoa channel toward the payee — the
                                         mesh credit is cumulative
                                         (remaining = limit − sent), so
                                         without it the 2nd order in a pass
                                         re-opens a fresh, already-exhausted
                                         line and fails "payment exceeds
                                         credit limit"
    journal-balance [--account debit|credit]  Double-entry balance view
    journal-export [--from <ISO-8601>]   Export journal (audit)
    reconcile-pull --date <d> --file <PATH> [--rail <r>] [--currency <CCY>]
                                         Ingest PSP file (P5). One per
                                         currency — each persists as
                                         <date>.<CCY>.json and the run
                                         merges every pulled file
    reconcile-run [--date <d>]           Compare + classify + MMR checkpoint (P5)
    reconcile-export --run <id> --format plain|soc2|pcidss|hipaa --out <PATH>
    reconcile-list                       List runs
    dlq-list                             List dead-letter records
    dlq-requeue <order-id>               Alias of order-retry
    notifications-list                   P6 settlement notifications
    psp-configure <http402|card|ach> --secret-file <PATH>
                 [--facilitator-url <URL>] --totp <code>   (P7/P10–P13;
                 stores the facilitator URL + API key in the PSP vault;
                 the executor uses them for the x402 verify/settle split,
                 the card /authorize call, and the ACH/SEPA fiat
                 facilitator)
    keys-backup --shards <N> --threshold <K> --totp <code>  (P7 custody)
    keys-recover <share...> [--out <PATH>] (needs -p/--passphrase-file)
    admin2fa-init                        Print otpauth URI; gates admin cmds
    audit-show [--filter-key <K>]        origin-attest stream (P7)
    audit-verify                         Verify the hash chain
    audit-export --format plain|soc2|pcidss|hipaa --out <PATH>
    status                           One-glance ops dashboard: orders by
                                     status, retries + DLQ, journal net,
                                     last reconcile, audit health, 2FA/custody
    completions <bash|zsh|fish>      Shell completion scripts
    audit-show [--filter-key <K>]        origin-attest stream (P7)
    audit-verify                         Verify the hash chain
    audit-export --format plain|soc2|pcidss|hipaa --out <PATH>
    status                           One-glance ops dashboard: orders by
                                     status, retries + DLQ, journal net,
                                     last reconcile, audit health, 2FA/custody
    completions <bash|zsh|fish>      Shell completion scripts
```

`order-create` generates `payment_order_id` server-side (a uuid v4) —
the idempotency key. A re-submission of the same key returns the existing
order instead of creating a duplicate (the replay path, exercised in
tests).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Internal / crypto error / not-yet-wired feature |
| `2` | Operator-fixable input/auth error (duplicate key, already initialized) |
| `3` | Not-found / input error (unknown order, missing settlement file) |
| `4` | Payment-domain error (invalid amount, unbalanced journal, illegal transition, rail decline) |
| `127` | CLI parse error |

---

## 7. Error handling

```rust
pub enum Error {
    // Store
    OrderAlreadyExists { payment_order_id: String },   // idempotency hit
    OrderNotFound { payment_order_id: String },
    StoreCorrupted { details: String },                // hash-chain break
    // State machine
    InvalidTransition { from: OrderStatus, to: OrderStatus },
    OrderStuckInExecuting { payment_order_id: String }, // crash recovery
    // Rails
    RailUnavailable { rail: String, details: String },
    RailDeclined { rail: String, reason: String },      // retryable? flag
    ReceiptVerificationFailed { details: String },
    // Journal
    JournalNotBalanced { batch_id: String },            // sum != 0 — abort
    // Reconciliation
    SettlementFileInvalid { path: String, details: String },
    SettlementStampMismatch { path: String },
    // Crypto / vault / audit (delegated)
    CryptoError { details: String },
    VaultError { details: String },
    AuditError { details: String },
    // User
    PassphraseTooWeak { min_length: usize },
}
```

Every error is also written to the origin-secrets-style failure journal
(`~/.origin/failures.log`, one JSON line per event, vault-independent) so
*denied* money movements are auditable even when the store is down.

---

## 8. Security considerations

| Threat (Chapter 26) | Mitigation in Origin Payments |
|---|---|
| Eavesdropping on internal/client traffic | `origin-channel` ratcheted sessions (Noise IK + double ratchet, replay protection) over `origin-network`; x402 rail speaks TLS at the endpoint |
| Data tampering | AEAD (XChaCha20-Poly1305) at rest via origin-common Envelope; hybrid Ed25519 + Falcon-1024 signatures on every event, order, posting, audit entry, and settlement-file stamp |
| Man-in-the-middle | Noise IK handshake identity-pinned to MeshId (origin-network/identity); x402 payment authorizations hybrid-signed with the operator identity and bound to the resource URL (cross-resource replay rejected) |
| Data loss | MMR-backed journal (origin-proof); K-of-N Reed-Solomon custody of merchant keys (origin-shard + origin-secrets); wallet shard backup |
| DDoS / abuse | `origin-network` ingress gate: TokenBucket rate limit, PoW gate, cookie challenge; per-rail spend caps (Stoa SpendPolicy) |
| Card theft | **No card data ever stored.** CardAcp rail handles tokens + last4 only; x402 hosted flow keeps payment info at the PSP |
| PCI compliance | Out of scope by design — the system is a token/rail client, never a cardholder-data environment |
| Fraud | Merchant risk via `origin-attest` TrustGraph; entropy gates at keygen; TOTP 2FA (origin-pass) on operator admin commands; standing + per-call spend caps |
| Key compromise | Domain-derived subkeys (origin-seed) so no single leak exposes the identity seed; `origin-attest` RevocationJournal for compromised PSP credentials; passphrase rotation (origin-secrets pattern) |

**Amounts are plaintext** (Stoa §10.4, per requirements); stealth
addresses give per-payment unlinkable surfaces, not hidden amounts.

---

## 9. Testing strategy

### Unit tests (in-crate, `#[cfg(test)]`)
- Status machine: every legal transition; `InvalidTransition` on illegal ones.
- Idempotency: re-submitting an order id returns the existing order;
  the store's unique-key rejection is a no-op replay, not an error.
- Journal: **every batch sums to zero** (property); hash chain is
  append-only; a tampered posting breaks the chain.
- Retry scheduler: backoff schedule (base/factor/cap), `Retry-After`
  hint honored and capped, terminal errors skip the queue → DLQ.
- Mismatch classifier: Match / Adjustable / Unclassifiable decisions.
- Crash recovery: an order stuck in `EXECUTING` past TTL is re-queued
  with the same idempotency key.

### Integration tests (`origin-payments/tests/`)
1. `init → order create → executor run → journal balance → audit` happy
   path on the native rail (against a loopback Stoa mesh, mirroring
   origin-wallet's tests).
2. Exactly-once: executor runs twice on the same order; the rail's
   receipt-hash cache returns the cached receipt; journal has one batch.
3. DLQ: a terminal rail decline lands in the DLQ; `dlq requeue` replays
   with the same order id and the store still rejects duplicates.
4. Reconciliation: a tampered settlement file fails the provenance
   stamp; an adjustable delta posts a corrective entry; an
   unclassifiable mismatch lands in the finance queue; the run's
   checkpoint is provable in the MMR.
5. Spend policy: per-tx / per-day / per-month caps refuse before any
   rail call (existing Stoa semantics, asserted at the payments layer).

### Cross-tool tests (`origin-cross-tests/`)
- payments + wallet + proof: pay → MMR receipt → journal → reconcile
  checkpoint → MMR membership proof verifies.
- payments + secrets + shard: merchant key backed up K-of-N, recovered,
  and used to sign an order.
- payments + attest + pass: audit stream verifies; operator admin op
  requires TOTP.

---

## 10. Dependencies

```toml
[dependencies]
# Chief dependency — the sole crypto provider.
origin-crypto-sdk = { workspace = true }
# Sibling composition crates.
origin-common     = { workspace = true }
origin-identity   = { workspace = true }
origin-seal       = { workspace = true }
origin-seed       = { workspace = true }
origin-shard      = { workspace = true }
origin-proof      = { workspace = true }
origin-stealth    = { workspace = true }
origin-schnorr    = { workspace = true }
origin-entropy    = { workspace = true }
origin-pass       = { workspace = true }
origin-attest     = { workspace = true }
origin-channel    = { workspace = true }
origin-network    = { workspace = true }
origin-wallet     = { workspace = true }   # the Stoa pay surface

# External (same set the suite already uses)
clap = { version = "4", features = ["derive"] }
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { version = "1", features = ["v4"] }
chrono = "0.4"
hex = "0.4"
zeroize = { version = "1", features = ["derive"] }
thiserror = "1"
tokio = { workspace = true }
async-trait = "0.1"

[dev-dependencies]
tempfile = "3"
```

---

## 11. Implementation sequencing

Each phase is independently testable; the suite stays green between phases.

| Phase | Scope | Exit criterion |
|---|---|---|
| P1 | Crate skeleton, store (events/orders, unique `payment_order_id`), status machine, `init` | Store round-trips; duplicate order id rejected | ✅
| P2 | Journal: double-entry postings, hash chain, balance view, sum-zero property tests | `journal balance` matches posted orders | ✅
| P3 | Executor v1 on the native rail via `origin-wallet::pay_native`, EXECUTING-before-call, crash recovery, retry queue + DLQ — `origin-payments` reaches the mesh only through `origin-wallet` re-exports (no direct stoa dep) | Exactly-once replay test green; native executor test green via wallet re-exports | ✅
| P4 | Retry machinery (backoff + jitter + `Retry-After` + DLQ), `REQUIRES_ACTION` + resume, rail routing/fallback — **`order-resume` returns a resolved REQUIRES_ACTION order to NOT_STARTED** so the next executor pass settles it (a resume to EXECUTING would strand it — the executor only picks up NOT_STARTED + due retries) | Retry/DLQ + resume tests green | ✅ (retry, REQUIRES_ACTION, routing, pay-out, caps)
| P11 | **Card rail (CardAcp) — tokenized authorization**: `PaymentOrder.card_token/network/last4` (set together by `order-create --card-*`, implies `--rail card`, never the PAN — PCI out of scope holds by construction); the executor asks the vault-configured ACP facilitator (`psp-configure card`) to authorize the token via `POST /authorize` (x-api-key authenticated, same transport incl. optional TLS); `success` → journal + `RailReceipt::CardAcp` + settle, `settlement_pending` → `REQUIRES_ACTION`, `declined` → terminal DLQ; missing token/config refuse before any HTTP call with an actionable hint | Mock-ACP executor tests (settle / pending / decline-DLQ / not-configured / no-token) + card unit tests + card CLI validation tests green | ✅ (tokenized authorization end-to-end; live PSP contract external, same as x402)
| P5 | Reconciliation: settlement pull, provenance stamps, mismatch classifier, MMR checkpoint | Tamper + delta + finance-queue integration tests green | ✅
| P6 | Pay-out flow, merchant notifications (origin-network mail/webhook), spend-policy enforcement at the payments layer | Pay-out happy path + caps tests green | ✅ (payout direction, notifications, per-tx cap; webhook transport deferred)
| P7 | Audit/compliance exports (SOC2/PCI-DSS/HIPAA), K-of-N key custody via origin-secrets, TOTP 2FA admin ops | Cross-tool tests green; coverage ≥ 85 % | ✅
| P8 | x402 rail: V2 header handshake (PAYMENT-REQUIRED/SIGNATURE/RESPONSE), `settlement_pending` → `REQUIRES_ACTION`, receipt evidence, **hybrid-signed payment authorizations** (operator `HybridSigner`; `verify_payment_payload`; mock facilitator rejects tampered/cross-resource payloads; unsigned payments refused); **optional `tls` feature** — `https://` endpoints get a rustls stream upgrade (system roots via `rustls-native-certs`; `http://` keeps the std path), off by default to stay dependency-light | Mock-server handshake + executor settle/pending/DLQ tests green; TLS loopback handshake+request test green (feature `tls`) | ✅ (protocol + real origin-crypto-sdk hybrid signing + optional real-world TLS)
| P10 | **x402 facilitator verify/settle split + vault wiring + deferred settlement**: executor sends the signed authorization to a configured facilitator (`POST /verify` cheap pre-spend gate, then `POST /settle`; API key from the PSP vault); **deferred settlement** batches signed commitments into tamper-evident manifests MMR-checkpointed for batched/daily settlement — `deferred_commitments` JSONL + `deferred_settlement_enabled` config drive a **scheduled commit in `executor::run_once`** (commit clears the queue; forged/replayed commitments refused, queue preserved) | Facilitator verify→settle executor tests + deferred-batch persistence/proof/scheduling tests green | ✅ (all within origin-payments; live facilitator contract still external — https facilitators need `--features tls`)
| P9 | Multi-currency: per-currency journal balances with explicit FX legs (`FxRate` on postings, signed canonical bytes), **`PaymentOrder.fx`** (from/to/rate) drives an FX batch (`append_order_batch` dispatches FX vs plain), **per-currency settlement-file export** (`export_per_currency` — one provenance-stamped file per settlement currency) | 2-currency FX batch tests + rate-tamper rejection + FX-order dispatch + per-currency export tests green | ✅ (journal capability complete: per-currency settlement files + FX order field now implemented)
| P12 | **Rail-level receipt dedupe cache** (x402 spec §4.2 — duplicate-settlement protection): `store.record_receipt_hash` / `store.is_receipt_settled` backed by `receipt_dedupe.jsonl`; the executor's `settle_http402_success` and `settle_card_success` compute SHA-3-256 of the receipt bytes, check the cache before journaling (duplicate → terminal error with evidence), and record the hash after. Prevents the same facilitator receipt from settling two different orders. | Receipt dedupe unit tests + executor integration tests green | ✅
| P13 | **ACH/SEPA fiat rail** — `RailHint::Ach` routes through an x402-style fiat facilitator (`psp-configure ach`); same verify/settle split as http402, but the facilitator settles on a traditional payment network (ACH, SEPA, wire); `RailReceipt::Ach { settlement_ref, auth }` carries the bank-rail trace id; `settlement_pending` → `REQUIRES_ACTION`, rejected → terminal DLQ; receipt dedupe cache applies. | ACH settle executor tests (facilitator settle/pending/reject/not-configured) green | ✅ (x402 V2 §2: "Facilitators for ACH, SEPA, or card networks fit the same payment model")
| P14 | **Merchant settlement preference** — `PaymentsConfig.settlement_preference` (Hold / OffRamp / Split) + `split_pct`; the payout layer uses this to decide whether to hold stablecoin, off-ramp to fiat, or split at a configurable ratio. Fireblocks PSP blueprint pattern. | Config roundtrip + payout-layer tests green | ✅ (merchant-level optionality; off-ramp facilitator wired via `psp-configure`)
| P15 | **Compliance scoring interface** — `ComplianceScorer` trait (`score(&PaymentOrder) → Accept / Flag / Reject`) with `AcceptAll` (default) and `RuleBasedScorer` (amount thresholds + counterparty allowlist); the executor can call the scorer before settling each order; `Reject` → DLQ with evidence, `Flag` → proceed with audit note. Plugin interface for Chainalysis/Elliptic backends. | Compliance trait unit tests (accept-all, rule-based thresholds, counterparty allowlist) green | ✅ (research §5 — "inbound compliance screening before crediting")
| P16 | **Wire compliance scoring into executor** — `settle()` accepts `Option<Box<dyn ComplianceScorer>>`; `Reject` → terminal DLQ with audit note, `Flag` → proceed with audit annotation. CLI gets `--compliance-rule <json>` / `--compliance-accept-all`. Compliance integration tests (accept, reject→DLQ, flag→audit) green. | ✅
| P17 | **Deferred settlement CLI** — `deferred-list` (inspect pending deferred commitments), `deferred-commit <batch-id>` (manually trigger a batch), `deferred-inspect <batch-id>` (view committed batch details). All operators can inspect/trigger deferred batches without running the executor. | ✅
| P18 | **Parse `Retry-After` from facilitator responses** — `FacilitatorSettleOutcome` carries `retry_after_ms: Option<u64>`; `settle_http402` / `settle_ach` parse the HTTP `Retry-After` header and pass it through to `schedule_retry`. When a facilitator says "retry in 30s", the executor respects it instead of using its own backoff. | ✅
| P19 | **Webhook receiver for async settlement callbacks** — `POST /settlement-callback` (std TcpListener, no new deps); validates HMAC-SHA256 callback signature against vault-stored secret; looks up the order by `settlement_ref` and transitions `REQUIRES_ACTION → NOT_STARTED` so the next executor pass picks it up. `webhook-listen --addr` CLI command. | ✅
| P20 | **FxRate markup_bps** — `FxRate` gains `markup_bps: u64` (merchant's margin in basis points); the rate is signed as part of the canonical order body (`signed_body()`). CLI gets `--fx-markup <bps>`. Tampered markup rejected at order-verification time. | ✅
| P21 | **Settlement preference payout integration** — `PaymentsConfig.settlement_preference` (Hold / OffRamp / Split) + `split_pct` now drive the actual payout path. Inbound settlement: `Hold` → hold stablecoin, `OffRamp` → route to fiat off-ramp facilitator, `Split` → split at `split_pct` ratio. | ✅
| P22 | **CLI amount validation** — `order-create --amount` validated at the CLI layer: parses to minor units, rejects zero/negative/non-numeric with actionable error. Bad amounts no longer surface deep in `journal::parse_amount` during executor runs. | ✅

Research driving P8–P22: [`PAYMENTS_RESEARCH.md`](PAYMENTS_RESEARCH.md) — x402 governance/V2 (Linux Foundation, legacy-rail facilitators, `settlement_pending`, receipt dedupe) and multi-currency ledger + fiat-hybrid patterns.

---

## 12. Success criteria

- [x] Every money movement has exactly one journal batch; every batch sums to zero.
- [x] Replayed orders never double-execute (idempotency + rail dedupe).
- [x] Terminal failures land in the DLQ with evidence; requeue never duplicates.
- [x] A tampered settlement file is rejected at the provenance stamp.
- [x] Every reconcile run is provable in the MMR.
- [x] No card data stored; PCI out of scope holds by construction.
- [x] All unit/integration/cross-tool tests green; clippy `-D warnings`; fmt clean.

---

## 13. Open questions

1. **Store:** v1 file-based (one-home convention) vs SQLite for the
   orders/queue — SQLite buys transactional guarantees for the retry/DLQ
   state machine at the cost of a new dependency.
2. **Rail access:** should the executor call Stoa directly (like
   origin-wallet does) or only through `origin-wallet`'s public API? This
   design assumes the latter (composition stays inside origin-tools).
3. **Currency:** multi-currency journal capability is now in (P9: `FxRate`
   on postings, 2-currency batches). Order-level settlement-currency field
   and per-currency PSP settlement files are implemented. FX markup is now
   explicit (`markup_bps` on `FxRate`, signed in `signed_body()`). Open:
   who owns the FX rate source (operator-configured vs rail-provided).
4. **Webhooks:** webhook receiver is implemented (`webhook.rs`) for async
   settlement callbacks. Open: delivery guarantees (at-least-once vs
   exactly-once callback handling) and callback payload encryption
   (encrypted at rest in the vault vs plaintext JSONL).
5. **Settlement file format:** PSP-provided (CSV/JSON) vs our own
   signed format for the native rail — a signed native settlement file
   would make reconciliation fully automated on both sides.
6. **Fraud scoring:** `ComplianceScorer` trait is wired into the executor
   (P16). Open: production-grade scoring backends (Chainalysis/Elliptic)
   and per-transaction velocity limits.
7. **Card rail ACP contract:** the `POST /authorize` facilitator API is
   mocked in tests (P11). Open: real-world ACP spec alignment and 3-D
   Secure async flow for the `settlement_pending` path.

---

## 14. Appendix

### A. File paths

```
Payments root:    ~/.origin/payments/
Config:           ~/.origin/payments/config.toml
Events/orders:    ~/.origin/payments/payment_events.jsonl, payment_orders.jsonl
Journal:          ~/.origin/payments/journal.jsonl
Queues:           ~/.origin/payments/retry_queue.jsonl, dlq.jsonl
Reconcile runs:   ~/.origin/payments/reconcile/*.json
MMR state:        ~/.origin/payments/mmr.bin
PSP vault:        ~/.origin/payments/psp_vault/  (origin-pass)
Key custody:      ~/.origin/payments/keys/       (origin-secrets)
Failure journal:  ~/.origin/failures.log
```

### B. Related existing work (do not redo)

- **Stoa SPEC §10** (sibling `stoa` repo, embedded via `origin-wallet`):
  native evidence-based channels, multi-rail `pay()` + smart routing,
  spend policy, time-boxed finality, disputes → Snowball, stealth.
- **origin-crypto-sdk `signing::wire::HybridSig`** — the Ed25519+Falcon-1024
  hybrid-signature **wire format** lives in the SDK (sole crypto provider);
  `origin-payments` serializes/verifies via the SDK type so the bytes format
  crosses no external-crate boundary.
- **origin-wallet** (`pay_native`, `encode_ledger_entry`, `MeshId`/`Mesh`/
  `LedgerEntry` re-exports; `pay_service`, `settle_channel_with`, MMR
  history, shard backup): the origin-suite "Stoa pay surface". `origin-payments`
  reaches the whole native mesh rail through these re-exports and **no
  longer depends on the external stoa crate directly** (removed from its
  Cargo.toml + lockfile) — MeshId parsing, the Mesh transport, and ledger
  entry encoding all route through `origin-wallet`.
- **Sibling `payments` repo**: x402 multi-chain contracts (Base/Arbitrum/
  Flare) — the on-chain PSP rail for the `Http402` case.
- **origin-secrets**: threshold vault + audit/compliance export patterns
  reused verbatim for custody and compliance.

---

**Document Version:** 1.0.0
**Last Updated:** August 23, 2026
**Status:** Draft — ready for review before implementation
