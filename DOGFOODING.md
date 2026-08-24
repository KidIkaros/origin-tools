# Origin Payments — Dogfood Walkthrough

**Date:** August 23, 2026
**Binary:** `origin-payments` (CLI + lib), exercising the full operator
lifecycle through the real binary against a live payer wallet and a standing
payee Stoa node — no mocks below the rail layer.

This is the canonical end-to-end smoke test. Run it after any change that
touches the executor, journal, settlement, reconciliation, audit, or admin
surface. It doubles as a spec-by-example of the happy path and the failure
paths that are supposed to *work* (retry, DLQ, requeue).

---

## 0. Prerequisites

```bash
cargo build -p origin-payments -p origin-wallet
export ORIGIN_HOME=/tmp/do-origin   # or any scratch dir
DF=/tmp/do-origin
mkdir -p "$DF"
```

The executor's native rail pays from a payer wallet file to a payee
**MeshId** over a loopback Stoa mesh. You need:

1. A **payer wallet** (`origin-wallet` CLI) — the executor opens it with
   `-p <passphrase-file>`.
2. A **standing payee node** bound at a known loopback address. The wallet
   CLI binds nodes ephemerally per command, so for a durable payee use the
   same pattern as `origin-payments/tests/executor_native.rs`
   (`payer_and_payee`): `stoa::Mesh::bind` with the payee's node keys,
   then poll `ledger_snapshot()` in a loop to drive the mesh's I/O.
3. A **payments identity** for signed orders (optional; unsigned orders
   still flow through the full lifecycle with `signed: false`).

---

## 1. Init + wallets

```bash
origin-payments init --per-tx-cap 500.00
origin-payments status

# payer wallet (executor pays from this)
origin-wallet create --out "$DF/payer.wallet"

# payee node keys + MeshId — `network doctor` prints the MeshId; bind a
# standing node for the payee (see §0), e.g. 127.0.0.1:19000
```

---

## 2. Orders — plain and multi-currency (FX)

```bash
# plain USD order to the payee's MeshId
origin-payments order-create --checkout c-1 --to <payee-meshid> \
    --amount 7.77 --currency USD --json

# FX order: 10.00 USD -> EUR @ 0.9 (merchant settles in EUR)
origin-payments order-create --checkout c-2 --to <payee-meshid> \
    --amount 10.00 --currency USD --fx-from USD --fx-to EUR --fx-rate 0.9 --json
```

Both are idempotent on the order id and roll up into a `PaymentEvent`.

---

## 3. Executor pass (native rail)

```bash
origin-payments executor-run \
    --wallet "$DF/payer.wallet" \
    --peer-addr 127.0.0.1:19000 \
    -p "$DF/payer.passphrase"
```

The FX order settles as a **multi-currency batch** — the journal shows
`USD +10.00 / EUR −9.00` (10.00 USD @ 0.9), the P9 FX conversion working
end-to-end through the real binary + real mesh.

**Credit note:** the mesh credit is *cumulative* (`remaining = limit −
sent`), and without a standing line each order re-opens a fresh channel
whose limit is already exhausted by prior payments — the second order in a
pass fails with "payment exceeds credit limit" and retries with backoff.
Pre-fund the line to settle many orders against one channel:

```bash
origin-payments executor-run --wallet "$DF/payer.wallet" \
    --peer-addr 127.0.0.1:19000 -p "$DF/payer.passphrase" \
    --peer-credit 25.00
```

`--peer-credit` opens the channel with a 25.00 `ENTRY_OPEN` limit, so
7.77 + 10.00 both settle in one pass. `--peer-addr` is only required when
a ready order rides the native rail — http402/card passes run without it.

---

## 3b. Card rail (tokenized — no PAN, PCI out of scope)

The card rail is ACP-style tokenized authorization: the order carries a
PSP-issued **token reference** + network + last4 (`--card-*`, all three or
none — never the PAN), and the executor asks the vault-configured ACP
facilitator to authorize it:

```bash
# configure the ACP facilitator (URL + API key, TOTP-gated)
origin-payments psp-configure card --secret-file "$DF/acp.key" \
    --facilitator-url https://acp.example --totp <code>

# order with card tokenization (implies --rail card)
origin-payments order-create --checkout c-3 --to merchant-acct \
    --amount 19.99 --currency USD \
    --card-token tok_visa_4242 --card-network VISA --card-last4 4242

# executor pass settles it via the facilitator's POST /authorize
origin-payments executor-run -p "$DF/payer.passphrase"
```

- `success` → journal batch + `CardAcp` receipt (network •••• last4).
- `settlement_pending` (3DS / async auth) → `REQUIRES_ACTION`.
- `declined` → terminal → DLQ with evidence.
- Missing token or unconfigured facilitator refuses **before any HTTP
  call** with an actionable hint.

---

## 4. Journal + settlement export

```bash
origin-payments journal-balance
origin-payments journal-export --from 2026-08-23

# one provenance-stamped settlement file per currency (P9): the FX order
# is attributed to EUR — its settlement currency
origin-payments settlement-export --date 2026-08-23
```

---

## 5. Reconciliation (P5)

```bash
# pull one PSP settlement file per currency (multi-currency day — each
# pull persists per-currency and all files feed the run), then compare
# against the internally-settled orders
origin-payments reconcile-pull --date 2026-08-23 --file psp-eur.json --currency EUR
origin-payments reconcile-pull --date 2026-08-23 --file psp-usd.json --currency USD
origin-payments reconcile-run --date 2026-08-23
origin-payments reconcile-list

# CLEAN run => all orders matched / 0 mismatches, checkpointed to the MMR
origin-payments reconcile-export --run <run-id> --format soc2 --out reconcile-soc2.json
```

---

## 6. Audit (P7)

```bash
origin-payments audit-show
origin-payments audit-verify        # hash chain valid
origin-payments audit-export --format soc2 --out audit-soc2.json
```

---

## 7. Admin surface (TOTP-gated)

```bash
# 2FA first — prints the otpauth:// URI for the operator's authenticator
origin-payments admin2fa-init            # `admin-2fa-init` also works

# configure a PSP rail (TOTP-gated; secret + facilitator URL to the vault)
origin-payments psp-configure http402 \
    --secret-file "$DF/facilitator.key" \
    --facilitator-url http://facilitator:8080 \
    --totp <code>

# custody: 2-of-3 sharding of the merchant master key (TOTP-gated).
# Passphrases shorter than 12 chars are refused up front.
origin-payments keys-backup --shards 3 --threshold 2 --totp <code> -p "$DF/custody.passphrase"
```

---

## 8. Failure paths that are supposed to work

- **Retry with backoff + jitter** — a transient rail refusal (e.g. credit
  limit, unreachable peer) leaves the order `FAILED`, schedules a
  `RetryJob`, and re-attempts on later passes as deadlines lapse.
- **DLQ at max attempts** — after `max_attempts`, the order goes terminal
  and is dead-lettered with evidence (`dlq-list`).
- **Requeue** — `order-retry <id>` (alias `dlq-requeue`) moves a DLQ'd
  order back to `NOT_STARTED`; the next executor pass settles it.
- **Crash recovery** — orders stuck in `EXECUTING` past the TTL are
  re-queued by the sweep at the top of each pass.
- **Non-interactive passphrase** — `executor-run` without `-p` on a
  non-TTY stdin fails with a hint pointing at `-p/--passphrase-file`.

---

## Findings that came out of dogfooding (fixed)

| Finding | Fix |
|---|---|
| `admin-2fa-init` vs `admin-2fa-init` naming guess | `visible_alias = "admin-2fa-init"` — both spellings work |
| `executor-run` without TTY failed obscurely at the prompt | clear `-p/--passphrase-file` hint when stdin is not a TTY |
| Second order in a pass always hit the cumulative mesh credit limit | `--peer-credit <amount>` pre-funds one standing channel |
| Pulling a second currency's PSP file overwrote the first (`<date>.json` single-file key) — multi-currency days couldn't reconcile | `reconcile-pull --currency <CCY>` persists per-currency; `reconcile-run` merges every pulled file |
| Dashboard "last reconcile" was nondeterministic among same-day runs (`read_dir` order) | runs carry `created_at`; `reconcile-list`/`status` sort by date then created_at |
| Card rail was a stub (`enabled but not implemented`) | tokenized `POST /authorize` rail: `order-create --card-*`, `psp-configure card`, executor settle/pending/DLQ |
| `keys-backup` rejected weak passphrases without saying why | (already enforced; docs above state the 12-char minimum) |

## Additional capabilities (research-driven)

These shipped alongside the dogfood findings, driven by
[`PAYMENTS_RESEARCH.md`](PAYMENTS_RESEARCH.md) (x402 V2 + multi-currency
+ fiat research):

| Capability | What it does |
|---|---|
| **Rail-level receipt dedupe cache** | `receipt_dedupe.jsonl` — SHA-3-256 of receipt bytes checked before journaling; duplicate settlements refused (x402 spec §4.2) |
| **ACH/SEPA fiat rail** | `RailHint::Ach` — same verify/settle split as http402, but the facilitator settles on ACH/SEPA/wire; `psp-configure ach`; `RailReceipt::Ach` with bank-rail trace id |
| **Merchant settlement preference** | `config.toml: settlement_preference = "hold" | "off_ramp" | "split"` + `split_pct` — merchant-level optionality for inbound payments (Fireblocks pattern) |
| **Compliance scoring interface** | `ComplianceScorer` trait — `AcceptAll` (default), `RuleBasedScorer` (amount thresholds + counterparty allowlist); plugin for Chainalysis/Elliptic backends |
| **Compliance wired into executor** | `settle()` calls `ComplianceScorer` before each rail settle; `Reject` → DLQ, `Flag` → audit note; CLI `--compliance-rule <json>` / `--compliance-accept-all` |
| **Deferred settlement CLI** | `deferred-list`, `deferred-commit`, `deferred-inspect` — operators can inspect/trigger deferred batches without running the executor |
| **Retry-After from facilitators** | `settle_http402` / `settle_ach` parse `Retry-After` HTTP header; facilitator timing hints respected instead of hardcoded backoff |
| **Webhook receiver** | `POST /settlement-callback` (std TcpListener) — validates HMAC-SHA256 callback signature, looks up order by `settlement_ref`, transitions `REQUIRES_ACTION → NOT_STARTED`. CLI: `webhook-listen --addr` |
| **FxRate markup_bps** | `FxRate` gains `markup_bps` (merchant's margin in basis points); signed in canonical order body; CLI `--fx-markup <bps>` |
| **Settlement preference payout** | `settlement_preference` config now drives the payout path: `Hold` → hold stablecoin, `OffRamp` → fiat off-ramp, `Split` → split at `split_pct` |
| **CLI amount validation** | `order-create --amount` rejects zero/negative/non-numeric at CLI layer with actionable error |

---

## Verification checklist

- `cargo test -p origin-payments` — full suite, default features
- `cargo test -p origin-payments --features tls` — includes the real
  rustls loopback handshake test
- `cargo clippy -p origin-payments --no-deps -- -D warnings` (both configs)
- `cargo fmt -p origin-payments --check`
