# Origin Payments — Dogfood Walkthrough

**Date:** August 23, 2026 (updated August 28 — native rail now settles
through the offline `NativeRail` seam; no Stoa node required)
**Binary:** `origin-payments` (CLI + lib), exercising the full operator
lifecycle through the real binary against a payer wallet — no mocks below
the rail layer.

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

The executor's native rail pays from a payer wallet file through
`origin-wallet`'s **`NativeRail` trait seam** — the offline
`LocalNativeRail` default (debit an account, record an MMR transaction,
return a signed receipt; no peer address, no node). The external **stoa**
project implements the trait later for the real mesh rail. You need:

1. A **payer wallet** (`origin-wallet` CLI) — the executor opens it with
   `-p <passphrase-file>`.
2. A **payments identity** for signed orders (optional; unsigned orders
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
    -p "$DF/payer.passphrase"
```

The FX order settles as a **multi-currency batch** — the journal shows
`USD +10.00 / EUR −9.00` (10.00 USD @ 0.9), the P9 FX conversion working
end-to-end through the real binary. The offline native rail debits the
payer wallet and records an MMR leaf per order, and multiple orders in
one pass all settle (each payment is an independent debit — the mesh
credit-line semantics moved to stoa with the mesh).

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

- **Retry with backoff + jitter** — a transient rail refusal (e.g.
  insufficient funds on the offline native rail, an unreachable
  facilitator on http402/card) leaves the order `FAILED`, schedules a
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
| Second order in a pass always hit the cumulative mesh credit limit | (mesh rail moved to stoa) the offline native rail debits per order — no credit line; multiple orders settle in one pass |
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

---

# Every Crate as a Foundational Dependency — Dogfood Walkthrough

**Date:** August 28, 2026

Each `origin-*` crate in the workspace is a starter-kit-style foundation that
downstream projects can consume as a dependency. This walkthrough dogfoods all
21 lib crates in dependency order through one runnable example per crate
(`<crate>/examples/dogfood.rs`), exercising the public library surface (typed
APIs, SDK paths, and `cli`+`commands` dispatch) the way a downstream consumer
would.

Run everything with:

```bash
cargo build --examples --workspace
for c in origin-common origin-identity origin-pass origin-seal origin-seed \
         origin-shard origin-proof origin-stealth origin-entropy \
         origin-schnorr origin-archive origin-provenance origin-attest \
         origin-channel origin-crawler origin-secrets origin-network \
         origin-vcs origin-canary origin-wallet origin-payments; do
    cargo run --quiet --example dogfood -p "$c"
done
```

## Status

| Crate | Layer | Example | Status |
|-------|-------|---------|--------|
| origin-common | 0 — home, identity store, envelope, I/O | `examples/dogfood.rs` | ✅ |
| origin-identity | 1a — hybrid Ed25519+Falcon identities | `examples/dogfood.rs` | ✅ |
| origin-pass | 1a — encrypted vault + TOTP | `examples/dogfood.rs` | ✅ |
| origin-seal | 1a — KDF + MAC + AEAD sealing | `examples/dogfood.rs` | ✅ |
| origin-seed | 1b — Argon2id-sealed seed blobs | `examples/dogfood.rs` | ✅ |
| origin-shard | 1b — Reed-Solomon K-of-N sharing | `examples/dogfood.rs` | ✅ |
| origin-proof | 1b — MMR commitments | `examples/dogfood.rs` | ✅ |
| origin-stealth | 1b — stealth addresses + PoW | `examples/dogfood.rs` | ✅ |
| origin-entropy | 1b — entropy audit gate | `examples/dogfood.rs` | ✅ |
| origin-schnorr | 1b — Schnorr batch proofs | `examples/dogfood.rs` | ✅ |
| origin-archive | 1c — encrypted archive | `examples/dogfood.rs` | ✅ |
| origin-provenance | 1c — stamps, manifests, watermarks | `examples/dogfood.rs` | ✅ |
| origin-attest | 1c — trust graph, audit, revocation | `examples/dogfood.rs` | ✅ |
| origin-channel | 1c — forward-secret sessions | `examples/dogfood.rs` | ✅ |
| origin-crawler | 1c — crawl frontier + corpus | `examples/dogfood.rs` | ✅ |
| origin-secrets | 2 — K-of-N custody + encrypted vault | `examples/dogfood.rs` | ✅ |
| origin-network | 2 — relay, presence, inbox | `examples/dogfood.rs` | ✅ |
| origin-vcs | 2 — git-like DVCS | `examples/dogfood.rs` | ✅ |
| origin-canary | 3 — canary embedding + verification | `examples/dogfood.rs` | ✅ |
| origin-wallet | 3 — wallet + native rail seam | `examples/dogfood.rs` | ✅ |
| origin-payments | 3 — payment backend | `examples/dogfood.rs` | ✅ |

## Findings (the point of dogfooding)

1. **`origin-entropy check` and `origin-stealth verify` are not embeddable.**
   Both commands call `std::process::exit(1)` when their check fails instead of
   returning `Err` — a downstream library consumer cannot recover from a failed
   gate/verification; the whole process dies. The examples work around this by
   probing the failing path in a subprocess and asserting the exit code.
   **Suggestion:** return `Result<(), Error>` and let the binary map it to an
   exit code.

2. **`origin-entropy check` flakes on 256-byte samples.** The Shannon gate
   (`>= 7.5 bits/byte`) rejects genuinely random 256-byte CSPRNG samples ~50%
   of the time — the Shannon estimator is biased low at small `n`. A 4096-byte
   sample passes consistently. **Suggestion:** require larger samples or lower
   the threshold for small inputs.

3. **`origin-network` store-and-forward is asynchronous across connections.**
   An `inbox_pull`/`advert_fetch` issued immediately after a push on a
   *different* connection can see zero or partial frames (ordering is only
   guaranteed per connection). Consumers should poll. The examples use bounded
   retry loops.

4. **`origin-vcs` ref names containing `/` break the store.** `branch feature/x`
   writes `refs/heads/feature/x`, turning `feature` into a directory; a later
   `read ref feature` fails with `Is a directory (os error 21)`. **Suggestion:**
   reject `/` in ref names at the CLI layer.

5. **`origin-vcs` working tree did not compile** (pre-existing, uncommitted):
   `commands.rs` used `"…" + "…"` string concatenation inside a `format!`
   (Rust has no implicit literal concatenation). Fixed in place (one line).

6. **`origin-wallet` / `origin-payments` carried a stoa dependency (removed).**
   Both crates depended on the sibling `stoa` checkout (`../../stoa`), which
   blocked them (and `origin-cross-tests`) from building in the workspace.
   The wall between the foundation and stoa has since been drawn: **stoa is a
   separate project that *uses* these crates**, so `origin-wallet` no longer
   embeds the mesh. `origin-payments`' native rail now settles through a
   **`NativeRail` trait seam** in `origin-wallet` with an offline
   `LocalNativeRail` default (no peer address, no mesh); the external stoa
   project is expected to implement that trait for the real mesh rail later.
   Both dogfood examples run clean.

7. **Workspace pin had drifted** (pre-existing): `Cargo.toml` pinned
   `origin-crypto-sdk = "=0.7.1-rc.5"` while the sibling checkout (via
   `[patch.crates-io]`) is `0.7.1-rc.6`, so the workspace did not resolve at
   all. Bumped the pin to `=0.7.1-rc.6` (and updated `Cargo.lock`).

8. **`origin-shard recover` needs the split manifest.** `split` writes N shard
   files **plus** `metadata.json`; recovery reads `metadata.json` from the input
   directory, so a subset must carry it. It does support true erasure recovery
   (fewer than N shards present → decoded from the survivors).

## Verification checklist

- `cargo build --examples --workspace --exclude origin`
- `cargo run --quiet --example dogfood -p <crate>` for each of the 21 crates above
- `cargo test --workspace --exclude origin` (includes `origin-cross-tests`)
- `cargo clippy --workspace --exclude origin --all-targets`
- `cargo fmt --all --check` (clean across the whole workspace — the
  `origin-archive` diffs were formatted with `cargo fmt -p origin-archive`)
