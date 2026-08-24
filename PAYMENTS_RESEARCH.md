# x402 + Multi-Currency (incl. Fiat): Research for origin-payments
*Generated: 2026-08-23 | Sources: 17 | Confidence: High (protocol/mechanics, primary sources) / Medium (market claims)*

## Executive Summary

x402 — the HTTP-402 stablecoin payment standard — has gone from a Coinbase
experiment (May 2025) to a Linux Foundation–governed standard with an
operational foundation (July 2026) and a traditional-payments charter member
(Fiserv). Its V2 (Dec 2025) explicitly targets exactly the two things this
research was asked about: **multi-chain stablecoin payments AND legacy fiat
rails** (ACH/SEPA/card "facilitators" fit the same payment model). The
facilitator architecture separates *verification* from *settlement*, and the
spec ships production semantics (`settlement_pending`, duplicate-settlement
caches) that map 1:1 onto origin-payments' executor retry, REQUIRES_ACTION,
and idempotency design. On multi-currency: the industry consensus is
per-currency balances with explicit FX legs and fee postings in a double-entry
journal — precisely the extension the origin-payments journal (§13 Q3) was
already anticipating. For fiat, the mature pattern is **optionality at the
merchant account level**: hold stablecoin, off-ramp to fiat, or split — with
net settlement of inbound/outbound stablecoin flows to minimize on/off-ramp
fees.

---

## 1. x402: what it is, who governs it, where it stands

**Mechanics.** x402 revives the dormant HTTP `402 Payment Required` status as
a machine-readable payment signal. A client requests a gated resource; the
server replies `402` with payment requirements; the client signs a payment
payload and retries with a payment header; a **facilitator** verifies the
payload and settles on-chain; the server returns the resource plus a receipt
header ([Cloudflare, x402 Foundation launch](https://blog.cloudflare.com/x402/);
[x402 docs — Facilitator](https://docs.x402.org/core-concepts/facilitator)).
V2 moved all payment data into headers (`PAYMENT-REQUIRED`,
`PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`), all Base64-encoded JSON
([x402 V2 launch](https://x402.org/x402-v2-launch/)).

**Origin & governance.** Authored by Coinbase (May 2025)
([Coinbase developer platform](https://www.coinbase.com/developer-platform/discover/launches/x402)).
The x402 Foundation was launched with Cloudflare (Sep 2025)
([Cloudflare](https://blog.cloudflare.com/x402/)); the Linux Foundation
launched the x402 Foundation and accepted the protocol donation on **April 2,
2026** ([Linux Foundation press](https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol)),
with **operational launch July 14, 2026**
([Linux Foundation press](https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications)).
Fiserv — a top-tier traditional processor — joined as a charter member
([Fiserv](https://investors.fiserv.com/news-releases/news-release-details/fiserv-named-charter-member-x402-foundation)),
and MetaMask's explainer summarizes it as "Coinbase created it in 2025; the
Linux Foundation has governed it since April 2, 2026"
([MetaMask](https://metamask.io/news/what-is-x402)).

**Scale (vendor-claimed).** x402 V2 states the protocol processed **100M+
payments** in its first ~6 months across APIs, apps, and agents
([x402 V2](https://x402.org/x402-v2-launch/)). Treat the number as a
vendor claim; the governance + adoption signals (Cloudflare Agents SDK/MCP
integration, Fireblocks/Thirdweb/Nevermined facilitators, Fiserv) are the
more durable evidence.

---

## 2. x402 V2: the parts that matter for origin-payments

V2 (Dec 2025) was explicitly designed for extensibility across networks and
payment types ([x402 V2](https://x402.org/x402-v2-launch/)):

- **Multi-chain by default** — stablecoins/tokens on Base, Solana, other L2s,
  "no custom logic required."
- **Legacy rail compatibility** — "Facilitators for ACH, SEPA, or card
  networks fit into the same payment model." This is the fiat bridge: an
  x402 requirement can be satisfied by a *fiat* facilitator, not only an
  on-chain one. Cloudflare's launch post said the same: "Future versions of
  x402 could be agnostic of the payment rails, accommodating credit cards and
  bank accounts in addition to stablecoins" ([Cloudflare](https://blog.cloudflare.com/x402/)).
- **Dynamic `payTo` routing** — per-request recipient routing (addresses,
  roles, callback-based payout) for marketplaces/multi-tenant APIs.
- **Wallet-based sessions** — reusable access so clients skip re-paying on
  repeated calls (foundation for subscription/session patterns; SIWx via
  CAIP-122 as a fast-follow).
- **Discovery extension** — facilitators index available endpoints/pricing.

**Facilitator settlement semantics that map onto the executor**
([x402 docs — Facilitator](https://docs.x402.org/core-concepts/facilitator)):

1. **`settlement_pending` (EVM)** — when a settlement tx is broadcast but
   confirmation can't be established (RPC error/timeout), the facilitator
   returns a **non-terminal** `settlement_pending` with the broadcast tx hash
   so callers "can reconcile on chain before deciding whether to retry."
   → This is *exactly* the origin-payments `REQUIRES_ACTION` / retryable
   failure class: don't DLQ; reconcile against the tx hash in the receipt.
2. **Duplicate-settlement protection (Solana)** — facilitators keep a
   `SettlementCache` that rejects duplicate settlement attempts for the same
   payload; merchants settling directly "must implement equivalent duplicate
   detection yourself."
   → This is the rail-level twin of origin-payments' `payment_order_id`
   idempotency: the receipt hash cache in the executor's settle path.
3. **Facilitator is non-custodial** — it verifies and executes signed
   payloads; it never holds funds.
4. **Reference `verify`/`settle` API shape** — `POST /verify` (validate +
   simulate) and `POST /settle` (execute + return receipt); the receipt
   returned to the client is the `PAYMENT-RESPONSE` header
   ([Nevermined facilitator](https://nevermined.ai/blog/the-payment-layer-ai-agents-actually-need-introducing-the-nevermined-x402-facilitator);
   [Coinbase CDP verify-payment](https://docs.cdp.coinbase.com/api-reference/v2/rest-api/x402-facilitator/verify-payment)
   — `exact`, `upto`, and `batch-settlement` schemes; [Avalanche Builder Hub flow](https://build.avax.network/academy/blockchain/x402-payment-infrastructure/03-technical-architecture/01-payment-flow)).

**Deferred settlement (proposed by Cloudflare).** Cloudflare proposed a
"deferred" x402 scheme that decouples the cryptographic handshake from
settlement: signature-verified commitments roll up into **daily/batch
settlement** over traditional rails (cards/bank) or stablecoins
([Cloudflare](https://blog.cloudflare.com/x402/)). This is a standards-level
endorsement of the *exact* batching origin-payments already does in the
executor + reconciliation loop.

---

## 3. Multi-currency: the ledger model

The consensus architecture for multi-currency fintech ledgers
([SDK.finance — multi-currency ledger](https://sdk.finance/blog/what-is-a-multi-currency-ledger-how-fintechs-track-balances-transfers-and-settlement-across-currencies/)):

- **Separate balance state per currency** — USD/EUR/GBP are distinct balance
  objects with independent posting histories; never one aggregate number.
- **Double-entry with currency context** — every posting carries its currency;
  the balancing rule applies **within each currency**, not across them.
- **Cross-currency movements are explicit** — a USD receipt funding a EUR
  payout is modeled as currency-specific postings **plus a separate FX entry
  against a dedicated fee/PL account**, not one opaque net update.
- **Fees are first-class postings** (application fee, FX markup, payout fee).
- **Reconciliation-ready history** — every entry carries enough metadata
  (provider reference, payment ID, settlement batch) to stitch back to bank
  files / processor settlement reports; settlement is matched per currency.

NetSuite's multicurrency guidance agrees: consistent conversion to a reporting
currency, uniformly applied ([NetSuite](https://www.netsuite.com/portal/resource/articles/accounting/multi-currency-accounting.shtml)).

**FX accounting mechanics.** Realized/unrealized FX gains and losses are
recognized when rates move between transaction and settlement dates; a
conversion is journaled with an FX gain/loss leg in the reporting currency
([CFI — FX gain/loss](https://corporatefinanceinstitute.com/resources/accounting/foreign-exchange-gain-loss/);
[Zuora — FX journal entries](https://docs.zuora.com/en/accounts-receivable/finance/accounting-periods/view-accounting-period-balances/foreign-currency-gains-and-losses-journal-entries)).
On the acquiring side, **dynamic currency conversion (DCC)** is how card rails
monetize conversions — merchants can be charged up to ~7% for the conversion
service on top of scheme FX fees ([Stripe — DCC](https://stripe.com/resources/more/dynamic-currency-conversion-how-it-works-how-to-handle-it-and-how-stripe-can-help);
[Absa/Botswana DCC note](https://www.facebook.com/AbsaBankBotswana/posts/dynamic-currency-conversion-dcc-allows-international-customers-to-pay-in-their-h/1489757256516183/)).
The takeaway: an FX leg is both an accounting necessity and a margin line —
the operator should control the rate/markup, not silently inherit a rail's.

---

## 4. Fiat + stablecoin hybrid rails

The mature pattern for mixing stablecoin and fiat is **merchant-level
optionality with net settlement**
([Fireblocks — PSP payments blueprint](https://www.fireblocks.com/report/payments-blueprint-stablecoin-pay-ins-settlement-psps)):

- **Segregated deposit accounts per merchant** — every inbound payment is
  attributable without matching logic; multi-chain receive support.
- **Inbound compliance screening before crediting** (Chainalysis/Elliptic
  scoring, Travel Rule, auto-quarantine of flagged payments) — the fraud/risk
  question (§13 Q6) has a concrete reference shape.
- **Sweep + convert optionality** — per-merchant preference: hold stablecoin,
  off-ramp to fiat, or a split; the off-ramp converts to local currency and
  pays the merchant's bank account.
- **Net settlement** — inbound stablecoin flows feed outbound settlement
  directly, avoiding fiat round-trips and on/off-ramp fees.
- **T+0 settlement** vs T+2/T+3 on card rails; stablecoin acceptance ≈0.5%
  vs 2–3% card; no chargebacks (blockchain finality).

The "stablecoin sandwich" (fiat → stablecoin → transfer → fiat) is the
academic frame for cross-border rails: on-ramp, on-chain transfer, off-ramp,
with FX executed near benchmark rates ([HBS — competing rails for cross-border payments](https://www.hbs.edu/ris/download.aspx?name=Du_Huang_Scharfstein_14Feb2016.pdf)).
WalletConnect Pay and similar gateways already offer merchants **settlement
choice**: stablecoin on-chain, or fiat via off-ramp
([WalletConnect Pay](https://x.com/WalletConnect/article/2059930030168215749)).

---

## 5. Mapping to origin-payments: concrete recommendations

**x402 rail (the `Http402` stub):**
1. Adopt the **V2 header shape** as the rail contract: `PAYMENT-REQUIRED`
   (base64 requirements) → `PAYMENT-SIGNATURE` (signed payload) →
   `PAYMENT-RESPONSE` (base64 settlement receipt). The receipt becomes
   `RailReceipt::Http402 { receipt }` — it is already base64 JSON, so the
   current `Vec<u8>` field fits.
2. Implement the **facilitator `verify`/`settle` split** in the executor:
   `verify` is the cheap pre-rail check (policy/cap before any spend);
   `settle` is the money move. This mirrors the existing EXECUTING-before-call
   discipline.
3. Treat **`settlement_pending` as the `REQUIRES_ACTION` / retryable class**,
   with the tx hash from the receipt as reconciliation evidence — do not DLQ
   it. This is a *spec-sanctioned* justification for the REQUIRES_ACTION
   state that currently has no producing rail.
4. Wire the **receipt-hash dedupe** (rail-level) into the settle path — the
   spec explicitly requires merchants settling directly to implement
   duplicate detection; origin-payments' `payment_order_id` idempotency is
   the complementary layer.
5. The sibling `payments` repo's x402 contracts (Base/Arbitrum/Flare) are the
   natural first `networkId`s for the facilitator config.

**Multi-currency (§13 Q3):**
6. Keep per-currency balances (already the journal's model — postings carry
   currency; net-by-currency exists). The change is narrow: **allow batches
   with an FX leg** — debit USD, credit EUR, plus a third posting to an
   `FX`/PL account carrying the conversion markup. The existing
   "sum must be zero **within a currency**" rule becomes "per-currency net
   sums to zero, plus an FX-settlement posting"; property tests extend to
   3-leg FX batches.
7. Make the FX rate/markup an **explicit, signed part of the order/batch**
   (not inherited from a rail) — both for audit and because DCC-style
   markups are a margin line the operator should own.

**Fiat (§13 Q3/Q4/Q5):**
8. Model fiat as **just another rail** via x402's legacy-rail facilitators
   (ACH/SEPA/card fit the same payment model — no special casing), or as a
   PSP rail (`CardAcp`) with the settlement file being the PSP's per-currency
   file. Reconciliation already compares per-currency internal net against
   the PSP file — extend `SettlementRow` with a currency field.
9. Add **merchant-level settlement preference** to the payout design (P6):
   hold / off-ramp / split, with net settlement of inbound stablecoin against
   outbound payouts — the current `OrderDirection::Payment|Payout` +
   `psp-configure` vault is the natural home for the off-ramp credential.
10. **Compliance screening on inbound** (Chainalysis/Elliptic-style scoring,
    quarantine) is the concrete answer to §13 Q6 — a plugin interface rather
    than a hard dependency, matching the suite's TrustGraph-as-signal stance.

---

## Key Takeaways

- **x402 is real, governed, and converging on origin-payments' design.**
  V2's rail-agnostic facilitators make fiat a first-class x402 concept; the
  Linux Foundation + Fiserv signal it will outlive the AI-agent hype cycle.
- **The spec already defines the executor's hard cases.** `settlement_pending`
  legitimizes `REQUIRES_ACTION` + on-chain reconciliation; duplicate-settlement
  caches legitimize receipt-hash idempotency. Implementing the V2 header
  contract is a small, well-specified surface.
- **Multi-currency is a journal extension, not a rewrite.** Per-currency
  balances + explicit FX/fee legs is the industry-standard model and matches
  the existing double-entry design; the work is a 3-leg FX batch + signed
  rate, plus per-currency settlement files.
- **Fiat belongs in the rail abstraction, not beside it.** x402 legacy-rail
  facilitators (or PSP rails) slot into the existing
  `RailHint`/`enabled_rails`/receipt pipeline; merchant optionality
  (hold/off-ramp/split) + net settlement is the payout-layer feature.

## Sources

1. [Cloudflare — Launching the x402 Foundation](https://blog.cloudflare.com/x402/) — x402 flow, deferred settlement proposal, rail-agnostic future (read in full).
2. [x402 — Introducing x402 V2](https://x402.org/x402-v2-launch/) — V2 feature set, 100M+ payments claim, multi-chain + legacy rails (read in full).
3. [x402 docs — Facilitator](https://docs.x402.org/core-concepts/facilitator) — verify/settle split, settlement_pending, duplicate-settlement cache (read in full).
4. [Coinbase — Introducing x402](https://www.coinbase.com/developer-platform/discover/launches/x402) — original launch, May 2025.
5. [Linux Foundation — x402 Foundation launch](https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol) — April 2, 2026 governance handover.
6. [Linux Foundation — Operational launch](https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications) — July 14, 2026.
7. [Fiserv — charter member](https://investors.fiserv.com/news-releases/news-release-details/fiserv-named-charter-member-x402-foundation) — traditional-payments adoption signal.
8. [MetaMask — What is x402?](https://metamask.io/news/what-is-x402) — concise explainer; governance summary.
9. [Eco — x402 Protocol Explained](https://eco.com/support/en/articles/14839402-x402-protocol-explained) — facilitator confirms settlement, receipt header.
10. [Nevermined — x402 facilitator](https://nevermined.ai/blog/the-payment-layer-ai-agents-actually-need-introducing-the-nevermined-x402-facilitator) — reference verify/settle API shape.
11. [Coinbase CDP — verify-payment](https://docs.cdp.coinbase.com/api-reference/v2/rest-api/x402-facilitator/verify-payment) — exact/upto/batch-settlement schemes.
12. [Avalanche Builder Hub — x402 payment flow](https://build.avax.network/academy/blockchain/x402-payment-infrastructure/03-technical-architecture/01-payment-flow) — X-PAYMENT header flow.
13. [SDK.finance — What is a multi-currency ledger](https://sdk.finance/blog/what-is-a-multi-currency-ledger-how-fintechs-track-balances-transfers-and-settlement-across-currencies/) — per-currency balances, FX legs, reconciliation (read in full).
14. [NetSuite — Multicurrency accounting](https://www.netsuite.com/portal/resource/articles/accounting/multi-currency-accounting.shtml) — conversion to reporting currency.
15. [CFI — Foreign exchange gain/loss](https://corporatefinanceinstitute.com/resources/accounting/foreign-exchange-gain-loss/) — realized vs unrealized FX accounting.
16. [Fireblocks — PSP payments blueprint](https://www.fireblocks.com/report/payments-blueprint-stablecoin-pay-ins-settlement-psps) — stablecoin pay-ins, merchant optionality, net settlement (read in full).
17. [Stripe — Dynamic currency conversion](https://stripe.com/resources/more/dynamic-currency-conversion-how-it-works-how-to-handle-it-and-how-stripe-can-help) — DCC markup model.
18. [HBS — Competing rails for cross-border payments](https://www.hbs.edu/ris/download.aspx?name=Du_Huang_Scharfstein_14Feb2016.pdf) — stablecoin-sandwich academic frame.

## Methodology

Searched 8 query variations across general web + news (Serper-backed search).
Deep-read 5 primary sources in full: Cloudflare x402 Foundation post, x402 V2
launch, x402 facilitator docs, SDK.finance multi-currency ledger, Fireblocks
PSP blueprint. Analyzed ~18 sources total; protocol/mechanics claims rely on
primary (x402.org, Linux Foundation, Cloudflare, Coinbase) documentation;
market claims (100M+ payments) are flagged as vendor-sourced. Sub-questions:
(1) what is x402 + governance timeline; (2) V2 capabilities incl. legacy/fiat
rails; (3) facilitator settlement semantics and how they map to retry/
idempotency; (4) multi-currency ledger + FX accounting mechanics;
(5) fiat+stablecoin hybrid patterns (PSPs, on/off-ramps, net settlement).
Gaps: no independent verification of the 100M-payment figure; x402 deferred
settlement is a Cloudflare proposal, not yet a ratified spec feature.
