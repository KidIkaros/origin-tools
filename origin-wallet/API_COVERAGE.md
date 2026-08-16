# Stoa Mesh API coverage — origin-wallet

Status: **audited 2026-08-16** against stoa `a419f0c` (re-audited
2026-08-16: the Mesh API is unchanged — this round touched only stoa
tests/docs). This is the definitive map of what the wallet's network
surface (`network.rs`) exposes from the full `stoa::Mesh` API — and the
deliberate gaps.

## Exposed

| Area | Mesh API | Wallet surface |
|---|---|---|
| Identity | `stoa_node_keys` → seed-derived node | `Wallet::stoa_node_keys` (stable per wallet, tested) |
| Bind / dial | `bind`, `local_mesh_id`, `local_addr`, `connect` | `pay_native`, `pay_native_via_relay`, `send_mail`, `discover_with`, `chat_*`, `serve_relay`, `lookup_service` |
| Relay | `dial_relayed`, `dial_any`, `upgrade_to_direct`, `serve_relay_with`, `publish_relay_hint` | `chat send --relay` (session pipe, upgrade to direct), `relay serve` (serves + now publishes its hint) |
| Payments | `open_channel`, `stream_payment`, `channel_state` | `pay` (direct) and `pay --relay` (A→relay→C), MMR history recording |
| Mail | `send_mail`, `poll_mail`, `mailbox`, `sync_registries` | `mail send`, `mail inbox` (persisted deduped mailbox, reloads across restart) |
| Chat | `subscribe`, `publish` | `chat send` (direct / relayed / upgraded tiers), `chat repl` (long-lived node), `chat listen` |
| Discovery | `discover`, `discover_in_room`, `lookup_service` | `discover --query [--room --point --peer-addr --save]` |
| Trust | `trust_scores` (indirectly, through discovery ranking) | `discover` ranks by cosine × trust |
| Relay ops | `relay_evict`, `relay_pardon`, `relay_stats` | `relay stats` / `relay evict` / `relay pardon` (abuse-control state, persisted across restarts — tested) |
| Service pay | `lookup_service`, `open_channel`, `stream_payment` | `pay --service <id>` (resolve a discovered service's record, pay its payment address — tested) |
| Settle | `settle_channel`, `channel_state` | `settle --to <id>` (time-boxed finality, SPEC §10.3 — tested) |
| Ops | `metrics`, `run_punch_refresh` | `network status` (mesh degree, pulse liveness, sync lag, gossip drop), `network doctor` (full SPEC §13 under the wallet identity) |
| Contacts | — | `contact add/list`, `discover --save` (top hit → contact in one step) |

## Not exposed (deliberate — agent-layer, not wallet-layer)

The wallet is the **human-facing surface**; the agent-economy decision
layer stays in stoa. These are all reachable by embedding the crate; the
CLI deliberately does not surface them:

- **Endorsements & trust web** — `publish_endorsement`, `endorsements`,
  `publish_vouches`, `spend_receipt`, `resolve_conflict`,
  `spent_claims`, `spent_conflicts`. The P4/P6 decision core runs inside
  the node (ingesting gossip), not as wallet commands.
- **Disputes & reputation** — `publish_dispute_verdict`, `disputes`,
  `publish_reputation`, `reputation`. Settled automatically; a manual
  CLI would invite mistakes a wallet user can't audit.
- **Multi-rail pay** — `pay`, `pay_stealth`, `pay_service`,
  `configure_pay`. The wallet exposes the **native rail** only; the
  test-rail x402/ACP paths exist for the sim and embedders. A wallet
  `pay` routing over HTTP rails would need credential handling the CLI
  doesn't have yet.
- **Raw DHT / rendezvous** — `put`, `get`, `register`, `query`,
  `resolve_relay_hint`. Used *inside* discovery and relay logic; no
  command-line JSON spelunking.
- **Pulse / liveness** — `pulse`, `pulse_live`, `pulse_stale`. Consumed
  as metrics in `network status`; the registry itself is node-internal.
- **Registry sync control** — `sync_registries`, `set_sync_interval`.
  Driven internally; `mail send`/`chat` call it where delivery depends
  on it.

## Gaps found by the audit (and closed)

1. **`serve_relay` never published its relay hint.** A wallet opted into
   serving circuits was undiscoverable — `dial_any` resolves targets'
   hints from the DHT (RELAY.md §7), and the wallet's relay published
   none. **Fixed:** `serve_relay` now publishes its hint (5 min TTL,
   refreshed by the existing punch-refresh loop). Test asserts the hint
   resolves with the right `(relay, addr)`.

## Closed since the audit (2026-08-16)

The three priority additions recommended in the audit are all shipped:

1. **`relay stats` / `relay evict` / `relay pardon`** — the R4 abuse
   surface now has an operator view. `relay serve` gained a `--addr`
   flag (pin the port for automation); the management commands bind
   with the relay role *loaded* (state restored, no circuits served,
   no hint published), act, and shut down (persisting). Tested:
   eviction survives the admin handle, pardon clears it, both persist.
2. **`pay --service <id>`** — "call this provider": resolves the
   service's signed record (local cache or DHT) and pays its payment
   address in one command. Tested end-to-end (receipt ingests on the
   service's node).
3. **`settle --to <id>`** — the operator-facing `settle_channel` call:
   records the total paid out as an `ENTRY_SETTLE` with time-boxed
   finality (SPEC §10.3). Tested (settled view not final until the
   dispute window passes; further payments rejected).

Also added: a global `--passphrase` flag for non-interactive use
(scripts/CI/tests — `rpassword` reads the TTY otherwise), and the
**two-process e2e** (`tests/e2e_relayed_pay.rs`): the real
`origin-wallet relay serve` binary is spawned as a child process and a
wallet pays through it — the payee ingests the receipt with no direct
payer→payee link, then the channel settles with time-boxed finality.

## Re-audit (2026-08-16) — surface is complete for the human layer

Re-checked against the full `stoa::Mesh` API: nothing new landed in stoa
since `a419f0c` (the fuzz campaign and the eviction-teardown test are
stoa-side, no API change), and the wallet exposes every human-facing
capability. The remaining not-exposed rows are all deliberate: the
agent-economy decision core (endorsements, disputes, reputation, spent
claims), raw DHT/rendezvous plumbing, and multi-rail pay.

**Next additions (in priority order):**

1. **`network sync`** — bind the node and force `sync_registries` on
   demand. Today the 60 s sync cadence (SPEC §6.2) is the delivery path
   for `pay --relay` receipts and inbound mail; a manual "pull now"
   command closes the latency gap for a human waiting on a payment
   that's already on the relay. Cheap: one command wrapping the existing
   `sync_registries` call, no new stoa API.
2. **Multi-rail pay** (`pay_stealth` / `pay_service` over the test-rail
   x402/ACP paths) — the only remaining product-shaped gap, and it is
   deliberately deferred: routing a wallet `pay` over HTTP rails needs
   credential handling the CLI doesn't have yet. Pull when standing-
   network rails exist.
3. **Nothing further** — endorsements/disputes/reputation stay in stoa
   (they run inside the node, ingesting gossip); surfacing them as CLI
   commands would invite mistakes a wallet user can't audit.
