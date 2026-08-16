# Stoa Mesh API coverage — origin-wallet

Status: **audited 2026-08-16** against stoa `a419f0c`. This is the
definitive map of what the wallet's network surface (`network.rs`) exposes
from the full `stoa::Mesh` API — and the deliberate gaps.

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
- **Relay abuse control** — `relay_evict`, `relay_pardon`, `relay_stats`.
  The relay operator's moderation surface; no CLI yet (see below).
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

## Recommended next CLI additions (priority order)

1. **`relay stats` / `relay evict` / `relay pardon`** — the R4 abuse
   surface (cookie strikes, eviction) currently has no operator view;
   a relay operator serving circuits from a wallet should be able to see
   who's burning circuits and revoke them.
2. **`pay_service`** — "call this provider": the `discover` → `pay` flow
   currently needs a manual MeshId copy; `discover --save` then `pay
   --to <contact>` closes the loop.
3. **`settle`** — a wallet that has streamed payments has no CLI to
   settle the channel (time-boxed finality, SPEC §10.3). The evidence
   settles on both sides automatically, but the operator-facing
   `settle_channel` call is missing.
