# Standing Network Testnet

The next roadmap item (2026-08-16 decision): take the mesh off the sim's
single-process actor model and onto **real processes** — the fidelity
step that separates "the protocol converges on loopback" from "the
product works on a network".

## Why a standing network, and what it measures that the sim can't

`stoa-sim` (stoa/scripts/soak.sh) binds every node in one process. It
proves convergence, budget, and churn recovery at the *actor* level. A
standing network of real `origin-wallet` processes measures the seams
that one-process loopback hides:

| Seam | What one-process hides | What a standing network exposes |
|---|---|---|
| **Process boundary** | All actors share one runtime, one clock | Real QUIC endpoints, real OS scheduling, real stdout/stderr per node |
| **Persistence** | In-memory state is trivially shared | `$STOA_HOME` disk state — cookies/evictions/strikes must survive real restarts |
| **CLI surface** | Tests call library fns | Every flag, every parse, every non-interactive path is exercised (scripts/CI) |
| **Discovery** | DHT routing tables are in-process | Hint/DHT records must be found across real sockets, real routing tables |
| **NAT** | Loopback is always reachable | Real NAT needs real machines or a NAT proxy (Tier 2) |

## The tiers

- **Tier 0 — single-machine, multi-process (SHIPPED).** `scripts/standing.sh`
  boots a rendezvous point, two chain-capable relays that auto-peer
  through the directory, an endpoint that publishes its chain-capable
  hint, and an initiator that resolves the far relay from the hint
  (`--chain-auto`) and chains near → far → endpoint across process
  boundaries. The only thing faked is NAT (loopback direct dials). This
  is the honest first artifact: real processes, real sockets, real disk,
  real CLI — one machine.
- **Tier 1 — multi-machine LAN.** The same topology across machines on a
  LAN: real interfaces, real multicast-free discovery, real latency
  (sub-ms → tens of ms), no NAT. Exercises interface enumeration, punch
  candidates across hosts, and cross-host relay peering. Requires
  standing hosts; the harness has the `--host` inventory mode
  (`scripts/standing.sh --lan` + `STANDING_HOSTS`).
- **Tier 2 — internet, real NAT.** The full testnet: nodes behind
  residential/NAT'd networks, STUN + hole-punch + relay fallback under
  real remaps, and the honest measurement that unlocks the padding knobs
  (PADDING.md §7 — the latency budget is a standing-network decision).
  This is where the relay directory's 300 s refresh and the pre-warm
  cold-path gap (RELAY.md §13.4) get their real-world exercise.

## What ships today (Tier 0)

`scripts/standing.sh` — one run, exit 0 proves the standing chain:

```
point (relay serve, the directory anchor)
  ├─ r1 (relay serve --discovery-point --discovery-refresh 1)
  └─ r2 (relay serve --discovery-point --discovery-refresh 1)   ── auto-peer via the directory
endpoint (chat-listen --via-relay r2 --addr <pinned>)            ── publishes "reachable via r2, chain:true"
initiator (chat send --relay r1 --chain-auto --peer-addr <endpoint>)
```

The initiator's direct link to the endpoint (`--peer-addr`) is used
**only** for the DHT hint lookup; the message rides the chain
(`r1 → r2 → endpoint`), never the direct link. The endpoint terminates
the circuit — `chat listen`/`chat repl` now `accept_relayed()`, the
missing piece that let a relayed or chained chat actually land on a
circuit instead of silently falling back to the addressed topic.

### How to run

```bash
cd origin-tools
cargo build --release --bin origin-wallet   # once
bash scripts/standing.sh                     # Tier 0: exit 0 = the chain delivered
```

### Tier 1 (LAN)

`--lan` runs the same topology across machines. `STANDING_HOSTS` maps
roles to hosts; every listed role runs over `ssh` on its host (fixed
`STANDING_PORT`, default 47000 — cross-host port collisions don't
exist), and every **unlisted** role runs locally, so a partial inventory
(e.g. `r2` on another box) works too. The wallet `.dat` files and the
release binary are staged to `STANDING_WDIR` (default `~/standing`) on
each remote host; logs are written there and read back over `ssh` for
the assertion.

```bash
cd origin-tools
cargo build --release --bin origin-wallet
STANDING_HOSTS="point=10.0.0.2,r1=10.0.0.3,r2=10.0.0.4,endpoint=10.0.0.5" \
  bash scripts/standing.sh --lan    # exit 0 = the chain delivered across machines
```

Env knobs: `STANDING_PORT` (remote port), `STANDING_SSH` (ssh prefix),
`STANDING_WDIR` (remote working dir), `STANDING_HOME`/`STANDING_PASS`
(shared with Tier 0). The one thing Tier 1 still fakes is NAT — that's
Tier 2's job.

## Acceptance criteria (Tier 0, the shipped gate)

1. The initiator's `chat send --chain-auto` resolves the endpoint's far
   relay from its published hint (not a hardcoded path) and reports the
   **relayed** tier (a chain never upgrades to direct, RELAY.md §13).
2. The endpoint prints the message body — it terminated the circuit.
3. `relay stats` on either relay shows `validated clients ≥ 1` (the
   directory pre-warm ran across processes).

## Honest gaps

- **NAT is faked at Tier 0/1.** Loopback (Tier 0) and LAN (Tier 1) direct
  dials; the punch/relay fallback and interface enumeration need Tier 2's
  real NAT.
- **`RelayedSession::peer()` shipped** — the L3-proven initiator is now
  exposed, and `chat listen`/`chat repl` report the true sender (`via
  relay <immediate-hop>`), so a chained chat names the real initiator
  rather than the far relay.
- **Chain endpoints need `accept_relayed()`.** Shipped for `chat
  listen`/`chat repl`; any other endpoint role must do the same or the
  chain's final leg refuses the ring (RELAY.md §13.4).
- **The pre-warm cold-path gap is closed** (RELAY.md §13.4): a stale hop
  now degrades to a slow open via challenge-on-ring (a lapsed cookie
  makes the ringed relay challenge the leg peer, which re-solves and
  re-rings) instead of a hard miss. Tested at
  `r6_stale_prewarm_degrades_to_slow_open_not_hard_miss`; the depth-4
  soak's t=270 transient was exactly this refusal, now a slow open.

## Roadmap

Tier 0 is the shipped gate. Tier 1 (LAN) is the next pull — it needs a
`--host` inventory mode in the harness and standing hosts. Tier 2
(internet) is where the padding-knob latency budget (PADDING.md) and the
TEE-attestation / PQ-aggregate-signature items get their measurement —
both stay standards-blocked until then.
