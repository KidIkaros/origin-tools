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
  standing hosts; the harness needs a `--host` inventory mode.
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
bash scripts/standing.sh                     # exit 0 = the chain delivered
```

## Acceptance criteria (Tier 0, the shipped gate)

1. The initiator's `chat send --chain-auto` resolves the endpoint's far
   relay from its published hint (not a hardcoded path) and reports the
   **relayed** tier (a chain never upgrades to direct, RELAY.md §13).
2. The endpoint prints the message body — it terminated the circuit.
3. `relay stats` on either relay shows `validated clients ≥ 1` (the
   directory pre-warm ran across processes).

## Honest gaps (unchanged, named)

- **NAT is faked at Tier 0.** Loopback direct dials; the punch/relay
  fallback and interface enumeration need Tier 1/2.
- **The relayed tier's `from` is the immediate relay.** The L3 handshake
  proves the real initiator end-to-end, but the session wrapper doesn't
  expose it, so `chat listen` reports the far relay as the sender. A
  `RelayedSession::peer()` plumbing is a candidate refinement.
- **Chain endpoints need `accept_relayed()`.** Shipped here for
  `chat listen`/`chat repl`; any other endpoint role must do the same or
  the chain's final leg refuses the ring (RELAY.md §13.4).
- **The pre-warm cold-path gap** (RELAY.md §13.4): a stale hop is a hard
  miss, not a slow open. A challenge-on-ring fallback is the candidate
  refinement if a standing network shows stale pre-warms beyond the
  re-serve race.

## Roadmap

Tier 0 is the shipped gate. Tier 1 (LAN) is the next pull — it needs a
`--host` inventory mode in the harness and standing hosts. Tier 2
(internet) is where the padding-knob latency budget (PADDING.md) and the
TEE-attestation / PQ-aggregate-signature items get their measurement —
both stay standards-blocked until then.
