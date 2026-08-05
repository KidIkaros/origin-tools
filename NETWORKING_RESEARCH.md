# Origin Networking — Background Research

**Research Date:** August 4, 2026
**Crate:** `origin-network` (proposed, new workspace member)
**Status:** research complete, awaiting design sign-off

---

## Executive Summary

origin-tools has 15 crates of crypto and protocol logic and **zero bytes of
transport code** (verified by grep: the only socket references in the
workspace are test fixtures). `origin-channel` holds a complete
Noise-IK + double-ratchet session layer, but it is transport-agnostic —
nothing can carry those frames between machines. Every future networked
feature (messaging rebuild, vault sync, relay) would otherwise reinvent
transport, violating one-system-one-loop.

**Recommendation:** build `origin-network` as the single transport
foundation layer, sitting *below* `origin-channel`:

```
applications (messaging, sync, relay daemon)
        │
origin-channel   ← session crypto (Noise IK + ratchet + replay)
        │
origin-network   ← transport, addressing, NAT traversal, relay   ← THIS CRATE
        │
origin-crypto-sdk + origin-attest + origin-stealth (cross-cutting)
```

Stack choice: **QUIC via `quinn` (tokio) with identity-pinned self-signed
TLS**, with `origin-channel` riding on top as the end-to-end layer.
Phased delivery starts with a TCP-only phase so the crate ships value
with zero new dependencies before QUIC and NAT traversal land.

---

## 1. What we already have (integration surfaces)

Measured from the workspace, not estimated:

| Crate | Relevant surface | Networking role |
|---|---|---|
| `origin-channel` (2,565 LOC, 81 tests) | `Handshake` state machine (Noise IK over X25519, 3-message, transport-agnostic — takes/returns byte messages), `RatchetedSession` (encrypt/decrypt), `codec` (length-prefixed framing over plain buffers) | **The session layer.** origin-network must carry handshake messages, then pump ratcheted frames. |
| `origin-attest` | `CookieSecret` / cookie challenge (WireGuard-style HMAC of source addr) | **Handshake DoS gate** before any expensive crypto. Ready-made for the network ingress. |
| `origin-stealth` → SDK `stealth::pow` | `solve(pk, dest_hint, difficulty)` / `verify` | **Spam gating** for unknown senders via relay. |
| `origin-identity` | `HybridSigningKeyBundle::from_seed(seed, domain)` — Ed25519 + Falcon-1024 hybrid signatures | **Peer authentication.** Network identity = identity key fingerprint. Note: identity keys are *signing* keys; X25519 transport keys live in origin-channel today and need a defined binding. |
| `origin-common` | `OriginHome` (~/.origin), `IdentityStore`, `Envelope` | Peer directory storage, config home. |
| `origin-crypto-sdk` | XChaCha20-Poly1305, Argon2id, HKDF-SHA3, BLAKE3, `fill_random` | All network-layer crypto goes through the SDK. No exceptions. |

Key structural facts:

- **Every crate is synchronous.** No tokio, no async anywhere in the
  workspace. origin-network will be the first async crate — see §6.
- `origin-channel`'s codec is buffer-in/buffer-out (`decode_frame(buf) ->
  Option<(payload, consumed)>`) — deliberately transport-agnostic. A socket
  adapter is ~50 lines.
- The deprecated signet project's daemon/relay/a2a **topology** remains the
  blueprint (per prior decision): a trust-preserving relay that forwards
  opaque bytes and sees no plaintext, plus Noise-authenticated routing —
  re-implemented, nothing copied.

---

## 2. The problem space: what "networking" actually requires

Seven capabilities, in dependency order:

1. **Addressing** — dial a peer by *key*, not IP. The address must be
   derivable from an identity (fingerprint), stable across network
   changes, and human-checkable (compare out-of-band, like a Signal
   safety number).
2. **Transport** — reliable, ordered, multiplexed, encrypted byte
   streams. Must survive the real internet: firewalls, NATs, mobile
   roaming.
3. **Endpoint authentication** — on connect, prove the remote key
   matches the dialed identity. No PKI, no CAs; pinning and
   trust-on-first-use backed by origin-attest endorsement later.
4. **NAT traversal** — most peers sit behind NAT. Requires: learning
   one's own public address (STUN), exchanging endpoint candidates,
   hole punching where possible, and **relay fallback where it isn't**
   (CGNAT, symmetric NATs — Tailscale's operational experience says a
   meaningful minority of peers can *only* relay).
5. **Relay infrastructure** — servers that forward opaque encrypted
   traffic without seeing plaintext (the signet-relay topology). Relays
   are untrusted with content; they must still be protected from abuse
   (attest cookies + stealth PoW).
6. **Discovery / directory** — fingerprint → last-known-endpoints map,
   persisted in `~/.origin`. Peers publish fresh candidates on contact.
7. **Roaming / migration** — a phone moving from wifi to LTE should not
   drop the session. This is a transport-layer property (connection
   migration), not an app-layer one.

Anything less than all seven leaves messaging (the rebuild's goal)
broken for a real-world fraction of users.

---

## 3. Ecosystem survey

Measured today (crates.io API), August 2026:

| Crate / project | Version | Last updated | Downloads | Verdict |
|---|---|---|---|---|
| **quinn** (QUIC) | 0.11.11 | 2026-06-22 | 250.7M | ⭐ The Rust QUIC implementation. Mature, async, battle-tested. |
| **quinn-proto** | 0.11.16 | 2026-07-04 | 256.9M | Protocol core, no IO — available if a custom UDP loop is ever wanted. |
| **iroh** | 1.0.3 | 2026-07-20 | 1.5M | Full p2p QUIC stack (hole punching + DERP-style relays + discovery), hit 1.0 in June 2026. Architecture is the reference model (their own comparison work benchmarks it against WebRTC and libp2p). |
| **snow** (Noise) | 0.10.0 | 2025-07-19 | 24.9M | Noise framework. **Not needed** — origin-channel already implements Noise IK natively on the SDK. |
| **quinn-hyphae** | 0.1.0-beta.0 | 2024-10-15 | 2.2k | Noise-instead-of-TLS for QUIC. Effectively unmaintained upstream. |
| **asport-quinn-hyphae** | 0.1.0-beta.1 | 2026-02-16 | 269 | Maintained fork of the above. Still beta, tiny adoption. |
| **quinn-noise** (ipfs-rust) | 0.4.0 | 2022-11-27 | 21.6k | Stale since 2022. |
| **libp2p** | — | active | large | General p2p framework (gossipsub, Kademlia, transports). Huge surface, its own identity/crypto conventions. |
| **renet** | 2.0.0 | 2026-01-20 | 162k | Game-networking library (UDP, channels). Wrong domain — no NAT traversal story, no identity model. |

### Decision table

| Candidate | For | Against | Verdict |
|---|---|---|---|
| **A. Adopt iroh wholesale** | Hole punching + relays + discovery solved; 1.0 maturity | Its own identity (Ed25519 node IDs), its own crypto/TLS conventions — a parallel foundation bolted under ours; violates SDK-only crypto; we'd wrap instead of own | ✗ |
| **B. libp2p** | Mature transports + NAT (via libp2p stack) | Massive dependency surface, async ecosystem churn, its own auth patterns; we'd spend more time configuring it than owning our layer | ✗ |
| **C. quinn + own topology** ⭐ | Own the layer; QUIC gives multiplexing, 0-RTT, connection migration, UDP (required for hole punching); 250M-dl maturity; iroh *proves* QUIC+relays is the right shape | Must build traversal/relay ourselves (but that topology is already designed — signet blueprint); tokio enters the workspace | ✓ |
| **D. Hand-rolled UDP protocol** | Total control | Reimplement congestion control, loss recovery, migration — years of work quinn already did | ✗ |

**Choice: C.** Build the topology (addressing, directory, traversal,
relay) ourselves on quinn, borrowing the *architecture* iroh and
Tailscale have validated: identity-keyed endpoints, STUN + hole
punching, DERP-style trust-preserving relay fallback.

### Why not Noise-inside-QUIC (hyphae)?

The nQUIC/hyphae line replaces QUIC's TLS with Noise. It's the
"correct" purist design, but both implementations are beta with
negligible adoption, and we gain nothing we don't already have better:
`origin-channel`'s Noise IK + double ratchet runs **on top** of the
transport anyway, providing end-to-end forward secrecy and replay
protection regardless of the transport's own encryption. Standard TLS
1.3 with **self-signed certificates pinned to identity keys** gets us
transport encryption + peer authentication with zero exotic
dependencies; the channel layer above is the real security boundary.
If hyphae matures, it can swap in later without touching anything above
the transport — the layering allows it.

---

## 4. Proposed architecture

```
origin-network
├── address/      OriginAddress = identity fingerprint + endpoint hints
│                 (rendered in a human-checkable form; dial-by-key)
├── endpoint/     Endpoint: the single object that listens + dials +
│                 migrates ("magic endpoint" pattern, à la iroh/Tailscale)
├── transport/    QUIC (quinn) primary; TCP adapter phase 1
├── nat/          STUN client, endpoint candidates, hole punching
├── relay/        Relay client + relay SERVER (trust-preserving
│                 forwarder — opaque bytes only, signet topology)
├── directory/    Peer store in ~/.origin (fingerprint → endpoints,
│                 last-seen, endorsement status via origin-attest)
├── guard/        Ingress: attest cookies before crypto, stealth PoW
│                 for unknown peers over relay
└── upgrade       stream + identity → origin-channel handshake
                  → RatchetedSession
```

### Identity binding (the one genuinely new design element)

origin-identity keys are signing keys (Ed25519 + Falcon-1024);
origin-channel uses separate X25519 statics. The network layer must
bind them:

- Derive a per-domain network key from the identity seed via
  `SeedHandle::derive_key("origin-network:x25519:v1", ...)` — same
  lineage as everything else, no new secret storage.
- The TLS certificate presented in QUIC embeds the identity's
  **verifying key**; the handshake payload carries a hybrid signature
  (Ed25519+Falcon) over the transcript proving possession.
- Result: dialing a fingerprint authenticates the same identity the
  user verified out-of-band. Falcon signatures are used **once per
  handshake**, never per packet (size: ~1.3KB each).

### Threat model notes

- Relay sees: opaque QUIC datagrams, timing, volume. Mitigations later
  (padding, mix-style scheduling) — out of scope v1, documented.
- Network eavesdropper: TLS + channel-layer AEAD; zero plaintext.
- DoS: attest cookie gates the handshake CPU cost; stealth PoW gates
  unknown-sender relay delivery; per-peer rate limits in `guard`.
- Key compromise: channel ratchet gives forward secrecy for traffic
  after compromise; revocation journals (origin-attest) for identity.

---

## 5. What changes in the workspace

- New member `origin-network` in the workspace list + workspace
  dependency entry.
- **tokio + quinn become workspace dependencies** (first async deps).
- `origin` umbrella CLI gains a `network` subcommand (doctor-style
  checks: bind, STUN reachability, relay reachability).
- origin-channel: **no changes needed** — its buffer codec already fits.
- origin-common: possibly a small async-io helper module; likely none.

---

## 6. The async decision (the real inflection point)

Every existing crate is synchronous. origin-network cannot be: socket
handling, timeouts, and multiplexed streams need an event loop. Options:

| Option | Meaning | Cost |
|---|---|---|
| **a. Full tokio inside origin-network, blocking facade out** | crate exposes `Endpoint` with an internal runtime; sync callers get blocking wrappers; async callers get the real API | Small facade; both worlds usable |
| b. Sync-only networking (blocking sockets + threads) | fits current style | No multiplexing, no migration, dead end for the messaging rebuild |
| c. Go async-native workspace-wide | cleanest long-term | Rewrites nothing now but sets the direction: future daemon/messaging crates are tokio too |

Recommendation: **a now, c as direction.** The signet daemon (hyper +
async) already proved the daemon pattern; the messaging rebuild will be
a daemon. origin-network is async-native internally with a thin blocking
facade for CLI tools.

---

## 7. Phased build plan

| Phase | Scope | New deps | Exit criterion |
|---|---|---|---|
| **P1 — TCP + channel** | `address`, `directory`, TCP transport, upgrade-to-channel, blocking facade, `origin network` CLI | none (std TCP) | Two processes on a LAN exchange ratcheted, replay-protected messages addressed by fingerprint |
| **P2 — QUIC** | quinn transport behind the same `Transport` trait, identity-pinned TLS certs, multiplexed streams, 0-RTT resume | tokio, quinn, rcgen | Same test over QUIC; multiple concurrent sessions on one connection |
| **P3 — NAT traversal + relay** | STUN, candidate exchange, hole punching, relay client + relay server binary, guard (cookies + PoW) | (stun crate or ~200 LOC) | Two peers behind NATs connect direct; symmetric-NAT peer connects via relay; relay sees no plaintext |
| **P4 — daemon + messaging hookup** | long-running daemon exposing the Endpoint, consumed by the messaging rebuild | — | messaging rebuild built on origin-network, not beside it |

Each phase independently testable; P1 ships a usable crate with zero
dependency growth. Tests pass between phases (house rule).

---

## 8. Open questions for sign-off

1. **Async adoption** — confirm option (a): tokio inside, blocking
   facade, async-native direction for future daemons.
2. **Relay hosting model** — self-hosted relays only for v1 (no public
   relay fleet)? The crate ships the relay *server*; who runs it is an
   ops question.
3. **TCP phase worth it?** — P1 with plain TCP buys dependency-free
   progress and validates the channel adapter; P2 replaces the
   transport under the same trait. Confirm the phasing vs jumping
   straight to QUIC.
4. **Naming** — `origin-network` for the crate, `origin network` for
   the CLI verb. Address string format proposal:
   `origin:<fingerprint-hex>` with `@<relay-or-ip:port>` hints optional.

---

## Sources

- crates.io API queries (quinn, quinn-proto, quinn-hyphae,
  asport-quinn-hyphae, quinn-noise, snow, iroh, renet) — 2026-08-04.
- iroh architecture (QUIC + hole punching + DERP-style relays), iroh 1.0
  launch discussion, June 2026; Tailscale DERP design references.
- nQUIC (IACR ePrint 2019/028) and quic-noise-spec — Noise-in-QUIC
  landscape.
- Workspace measurement: grep-verified absence of transport code;
  origin-channel handshake/codec/session API; origin-attest cookies;
  SDK stealth PoW; origin-identity hybrid signing.
- Prior session research (tgui-lab RESEARCH-2.md): origin-network
  roadmapped as phase R-A, transport below origin-channel, signet-relay
  topology blueprint.
