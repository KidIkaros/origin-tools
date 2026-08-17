#!/usr/bin/env bash
# The standing-network smoke: real `origin-wallet` processes, real QUIC
# sockets, real disk persistence — the only thing faked is NAT (loopback
# direct dials). Boots:
#
#   point     — a long-lived node hosting the relay directory registry
#   r1, r2    — chain-capable relays that AUTO-PEER via the directory
#               (--discovery-refresh 1 so the smoke doesn't wait 300 s)
#   endpoint  — publishes its chain-capable hint ("reachable via r2")
#   initiator — resolves the endpoint's far relay from the hint
#               (--chain-auto) and chains r1 → r2 → endpoint, so no
#               single relay learns both endpoints.
#
# The initiator's direct link to the endpoint (--peer-addr) is used ONLY
# for the DHT hint lookup — the message itself rides the chain, never
# the direct link. Asserts the endpoint received the message, then tears
# everything down.
#
# This is the honest first standing-network artifact: it exercises the
# full product surface across real process boundaries (the sim's
# single-process actor model can't), but on one machine — the NAT tier
# still needs real machines or a NAT-simulating proxy (TESTNET.md).
#
# Usage: scripts/standing.sh
# Env:   STANDING_HOME (default: mktemp -d), STANDING_PASS (default: pass)
set -euo pipefail
cd "$(dirname "$0")/.."

PASS="${STANDING_PASS:-pass}"
WORK="${STANDING_HOME:-$(mktemp -d /tmp/standing-XXXXXX)}"
export STOA_HOME="$WORK/stoa"
mkdir -p "$STOA_HOME"

# The binary: prefer a built release; build if missing.
BIN="$PWD/target/release/origin-wallet"
if [ ! -x "$BIN" ]; then
  echo "building origin-wallet (release)…" >&2
  cargo build --release --bin origin-wallet
fi

# A free port on loopback (bind a probe, note the port, drop it — the
# tiny race window is acceptable for a smoke).
free_port() {
  python3 - <<'EOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

# 1. Wallets (seed-derived node identities; --passphrase is global).
for w in point r1 r2 endpoint initiator; do
  "$BIN" create --output "$WORK/$w.dat" --passphrase "$PASS" >/dev/null
done

# 2. Mesh ids the CLI prints under `network status`.
mesh_id() {
  "$BIN" network status --file "$1" --passphrase "$PASS" 2>/dev/null \
    | sed -n 's/^ *mesh id *: *//p' | head -1
}
POINT_ID=$(mesh_id "$WORK/point.dat")
R1_ID=$(mesh_id "$WORK/r1.dat")
R2_ID=$(mesh_id "$WORK/r2.dat")
ENDPOINT_ID=$(mesh_id "$WORK/endpoint.dat")

echo "standing network: point=$POINT_ID"
echo "  r1=$R1_ID r2=$R2_ID endpoint=$ENDPOINT_ID"

# 3. Ports.
P_PORT=$(free_port); R1_PORT=$(free_port); R2_PORT=$(free_port); C_PORT=$(free_port)

# 4. Boot the mesh: point first (the directory anchor), then the relays.
# point: a long-lived node (relay serve keeps it alive; it hosts the
# `stoa:relays` registry the relays register against).
"$BIN" relay serve --file "$WORK/point.dat" \
  --addr "127.0.0.1:$P_PORT" --passphrase "$PASS" >"$WORK/point.log" 2>&1 &
PIDS+=($!)
for r in r1 r2; do
  if [ "$r" = r1 ]; then RID=$R1_ID; RPORT=$R1_PORT; else RID=$R2_ID; RPORT=$R2_PORT; fi
  "$BIN" relay serve --file "$WORK/$r.dat" --difficulty 8 \
    --addr "127.0.0.1:$RPORT" \
    --discovery-point "$POINT_ID" --discovery-addr "127.0.0.1:$P_PORT" \
    --discovery-refresh 1 --passphrase "$PASS" >"$WORK/$r.log" 2>&1 &
  PIDS+=($!)
done

# 5. Let the directory auto-peer r1↔r2 and pre-warm their cookies
#    (refresh 1 s, so a few seconds is plenty).
echo "waiting for the relay directory to auto-peer r1↔r2…"
sleep 6

# 6. Boot the endpoint LAST so its 60 s listen window starts fresh right
#    before the send: it connects to r2 and publishes its chain-capable
#    hint ("reachable via r2"), then listens for the addressed topic.
"$BIN" chat-listen --file "$WORK/endpoint.dat" \
  --via-relay "$R2_ID" --relay-addr "127.0.0.1:$R2_PORT" \
  --addr "127.0.0.1:$C_PORT" --passphrase "$PASS" >"$WORK/endpoint.log" 2>&1 &
PIDS+=($!)
sleep 2

# 7. The initiator: resolve the endpoint's far relay from its published
#    hint (--chain-auto) and chain r1 → r2 → endpoint. The --peer-addr
#    link is only for the DHT hint lookup; the message rides the chain.
echo "initiator: --chain-auto through r1 → (r2 from hint) → endpoint"
"$BIN" chat send --file "$WORK/initiator.dat" \
  --to "$ENDPOINT_ID" --peer-addr "127.0.0.1:$C_PORT" \
  --relay "$R1_ID" --relay-addr "127.0.0.1:$R1_PORT" \
  --chain-auto --body "standing-chain-auto" --passphrase "$PASS" \
  >"$WORK/initiator.log" 2>&1 || {
    echo "✗ initiator chain-auto send failed" >&2
    cat "$WORK/initiator.log" >&2
    exit 1
  }

# 8. Assert the endpoint received the message.
for i in $(seq 1 30); do
  if grep -q "standing-chain-auto" "$WORK/endpoint.log"; then
    echo "✓ endpoint received the chained message (~${i}s)"
    echo "--- initiator.log ---"; cat "$WORK/initiator.log"
    echo "--- endpoint.log ---"; cat "$WORK/endpoint.log"
    exit 0
  fi
  sleep 1
done

echo "✗ endpoint never received the chained message" >&2
echo "--- initiator.log ---"; cat "$WORK/initiator.log" >&2
echo "--- endpoint.log ---"; cat "$WORK/endpoint.log" >&2
exit 1
