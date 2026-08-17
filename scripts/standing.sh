#!/usr/bin/env bash
# The standing-network smoke: real `origin-wallet` processes, real QUIC
# sockets, real disk persistence — the only thing faked at Tier 0 is NAT
# (loopback direct dials). Boots:
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
# Tiers (TESTNET.md):
#   Tier 0 — one machine: everything on 127.0.0.1.  scripts/standing.sh
#   Tier 1 — multi-machine LAN: STANDING_HOSTS maps roles to machines;
#            each listed role runs over ssh on its host (fixed port —
#            cross-host port collisions don't exist), and every UNLISTED
#            role runs locally, so a partial inventory (e.g. only r2 on
#            another box) works too.
#
# Usage: scripts/standing.sh [--lan]
# Env:
#   STANDING_HOME   scratch dir (default: mktemp -d)
#   STANDING_PASS   wallet passphrase (default: pass)
#   STANDING_HOSTS  LAN inventory, comma list: "point=10.0.0.2,r1=10.0.0.3,r2=10.0.0.4,endpoint=10.0.0.5"
#   STANDING_PORT   fixed remote port per role (default 47000)
#   STANDING_SSH    ssh prefix (default: ssh)
#   STANDING_WDIR   remote working dir (default: ~/standing)
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

LAN=0
if [ "${1:-}" = "--lan" ]; then LAN=1; fi
REMOTE_PORT="${STANDING_PORT:-47000}"
WDIR="${STANDING_WDIR:-~/standing}"
SSH=(${STANDING_SSH:-ssh})

# Parse STANDING_HOSTS into ROLES[role]=host. Every role not listed runs
# locally (Tier 0 by default).
declare -A ROLES=()
if [ -n "${STANDING_HOSTS:-}" ]; then
  IFS=',' read -ra ENTRIES <<<"$STANDING_HOSTS"
  for entry in "${ENTRIES[@]}"; do
    role=${entry%%=*}
    host=${entry#*=}
    ROLES["$role"]="$host"
  done
fi
if [ "$LAN" = 1 ] && [ "${#ROLES[@]}" = 0 ]; then
  echo "✗ --lan requires STANDING_HOSTS (e.g. point=10.0.0.2,r1=10.0.0.3,…)" >&2
  exit 2
fi

host_of() { echo "${ROLES[$1]:-127.0.0.1}"; }
is_remote() { [ -n "${ROLES[$1]:-}" ]; }

# A free port on loopback (bind a probe, note the port, drop it — the
# tiny race window is acceptable for a smoke). Local roles only; remote
# roles use the fixed STANDING_PORT on their own host.
free_port() {
  python3 - <<'EOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

# Each role's dial address, computed ONCE here in the parent shell. A
# `$(...)` command substitution runs in a subshell, so any memoization
# inside a helper is lost per call — each role's address must be captured
# into a variable up front and reused everywhere (a fresh probe per call
# would bind the endpoint on one port and point the initiator at another).
declare -A ADDR=()
for role in point r1 r2 endpoint; do
  if is_remote "$role"; then
    ADDR["$role"]="$(host_of "$role"):$REMOTE_PORT"
  else
    ADDR["$role"]="127.0.0.1:$(free_port)"
  fi
done

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for role in "${!ROLES[@]}"; do
    "${SSH[@]}" "$(host_of "$role")" \
      "test -f '$WDIR/$role.pid' && kill \$(cat '$WDIR/$role.pid') 2>/dev/null || true; rm -f '$WDIR/$role.pid'" \
      >/dev/null 2>&1 || true
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

echo "standing network ($([ "$LAN" = 1 ] && echo LAN || echo loopback)): point=$POINT_ID"
echo "  r1=$R1_ID r2=$R2_ID endpoint=$ENDPOINT_ID"
if [ "$LAN" = 1 ]; then
  for role in point r1 r2 endpoint; do
    loc=$(is_remote "$role" && echo remote || echo local)
    echo "  $role → $(host_of "$role"):$REMOTE_PORT ($loc)"
  done
fi

# 3. Stage the binary + wallets on remote hosts, mirroring the local
#    layout (cwd = $WDIR remotely, $WORK locally) so the arg list is
#    identical on both sides.
for role in point r1 r2 endpoint; do
  if is_remote "$role"; then
    "${SSH[@]}" "$(host_of "$role")" "mkdir -p '$WDIR/stoa'" >/dev/null
    scp -q "$BIN" "$WORK/$role.dat" "$(host_of "$role"):'$WDIR'/"
  fi
done

# 4. Boot the long-lived roles. point first (the directory anchor), then
#    the relays (--difficulty 8 keeps the PoW snappy; --discovery-refresh
#    1 so the smoke doesn't wait 300 s for the auto-peer loop).
run_role() {
  local role=$1; shift
  if is_remote "$role"; then
    "${SSH[@]}" "$(host_of "$role")" \
      "cd '$WDIR' && STOA_HOME='$WDIR/stoa' nohup ./origin-wallet $* >'$WDIR/$role.log' 2>&1 & echo \$! >'$WDIR/$role.pid'"
  else
    (cd "$WORK" && "$BIN" "$@" >"$WORK/$role.log" 2>&1) &
    PIDS+=($!)
  fi
}

role_log() {
  local role=$1
  if is_remote "$role"; then
    "${SSH[@]}" "$(host_of "$role")" "cat '$WDIR/$role.log'"
  else
    cat "$WORK/$role.log"
  fi
}
role_grep() {
  local role=$1 pattern=$2
  if is_remote "$role"; then
    "${SSH[@]}" "$(host_of "$role")" "grep -q -- '$pattern' '$WDIR/$role.log'"
  else
    grep -q -- "$pattern" "$WORK/$role.log"
  fi
}

run_role point relay serve --file point.dat \
  --addr "${ADDR[point]}" --passphrase "$PASS"
for r in r1 r2; do
  if [ "$r" = r1 ]; then RID=$R1_ID; else RID=$R2_ID; fi
  run_role "$r" relay serve --file "$r.dat" --difficulty 8 \
    --addr "${ADDR[$r]}" \
    --discovery-point "$POINT_ID" --discovery-addr "${ADDR[point]}" \
    --discovery-refresh 1 --passphrase "$PASS"
done

# 5. Let the directory auto-peer r1↔r2 and pre-warm their cookies
#    (refresh 1 s, so a few seconds is plenty; LAN RTTs are sub-ms to
#    tens of ms, far inside the 60 s cookie TTL).
echo "waiting for the relay directory to auto-peer r1↔r2…"
sleep 6

# 6. Boot the endpoint LAST so its 60 s listen window starts fresh right
#    before the send: it connects to r2 and publishes its chain-capable
#    hint ("reachable via r2"), then listens for the addressed topic.
run_role endpoint chat-listen --file endpoint.dat \
  --via-relay "$R2_ID" --relay-addr "${ADDR[r2]}" \
  --addr "${ADDR[endpoint]}" --passphrase "$PASS"
sleep 2

# 7. The initiator (always local, short-lived): resolve the endpoint's
#    far relay from its published hint (--chain-auto) and chain r1 → r2 →
#    endpoint. The --peer-addr link is only for the DHT hint lookup; the
#    message rides the chain.
echo "initiator: --chain-auto through r1 → (r2 from hint) → endpoint"
"$BIN" chat send --file "$WORK/initiator.dat" \
  --to "$ENDPOINT_ID" --peer-addr "${ADDR[endpoint]}" \
  --relay "$R1_ID" --relay-addr "${ADDR[r1]}" \
  --chain-auto --body "standing-chain-auto" --passphrase "$PASS" \
  >"$WORK/initiator.log" 2>&1 || {
    echo "✗ initiator chain-auto send failed" >&2
    cat "$WORK/initiator.log" >&2
    exit 1
  }

# 8. Assert the endpoint received the message.
for i in $(seq 1 30); do
  if role_grep endpoint "standing-chain-auto"; then
    echo "✓ endpoint received the chained message (~${i}s)"
    echo "--- initiator.log ---"; cat "$WORK/initiator.log"
    echo "--- endpoint.log ---"; role_log endpoint
    exit 0
  fi
  sleep 1
done

echo "✗ endpoint never received the chained message" >&2
echo "--- initiator.log ---"; cat "$WORK/initiator.log" >&2
echo "--- endpoint.log ---"; role_log endpoint >&2
exit 1
