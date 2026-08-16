#!/usr/bin/env bash
# Two-wallet dogfood — every rail, live, end to end (INTEGRATION.md).
#
# Creates wallets A and B and drives the full surface across the live
# mesh, phased so only ONE node instance per wallet identity is ever
# alive (see "why phased" below):
#   phase 1 — A active, B passive (B's REPL is the receiving node):
#       chat A→B, mail A→B (REPL polls + prints it), pay A→B;
#       then B's `mail inbox` shows the persisted mailbox.
#   phase 2 — B active, A passive (A's REPL is the receiving node):
#       chat B→A, mail B→A, pay B→A; then A's `mail inbox`.
#
# Why phased: the mesh keys connections by MeshId, so a second live node
# instance with the same identity (e.g. a `chat send` command while the
# REPL is running) replaces the first instance's connections at its
# peers — a short-lived command can orphan the REPL's links. The dogfood
# runs one instance per identity at a time, which is also the realistic
# wallet deployment (one node per wallet).
#
# Requires: the built binary (`cargo build -p origin-wallet`), `expect`
# (the passphrase prompt reads the tty), and `script` (pty wrapper for
# the long-lived REPL).
#
# Usage: scripts/dogfood.sh
# Env:   WALLET_BIN overrides the binary; DOGFOOD_PASS the passphrase.

set -euo pipefail
cd "$(dirname "$0")/../.."

WALLET_BIN="${WALLET_BIN:-$(pwd)/target/debug/origin-wallet}"
PASS="${DOGFOOD_PASS:-dogfood-pass}"
WORK="$(mktemp -d /tmp/dogfood.XXXXXX)"
export STOA_HOME="$WORK/stoa-home"
mkdir -p "$STOA_HOME"

A_DAT="$WORK/a.dat"
B_DAT="$WORK/b.dat"
A_LOG="$WORK/a-repl.log"
B_LOG="$WORK/b-repl.log"

cleanup() {
  set +e
  kill "${A_PID:-}" "${B_PID:-}" 2>/dev/null
  wait "${A_PID:-}" "${B_PID:-}" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { echo; echo "── $*"; }

create_wallet() {
  local file="$1"
  expect -c "
    set timeout 60
    spawn $WALLET_BIN --file $file create --output $file
    expect \"Enter passphrase:\"
    send \"$PASS\r\"
    expect \"Confirm passphrase:\"
    send \"$PASS\r\"
    expect eof
  " > /dev/null
}

# One wallet command that prompts for the passphrase once; output to a log.
run_cmd() {
  local log="$1"; shift
  expect -c "
    set timeout 120
    spawn $WALLET_BIN $*
    expect \"Enter passphrase:\"
    send \"$PASS\r\"
    expect eof
  " > "$log" 2>&1
}

poll() { # poll <log> <pattern> <desc> [max_seconds]
  local log="$1" pat="$2" desc="$3" max="${4:-60}"
  for _ in $(seq 1 "$max"); do
    grep -q "$pat" "$log" && { echo "  ✓ $desc"; return 0; }
    sleep 1
  done
  echo "  ✗ TIMEOUT waiting for: $desc (pattern '$pat' in $log)"
  tail -20 "$log" >&2 || true
  return 1
}

# Start a REPL for one wallet, setting PID_VAR and PORT_VAR in the
# CALLING shell (no command substitution — a subshell's `exec` fds would
# die with it, EOF-ing the REPL's stdin). Extra args (e.g. --peer) are
# passed through. fd 5 is the REPL's fifo writer.
start_repl() {
  local dat="$1" log="$2" fifo="$3" pid_var="$4" port_var="$5"; shift 5
  mkfifo "$fifo"
  script -qefc "$WALLET_BIN --file $dat chat repl $*" "$log" < "$fifo" &
  local pid=$!
  eval "$pid_var=$pid"
  exec 5>"$fifo"          # unblocks both fifo ends; holds the writer open
  printf '%s\r' "$PASS" >&5
  poll "$log" "bound :" "REPL up ($dat)" || return 1
  local port
  port="$(grep -oP 'bound\s*:\s*127\.0\.0\.1:\K[0-9]+' "$log" | head -1)"
  [ -n "$port" ] || { echo "  ✗ could not read REPL bound port"; return 1; }
  eval "$port_var=$port"
}

stop_repl() {
  printf 'quit\r' >&5
  exec 5>&-
}

# ── 0. Wallets ───────────────────────────────────────────────────────
step "create wallets"
create_wallet "$A_DAT"
create_wallet "$B_DAT"

step "derive node identities"
run_cmd "$WORK/a-status.log" --file "$A_DAT" network status
run_cmd "$WORK/b-status.log" --file "$B_DAT" network status
A_MESH="$(grep -oP 'mesh id\s*:\s*\K[0-9a-f]{64}' "$WORK/a-status.log" | head -1)"
B_MESH="$(grep -oP 'mesh id\s*:\s*\K[0-9a-f]{64}' "$WORK/b-status.log" | head -1)"
[ -n "$A_MESH" ] && [ -n "$B_MESH" ] || { echo "failed to derive MeshIds"; exit 1; }
echo "  A = $A_MESH"
echo "  B = $B_MESH"

# ── Phase 1 — A active, B passive ────────────────────────────────────
step "phase 1: B's REPL up (receiving node)"
start_repl "$B_DAT" "$B_LOG" "$WORK/b-in" B_PID B_PORT
echo "  B REPL on 127.0.0.1:$B_PORT"

step "chat A→B"
run_cmd "$WORK/a-chat.log" --file "$A_DAT" chat send --to "$B_MESH" \
  --peer-addr "127.0.0.1:$B_PORT" --body "dogfood-a-to-b"
poll "$B_LOG" "dogfood-a-to-b" "B received A's chat" || exit 1

step "mail A→B (B's REPL polls and prints it)"
run_cmd "$WORK/a-mail.log" --file "$A_DAT" mail send --to "$B_MESH" \
  --peer-addr "127.0.0.1:$B_PORT" --body "dogfood-mail-a-to-b"
poll "$WORK/a-mail.log" "✓ Mail delivered" "A's mail sent" || exit 1
poll "$B_LOG" "dogfood-mail-a-to-b" "B's REPL polled + printed the mail" || exit 1

step "pay A→B (native rail)"
run_cmd "$WORK/a-pay.log" --file "$A_DAT" pay --to "$B_MESH" \
  --amount 111 --peer-addr "127.0.0.1:$B_PORT"
poll "$WORK/a-pay.log" "✓ Payment recorded" "A's receipt recorded" || exit 1

step "B's mail inbox (persisted mailbox, after B's REPL quits)"
stop_repl
run_cmd "$WORK/b-inbox.log" --file "$B_DAT" mail inbox
poll "$WORK/b-inbox.log" "dogfood-mail-a-to-b" "B's inbox holds A's mail" || exit 1

# ── Phase 2 — B active, A passive ────────────────────────────────────
step "phase 2: A's REPL up (receiving node)"
start_repl "$A_DAT" "$A_LOG" "$WORK/a-in" A_PID A_PORT
echo "  A REPL on 127.0.0.1:$A_PORT"

step "chat B→A"
run_cmd "$WORK/b-chat.log" --file "$B_DAT" chat send --to "$A_MESH" \
  --peer-addr "127.0.0.1:$A_PORT" --body "dogfood-b-to-a"
poll "$A_LOG" "dogfood-b-to-a" "A received B's chat" || exit 1

step "mail B→A (A's REPL polls and prints it)"
run_cmd "$WORK/b-mail.log" --file "$B_DAT" mail send --to "$A_MESH" \
  --peer-addr "127.0.0.1:$A_PORT" --body "dogfood-mail-b-to-a"
poll "$WORK/b-mail.log" "✓ Mail delivered" "B's mail sent" || exit 1
poll "$A_LOG" "dogfood-mail-b-to-a" "A's REPL polled + printed the mail" || exit 1

step "pay B→A (native rail)"
run_cmd "$WORK/b-pay.log" --file "$B_DAT" pay --to "$A_MESH" \
  --amount 222 --peer-addr "127.0.0.1:$A_PORT"
poll "$WORK/b-pay.log" "✓ Payment recorded" "B's receipt recorded" || exit 1

step "A's mail inbox (persisted mailbox, after A's REPL quits)"
stop_repl
run_cmd "$WORK/a-inbox.log" --file "$A_DAT" mail inbox
poll "$WORK/a-inbox.log" "dogfood-mail-b-to-a" "A's inbox holds B's mail" || exit 1

echo
echo "✓✓ Dogfood complete — chat, mail, and pay carried live, both directions."
