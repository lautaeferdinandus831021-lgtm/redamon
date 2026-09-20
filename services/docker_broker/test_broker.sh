#!/usr/bin/env bash
# Standalone test for the Docker broker (V4). Starts the broker against the host
# Docker socket, points a docker client at the broker socket, and asserts the
# allow/deny policy. No impact on the WhiteHat stack.
#
# Run: bash services/docker_broker/test_broker.sh
set -uo pipefail
cd "$(dirname "$0")/.."

WORK=/tmp/rbt
PASS=0; FAIL=0
ok(){  printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

pkill -f docker_broker/broker.py 2>/dev/null || true
sleep 1
rm -rf "$WORK"; mkdir -p "$WORK"

DOCKER_BROKER_UPSTREAM=/var/run/docker.sock \
DOCKER_BROKER_LISTEN="$WORK/docker.sock" \
DOCKER_BROKER_ALLOWED_BIND_PREFIXES=/tmp \
  python3 docker_broker/broker.py > "$WORK/broker.log" 2>&1 &
BPID=$!
for _ in $(seq 1 20); do [ -S "$WORK/docker.sock" ] && break; sleep 0.3; done
H="unix://$WORK/docker.sock"

# helper: run a docker command via the broker, capture combined output
dock(){ docker -H "$H" "$@" 2>&1; }
# assert the command SUCCEEDED and output contains a marker
allow(){ local desc="$1" marker="$2"; shift 2
  out="$(dock "$@")"
  if printf '%s' "$out" | grep -q "$marker"; then ok "$desc"; else bad "$desc :: $(printf '%s' "$out" | tail -1)"; fi; }
# assert the command was DENIED by the broker
deny(){ local desc="$1"; shift
  out="$(dock "$@")"
  if printf '%s' "$out" | grep -q "denied by docker-broker"; then ok "$desc"; else bad "$desc :: NOT denied :: $(printf '%s' "$out" | tail -1)"; fi; }

echo "=== ALLOW (legitimate tool runs) ==="
allow "normal run (allowlisted image)"      "hi-allowed"  run --rm alpine echo hi-allowed
allow "bind mount under allowed prefix"     "bind-ok"     run --rm -v /tmp:/data:ro alpine sh -c 'echo bind-ok'
allow "capability NET_RAW (naabu SYN)"      "netraw-ok"   run --rm --cap-add NET_RAW alpine echo netraw-ok
out="$(echo stdin-ok | docker -H "$H" run --rm -i alpine cat 2>&1)"
if printf '%s' "$out" | grep -q "stdin-ok"; then ok "stdin hijack (bidirectional stream)"; else bad "stdin hijack :: $out"; fi

echo "=== DENY (host-escape attempts) ==="
deny "mount host root  -v /:/host"          run --rm -v /:/host alpine ls /host
deny "mount docker.sock"                    run --rm -v /var/run/docker.sock:/s alpine echo x
deny "--privileged"                         run --rm --privileged alpine echo x
deny "dangerous cap SYS_ADMIN"              run --rm --cap-add SYS_ADMIN alpine echo x
deny "bind outside allowlist  -v /etc:/e"   run --rm -v /etc:/e alpine ls /e
deny "non-allowlisted image (busybox)"      run --rm busybox echo x
deny "pid namespace host"                   run --rm --pid=host alpine echo x

kill "$BPID" 2>/dev/null || true
echo ""
echo "=== broker decisions ==="
grep -E "ALLOW|DENY" "$WORK/broker.log" | tail -20 || true
echo ""
printf 'RESULT: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "ALL GREEN"; exit 0; } || { echo "FAILURES"; exit 1; }
