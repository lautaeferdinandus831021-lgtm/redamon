#!/usr/bin/env bash
# =============================================================================
# SMOKE tests for supply-chain memory governance against the REAL stack.
#
# The unit and integration suites prove the numbers are computed correctly. They
# cannot prove that Docker ACCEPTS them, that the running orchestrator actually
# applies them, or that the L3 lane survives a real HTTP round trip. Every bug
# this subsystem shipped was invisible to a mock:
#
#   * a governed value in a format `docker run` rejects would fail only at spawn
#   * a mem_limit computed but never passed would show up only in docker inspect
#   * a reservation that leaks would only be visible in live /system/stats
#
# Requires: a running stack (docker compose up) and the analyzer image.
# Read-only apart from one short-lived alpine/analyzer container it removes.
#
# Run:  bash tests/supply_chain_governor_smoke.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n         got:  %s\n         want: %s\n' "$1" "$2" "$3"; }
skip() { SKIP=$((SKIP+1)); printf '  skip  %s (%s)\n' "$1" "$2"; }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
has()  { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "$2" "contains: $3"; fi; }
gt()   { if [[ "$2" -gt "$3" ]]; then ok "$1"; else bad "$1" "$2" "> $3"; fi; }

need_stack() { docker compose ps --format '{{.Service}}' 2>/dev/null | grep -q recon-orchestrator; }

orch() { docker compose exec -T recon-orchestrator sh -c "$1" 2>/dev/null; }

echo "== preconditions =="
if ! command -v docker >/dev/null 2>&1; then
  echo "docker unavailable - smoke tests cannot run"; exit 0
fi
if ! need_stack; then
  echo "stack not running (docker compose up) - smoke tests cannot run"; exit 0
fi
ok "stack is up"

# -----------------------------------------------------------------------------
echo "== the governed value is a format Docker accepts =="
# The governor emits plain bytes. If it ever emitted "1.5g", a float, or a
# negative, `docker run` would reject the spawn at runtime and the analyzer would
# fail with a message nowhere near the memory governor.
MEM_VALUE="$(orch 'cd /app && python3 -c "
import resource_governor as rg
print(rg.container_cap(rg.tool_container_envelope(\"supply_chain_analyzer\")))
"')"
MEM_VALUE="$(echo "$MEM_VALUE" | tr -d '\r\n ')"
if [[ "$MEM_VALUE" =~ ^[0-9]+$ ]]; then ok "governed ceiling is an integer ($MEM_VALUE bytes)"
else bad "governed ceiling is an integer" "$MEM_VALUE" "digits only"; fi
gt "ceiling is above Docker's 6MB floor" "$MEM_VALUE" "6291456"

OUT="$(docker run --rm --memory "$MEM_VALUE" alpine:latest echo accepted 2>&1 | tail -1)"
eq "docker run accepts the governed --memory verbatim" "$OUT" "accepted"

# -----------------------------------------------------------------------------
echo "== the analyzer really gets the limit applied =="
if docker image inspect whitehat-supply-chain-analyzer:latest >/dev/null 2>&1; then
  NAME="whitehat-smoke-analyzer-$$"
  docker run -d --name "$NAME" --memory "$MEM_VALUE" --cap-drop ALL --read-only \
    --tmpfs /tmp:size=1g,exec --pids-limit 512 --entrypoint sleep \
    whitehat-supply-chain-analyzer:latest 30 >/dev/null 2>&1
  APPLIED="$(docker inspect "$NAME" --format '{{.HostConfig.Memory}}' 2>/dev/null)"
  CAPS="$(docker inspect "$NAME" --format '{{.HostConfig.CapDrop}}' 2>/dev/null)"
  ROOTFS="$(docker inspect "$NAME" --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null)"
  PIDS="$(docker inspect "$NAME" --format '{{.HostConfig.PidsLimit}}' 2>/dev/null)"
  docker rm -f "$NAME" >/dev/null 2>&1
  eq "analyzer container carries the exact governed limit" "$APPLIED" "$MEM_VALUE"
  has "analyzer drops all capabilities" "$CAPS" "ALL"
  eq "analyzer rootfs is read-only" "$ROOTFS" "true"
  eq "analyzer PID ceiling applied" "$PIDS" "512"
else
  skip "analyzer container limits" "whitehat-supply-chain-analyzer image not built"
fi

# -----------------------------------------------------------------------------
echo "== every running WhiteHat container is capped =="
# Scope to the STACK's own services. Other compose projects (guinea-pig targets)
# are outside the ledger by construction, so they get their own advisory check
# rather than failing this one.
UNCAPPED=""
for c in $(docker compose ps --format '{{.Name}}' 2>/dev/null); do
  M="$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)"
  [[ "$M" == "0" ]] && UNCAPPED="$UNCAPPED $c"
done
eq "no always-on stack container runs uncapped" "${UNCAPPED:-none}" "none"

# Advisory: a guinea-pig target shares the host but not the ledger. It cannot be
# reserved for, so the least it can do is carry its own ceiling.
STACK="$(docker compose ps --format '{{.Name}}' 2>/dev/null | tr '\n' ' ')"
OUTSIDE=""
for c in $(docker ps --format '{{.Names}}' | grep '^whitehat-'); do
  [[ " $STACK " == *" $c "* ]] && continue
  M="$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)"
  [[ "$M" == "0" ]] && OUTSIDE="$OUTSIDE $c"
done
if [[ -z "$OUTSIDE" ]]; then
  ok "no out-of-stack whitehat container runs uncapped"
else
  skip "out-of-stack containers are uncapped:$OUTSIDE" "recreate them to pick up caps"
fi

# -----------------------------------------------------------------------------
echo "== live governor state =="
STATS="$(orch 'cd /app && python3 -c "
import urllib.request, os, json
k = os.environ[\"ORCHESTRATOR_API_KEY\"]
r = urllib.request.urlopen(urllib.request.Request(
    \"http://localhost:8010/system/stats\", headers={\"X-Orchestrator-Key\": k}))
d = json.loads(r.read())
print(d[\"governor_enabled\"], d[\"mem\"][\"committed\"], d[\"mem\"][\"pressure\"])
"')"
read -r GOV COMMITTED PRESSURE <<<"$(echo "$STATS" | tr -d '\r')"
eq "governor is enabled on the live orchestrator" "$GOV" "True"
eq "no reservations are leaked at rest" "$COMMITTED" "0"
if [[ "$PRESSURE" == "ok" || "$PRESSURE" == "warn" || "$PRESSURE" == "critical" ]]; then
  ok "pressure reports a known state ($PRESSURE)"
else bad "pressure reports a known state" "$PRESSURE" "ok|warn|critical"; fi

# -----------------------------------------------------------------------------
echo "== the live envelopes are the shipped ones =="
ENVS="$(orch 'cd /app && python3 -c "
import resource_governor as rg
print(rg.scan_job_envelope(\"supply_chain\"),
      rg.scan_job_envelope(\"partial_recon:SupplyChainRecon\"),
      rg.scan_job_envelope(\"partial_recon\"),
      rg.tool_container_envelope(\"supply_chain_analyzer\"))
"')"
read -r E_SC E_SCP E_P E_AN <<<"$(echo "$ENVS" | tr -d '\r')"
gt "supply_chain envelope covers its analyzer" "$E_SC" "$E_AN"
gt "supply-chain partial envelope covers its analyzer" "$E_SCP" "$E_AN"
gt "supply-chain partial costs more than a plain partial" "$E_SCP" "$E_P"

# -----------------------------------------------------------------------------
echo "== L3 lane: real HTTP round trip through the orchestrator =="
# An unsupported ecosystem is refused by the input gate BEFORE any container is
# spawned, so this exercises route + admission + release with no tarball
# download and no network egress.
L3="$(orch 'cd /app && python3 -c "
import urllib.request, urllib.error, os, json
k = os.environ[\"ORCHESTRATOR_API_KEY\"]
body = json.dumps({\"ecosystem\": \"cargoX\", \"name\": \"left-pad\", \"version\": \"\"}).encode()
req = urllib.request.Request(\"http://localhost:8010/supply-chain/guarddog\", data=body,
    headers={\"X-Orchestrator-Key\": k, \"Content-Type\": \"application/json\"})
try:
    d = json.loads(urllib.request.urlopen(req).read())
    print(\"status=200\", \"error=\" + str(d.get(\"error\"))[:40], \"issues=\" + str(d.get(\"issues\")))
except urllib.error.HTTPError as e:
    print(\"status=\" + str(e.code), e.read()[:120].decode())
"')"
has "guarddog route answers" "$L3" "status=200"
has "input gate refuses an unknown ecosystem" "$L3" "unsupported ecosystem"
has "a refused call still returns the result quadruple" "$L3" "issues=0"

AFTER="$(orch 'cd /app && python3 -c "
import urllib.request, os, json
k = os.environ[\"ORCHESTRATOR_API_KEY\"]
r = urllib.request.urlopen(urllib.request.Request(
    \"http://localhost:8010/system/stats\", headers={\"X-Orchestrator-Key\": k}))
print(json.loads(r.read())[\"mem\"][\"committed\"])
"' | tr -d '\r\n ')"
eq "the L3 reservation was released after the call" "$AFTER" "0"

# -----------------------------------------------------------------------------
echo "== broker allowlist still covers the analyzer =="
ALLOW="$(grep -c 'whitehat-supply-chain-analyzer' services/docker_broker/broker.py 2>/dev/null || echo 0)"
gt "analyzer image is referenced by the broker policy" "$ALLOW" "0"

echo
printf 'RESULT: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
