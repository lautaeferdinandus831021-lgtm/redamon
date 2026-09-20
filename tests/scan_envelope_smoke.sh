#!/usr/bin/env bash
# =============================================================================
# Smoke test: per-scan-type memory envelopes, as actually DEPLOYED.
#
# The unit/integration suites inject synthetic memory. This one runs against the
# LIVE stack and the real /proc/meminfo, and checks the deployment shape that a
# unit test cannot see:
#   - the shipped profile is tracked by git (survives a clone) and not gitignored
#   - it is baked into the image AND visible inside the running container
#   - the governor inside the container resolves a per-type envelope for every
#     scan type the orchestrator can spawn
#   - admission arithmetic on THIS host is self-consistent and reported
#   - GET /system/stats still answers
#
# Read-only: starts nothing, stops nothing, touches no reservation.
# Run:  bash tests/scan_envelope_smoke.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

SVC="recon-orchestrator"
PROFILE="resource_profile.default.json"
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mskip\033[0m %s (%s)\n' "$1" "${2:-}"; }

echo "== repo / packaging =="

if python3 -c "import json,sys; json.load(open('recon_orchestrator/$PROFILE'))" 2>/dev/null; then
  ok "recon_orchestrator/$PROFILE is valid JSON"
else
  bad "recon_orchestrator/$PROFILE is valid JSON" "parse failed"
fi

if git ls-files --error-unmatch "recon_orchestrator/$PROFILE" >/dev/null 2>&1; then
  ok "shipped profile is tracked by git (a fresh clone gets it)"
else
  bad "shipped profile is tracked by git" "untracked: git add recon_orchestrator/$PROFILE"
fi

if git check-ignore -q "recon_orchestrator/$PROFILE"; then
  bad "shipped profile is not gitignored" "matched a .gitignore rule"
else
  ok "shipped profile is not gitignored"
fi

if grep -q "COPY $PROFILE" recon_orchestrator/Dockerfile; then
  ok "Dockerfile bakes the shipped profile into the image"
else
  bad "Dockerfile bakes the shipped profile into the image" "no COPY line in recon_orchestrator/Dockerfile"
fi

echo "== live container =="

if ! docker compose ps --status running --services 2>/dev/null | grep -qx "$SVC"; then
  skip "container checks" "$SVC not running; start with: docker compose up -d $SVC"
  echo; printf 'passed %d, failed %d, skipped %d\n' "$PASS" "$FAIL" "$SKIP"
  [[ $FAIL -eq 0 ]] || exit 1
  exit 0
fi

if docker compose exec -T "$SVC" test -f "/app/$PROFILE" 2>/dev/null; then
  ok "shipped profile is visible at /app/$PROFILE inside the container"
else
  bad "shipped profile is visible inside the container" "missing /app/$PROFILE"
fi

# Resolve every spawnable scan type through the governor + ledger IN the container,
# against the real /proc/meminfo. Prints the table, then asserts the invariants.
ENVOUT=$(docker compose exec -T "$SVC" python -c '
import asyncio, sys
sys.path.insert(0, "/app")
import resource_governor as rg
import admission_ledger as al

KINDS = ("full_recon", "partial_recon", "ai_attack", "gvm", "github_hunt", "trufflehog")
OLD_BLANKET = 4_000_000_000
led = al.ReservationLedger()
mem = rg.read_mem()
problems = []

print("  host: total=%.2f GB available=%.2f GB pressure=%s" % (
    (mem[0] / 1024**3) if mem else 0, (mem[1] / 1024**3) if mem else 0, rg.pressure()))
print("  os_headroom=%.2f GB service_baseline=%.2f GB scan_pool=%.2f GB committed=%.2f GB" % (
    led.os_headroom() / 1024**3, led.service_baseline() / 1024**3,
    led.scan_pool() / 1024**3, led.committed_bytes() / 1024**3))
print("  active_scans=%d remaining_for_new=%.2f GB" % (
    led.active_count(), led.remaining_for_new() / 1024**3))

envs = {}
for kind in KINDS:
    try:
        envs[kind] = led.envelope_for(kind)
    except Exception as exc:
        problems.append("envelope_for(%s) raised %s" % (kind, type(exc).__name__))
        continue
    if envs[kind] <= 0:
        problems.append("%s envelope is %d (would admit every scan)" % (kind, envs[kind]))
    if envs[kind] >= OLD_BLANKET:
        problems.append("%s envelope %d is back at the blanket worst case" % (kind, envs[kind]))

avail = led.available()
for kind, env in sorted(envs.items(), key=lambda kv: kv[1]):
    needed = env + led.os_headroom()
    fits = "fits" if avail >= needed else "NEEDS %.2f GB free" % (needed / 1024**3)
    print("  %-14s envelope %6.2f GB   needs %5.2f GB free -> %s" % (
        kind, env / 1024**3, needed / 1024**3, fits))

if envs.get("partial_recon", 0) >= envs.get("full_recon", 0):
    problems.append("partial_recon is not cheaper than full_recon")

# Dry-run admission on a THROWAWAY ledger so the live reservations are untouched.
probe = al.ReservationLedger()
res = asyncio.run(probe.try_admit("smoke:probe", envs.get("partial_recon", 0)))
print("  dry-run partial_recon admission: %s%s" % (
    res.admitted, "" if res.admitted else " (%s: %s)" % (res.limit_type, res.detail)))

if problems:
    print("PROBLEMS: " + " | ".join(problems))
    sys.exit(1)
print("ENVELOPES_OK")
' 2>&1)

echo "$ENVOUT" | grep -v -e '^ENVELOPES_OK$' -e '^PROBLEMS:'
if echo "$ENVOUT" | grep -q '^ENVELOPES_OK$'; then
  ok "every spawnable scan type resolves a sane per-type envelope in-container"
else
  bad "every spawnable scan type resolves a sane per-type envelope in-container" \
      "$(echo "$ENVOUT" | grep '^PROBLEMS:' || echo "$ENVOUT" | tail -3)"
fi

echo "== live API =="

KEY=$(grep -E '^ORCHESTRATOR_API_KEY=' .env 2>/dev/null | head -1 | cut -d= -f2-)
PORT=$(grep -E '^RECON_ORCH_PORT=' .env 2>/dev/null | head -1 | cut -d= -f2-)
PORT=${PORT:-8010}
if [[ -z "$KEY" ]]; then
  skip "GET /system/stats" "ORCHESTRATOR_API_KEY not found in .env"
else
  STATS=$(curl -fsS -m 10 -H "X-Orchestrator-Key: $KEY" \
          "http://127.0.0.1:${PORT}/system/stats" 2>/dev/null)
  if [[ -z "$STATS" ]]; then
    bad "GET /system/stats" "no response on 127.0.0.1:${PORT}"
  elif python3 -c "
import json,sys
d = json.loads(sys.argv[1])
need = {'host_total','available','os_headroom','service_baseline','scan_pool',
        'committed','active_scans','remaining_for_new','pressure'}
missing = need - set(d.get('mem', {}))
sys.exit(1 if missing or not d['mem'].get('host_total') else 0)
" "$STATS" 2>/dev/null; then
    ok "GET /system/stats returns a complete mem snapshot"
  else
    bad "GET /system/stats returns a complete mem snapshot" "$STATS"
  fi
fi

# The orchestrator bind-mounts /app, so the FILES are already updated, but the
# long-running uvicorn process keeps the profile cached in memory from boot.
STARTED=$(docker inspect -f '{{.State.StartedAt}}' whitehat-recon-orchestrator 2>/dev/null)
if [[ -n "$STARTED" ]]; then
  START_S=$(date -d "$STARTED" +%s 2>/dev/null || echo 0)
  FILE_S=$(stat -c %Y "recon_orchestrator/$PROFILE" 2>/dev/null || echo 0)
  if [[ "$START_S" -gt 0 && "$FILE_S" -gt "$START_S" ]]; then
    printf '  \033[33mnote\033[0m the running container predates the current profile;\n'
    printf '       run "docker compose restart %s" to load it (no rebuild needed)\n' "$SVC"
  else
    ok "running container started after the current profile was written"
  fi
fi

echo
printf 'passed %d, failed %d, skipped %d\n' "$PASS" "$FAIL" "$SKIP"
[[ $FAIL -eq 0 ]]
