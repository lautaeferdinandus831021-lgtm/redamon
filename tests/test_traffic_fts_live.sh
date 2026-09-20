#!/usr/bin/env bash
#
# Live test for Phase 3 body full-text search (pg_trgm). Verifies:
#   - CAPTURE_PROXY_FTS=true  -> the webapp entrypoint creates the trgm indexes
#   - body search (?bodyq=) finds secrets / identifiers / words in resp_body
#   - cross-user body search is tenant-scoped (404)
#   - CAPTURE_PROXY_FTS=false -> the entrypoint drops the indexes (reclaim space)
#
# Recreates the webapp twice (to toggle the flag). Seeds + cleans up fixtures.
# Run: bash tests/test_traffic_fts_live.sh
set -uo pipefail

BASE="${BASE_URL:-http://localhost:3000}"
DC="docker compose"
TMP="$(mktemp -d)"
KEY="$($DC exec -T recon-orchestrator sh -c 'printf %s "$SCANNER_API_KEY"')"

trap 'rm -rf "$TMP"; \
  $DC exec -T webapp node scripts/e2e-bola-cleanup.mjs >/dev/null 2>&1 || true; \
  CAPTURE_PROXY_FTS=false '"$DC"' up -d webapp >/dev/null 2>&1 || true' EXIT

PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1 -> $3"; else bad "$1 (expected $2, got $3)"; fi; }
contains(){ if echo "$2" | grep -q "$3"; then ok "$1"; else bad "$1 (missing '$3')"; fi; }
excludes(){ if echo "$2" | grep -q "$3"; then bad "$1 (LEAKED '$3')"; else ok "$1"; fi; }
login(){ curl -s -o /dev/null -c "$2" -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"e2epass123\"}"; }
gbody(){ curl -s -b "$1" "$BASE$2"; }
gcode(){ curl -s -o /dev/null -w '%{http_code}' -b "$1" "$BASE$2"; }
idx_count(){ $DC exec -T postgres psql -U whitehat -d whitehat -tAc "SELECT count(*) FROM pg_indexes WHERE tablename='captured_http_transactions' AND indexname LIKE 'idx_cht_%_trgm';" | tr -d '\r\n '; }
wait_health(){ for i in $(seq 1 20); do sleep 3; [ "$(docker inspect -f '{{.State.Health.Status}}' whitehat-webapp 2>/dev/null)" = healthy ] && return 0; done; return 1; }

echo "== Enable FTS: recreate webapp with CAPTURE_PROXY_FTS=true =="
CAPTURE_PROXY_FTS=true $DC up -d webapp >/dev/null 2>&1
wait_health || { echo "webapp not healthy"; exit 1; }
check "3 trgm indexes created by entrypoint" "3" "$(idx_count)"

echo "== Seed + ingest bodies =="
SEED="$($DC exec -T webapp node scripts/e2e-bola-seed.mjs)" || { echo "seed failed"; exit 1; }
eval "$SEED"
login bola-a@e2e.local "$TMP/a.jar"
$DC exec -T postgres psql -U whitehat -d whitehat -tAc "UPDATE projects SET capture_proxy_enabled=true WHERE id='$PA_ID';" >/dev/null
ING='{"source":"recon","runId":"ttest-fts","transactions":['
ING+='{"tool":"httpx","host":"leak.test","scheme":"https","port":443,"path":"/a","method":"GET","statusCode":200,"respHeaders":{},"respBody":"config aws_key=AKIAIOSFODNN7EXAMPLE oops","respBodySize":30,"startedAt":"2026-07-19T10:00:00Z"},'
ING+='{"tool":"httpx","host":"err.test","scheme":"https","port":443,"path":"/b","method":"GET","statusCode":500,"respHeaders":{},"respBody":"java.lang.NullPointerException at com.foo.Bar","respBodySize":40,"startedAt":"2026-07-19T10:00:00Z"},'
ING+='{"tool":"httpx","host":"ok.test","scheme":"https","port":443,"path":"/c","method":"GET","statusCode":200,"respHeaders":{},"respBody":"welcome nothing to see","respBodySize":22,"startedAt":"2026-07-19T10:00:00Z"}'
ING+=']}'
contains "ingest 3 bodies" "$(curl -s -X POST "$BASE/api/traffic/$PA_ID/ingest" -H "X-Internal-Key: $KEY" -H 'Content-Type: application/json' -d "$ING")" '"stored":3'

echo "== Body search (?bodyq=) — secret, identifier, none =="
S1="$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID?bodyq=AKIA")"
contains "search 'AKIA' finds the leaked-key row" "$S1" 'leak.test'
excludes "search 'AKIA' excludes the clean row"   "$S1" 'ok.test'
S2="$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID?bodyq=NullPointerException")"
contains "search 'NullPointerException' finds the error row" "$S2" 'err.test'
S3="$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID?bodyq=zzznotpresentzzz")"
contains "search for absent term -> 0 total" "$S3" '"total":0'
check "cross-user body search -> 404" 404 "$(gcode "$TMP/a.jar" "/api/traffic/$PB_ID?bodyq=AKIA")"

echo "== Disable FTS: recreate webapp with CAPTURE_PROXY_FTS=false -> indexes dropped =="
CAPTURE_PROXY_FTS=false $DC up -d webapp >/dev/null 2>&1
wait_health || { echo "webapp not healthy"; exit 1; }
check "trgm indexes dropped by entrypoint" "0" "$(idx_count)"
# search still works (correct, just unindexed) with FTS off
contains "body search still correct with FTS off" "$(gbody "$TMP/a.jar" "/api/traffic/$PA_ID?bodyq=AKIA")" 'leak.test'

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
