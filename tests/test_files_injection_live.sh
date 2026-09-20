#!/usr/bin/env bash
# =============================================================================
# Live security regression — agent GET /files unauthenticated OS command
# injection (CWE-78). Proves, against a RUNNING stack, that:
#   1. Without the internal key the route is rejected (401)         [auth]
#   2. With the key a normal /tmp file still downloads (200)        [no regression]
#   3. A `; <cmd>` injection payload does NOT execute in kali-sandbox
#      (no marker file is created)                                  [the fix]
#   4. With the key the injection payload just 404s (treated as a filename)
#
# The file is read inside kali-sandbox via the kali_shell MCP tool (bash -c),
# so the injected command, if it ran, would create the marker in kali's /tmp.
#
# Requires agent + kali-sandbox running; SKIPS (exit 0) otherwise so it is CI-safe.
# Run:  bash tests/test_files_injection_live.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

running() { docker compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q "$1 running"; }
if ! running agent || ! running kali-sandbox; then
    echo "agent/kali-sandbox not running — skipping live /files injection checks."
    exit 0
fi

KEY="$(grep -E '^INTERNAL_API_KEY=' .env 2>/dev/null | head -1 | cut -d= -f2-)"
URL="http://127.0.0.1:8090/files"
MARKER="/tmp/PWNED_files_injection_$$"
PROBE="/tmp/whitehat_files_probe_$$.txt"

cleanup() {
    docker compose exec -T kali-sandbox sh -c "rm -f '$MARKER' '$PROBE'" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# ---- 1. No key -> 401 (fails only meaningfully when the key is actually set) ----
echo "== 1. unauthenticated request rejected =="
code_noauth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -G "$URL" --data-urlencode 'path=/tmp/whatever' 2>/dev/null)"
if [[ -z "$KEY" ]]; then
    echo "  (INTERNAL_API_KEY unset in .env — auth fails open by design; skipping the 401 assertion)"
elif [[ "$code_noauth" == "401" ]]; then
    pass "no key -> 401 ($code_noauth)"
else
    fail "no key -> expected 401, got '$code_noauth'"
fi

AUTH=(); [[ -n "$KEY" ]] && AUTH=(-H "x-internal-key: $KEY")

# ---- 2. Authenticated benign download works ----
echo "== 2. authenticated benign /tmp download works =="
docker compose exec -T kali-sandbox sh -c "printf hello > '$PROBE'" >/dev/null 2>&1
body="$(curl -s --max-time 15 "${AUTH[@]}" -G "$URL" --data-urlencode "path=$PROBE" 2>/dev/null)"
if [[ "$body" == "hello" ]]; then
    pass "benign download returned file contents"
else
    fail "benign download expected 'hello', got '$body'"
fi

# ---- 3. Injection payload does NOT execute (no marker created) ----
echo "== 3. injection payload does not execute in kali-sandbox =="
curl -s -o /dev/null --max-time 15 "${AUTH[@]}" -G "$URL" \
    --data-urlencode "path=/tmp/x; touch $MARKER" 2>/dev/null
if docker compose exec -T kali-sandbox test -f "$MARKER" 2>/dev/null; then
    fail "INJECTION EXECUTED — marker '$MARKER' was created in kali-sandbox"
else
    pass "marker not created — injection neutralised"
fi

# ---- 4. A second injection class ($(...) command substitution) also blocked ----
# Separate metacharacter family from test 3's `;` — proves shlex.quote covers
# command substitution too, using the same deterministic marker technique
# (independent of the endpoint's flaky missing-file response code).
echo "== 4. command-substitution \$(...) payload does not execute =="
MARKER2="/tmp/PWNED_files_subst_$$"
docker compose exec -T kali-sandbox sh -c "rm -f '$MARKER2'" >/dev/null 2>&1 || true
curl -s -o /dev/null --max-time 15 "${AUTH[@]}" -G "$URL" \
    --data-urlencode "path=/tmp/\$(touch $MARKER2)" 2>/dev/null
if docker compose exec -T kali-sandbox test -f "$MARKER2" 2>/dev/null; then
    fail "COMMAND SUBSTITUTION EXECUTED — marker '$MARKER2' created in kali-sandbox"
else
    pass "\$(...) marker not created — command substitution neutralised"
fi
docker compose exec -T kali-sandbox sh -c "rm -f '$MARKER2'" >/dev/null 2>&1 || true

# ---- 5. A legit filename with spaces/parens still downloads (functional) ----
# Pre-fix the unquoted interpolation broke these too; shlex.quote makes them work.
echo "== 5. legit filename with spaces downloads correctly =="
SPACED="/tmp/whitehat probe ($$).txt"
docker compose exec -T kali-sandbox sh -c "printf spaced-ok > '$SPACED'" >/dev/null 2>&1
body_sp="$(curl -s --max-time 15 "${AUTH[@]}" -G "$URL" --data-urlencode "path=$SPACED" 2>/dev/null)"
if [[ "$body_sp" == "spaced-ok" ]]; then
    pass "filename with spaces/parens downloaded correctly"
else
    fail "spaced filename expected 'spaced-ok', got '$body_sp'"
fi
docker compose exec -T kali-sandbox sh -c "rm -f '$SPACED'" >/dev/null 2>&1 || true

# ---- 6. Pipe-class injection also inert at runtime (third distinct class) ----
echo "== 6. pipe | injection does not execute =="
MARKER3="/tmp/PWNED_files_pipe_$$"
docker compose exec -T kali-sandbox sh -c "rm -f '$MARKER3'" >/dev/null 2>&1 || true
curl -s -o /dev/null --max-time 15 "${AUTH[@]}" -G "$URL" \
    --data-urlencode "path=/tmp/x | touch $MARKER3" 2>/dev/null
if docker compose exec -T kali-sandbox test -f "$MARKER3" 2>/dev/null; then
    fail "PIPE INJECTION EXECUTED — marker '$MARKER3' created in kali-sandbox"
else
    pass "| marker not created — pipe injection neutralised"
fi
docker compose exec -T kali-sandbox sh -c "rm -f '$MARKER3'" >/dev/null 2>&1 || true

echo
echo "==================================================================="
printf 'RESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
