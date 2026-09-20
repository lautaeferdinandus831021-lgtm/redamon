#!/usr/bin/env bash
# =============================================================================
# Test suite for the admin-account creation logic in whitehat.sh (issue #156).
#   - _wait_for_webapp        -> returns 0 when healthy, 1 on timeout (no dead-end)
#   - _admin_exists           -> parses check-admin.mjs count robustly
#   - _prompt_and_create_admin-> non-interactive env path + min-length gate
#   - ensure_admin            -> actionable skip message (points at create-admin)
#   - cmd_create_admin        -> standalone recovery command (upsert = safe re-run)
#   - dispatch + help wiring   for `create-admin`
#
# Pure unit tests: `docker`/`sleep` are stubbed, no daemon needed, CI-friendly.
# Run:  bash tests/whitehat_admin_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script (BASH_SOURCE guard prevents command dispatch).
# shellcheck disable=SC1090
source "$REPO_ROOT/whitehat.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_true()  { if eval "$2"; then pass "$1"; else fail "$1 (cmd: $2)"; fi; }
assert_false() { if eval "$2"; then fail "$1 (cmd unexpectedly true: $2)"; else pass "$1"; fi; }
assert_eq()    { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }

# Keep the polling loops instant.
sleep() { :; }

echo "== _wait_for_webapp: healthy immediately -> 0 =="
docker() { return 0; }   # wget --spider succeeds on the first probe
_wait_for_webapp 5; assert_eq "returns 0 when webapp answers" "$?" "0"
unset -f docker

echo "== _wait_for_webapp: never healthy -> 1 (times out, no hang) =="
docker() { return 1; }   # health probe always fails
_wait_for_webapp 3; assert_eq "returns 1 after the retry budget" "$?" "1"
unset -f docker

echo "== _admin_exists: count parsing =="
# check-admin.mjs prints the admin count on stdout (via `docker compose exec`).
docker() { echo "1"; return 0; }
assert_true  "count 1 -> admin exists"        "_admin_exists"
docker() { echo "3"; return 0; }
assert_true  "count 3 -> admin exists"        "_admin_exists"
docker() { echo "0"; return 0; }
assert_false "count 0 -> no admin"            "_admin_exists"
docker() { echo ""; return 0; }
assert_false "empty output -> no admin (fresh DB / error)" "_admin_exists"
unset -f docker

echo "== _prompt_and_create_admin: non-interactive env path passes values through =="
# Stub docker to CAPTURE the args create-admin.mjs is invoked with, so we can
# prove the env-provided name/email/password are forwarded verbatim.
# Stub records the exec args into a file (a plain `CAP=$*` would be lost because
# the call runs inside `$(...)`, a subshell). Read the file back afterwards.
CAPFILE="$(mktemp)"
docker() { echo "$*" > "$CAPFILE"; return 0; }
ADMIN_NAME="Alice" ADMIN_EMAIL="alice@example.com" ADMIN_PASSWORD="supersecret123" \
  out="$(_prompt_and_create_admin 2>&1)"; rc=$?
CAP="$(cat "$CAPFILE")"
assert_eq   "non-interactive call succeeds"          "$rc" "0"
assert_true "invokes create-admin.mjs"               "echo \"\$CAP\" | grep -q 'scripts/create-admin.mjs'"
assert_true "forwards ADMIN_NAME"                    "echo \"\$CAP\" | grep -q 'ADMIN_NAME=Alice'"
assert_true "forwards ADMIN_EMAIL"                   "echo \"\$CAP\" | grep -q 'ADMIN_EMAIL=alice@example.com'"
assert_true "forwards ADMIN_PASSWORD"                "echo \"\$CAP\" | grep -q 'ADMIN_PASSWORD=supersecret123'"
rm -f "$CAPFILE"; unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD

echo "== _prompt_and_create_admin: non-interactive rejects a too-short password =="
docker() { return 0; }
ADMIN_NAME="Bob" ADMIN_EMAIL="bob@example.com" ADMIN_PASSWORD="short" \
  out="$(_prompt_and_create_admin 2>&1)"; rc=$?
assert_eq   "exits non-zero on weak env password"   "$rc" "1"
assert_true "explains the minimum length"           "echo \"\$out\" | grep -qi 'too short'"
assert_false "did NOT reach create-admin.mjs"       "echo \"\$out\" | grep -q 'Admin user ready'"
unset -f docker; unset ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD

echo "== ensure_admin: webapp never ready -> actionable skip (points at create-admin) =="
docker() { return 1; }   # health probe never succeeds -> _wait_for_webapp fails
out="$(ensure_admin 2>&1)"; rc=$?
assert_eq   "ensure_admin returns (does not abort the caller)" "$rc" "0"
assert_true "tells the user to run create-admin" "echo \"\$out\" | grep -q './whitehat.sh create-admin'"
assert_false "no cryptic dead-end 'skipping admin check'" "echo \"\$out\" | grep -qi 'skipping admin check'"
unset -f docker

echo "== cmd_create_admin: existing admin -> warns it will add/reset (upsert is safe) =="
# Stub the heavy prerequisites so we exercise only the command's own logic.
print_banner() { :; }
check_prerequisites() { :; }
_wait_for_webapp() { return 0; }
_admin_exists() { return 0; }              # pretend an admin already exists
_prompt_and_create_admin() { echo "[prompt ran]"; }
out="$(cmd_create_admin 2>&1)"; rc=$?
assert_eq   "cmd_create_admin succeeds"              "$rc" "0"
assert_true "warns an admin already exists"          "echo \"\$out\" | grep -qi 'admin user already exists'"
assert_true "explains add-new-or-reset semantics"    "echo \"\$out\" | grep -qiE 'reset|add a new'"
assert_true "still proceeds to the prompt"           "echo \"\$out\" | grep -q '\[prompt ran\]'"
unset -f print_banner check_prerequisites _wait_for_webapp _admin_exists _prompt_and_create_admin

echo "== cmd_create_admin: webapp down -> clear error, non-zero exit =="
print_banner() { :; }
check_prerequisites() { :; }
_wait_for_webapp() { return 1; }           # never comes up
out="$(cmd_create_admin 2>&1)"; rc=$?
assert_eq   "exits non-zero when webapp is down"     "$rc" "1"
assert_true "tells the operator to start the stack"  "echo \"\$out\" | grep -q './whitehat.sh up'"
unset -f print_banner check_prerequisites _wait_for_webapp

echo "== dispatch + help wiring for create-admin =="
SRC="$REPO_ROOT/whitehat.sh"
assert_true "dispatch has a create-admin) arm"       "grep -qE '^\s*create-admin\)\s*cmd_create_admin' '$SRC'"
assert_true "cmd_create_admin is defined"            "grep -q '^cmd_create_admin()' '$SRC'"
# Capture FIRST, then grep. Piping the script straight into `grep -q` is a race:
# grep exits the instant it matches and closes the pipe, `whitehat.sh help` is
# still writing its ~40 lines and dies with SIGPIPE (141), and `set -o pipefail`
# then reports the whole pipeline as failed. On an idle box the writer finishes
# first and it passes; under load it loses the race. Measured before this fix:
# 40/40 pass serially, 14/24 FAIL when run concurrently.
HELP_OUT="$(cd "$REPO_ROOT" && ./whitehat.sh help 2>/dev/null || true)"
assert_true "help lists create-admin"                "echo \"\$HELP_OUT\" | grep -qi 'create-admin'"

echo
echo "-----------------------------------------"
printf 'Admin suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
