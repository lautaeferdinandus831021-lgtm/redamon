#!/usr/bin/env bash
# =============================================================================
# I7 — deploy.env (+ cert/) removed on run exit by the cleanup_ssh EXIT trap.
#
# Static-asserts the wiring, then extracts cleanup_ssh from deploy.sh and runs it
# with a stubbed $SSH to prove it issues the remote shred+rm and removes the
# local staged copy, on both a clean and an SSH-error path.
#
# Run: bash tests/deploy_env_cleanup_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host/deploy.sh"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

echo "== static wiring =="
grep -q 'trap cleanup_ssh EXIT' "$DEPLOY" && pass "cleanup_ssh armed on EXIT" || fail "no EXIT trap"
awk '/^cleanup_ssh\(\) \{/,/^\}/' "$DEPLOY" | grep -q 'rm -rf ${REMOTE_TMP}' \
  && pass "cleanup removes REMOTE_TMP" || fail "cleanup does not rm REMOTE_TMP"
awk '/^cleanup_ssh\(\) \{/,/^\}/' "$DEPLOY" | grep -q 'shred' \
  && pass "cleanup shreds deploy.env" || fail "cleanup does not shred"
awk '/^cleanup_ssh\(\) \{/,/^\}/' "$DEPLOY" | grep -q 'cert' \
  && pass "cleanup removes cert/" || fail "cleanup does not remove cert/"

echo "== functional (stubbed SSH) =="
# Extract cleanup_ssh() and eval it in this shell.
CLEANUP_SRC="$(awk '/^cleanup_ssh\(\) \{/,/^\}/' "$DEPLOY")"
eval "$CLEANUP_SRC"

# Common stubs.
REMOTE_TMP="/tmp/whitehat-deploy"
REMOTE_USER="op"; HOST_IP="203.0.113.1"; SSH_CONTROL_PATH=""
SSH_CALLS=""

# Success path: SSH records the remote command it was asked to run.
SSH='record_ssh'
record_ssh() { SSH_CALLS="$SSH_CALLS
$*"; return 0; }
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"; : > "$TMP/.deploy.env.staged"
cleanup_ssh
echo "$SSH_CALLS" | grep -q "rm -rf ${REMOTE_TMP}" && pass "remote rm -rf REMOTE_TMP issued" || fail "remote rm not issued"
echo "$SSH_CALLS" | grep -q "shred -u ${REMOTE_TMP}/deploy.env" && pass "remote shred issued" || fail "remote shred not issued"
[[ ! -f "$TMP/.deploy.env.staged" ]] && pass "local staged copy removed" || fail "local staged copy left behind"
rm -rf "$TMP"

# Error path: SSH fails (e.g. host already gone) -> cleanup must NOT abort.
SSH_CALLS=""
record_ssh_fail() { return 255; }
SSH='record_ssh_fail'
TMP=$(mktemp -d); SCRIPT_DIR="$TMP"; : > "$TMP/.deploy.env.staged"
if cleanup_ssh; then pass "cleanup survives SSH failure (still exit 0)"; else fail "cleanup aborted on SSH failure"; fi
[[ ! -f "$TMP/.deploy.env.staged" ]] && pass "local staged removed even on SSH failure" || fail "local staged left on SSH failure"
rm -rf "$TMP"

echo
echo "-----------------------------------------"
printf 'deploy.env cleanup suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
