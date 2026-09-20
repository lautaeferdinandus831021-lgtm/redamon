#!/usr/bin/env bash
# =============================================================================
# Test suite for cmd_sca_intel_sync / ensure_sca_intel in whitehat.sh.
#
# Why this exists: an air-gapped deploy (SCA_INTEL_AUTO_REFRESH=false) skipped
# the incident catalog entirely, so it never received the bundled offline copy
# and kept an empty catalog forever. It now runs `--seed-only`, which must never
# reach the network, and must never abort install/update when it fails.
#
# Pure unit test: `docker` is stubbed as a bash function, so it runs anywhere
# with no Docker daemon.  Run:  bash tests/whitehat_sca_intel_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/whitehat.sh"   # BASH_SOURCE guard blocks command dispatch
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
assert_contains() {
  if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi
}
assert_not_contains() {
  if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3' in: $2)"; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCRIPT_DIR="$TMP"            # ensure_sca_intel reads $SCRIPT_DIR/.env
RUNS="$TMP/runs"

# --- stubs -------------------------------------------------------------------
# ANALYZER_PRESENT=0 makes `docker image inspect` fail; RUN_RC is what
# `docker run` exits with. Every `docker run` argv is appended to $RUNS.
ANALYZER_PRESENT=1
RUN_RC=0
docker() {
  case "$1 ${2:-}" in
    "image inspect")  [[ "$ANALYZER_PRESENT" == 1 ]] ;;
    "volume inspect") return 0 ;;
    "run "*)          printf '%s\n' "$*" >> "$RUNS"; return "$RUN_RC" ;;
    *)                return 0 ;;
  esac
}
export_version() { :; }
compose_build() { return 1; }

reset() { : > "$RUNS"; : > "$SCRIPT_DIR/.env"; ANALYZER_PRESENT=1; RUN_RC=0; }

# ---------------------------------------------------------------------------
section "cmd_sca_intel_sync builds the right container command"

reset
( cmd_sca_intel_sync ) >/dev/null 2>&1
RUN="$(cat "$RUNS")"
assert_contains     "plain sync runs intel_sync"            "$RUN" "-m supply_chain_common.intel_sync --out /sca-intel"
assert_not_contains "plain sync keeps its network"          "$RUN" "--network none"
assert_not_contains "plain sync passes no mode flag"        "$RUN" "--seed-only"

reset
( cmd_sca_intel_sync --force ) >/dev/null 2>&1
RUN="$(cat "$RUNS")"
assert_contains     "--force is passed through"             "$RUN" "--out /sca-intel --force"
assert_not_contains "--force keeps its network"             "$RUN" "--network none"

reset
( cmd_sca_intel_sync --seed-only ) >/dev/null 2>&1
RUN="$(cat "$RUNS")"
assert_contains     "--seed-only is passed through"         "$RUN" "--out /sca-intel --seed-only"
assert_contains     "--seed-only runs with no network"      "$RUN" "--network none"
assert_contains     "--seed-only still mounts supply_chain_common" "$RUN" "/app/supply_chain_common:ro"

reset
OUT="$( ( cmd_sca_intel_sync --bogus ) 2>&1 )"; RC=$?
if [[ $RC -ne 0 ]]; then pass "an unknown flag exits non-zero"; else fail "an unknown flag exited 0"; fi
assert_contains     "an unknown flag is named"              "$OUT" "--bogus"
if [[ ! -s "$RUNS" ]]; then pass "an unknown flag runs nothing"; else fail "an unknown flag still ran docker"; fi

reset; RUN_RC=1
( cmd_sca_intel_sync ) >/dev/null 2>&1; RC=$?
if [[ $RC -eq 1 ]]; then pass "a failed sync exits 1"; else fail "a failed sync exited $RC"; fi

# ---------------------------------------------------------------------------
section "ensure_sca_intel (install / update / up)"

reset
ensure_sca_intel >/dev/null 2>&1
RUN="$(cat "$RUNS")"
assert_not_contains "auto-refresh on: a normal sync, not seed-only" "$RUN" "--seed-only"
assert_contains     "auto-refresh on: the sync runs"        "$RUN" "supply_chain_common.intel_sync"

reset
echo "SCA_INTEL_AUTO_REFRESH=false" > "$SCRIPT_DIR/.env"
ensure_sca_intel >/dev/null 2>&1; RC=$?
RUN="$(cat "$RUNS")"
assert_contains     "air-gapped: installs the bundled copy" "$RUN" "--seed-only"
assert_contains     "air-gapped: with no network"           "$RUN" "--network none"
if [[ "$(wc -l < "$RUNS")" -eq 1 ]]; then pass "air-gapped: exactly one container, no feed sync"; else fail "air-gapped: ran $(wc -l < "$RUNS") containers"; fi
if [[ $RC -eq 0 ]]; then pass "air-gapped: returns 0"; else fail "air-gapped: returned $RC"; fi

reset
echo "SCA_INTEL_AUTO_REFRESH=false" > "$SCRIPT_DIR/.env"; RUN_RC=1
OUT="$(ensure_sca_intel 2>&1)"; RC=$?
if [[ $RC -eq 0 ]]; then pass "air-gapped: a failed seed never aborts install/update"; else fail "air-gapped: failure returned $RC"; fi
assert_contains     "air-gapped: a failed seed is reported" "$OUT" "Could not install the bundled incident catalog"

reset; RUN_RC=1
ensure_sca_intel >/dev/null 2>&1; RC=$?
if [[ $RC -eq 0 ]]; then pass "a failed sync never aborts install/update"; else fail "a failed sync returned $RC"; fi

reset; ANALYZER_PRESENT=0
echo "SCA_INTEL_AUTO_REFRESH=false" > "$SCRIPT_DIR/.env"
ensure_sca_intel >/dev/null 2>&1; RC=$?
if [[ $RC -eq 0 && ! -s "$RUNS" ]]; then pass "no analyzer image: skipped, nothing run"; else fail "no analyzer image: rc=$RC runs=$(cat "$RUNS")"; fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
