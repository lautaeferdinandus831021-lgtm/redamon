#!/usr/bin/env bash
# =============================================================================
# The gate must not be able to go green having run nothing.
#
# Two silent skips used to exist in `cmd_test`, and both mattered:
#
#   _test_run_webapp   returned 0 when webapp/node_modules was absent
#   _test_run_section  returned 0 when the section's image was not built
#
# The second is the wider hole: a missing `whitehat-recon` image skipped every
# runtime test that protects the engagement rate ceiling. Most of the recon
# settings registry's enforcement is TypeScript, so the first skip made the rest
# of that layer unverified too.
#
# These suites assert the SKIP-IS-A-FAILURE behaviour directly, by calling the
# helpers with their inputs missing. They run on the host with no image and no
# node_modules, which is exactly the situation they describe.
#
# Run:  bash tests/whitehat_gate_unskippable_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/whitehat.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1 ($2)"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# Keep the helpers' own output capturable rather than silenced: several
# assertions below are about WHAT it prints.

# =============================================================================
section "T26: a missing input fails the unit tier"
# =============================================================================

out="$(_test_missing_input demo "the demo image is not built" "build it" unit 2>&1)"
rc=$?
assert_eq "unit tier returns non-zero" "$rc" "1"
assert_contains "names the section" "$out" "demo"
assert_contains "says it cannot run" "$out" "CANNOT RUN"
assert_contains "gives the fix" "$out" "build it"
assert_contains "names the opt-out" "$out" "WHITEHAT_TEST_ALLOW_MISSING"

out="$(_test_missing_input demo "not built" "build it" all 2>&1)"
assert_eq "all tier also fails" "$?" "1"

out="$(_test_missing_input demo "not built" "build it" coverage 2>&1)"
assert_eq "coverage tier also fails" "$?" "1"

# The narrower tiers are not the gate, so a missing input there is a skip.
out="$(_test_missing_input demo "not built" "build it" live 2>&1)"
assert_eq "live tier still skips" "$?" "0"

# =============================================================================
section "T26: the opt-out is deliberate, named, and loud"
# =============================================================================

out="$(WHITEHAT_TEST_ALLOW_MISSING=demo _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "an allowed section returns 0" "$?" "0"
assert_contains "but prints SKIPPED" "$out" "SKIPPED"
assert_contains "and names the opt-out that allowed it" "$out" "WHITEHAT_TEST_ALLOW_MISSING"

out="$(WHITEHAT_TEST_ALLOW_MISSING=other _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "a DIFFERENT section in the opt-out does not allow this one" "$?" "1"

out="$(WHITEHAT_TEST_ALLOW_MISSING=all _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "'all' allows any section" "$?" "0"

out="$(WHITEHAT_TEST_ALLOW_MISSING="webapp, demo ,recon" _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "a comma list tolerates spaces" "$?" "0"

# An empty opt-out is not an opt-out. This is the case a CI config reaches by
# exporting the variable unset, and it must not silently open the gate.
out="$(WHITEHAT_TEST_ALLOW_MISSING= _test_missing_input demo "not built" "build it" unit 2>&1)"
assert_eq "an empty opt-out still fails" "$?" "1"

# =============================================================================
section "T26: the real call sites route through it"
# =============================================================================

# webapp: node_modules absent -> non-zero for the gate tier.
_saved_dir="$SCRIPT_DIR"
SCRIPT_DIR="$(mktemp -d)"
out="$(_test_run_webapp unit 2>&1)"
assert_eq "_test_run_webapp fails when vitest is absent" "$?" "1"
assert_contains "names npm ci as the fix" "$out" "npm ci"

out="$(_test_run_webapp live 2>&1)"
assert_eq "_test_run_webapp still skips outside the gate tiers" "$?" "0"

# shell suites: no tests/*_test.sh -> non-zero for the gate tier.
out="$(_test_run_shell unit 2>&1)"
assert_eq "_test_run_shell fails when no suites are found" "$?" "1"
rmdir "$SCRIPT_DIR" 2>/dev/null
SCRIPT_DIR="$_saved_dir"

# section: an image that cannot exist -> non-zero for the gate tier.
if command -v docker >/dev/null 2>&1; then
    out="$(_test_run_section demo whitehat-no-such-image-xyz /repo /repo tests . "" unit 2>&1)"
    assert_eq "_test_run_section fails on an unbuilt image" "$?" "1"
    assert_contains "names the image" "$out" "whitehat-no-such-image-xyz"
else
    pass "docker absent, section-image case not exercised (helper covered above)"
fi

# =============================================================================
section "T27: the runner reports an executed-test count"
# =============================================================================

runner="$REPO_ROOT/tooling/scripts/pytest_isolated.py"
if command -v python3 >/dev/null 2>&1; then
    out="$(python3 -c "
import sys
sys.path.insert(0, '$REPO_ROOT/tooling/scripts')
from pytest_isolated import tests_executed
print(tests_executed('==== 12 passed, 3 skipped in 1.2s ===='))
print(tests_executed('==== 4 failed, 20 passed in 2s ===='))
print(tests_executed('nothing here'))
" 2>&1)"
    assert_eq "a summary line is counted" "$(echo "$out" | sed -n 1p)" "12"
    assert_eq "failures count as executed" "$(echo "$out" | sed -n 2p)" "24"
    assert_eq "no summary means zero" "$(echo "$out" | sed -n 3p)" "0"
    assert_contains "the runner prints the count" "$(grep -c 'TESTS EXECUTED' "$runner")" "1"
    assert_contains "the runner names files that collected nothing" \
        "$(grep -c 'collected NO tests' "$runner")" "1"
else
    fail "python3 unavailable; cannot check the runner"
fi

printf '\n\033[1mresult:\033[0m %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
