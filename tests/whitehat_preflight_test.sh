#!/usr/bin/env bash
# =============================================================================
# Test suite for the whitehat.sh preflight guards that keep a host from ending up
# with a dead stack behind a 502:
#
#   preflight_disk_gate / _disk_free_gb / _docker_disk_path   (disk governor)
#   ensure_core_images / _core_image_names                    (no images -> no silent start)
#   verify_core_running / _service_running                    (no "ready!" over a dead stack)
#   _restore_runtime_tracked_files                            (runtime scribbles block git pull)
#
# Every test stubs docker/df/git, so no daemon and no network are needed.
# Run:  bash tests/whitehat_preflight_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script (the BASH_SOURCE guard prevents command dispatch), then relax
# -e so a failing assertion does not abort the run. Same pattern as
# tests/whitehat_build_test.sh.
# shellcheck disable=SC1090
source "$REPO_ROOT/whitehat.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq()       { if [[ "$2" == "$3" ]]; then pass "$1 ($2)"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3')"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# Silence the script's own logging unless a test captures it.
info() { :; }
warn() { :; }
error() { :; }

# --- stubs -------------------------------------------------------------------
# df: report a settable number of free KB in POSIX `df -Pk` layout.
DF_AVAIL_KB=104857600     # 100GB
DF_RC=0
df() {
    [[ "$DF_RC" -ne 0 ]] && return "$DF_RC"
    echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
    echo "/dev/stub 1000000000 1000 ${DF_AVAIL_KB} 50% /"
    return 0
}
# gb <n> -> KB
gb() { echo $(( $1 * 1048576 )); }

section "UNIT: _disk_free_gb"
DF_AVAIL_KB="$(gb 100)"; assert_eq "100GB free"        "$(_disk_free_gb /x)" "100"
DF_AVAIL_KB="$(gb 7)";   assert_eq "7GB free"          "$(_disk_free_gb /x)" "7"
DF_AVAIL_KB=524288;      assert_eq "0.5GB rounds to 0" "$(_disk_free_gb /x)" "0"
assert_eq "empty path -> unknown" "$(_disk_free_gb '')" ""
DF_RC=1;                 assert_eq "df failure -> unknown" "$(_disk_free_gb /x)" ""
DF_RC=0

section "UNIT: _docker_disk_path"
_docker_info_field() { case "$1" in DockerRootDir) echo "$STUB_ROOT";; esac; }
STUB_ROOT="$(mktemp -d)"
assert_eq "existing docker root wins" "$(_docker_disk_path)" "$STUB_ROOT"
rmdir "$STUB_ROOT"
assert_eq "vanished root -> repo fallback" "$(_docker_disk_path)" "$SCRIPT_DIR"
STUB_ROOT=""
assert_eq "no docker info -> repo fallback" "$(_docker_disk_path)" "$SCRIPT_DIR"
# Keep the fallback path for the rest of the suite.
_docker_info_field() { printf ''; }

section "UNIT: preflight_disk_gate thresholds"
unset WHITEHAT_SKIP_DISK_GATE WHITEHAT_MIN_DISK_GB
_gate() { DF_AVAIL_KB="$(gb "$1")"; preflight_disk_gate "$2" test; echo "$?"; }
assert_eq "100GB vs 40 required -> pass"      "$(_gate 100 40)" "0"
assert_eq "exactly 40 vs 40 -> pass"          "$(_gate 40 40)"  "0"
assert_eq "39 vs 40 -> block"                 "$(_gate 39 40)"  "1"
assert_eq "0 free -> block"                   "$(_gate 0 40)"   "1"
assert_eq "20 vs 15 partial -> pass"          "$(_gate 20 15)"  "0"
assert_eq "14 vs 15 partial -> block"         "$(_gate 14 15)"  "1"
assert_eq "required 0 -> always pass"         "$(_gate 0 0)"    "0"

section "UNIT: preflight_disk_gate is advisory when unmeasurable"
DF_RC=1
assert_eq "df broken -> pass, never block" "$(preflight_disk_gate 40 test; echo $?)" "0"
DF_RC=0

section "UNIT: preflight_disk_gate overrides"
DF_AVAIL_KB="$(gb 1)"
assert_eq "1GB free blocks by default" "$(preflight_disk_gate 40 test; echo $?)" "1"
# Export inside the same subshell that runs the gate: a `VAR=x func` prefix does
# not reach a function called from a command substitution.
assert_eq "WHITEHAT_SKIP_DISK_GATE=1 bypasses" \
    "$( export WHITEHAT_SKIP_DISK_GATE=1; preflight_disk_gate 40 test; echo $? )" "0"
assert_eq "WHITEHAT_MIN_DISK_GB lowers the bar" \
    "$( export WHITEHAT_MIN_DISK_GB=1; preflight_disk_gate 40 test; echo $? )" "0"
assert_eq "WHITEHAT_MIN_DISK_GB raises the bar" \
    "$( DF_AVAIL_KB="$(gb 50)"; export WHITEHAT_MIN_DISK_GB=80; preflight_disk_gate 40 test; echo $? )" "1"
unset WHITEHAT_SKIP_DISK_GATE WHITEHAT_MIN_DISK_GB

section "UNIT: preflight_disk_gate messaging"
error() { echo "ERR:$*"; }
warn()  { echo "WARN:$*"; }
DF_AVAIL_KB="$(gb 5)"
OUT="$(preflight_disk_gate 40 'full image build' 2>&1)"
assert_contains "names the shortfall"   "$OUT" "5GB free"
assert_contains "names the requirement" "$OUT" "need ~40GB"
assert_contains "names the operation"   "$OUT" "full image build"
assert_contains "offers a way out"      "$OUT" "docker builder prune -af"
DF_AVAIL_KB="$(gb 45)"   # over 40, under the 60 comfort line
OUT="$(preflight_disk_gate 40 build 2>&1)"
assert_contains "warns when tight"      "$OUT" "Disk is tight"
assert_not_contains "but does not block" "$OUT" "Not enough disk space"
DF_AVAIL_KB="$(gb 200)"
OUT="$(preflight_disk_gate 40 build 2>&1)"
assert_eq "silent when roomy" "$OUT" ""
info() { :; }; warn() { :; }; error() { :; }

section "INTEGRATION: compose_build refuses to start a doomed build"
# Stub the build machinery so only the disk decision is under test.
detect_build_resources() { BUILD_MEM_MB=16384; BUILD_NCPU=8; BUILD_RES_SOURCE="stub"; }
DOCKER_CALLS="$(mktemp)"
docker() { echo "$*" >> "$DOCKER_CALLS"; return 0; }
# The parent must own DOCKER_CALLS: _cb runs inside a command substitution, so
# anything it assigns is lost when that subshell exits.
_cb() { : > "$DOCKER_CALLS"; DF_AVAIL_KB="$(gb "$1")"; shift; compose_build "$@"; echo "rc=$?"; }

assert_eq "full build blocked at 20GB"   "$(_cb 20 build)" "rc=1"
assert_eq "no docker call was made"      "$(cat "$DOCKER_CALLS")" ""
assert_eq "full build allowed at 60GB"   "$(_cb 60 build)" "rc=0"
assert_contains "and it did build"       "$(cat "$DOCKER_CALLS")" "build"
# A targeted rebuild uses the lower bar: 20GB is short for a full build but fine
# for one service. This is the case that must NOT regress into over-blocking.
assert_eq "partial build allowed at 20GB" "$(_cb 20 build docker-broker)" "rc=0"
assert_eq "partial build blocked at 5GB"  "$(_cb 5 build docker-broker)"  "rc=1"
assert_eq "tools full build blocked at 20GB" "$(_cb 20 --profile tools build)" "rc=1"

section "INTEGRATION: ensure_core_images"
_core_image_names() { printf 'whitehat-agent\nwhitehat-webapp\n'; }
# docker image inspect succeeds only for images listed in HAVE.
HAVE="whitehat-agent whitehat-webapp"
docker() {
    if [[ "$1" == "image" && "$2" == "inspect" ]]; then
        [[ " $HAVE " == *" $3 "* ]] && return 0 || return 1
    fi
    return 0
}
assert_eq "all images present -> pass" "$(ensure_core_images; echo $?)" "0"
HAVE="whitehat-agent"
assert_eq "one image missing -> block" "$(ensure_core_images; echo $?)" "1"
HAVE=""
assert_eq "no images at all -> block"  "$(ensure_core_images; echo $?)" "1"
error() { echo "ERR:$*"; }
OUT="$(ensure_core_images 2>&1)"
assert_contains "names the missing image" "$OUT" "whitehat-webapp"
assert_contains "points at the fix"       "$OUT" "./whitehat.sh install"
error() { :; }
# Unresolvable compose output must never block a working host.
_core_image_names() { printf ''; }
assert_eq "unresolvable names -> pass (never block on a guess)" "$(ensure_core_images; echo $?)" "0"

section "INTEGRATION: verify_core_running"
# ps -q returns an id per service in UP; inspect reports Running for ids in ALIVE.
UP="webapp agent"; ALIVE="id-webapp id-agent"
docker() {
    if [[ "$1" == "compose" && "$2" == "ps" ]]; then
        local svc="${*: -1}"
        [[ " $UP " == *" $svc "* ]] && echo "id-$svc"
        return 0
    fi
    if [[ "$1" == "inspect" ]]; then
        local id="${*: -1}"
        [[ " $ALIVE " == *" $id "* ]] && echo "true" || echo "false"
        return 0
    fi
    return 0
}
assert_eq "both running -> ready"  "$(verify_core_running; echo $?)" "0"
# The exact incident shape: compose exits 0, container is created but not running.
ALIVE="id-agent"
assert_eq "webapp created but dead -> NOT ready" "$(verify_core_running; echo $?)" "1"
ALIVE="id-webapp id-agent"; UP="webapp"
assert_eq "agent absent -> NOT ready" "$(verify_core_running; echo $?)" "1"
UP=""; ALIVE=""
assert_eq "nothing up -> NOT ready" "$(verify_core_running; echo $?)" "1"
error() { echo "ERR:$*"; }
OUT="$(verify_core_running 2>&1)"
assert_contains "explains the 502 symptom" "$OUT" "port 3000"
assert_contains "hands over a log command" "$OUT" "docker compose logs"
error() { :; }

section "REGRESSION: every 'ready'/'success' announcement is gated on a check"
# The whole point of verify_core_running is that nothing tells the user the stack
# is up without asking Docker first. A new banner added later must be gated too,
# so assert on the source rather than on behaviour alone.
SRC="$REPO_ROOT/whitehat.sh"
# Real banners only: skip comment lines, which legitimately quote the string.
banner_lines="$(grep -n 'is ready!' "$SRC" | grep -v '^[0-9]*:[[:space:]]*#' | cut -d: -f1)"
assert_eq "three ready banners exist (install, up, up dev)" \
    "$(printf '%s\n' "$banner_lines" | grep -c .)" "3"
for ln in $banner_lines; do
    # verify_core_running must appear in the ~12 lines above each banner.
    ctx="$(sed -n "$(( ln > 12 ? ln - 12 : 1 )),${ln}p" "$SRC")"
    if [[ "$ctx" == *"verify_core_running"* ]]; then
        pass "banner at line $ln is gated on verify_core_running"
    else
        fail "banner at line $ln announces readiness WITHOUT verifying"
    fi
done
upd_ln="$(grep -n 'success "Updated to v' "$SRC" | cut -d: -f1)"
ctx="$(sed -n "$(( upd_ln - 12 )),${upd_ln}p" "$SRC")"
assert_contains "update success is gated too" "$ctx" "verify_core_running"
assert_contains "and only when it was up before" "$ctx" "stack_was_up"

section "UNIT: update's stack_was_up guard"
# A stopped stack must not turn a legitimate update into a failure.
_upd_tail() {
    local stack_was_up="$1" running="$2"
    verify_core_running() { [[ "$running" == "yes" ]]; }
    if [[ "$stack_was_up" == "true" ]] && ! verify_core_running; then echo "FAILED"; else echo "OK"; fi
}
assert_eq "was up, still up -> success"        "$(_upd_tail true yes)"  "OK"
assert_eq "was up, now dead -> failure"        "$(_upd_tail true no)"   "FAILED"
assert_eq "was down, still down -> success"    "$(_upd_tail false no)"  "OK"
assert_eq "was down, came up -> success"       "$(_upd_tail false yes)" "OK"
unset -f verify_core_running
# shellcheck disable=SC1090
source "$REPO_ROOT/whitehat.sh"   # restore the real one
set +e
info() { :; }; warn() { :; }; error() { :; }

section "INTEGRATION: _restore_runtime_tracked_files"
# Real git repo, so the ls-files/diff/checkout semantics are the real ones.
TMP_REPO="$(mktemp -d)"
git -C "$TMP_REPO" init -q
git -C "$TMP_REPO" config user.email t@t; git -C "$TMP_REPO" config user.name t
mkdir -p "$TMP_REPO/recon/main_recon_modules/data/mitre_db"
MARKER="recon/main_recon_modules/data/mitre_db/.last_update"
echo "2026-01-01T00:00:00" > "$TMP_REPO/$MARKER"
git -C "$TMP_REPO" add -A && git -C "$TMP_REPO" commit -qm init

SCRIPT_DIR="$TMP_REPO"
RUNTIME_TRACKED_PATHS="$MARKER"

assert_eq "clean tree stays clean" \
    "$(_restore_runtime_tracked_files; git -C "$TMP_REPO" status --porcelain | wc -l | tr -d ' ')" "0"

# The incident: a scan rewrote the marker, so --ff-only would refuse to pull.
echo "2026-08-06T12:00:00" > "$TMP_REPO/$MARKER"
assert_eq "dirty marker detected" \
    "$(git -C "$TMP_REPO" status --porcelain | wc -l | tr -d ' ')" "1"
_restore_runtime_tracked_files
assert_eq "marker restored -> pull can fast-forward" \
    "$(git -C "$TMP_REPO" status --porcelain | wc -l | tr -d ' ')" "0"

# A real user edit elsewhere must survive untouched.
echo "user change" > "$TMP_REPO/README.md"
git -C "$TMP_REPO" add -A && git -C "$TMP_REPO" commit -qm readme
echo "my precious edit" > "$TMP_REPO/README.md"
_restore_runtime_tracked_files
assert_eq "unrelated user edits are preserved" \
    "$(cat "$TMP_REPO/README.md")" "my precious edit"

# Once untracked (this release), the helper simply skips it.
git -C "$TMP_REPO" rm -q --cached "$MARKER"
git -C "$TMP_REPO" commit -qm untrack
echo "rewritten again" > "$TMP_REPO/$MARKER"
_restore_runtime_tracked_files
assert_eq "untracked marker is left alone" \
    "$(cat "$TMP_REPO/$MARKER")" "rewritten again"
rm -rf "$TMP_REPO"

section "REGRESSION: this repo no longer tracks runtime markers"
for p in $(cd "$REPO_ROOT" && git ls-files 'recon/main_recon_modules/data/mitre_db/.last_update'); do
    fail "still tracked in git: $p"
done
if git -C "$REPO_ROOT" ls-files --error-unmatch 'recon/main_recon_modules/data/mitre_db/.last_update' &>/dev/null; then
    fail ".last_update is still tracked"
else
    pass ".last_update is untracked"
fi
if git -C "$REPO_ROOT" check-ignore -q 'recon/main_recon_modules/data/mitre_db/.last_update'; then
    pass ".last_update is gitignored"
else
    fail ".last_update is NOT gitignored (it will be re-added by the next git add -A)"
fi

echo ""
echo -e "\033[1m== the gates run BEFORE any Docker work (install/update) ==\033[0m"
# BUG: preflight_ram_gate lived only in cmd_up. `install` ends in a raw
# `docker compose up -d`, so it built 16 images (30-60 min) and only then
# discovered the host was too small; `update` never ran a RAM gate at all.
for _c in cmd_install cmd_update; do
    _body="$(awk -v f="^${_c}\\(\\)" '$0 ~ f {on=1} on {print} on && /^}/ {exit}' "$REPO_ROOT/whitehat.sh")"
    case "$_body" in
        *preflight_ram_gate*) pass "$_c runs the RAM gate" ;;
        *) fail "$_c runs the RAM gate (absent)" ;;
    esac
done
# Compare positions WITHIN cmd_install's own body: `compose_build` also appears
# elsewhere in the file, so a whole-file grep compares the wrong two lines.
_body="$(awk '/^cmd_install\(\)/{on=1} on {print} on && /^}/{exit}' "$REPO_ROOT/whitehat.sh")"
_gate_at=$(printf '%s\n' "$_body" | grep -n "preflight_ram_gate" | head -1 | cut -d: -f1)
_build_at=$(printf '%s\n' "$_body" | grep -n "compose_build" | head -1 | cut -d: -f1)
if [[ -n "$_gate_at" && -n "$_build_at" && "$_gate_at" -lt "$_build_at" ]]; then
    pass "install gates (body line $_gate_at) BEFORE its build (body line $_build_at)"
else
    fail "install gates before its build (gate=$_gate_at build=$_build_at)"
fi

echo -e "\033[1m== the disk threshold is proportional, not a flat 10GB ==\033[0m"
# A flat 10GB is 2% of the 500GB disk in the incident this came from: it would
# have warned only long after 97% full.
df() { printf 'x\n%sG\n' "$STUB_DISK_TOTAL_GB"; }
STUB_DISK_TOTAL_GB=100 ; assert_eq "100GB disk -> 10GB reserve"  "$(_disk_reserve_gb /x)" "10"
STUB_DISK_TOTAL_GB=500 ; assert_eq "500GB disk -> 50GB, not 10"  "$(_disk_reserve_gb /x)" "50"
STUB_DISK_TOTAL_GB=2000; assert_eq "2TB disk -> 200GB reserve"   "$(_disk_reserve_gb /x)" "200"
STUB_DISK_TOTAL_GB=20  ; assert_eq "small disk floors at 10GB"   "$(_disk_reserve_gb /x)" "10"
STUB_DISK_TOTAL_GB=400 ; assert_eq "DISK_RESERVE_PCT honoured"   "$(DISK_RESERVE_PCT=25 _disk_reserve_gb /x)" "100"
STUB_DISK_TOTAL_GB=""  ; assert_eq "unreadable df falls back"    "$(_disk_reserve_gb /x)" "10"
unset -f df

printf '\n\033[1m== RESULT ==\033[0m  \033[0;32m%d passed\033[0m, \033[0;31m%d failed\033[0m\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]

# `docker compose up -d`, so it built 16 images (30-60 min) and only then



