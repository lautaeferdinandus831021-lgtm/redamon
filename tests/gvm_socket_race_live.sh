#!/usr/bin/env bash
# =============================================================================
# LIVE proof for the GVM Postgres socket race (issue #174).
#
# Runs the REAL pg-gvm image with the entrypoint that actually ships in
# docker-compose.yml, then performs the exact operation that used to break the
# stack: a second `docker compose up -d` while Postgres is already running.
#
#   BEFORE: the stale-lock cleanup was a sibling one-shot sharing the socket
#           volume. Compose leaves an already-running service alone but still
#           re-runs an exited one-shot, so the cleanup deleted the LIVE socket.
#           Postgres kept running and kept reporting healthy; gvmd lost its
#           database and crash-looped for hours.
#   AFTER:  the cleanup runs inside gvm-postgres' own entrypoint, before the
#           server starts, so there is nothing live to delete.
#
# Not part of `./whitehat.sh test` (the gate matches tests/*_test.sh only). Run:
#     bash tests/gvm_socket_race_live.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_IMAGE="registry.community.greenbone.net/community/pg-gvm:stable"
PROJECT="whitehatgvmsocket"
CONTROL_PROJECT="whitehatgvmsocketctl"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }

skip() { echo "  SKIP  $1"; exit 0; }

command -v docker >/dev/null 2>&1 || skip "docker unavailable (GVM socket race)"
docker info >/dev/null 2>&1        || skip "docker daemon unreachable (GVM socket race)"
python3 -c "import yaml" >/dev/null 2>&1 || skip "pyyaml unavailable (GVM socket race)"
docker image inspect "$PG_IMAGE" >/dev/null 2>&1 \
    || skip "$PG_IMAGE not pulled locally (docker pull it to run this)"

cleanup() {
    docker compose -p "$PROJECT" -f - --project-directory "$REPO_ROOT" down -v >/dev/null 2>&1 <<< "services: {}"
    docker rm -f "${PROJECT}-pg-1" >/dev/null 2>&1
    docker rm -f "${CONTROL_PROJECT}-pg-1" "${CONTROL_PROJECT}-init-1" >/dev/null 2>&1
    docker rm -f "whitehatgvmsocketrec-pg-1" "whitehatgvmsocketrec-init-1" >/dev/null 2>&1
    docker volume rm -f "whitehatgvmsocketrec_sock" "whitehatgvmsocketrec_data" >/dev/null 2>&1
    docker volume rm -f "${PROJECT}_sock" "${PROJECT}_data" >/dev/null 2>&1
    docker volume rm -f "${CONTROL_PROJECT}_sock" "${CONTROL_PROJECT}_data" >/dev/null 2>&1
}
trap cleanup EXIT

# The entrypoint under test is read from the shipped compose file, so this proves
# what actually runs rather than a copy that can drift.
ENTRYPOINT_SH="$(python3 - "$REPO_ROOT/docker-compose.yml" <<'PY'
import sys, yaml, json
svc = yaml.safe_load(open(sys.argv[1]))["services"]["gvm-postgres"]
ep = svc["entrypoint"]
# ["/bin/sh", "-c", "<script>"] -> the script
print(json.dumps(ep[2] if isinstance(ep, list) else ep))
PY
)"
[[ -n "$ENTRYPOINT_SH" ]] || skip "could not read the gvm-postgres entrypoint"

compose_yaml() {
    python3 - "$PG_IMAGE" "$ENTRYPOINT_SH" "${1:-plain}" <<'PY'
import json, sys
image, script_json, mode = sys.argv[1], sys.argv[2], sys.argv[3]
script = json.loads(script_json)
services = {
    "pg": {
        "image": image,
        "entrypoint": ["/bin/sh", "-c", script],
        "volumes": ["data:/var/lib/postgresql", "sock:/var/run/postgresql"],
        "healthcheck": {
            "test": ["CMD-SHELL", "pg_isready -U postgres -h /var/run/postgresql"],
            "interval": "3s", "timeout": "3s", "retries": 30, "start_period": "20s",
        },
    }
}
if mode == "control":
    # The SHAPE THAT SHIPPED BEFORE THE FIX: a sibling one-shot that wipes the
    # socket from the shared volume, with Postgres gated behind it.
    services["init"] = {
        "image": "alpine:3.20",
        "volumes": ["data:/var/lib/postgresql", "sock:/var/run/postgresql"],
        "entrypoint": ["/bin/sh", "-c",
                       "rm -f /var/run/postgresql/.s.PGSQL.5432.lock "
                       "/var/run/postgresql/.s.PGSQL.5432 && echo cleaned"],
    }
    services["pg"]["entrypoint"] = None
    services["pg"].pop("entrypoint")
    services["pg"]["depends_on"] = {"init": {"condition": "service_completed_successfully"}}
print(json.dumps({"services": services, "volumes": {"data": None, "sock": None}}))
PY
}

up() {   # up <project> <mode>
    compose_yaml "$2" | docker compose -p "$1" -f - --project-directory "$REPO_ROOT" up -d --wait 2>&1 | tail -2
}
down() { compose_yaml "${2:-plain}" | docker compose -p "$1" -f - --project-directory "$REPO_ROOT" down -v >/dev/null 2>&1; }

socket_present() {   # socket_present <container>
    docker exec "$1" sh -c 'test -S /var/run/postgresql/.s.PGSQL.5432' >/dev/null 2>&1 && echo present || echo gone
}
pg_ready() {         # pg_ready <container>
    docker exec "$1" pg_isready -U postgres -h /var/run/postgresql >/dev/null 2>&1 && echo ready || echo unreachable
}

echo "== the shipped gvm-postgres survives a repeat \`up\` =="
down "$PROJECT"
if ! up "$PROJECT" plain >/dev/null 2>&1; then
    # --wait returns non-zero if it never turns healthy; report that as the failure.
    bad "gvm-postgres starts with the shipped entrypoint" "did not become healthy" "healthy"
else
    ok "gvm-postgres starts with the shipped entrypoint"
fi
PG_C="${PROJECT}-pg-1"
first_id="$(docker inspect -f '{{.Id}}' "$PG_C" 2>/dev/null)"

[[ "$(socket_present "$PG_C")" == "present" ]] \
    && ok "socket exists after the first up" \
    || bad "socket exists after the first up" "gone" "present"

up "$PROJECT" plain >/dev/null 2>&1
second_id="$(docker inspect -f '{{.Id}}' "$PG_C" 2>/dev/null)"

# The bug only bites when compose leaves the running service alone, so assert we
# actually reproduced that condition rather than accidentally recreating it.
[[ -n "$first_id" && "$first_id" == "$second_id" ]] \
    && ok "the second up left the running Postgres in place (the risky case)" \
    || bad "the second up left the running Postgres in place" "recreated" "same container"

[[ "$(socket_present "$PG_C")" == "present" ]] \
    && ok "the live socket SURVIVES the second up" \
    || bad "the live socket SURVIVES the second up" "gone" "present"

[[ "$(pg_ready "$PG_C")" == "ready" ]] \
    && ok "Postgres is still reachable over that socket" \
    || bad "Postgres is still reachable over that socket" "unreachable" "ready"

down "$PROJECT"

echo "== control: the pre-fix shape still demonstrates the race =="
# Guards the REASONING, not the product: if compose ever stops re-running exited
# one-shots on `up`, this flips and the analysis behind the fix needs revisiting.
down "$CONTROL_PROJECT" control
if up "$CONTROL_PROJECT" control >/dev/null 2>&1; then
    CTL_C="${CONTROL_PROJECT}-pg-1"
    before="$(socket_present "$CTL_C")"
    up "$CONTROL_PROJECT" control >/dev/null 2>&1
    after="$(socket_present "$CTL_C")"
    if [[ "$before" == "present" && "$after" == "gone" ]]; then
        ok "sibling one-shot deletes the live socket on a repeat up (the old bug)"
    else
        bad "sibling one-shot deletes the live socket on a repeat up" \
            "before=$before after=$after" "before=present after=gone"
    fi
else
    echo "  SKIP  control stack did not start"
fi
down "$CONTROL_PROJECT" control

echo "== recovery: \`whitehat.sh update\` repairs an ALREADY-broken stack =="
# The reporter of #174 is not in the "about to break" state, they are in the
# BROKEN one: socket already deleted, Postgres still running, gvmd crash-looping.
# `update` force-recreates gvm-postgres (docker-compose.yml changed => rebuild_all),
# so prove that specific command restores the socket rather than merely preventing
# the next deletion.
RECOVER_PROJECT="whitehatgvmsocketrec"
down "$RECOVER_PROJECT" control
if up "$RECOVER_PROJECT" control >/dev/null 2>&1; then
    REC_C="${RECOVER_PROJECT}-pg-1"
    # Reproduce the broken state exactly: delete the live socket underneath it.
    docker exec "$REC_C" rm -f /var/run/postgresql/.s.PGSQL.5432 >/dev/null 2>&1
    [[ "$(socket_present "$REC_C")" == "gone" ]] \
        && ok "starting state is broken (socket deleted under a running Postgres)" \
        || bad "starting state is broken" "$(socket_present "$REC_C")" "gone"

    # This is what cmd_update runs for the GVM stack.
    compose_yaml plain | docker compose -p "$RECOVER_PROJECT" -f - \
        --project-directory "$REPO_ROOT" up -d --force-recreate --wait pg >/dev/null 2>&1
    rc=$?

    [[ $rc -eq 0 ]] \
        && ok "the recreate completes and Postgres reports healthy" \
        || bad "the recreate completes and Postgres reports healthy" "exit $rc" "exit 0"
    [[ "$(socket_present "$REC_C")" == "present" ]] \
        && ok "the socket is RESTORED by the update path" \
        || bad "the socket is RESTORED by the update path" "gone" "present"
    [[ "$(pg_ready "$REC_C")" == "ready" ]] \
        && ok "Postgres is reachable again (gvmd can reconnect)" \
        || bad "Postgres is reachable again" "unreachable" "ready"

    # The removed one-shot lingers as an orphan on an existing install; it must
    # be inert, never restarted by the new compose file.
    orphan_state="$(docker inspect -f '{{.State.Status}}' "${RECOVER_PROJECT}-init-1" 2>/dev/null || echo absent)"
    case "$orphan_state" in
        exited|absent) ok "the removed init container stays inert (state: $orphan_state)" ;;
        *) bad "the removed init container stays inert" "$orphan_state" "exited or absent" ;;
    esac
else
    echo "  SKIP  recovery stack did not start"
fi
down "$RECOVER_PROJECT" control

echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
