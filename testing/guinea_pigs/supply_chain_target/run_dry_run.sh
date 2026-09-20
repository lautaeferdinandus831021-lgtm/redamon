#!/usr/bin/env bash
# Dry-run the real L2 harvest chain against the guinea pig.
#
#   ./guinea_pigs/supply_chain_target/run_dry_run.sh
#
# Brings nothing up: the target must already be running
# (cd guinea_pigs/supply_chain_target && docker compose up -d --build).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repo root. THREE levels up since 6.9.0 moved guinea_pigs/ under testing/;
# it was two, and the stale value silently mounted EMPTY auto-created dirs
# (Docker treats a missing bind source as "create it"), so the harness died
# with ModuleNotFoundError and left root-owned litter in testing/.
ROOT="$(cd "$HERE/../../.." && pwd)"
TARGET="${SC_TARGET_URL:-http://192.88.99.10}"
WORK="$HERE/.dryrun"
HTTPX_IMAGE="${HTTPX_DOCKER_IMAGE:-projectdiscovery/httpx:latest}"

mkdir -p "$WORK"

echo "[*] target: $TARGET"
if ! curl -fsS -m 5 "$TARGET/robots.txt" >/dev/null; then
  echo "[!] target unreachable. Start it first:" >&2
  echo "    cd $HERE && docker compose up -d --build" >&2
  exit 1
fi

echo "[*] httpx technology detection..."
# Probe BOTH surfaces: port 80 and the alt port 8080. Two probed URLs -> two
# BaseURL nodes -> the per-BaseURL anchoring loop is exercised.
docker run --rm --network host "$HTTPX_IMAGE" \
  -u "$TARGET/" -td -json -silent 2>/dev/null > "$WORK/httpx.json"
docker run --rm --network host "$HTTPX_IMAGE" \
  -u "${TARGET}:8080/" -td -json -silent 2>/dev/null >> "$WORK/httpx.json"
echo "[+] tech: $(python3 -c "import json;print(json.loads(open('$WORK/httpx.json').readline()).get('tech'))" 2>/dev/null || echo '?')"

echo "[*] running js_recon + supply_chain_recon in whitehat-recon..."
# The broker socket is now mounted UNCONDITIONALLY. retire.js is not part of
# the opt-in deep pass - it runs on every L2 scan, and like GuardDog it is
# dispatched into the hardened analyzer image over DOCKER_HOST. Gating the
# socket on SC_DEEP left retire dead in the default dry run, which is exactly
# the "harness proves less than the pipeline does" trap that hid the
# KATANA_EXCLUDE_PATTERNS bug.
#
# Reaching the socket needs root inside the container, so --user is not set and
# the artifact is chown'd back afterwards.
# SUPPLY_CHAIN_COMMON_HOST_PATH must be the path the DOCKER DAEMON resolves,
# not the in-container one: the analyzer bind-mounts it, and the broker rejects
# a source path that does not exist on the host. This mirrors what
# container_manager passes the real recon container.
#
# /tmp/whitehat must be bind-mounted AT THE SAME PATH, exactly as the real recon
# container has it. The analyzer job dir is created there and handed to the
# daemon as a mount source, so container path and host path have to agree - if
# they do not, docker silently creates an empty dir and the analyzer reports
# "cannot read job spec".
DEEP_ENV=(-e DOCKER_HOST=unix:///var/run/broker/docker.sock
          -e SUPPLY_CHAIN_COMMON_HOST_PATH="$ROOT/scanners/supply_chain_common"
          -v whitehat_broker_socket:/var/run/broker
          -v /tmp/whitehat:/tmp/whitehat)
if [ "${SC_DEEP:-0}" = "1" ]; then
  echo "[*] deep analysis ON (downloads real tarballs from the npm registry)"
  DEEP_ENV+=(-e SC_DEEP=1)
fi

docker run --rm --network host \
  "${DEEP_ENV[@]}" \
  -e HOME=/tmp \
  -e SC_TARGET_URL="$TARGET" \
  -e SC_HTTPX_JSON=/work/httpx.json \
  -e SC_DRYRUN_OUT=/work/dryrun_artifact.json \
  -e OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db \
  -e PYTHONPATH=/app \
  -v "$ROOT/recon":/app/recon:ro \
  -v "$ROOT/graph_db":/app/graph_db:ro \
  -v "$ROOT/scanners/supply_chain_common":/app/supply_chain_common:ro \
  -v "$HERE/dry_run_harvest.py":/app/dry_run_harvest.py:ro \
  -v "$WORK":/work:rw \
  -v whitehat-osv-db:/osv-db:ro \
  -e SCA_INTEL_PATH=/sca-intel \
  -v whitehat-sca-intel:/sca-intel:ro \
  --entrypoint python3 \
  whitehat-recon:latest /app/dry_run_harvest.py

# The run is root-in-container (it needs the broker socket); hand the output back.
sudo -n chown "$(id -u):$(id -g)" "$WORK"/*.json 2>/dev/null \
  || docker run --rm -v "$WORK":/w alpine chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 \
  || true

echo
echo "[+] artifact: $WORK/dryrun_artifact.json"
