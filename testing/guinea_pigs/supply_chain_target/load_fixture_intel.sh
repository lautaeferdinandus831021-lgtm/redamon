#!/usr/bin/env bash
# Load the guinea pig's FIXTURE incident catalog into whitehat-sca-intel, so the
# supply-chain intel layer (B, A1, A2, D) has deterministic hits.
#
# Why a fixture instead of the real catalog:
#
#   1. DETERMINISM. The live feed changes daily. An expectation written against
#      it rots, and a failed assertion would not tell you whether the code broke
#      or the publisher edited an incident.
#   2. SAFETY. Forcing a real hit means making the target reference a host that
#      is genuinely attacker-controlled. This fixture names only *.test hosts
#      (RFC 6761, guaranteed never to resolve on the public internet) and the
#      guinea pig's own address.
#
# Restore the real catalog afterwards with:  ./load_fixture_intel.sh --restore
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOLUME="${SCA_INTEL_VOLUME:-whitehat-sca-intel}"
IMAGE="${SCA_INTEL_HELPER_IMAGE:-whitehat-supply-chain-analyzer:latest}"
BACKUP_SUFFIX=".real"

usage() { sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 0; }
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && usage

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[!] $IMAGE not built. Run: docker compose --profile tools build supply-chain-analyzer" >&2
    exit 1
fi

docker volume inspect "$VOLUME" >/dev/null 2>&1 || docker volume create "$VOLUME" >/dev/null

if [[ "${1:-}" == "--restore" ]]; then
    docker run --rm --user root -v "$VOLUME:/out" --entrypoint sh "$IMAGE" -c '
        set -e
        restored=0
        for f in network_iocs.json packages.json typosquats.json manifest.json; do
            if [ -f "/out/$f'"$BACKUP_SUFFIX"'" ]; then
                mv "/out/$f'"$BACKUP_SUFFIX"'" "/out/$f"; restored=$((restored+1))
            fi
        done
        echo "[+] restored $restored file(s)"
        [ "$restored" = 0 ] && echo "[!] nothing to restore - run ./whitehat.sh sca-intel-sync --force" || true
    '
    exit 0
fi

echo "[*] backing up the real catalog (if any) and installing the fixture into $VOLUME"

# Copy in via a tar stream: the volume is only reachable through a container,
# and `docker cp` cannot address a bare volume.
tar -C "$HERE/fixture_intel" -cf - . | docker run --rm -i --user root \
    -v "$VOLUME:/out" --entrypoint sh "$IMAGE" -c '
        set -e
        for f in network_iocs.json packages.json typosquats.json manifest.json; do
            # Back up the real file once; never clobber an existing backup, or a
            # second run would overwrite the real catalog with the fixture.
            if [ -f "/out/$f" ] && [ ! -f "/out/$f'"$BACKUP_SUFFIX"'" ]; then
                cp "/out/$f" "/out/$f'"$BACKUP_SUFFIX"'"
            fi
        done
        tar -C /out -xf -
        # The scan containers run NON-root and read-only: without this they see
        # an empty directory and every lookup silently misses.
        chmod -R a+rX /out
        echo "[+] fixture installed:"
        for f in network_iocs.json packages.json typosquats.json manifest.json; do
            printf "      %-22s %s bytes\n" "$f" "$(wc -c < /out/$f)"
        done
    '

cat <<'NOTE'

[!] The orchestrator refreshes this volume on the scan-spawn path and would
    overwrite the fixture with the live feed. Before scanning, either:

      SCA_INTEL_AUTO_REFRESH=false docker compose up -d recon-orchestrator

    or accept that the fixture survives only until the 24h TTL expires (a fresh
    fixture manifest is written with today's mtime, so the next scan sees it as
    fresh and skips the refresh).

    Restore the real catalog with:  ./load_fixture_intel.sh --restore
NOTE
