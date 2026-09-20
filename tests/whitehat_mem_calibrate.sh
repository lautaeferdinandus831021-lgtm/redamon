#!/usr/bin/env bash
# =============================================================================
# Wrapper for the memory calibration harness (Part 0A). Runs mem_calibrate.py
# inside the orchestrator container (which has the Docker SDK + API access) and
# writes recon_orchestrator/resource_profile.json.
#
#   bash tests/whitehat_mem_calibrate.sh baseline
#   bash tests/whitehat_mem_calibrate.sh scan <project_id> [--seconds 120] [--user_id <id>]
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode="${1:-baseline}"
shift || true

docker compose exec -T recon-orchestrator python3 mem_calibrate.py "$mode" "$@"
