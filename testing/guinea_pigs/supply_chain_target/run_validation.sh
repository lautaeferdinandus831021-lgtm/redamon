#!/usr/bin/env bash
# Validate the Neo4j state left by a real recon scan of the guinea pig.
#
#   ./guinea_pigs/supply_chain_target/run_validation.sh <USER_ID> <PROJECT_ID>
#
# Reads NEO4J_PASSWORD from the repo .env if not already set.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Three levels up since 6.9.0 moved guinea_pigs/ under testing/ (see run_dry_run.sh).
ROOT="$(cd "$HERE/../../.." && pwd)"

if [ $# -lt 2 ]; then
  echo "usage: $0 <USER_ID> <PROJECT_ID> [--deep]" >&2
  echo "  --deep : require the GuardDog deep-analysis assertions" >&2
  exit 2
fi

if [ -z "${NEO4J_PASSWORD:-}" ] && [ -f "$ROOT/.env" ]; then
  NEO4J_PASSWORD="$(grep -E '^NEO4J_PASSWORD=' "$ROOT/.env" | head -1 | cut -d= -f2- | tr -d '"'"'"'')"
fi

docker run --rm --network host \
  -e NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}" \
  -e NEO4J_USER="${NEO4J_USER:-neo4j}" \
  -e NEO4J_PASSWORD="${NEO4J_PASSWORD:-}" \
  -e PYTHONPATH=/app \
  -v "$ROOT/graph_db":/app/graph_db:ro \
  -v "$HERE":/app/guinea_pigs/supply_chain_target:ro \
  --entrypoint python3 \
  whitehat-recon:latest \
  /app/guinea_pigs/supply_chain_target/validate_supply_chain_recon.py "$@"
