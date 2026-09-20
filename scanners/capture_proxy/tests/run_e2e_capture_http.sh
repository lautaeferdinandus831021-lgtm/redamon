#!/usr/bin/env bash
# Run the real-HTTP capture-proxy E2E inside the whitehat-capture-proxy image
# (it needs mitmproxy). By default it MOUNTS the host capture_proxy/ over /app so
# it exercises your working-tree code without a rebuild. Pass --baked to instead
# test the code baked into the image (run this after `docker compose --profile
# capture build capture-proxy`).
#
#   capture_proxy/tests/run_e2e_capture_http.sh            # working-tree code
#   capture_proxy/tests/run_e2e_capture_http.sh --baked    # baked image code
set -euo pipefail

IMAGE="${CAPTURE_PROXY_IMAGE:-whitehat-capture-proxy:latest}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ "${1:-}" == "--baked" ]]; then
  # Copy the test into the container's /app/tests via a tmp mount-free path is
  # awkward; baked image already has /app code, so mount ONLY the test file.
  exec docker run --rm --entrypoint python3 \
    -v "$REPO/capture_proxy/tests/e2e_capture_http.py:/app/tests/e2e_capture_http.py:ro" \
    "$IMAGE" /app/tests/e2e_capture_http.py
else
  exec docker run --rm --entrypoint python3 \
    -v "$REPO/capture_proxy:/app:ro" \
    "$IMAGE" /app/tests/e2e_capture_http.py
fi
