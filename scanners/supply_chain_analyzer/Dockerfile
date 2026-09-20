# WhiteHat Supply-Chain DIRTY analyzer
# ====================================
# This image processes UNTRUSTED bytes: package tarballs (GuardDog downloads
# them), target-served JS/source-maps, and manifests/SBOMs. It is the dirty zone
# of the DIRTY/CLEAN split (plan section 5.2), modeled on codefix_sandbox.
#
# It HOLDS NO SECRETS and is spawned network-isolated (OSV path = zero egress,
# GuardDog path = registry-only egress) with cap_drop=ALL + read_only rootfs +
# resource caps by recon_orchestrator/container_manager.py::start_supply_chain_analyzer.
# The hardening lives at the spawner; this image only ships the tools + entrypoint.
#
# Tools (pinned, verified 2026-08-06):
#   osv-scanner v2.4.0  (Go, built in stage 1)
#   guarddog    3.0.1   (Python, +semgrep +yara)
#   retire.js   5.4.3   (Node CLI)

# Stage 1: build the osv-scanner binary from the pinned tag (reliable across
# release-asset naming changes). osv-scanner v2.4.0 requires Go >= 1.26.4.
FROM golang:1-bookworm AS osv-builder
RUN GOBIN=/out go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0

# Stage 2: runtime. Python base (guarddog) + Node (retire.js) + the osv binary.
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/tmp \
    npm_config_cache=/tmp/.npm \
    PIP_CACHE_DIR=/tmp/.pip \
    XDG_CACHE_HOME=/tmp/.cache

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# osv-scanner binary from the build stage.
COPY --from=osv-builder /out/osv-scanner /usr/local/bin/osv-scanner

# retire.js (black-box JS harvest) pinned. no-install-ok: this is our own tool
# install at image-build time, never a target-derived manifest resolve (S1).
RUN npm install -g retire@5.4.3   # no-install-ok

# GuardDog (behavioural analysis) pinned; pulls semgrep + yara.
# no-install-ok: our tool, not a target manifest.
RUN pip install --no-cache-dir guarddog==3.0.1   # no-install-ok

# Warm GuardDog's typosquatting top-packages cache at build time (network is
# available here). The hardened runtime is read-only and may be network-isolated,
# and the non-root user cannot write into root-owned site-packages, so importing
# guarddog here (as root) pre-populates the cache, and the chmod lets a later
# refresh succeed on a non-read-only runtime. Best-effort: a build without net
# just leaves guarddog to fetch at first opt-in scan.
RUN python3 -c "import guarddog" 2>/dev/null || true; \
    chmod -R a+rX /usr/local/lib/python3.11/site-packages/guarddog/analyzer/metadata/resources 2>/dev/null || true

# Non-root user that runs every analysis command (uid 1001 matches the spawner).
RUN useradd --create-home --uid 1001 --shell /bin/bash analyzer

# Strip setuid/setgid bits (portable no-new-privileges equivalent, per codefix).
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# The supply_chain_common package is bind-mounted read-only at /app at spawn
# time (like graph_db), so the entrypoint can import the shared runners without
# baking them in. We copy the entrypoint itself so the image is self-contained.
COPY scanners/supply_chain_analyzer/entrypoint.py /usr/local/bin/sc-analyze
RUN chmod +x /usr/local/bin/sc-analyze

USER analyzer
WORKDIR /work

# Reset the base ENTRYPOINT so the hardened runtime can exec cleanly.
ENTRYPOINT []
# Stay alive so the orchestrator can `docker exec` a job into us (codefix model);
# one-shot invocation is also supported: `sc-analyze --job ... --out ...`.
CMD ["sleep", "infinity"]
