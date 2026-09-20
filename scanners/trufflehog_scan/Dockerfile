# =============================================================================
# WhiteHat TruffleHog Secret Scanner - Container
# =============================================================================
# Runs ONE TruffleHog source per container and writes findings to JSON.
# Holds no Neo4j credentials and makes no call back to the webapp: it is the
# dirty half of the dirty/clean split, so an exploited target image finds only
# the one source credential it was already given.
# =============================================================================

# Pinned to a specific Debian release, not the floating `slim` alias, so the
# base cannot change under a container that parses attacker-controlled bytes.
# Tighten to a @sha256 digest at deploy time if your registry mirror allows it.
FROM python:3.12-slim-bookworm

LABEL maintainer="WhiteHat Project"
LABEL description="TruffleHog-based secret scanner for WhiteHat"

WORKDIR /app

# The upstream one-liner (curl install.sh | sh) fetches an unpinned script from
# a mutable branch and resolves to whatever release is newest. Pin the version
# and download the release tarball directly; the release page publishes
# trufflehog_<version>_checksums.txt, which is verified before extraction.
ARG TRUFFLEHOG_VERSION=3.96.0
# Set by BuildKit to the image's architecture (arm64 on Apple Silicon / ARM
# hosts). The checksums file lists every architecture, so a hardcoded amd64
# asset verifies fine on arm64 and only dies at the `--version` smoke test with
# "Exec format error". dpkg covers the legacy builder, which leaves it unset.
ARG TARGETARCH

# git is required by TruffleHog for repo scanning.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git && \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac && \
    base="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}" && \
    asset="trufflehog_${TRUFFLEHOG_VERSION}_linux_${arch}.tar.gz" && \
    curl -sSfL -o "/tmp/${asset}" "${base}/${asset}" && \
    curl -sSfL -o /tmp/checksums.txt "${base}/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" && \
    (cd /tmp && grep " ${asset}\$" checksums.txt | sha256sum -c -) && \
    tar -xzf "/tmp/${asset}" -C /usr/local/bin trufflehog && \
    chmod 0755 /usr/local/bin/trufflehog && \
    rm -f "/tmp/${asset}" /tmp/checksums.txt && \
    /usr/local/bin/trufflehog --version && \
    apt-get purge -y curl && apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY scanners/trufflehog_scan/ ./trufflehog_scan/

# The scan runs as a non-root user with a read-only root filesystem; /tmp and
# the run dir are tmpfs mounts supplied at spawn.
RUN mkdir -p trufflehog_scan/output && \
    useradd --uid 10001 --create-home --shell /usr/sbin/nologin trufflehog && \
    chown -R trufflehog:trufflehog /app

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
# Pinned so the identity digests in findings.py stay reproducible even if a
# future change reintroduces a builtin hash() anywhere on this path.
ENV PYTHONHASHSEED=0

USER trufflehog

CMD ["python", "trufflehog_scan/main.py"]
