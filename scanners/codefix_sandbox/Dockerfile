# WhiteHat CodeFix build sandbox
#
# This image runs the UNTRUSTED clone+build+test step of the CodeFix (CypherFix)
# agent. A cloned repo is attacker-influenceable input (malicious postinstall
# scripts, prompt-injected build instructions), so `github_bash` is executed HERE
# instead of inside the secret-holding `agent` container (threats T6 / E10).
#
# Hardening is applied by the spawner (recon_orchestrator/container_manager.py):
# no secrets in env, cap_drop=ALL, no-new-privileges, read-only rootfs, nonroot
# user, resource limits, and a network (codefix-net) with NO WhiteHat peer.
#
# The container ships NO application code and exposes NO server. Commands arrive
# via `docker exec` from the orchestrator (which holds the real docker socket).
# It simply stays alive (`sleep infinity`) so it can be exec'd into.

FROM node:20-bookworm-slim

# Common build toolchains. Keep this list in sync with the stacks CodeFix is
# expected to build. Builds needing a toolchain not installed here will fail
# (documented limitation) — extend this layer to add coverage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        git \
        ripgrep \
        ca-certificates \
        curl \
        build-essential \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Non-root user that runs every build command. uid 1001 is matched by the
# orchestrator, which makes the cloned worktree group/other-writable so installs
# (node_modules, venvs) can write while .git stays read-only via a bind mount.
RUN useradd --create-home --uid 1001 --shell /bin/bash sandbox

# The worktree is cloned by the (root) agent and bind-mounted in with a different
# owner; without this, git-aware builds (setuptools_scm, `git describe`) abort
# with "detected dubious ownership". The worktree's .git is mounted read-only, so
# this cannot be used to tamper with history.
RUN git config --system --add safe.directory '*'

# Strip setuid/setgid bits from every binary so an untrusted build cannot use a
# setuid-root binary (su/mount/...) to escalate to root inside the sandbox. This
# is the portable equivalent of the `no-new-privileges` runtime flag, which we do
# NOT set at spawn time because it is incompatible with some hosts (snap Docker +
# AppArmor block execve for non-root users when no_new_privs is set).
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Package managers default their caches to $HOME; with a read-only rootfs those
# writes fail, so point everything at the writable tmpfs mounted at /tmp.
ENV HOME=/tmp \
    npm_config_cache=/tmp/.npm \
    PIP_CACHE_DIR=/tmp/.pip \
    XDG_CACHE_HOME=/tmp/.cache \
    GOCACHE=/tmp/.gocache \
    GIT_TERMINAL_PROMPT=0

USER sandbox
WORKDIR /work/repo

# Reset the base image's ENTRYPOINT (node ships `docker-entrypoint.sh`, which
# fails to exec under our hardened runtime — cap_drop=ALL + no-new-privileges +
# read-only rootfs — killing the container before CMD runs). We just need a box
# to `docker exec` into, so run the keep-alive command directly.
ENTRYPOINT []

# Stay alive so the orchestrator can `docker exec` build commands into us.
CMD ["sleep", "infinity"]
