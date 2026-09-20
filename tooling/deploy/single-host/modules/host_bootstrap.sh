#!/usr/bin/env bash
# host_bootstrap.sh -- dynamic prerequisite detection & install (§9.0).
# Probes each prerequisite and installs ONLY what is missing or too old. Every step is
# idempotent (present+correct -> skip). All installs go through run_sudo. A failure at
# any hard step exits 1 (a half-provisioned host must not proceed to the build).
#
# Reads (exported by deploy.sh): ACCESS_MODE, TLS_MODE, ENABLE_UFW, ENABLE_FAIL2BAN,
#   ENABLE_UNATTENDED_UPGRADES, ENABLE_ZRAM, SWAP_SIZE_GB, DOCKER_DNS, REMOTE_USER,
#   NEED_CERTBOT (precomputed true/false).
# Requires _common.sh to be sourced first.

# --- 1. apt base packages ---
bootstrap_base_packages() {
  step "Host bootstrap: base packages"
  # git-lfs intentionally NOT installed (.gitattributes only sets eol=lf, no LFS objects).
  # `expect` drives whitehat.sh's interactive admin prompt non-interactively during init.
  # `make` is required by whitehat.sh's KB bootstrap (make -C services/knowledge_base ...) when
  # ENABLE_KB=true; without it the initial ingestion fails and the agent starts empty.
  install_if_missing git make openssl curl jq ca-certificates gnupg lsb-release expect
  success "Base packages present"
}

# --- 2. Docker Engine + Compose v2 (from Docker's official apt repo) ---
# Require Compose >= 2.24: the prod overlay uses the `!override` YAML tag, added in 2.24.0.
# A preinstalled older v2 (e.g. 2.20) would parse-fail the overlay, so treat it as not-ok.
_docker_compose_v2_ok() {
  have docker || return 1
  local v major minor rest
  v=$(docker compose version --short 2>/dev/null) || return 1
  [[ "$v" =~ ^[0-9]+\.[0-9]+ ]] || return 1
  major=${v%%.*}; rest=${v#*.}; minor=${rest%%.*}
  [[ "$major" -gt 2 ]] && return 0
  [[ "$major" -eq 2 && "$minor" -ge 24 ]] && return 0
  return 1
}

bootstrap_docker() {
  step "Host bootstrap: Docker Engine + Compose v2"
  if _docker_compose_v2_ok; then
    success "Docker Engine + Compose v2 already present ($(docker compose version 2>/dev/null | head -1))"
  else
    info "Installing Docker Engine + Compose v2 from Docker's official apt repo"
    # Purge conflicting/old packages (docker.io ships an old engine + v1 compose)
    local conflicts=(docker.io docker-compose docker-compose-v2 podman-docker containerd runc)
    local c present=()
    for c in "${conflicts[@]}"; do pkg_installed "$c" && present+=("$c"); done
    if [[ ${#present[@]} -gt 0 ]]; then
      info "Removing conflicting packages: ${present[*]}"
      run_sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y "${present[@]}" || true
    fi
    # Add Docker's GPG key + repo
    run_sudo install -m 0755 -d /etc/apt/keyrings
    local codename
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | run_sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
    run_sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" \
      | run_sudo_tee /etc/apt/sources.list.d/docker.list
    run_sudo apt-get update -qq
    _APT_UPDATED=1
    run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
      docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  # Hard-fail if compose is still not >= 2.24 (needed for the overlay's !override tag)
  if ! _docker_compose_v2_ok; then
    err "docker compose is still < 2.24 after install -- the prod overlay's !override tag needs >= 2.24"
    exit 1
  fi
  success "Docker Compose: $(docker compose version 2>/dev/null | head -1)"
}

# --- 3. docker service enabled + user in docker group ---
bootstrap_docker_service() {
  step "Host bootstrap: docker service + group membership"
  run_sudo systemctl enable --now docker
  if id -nG "${REMOTE_USER}" | tr ' ' '\n' | grep -qx docker; then
    success "${REMOTE_USER} already in docker group"
  else
    info "Adding ${REMOTE_USER} to docker group"
    run_sudo usermod -aG docker "${REMOTE_USER}"
    warn "docker group applied for this run via 'sg docker'; a fresh login also picks it up"
  fi
}

# --- 4. nginx (always needed: it is the single public origin, even for http-* modes) ---
bootstrap_nginx() {
  step "Host bootstrap: nginx"
  install_if_missing nginx
  run_sudo systemctl enable nginx >/dev/null 2>&1 || true
  success "nginx present"
}

# --- 5. certbot (+nginx plugin) -- only when Let's Encrypt is actually used ---
bootstrap_certbot() {
  if ! is_true "${NEED_CERTBOT:-false}"; then
    info "certbot not needed for this ACCESS_MODE/TLS_MODE -- skipping"
    return 0
  fi
  step "Host bootstrap: certbot + nginx plugin"
  install_if_missing certbot python3-certbot-nginx
  success "certbot present"
}

# --- 6. ufw ---
bootstrap_ufw() {
  if ! is_true "${ENABLE_UFW:-true}"; then
    info "ENABLE_UFW=false -- skipping ufw install"
    return 0
  fi
  step "Host bootstrap: ufw"
  install_if_missing ufw
  success "ufw present"
}

# --- 7. fail2ban ---
bootstrap_fail2ban() {
  if ! is_true "${ENABLE_FAIL2BAN:-true}"; then
    info "ENABLE_FAIL2BAN=false -- skipping fail2ban install"
    return 0
  fi
  step "Host bootstrap: fail2ban"
  install_if_missing fail2ban
  success "fail2ban present"
}

# --- 8. unattended-upgrades ---
bootstrap_unattended_upgrades() {
  if ! is_true "${ENABLE_UNATTENDED_UPGRADES:-true}"; then
    info "ENABLE_UNATTENDED_UPGRADES=false -- skipping"
    return 0
  fi
  step "Host bootstrap: unattended-upgrades (install)"
  install_if_missing unattended-upgrades
  # Config + enable is done by modules/unattended_upgrades.sh in the hardening phase.
  success "unattended-upgrades present"
}

# --- 9. swap (hosts < 16GB, when SWAP_SIZE_GB>0 and no active swap) ---
bootstrap_swap() {
  # Swap as a PERCENTAGE of RAM, at every host size. It used to be a flat 8GB
  # created only when RAM < 16GB, so a 64GB host got none at all -- and the
  # memory governor keys its higher burst factor off having swap worth at least
  # BURST_SWAP_MIN_PCT (25%) of RAM, so "no swap" silently costs you headroom.
  local pct="${SWAP_PCT:-25}" size="${SWAP_SIZE_GB:-}" mem_kb mem_gb
  mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
  mem_gb=$(( mem_kb / 1024 / 1024 ))
  if [[ -n "$size" && "$size" =~ ^[0-9]+$ ]]; then
    : # explicit (deprecated) override wins
  else
    [[ "$pct" =~ ^[0-9]+$ ]] || pct=25
    size=$(( mem_gb * pct / 100 ))
  fi
  [[ "${size:-0}" -eq 0 ]] && { info "swap: disabled (SWAP_PCT=0 / SWAP_SIZE_GB=0)"; return 0; }
  if [[ -n "$(swapon --show 2>/dev/null)" ]]; then
    info "Active swap already present -- skipping"
    return 0
  fi
  step "Host bootstrap: ${size}GB swapfile (${pct}% of ~${mem_gb}GB RAM)"
  if [[ ! -f /swapfile ]]; then
    run_sudo fallocate -l "${size}G" /swapfile || run_sudo dd if=/dev/zero of=/swapfile bs=1M count=$((size*1024))
    run_sudo chmod 600 /swapfile
  fi
  run_sudo mkswap /swapfile
  run_sudo swapon /swapfile || true
  if ! grep -q '^/swapfile ' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' | run_sudo_tee -a /etc/fstab
  fi
  success "${size}GB swap active"
}

# --- 11. Docker DNS (only when operator opts in and daemon.json lacks it) ---
bootstrap_docker_dns() {
  local dns="${DOCKER_DNS:-}"
  [[ -z "${dns}" ]] && return 0
  step "Host bootstrap: Docker DNS (${dns})"
  local json_dns
  json_dns=$(printf '%s' "${dns}" | tr ',' '\n' | sed 's/^/"/;s/$/"/' | paste -sd, -)
  local current="{}"
  [[ -f /etc/docker/daemon.json ]] && current=$(run_sudo cat /etc/docker/daemon.json 2>/dev/null || echo '{}')
  if printf '%s' "${current}" | jq -e '.dns' >/dev/null 2>&1; then
    info "daemon.json already has a dns key -- leaving as-is"
    return 0
  fi
  run_sudo mkdir -p /etc/docker
  printf '%s' "${current}" | jq ". + {dns: [${json_dns}]}" | run_sudo_tee /etc/docker/daemon.json
  run_sudo systemctl restart docker
  success "Docker DNS set to ${dns}"
}

# --- 12. BuildKit cache cap (bound build-cache disk growth across updates) ---
# whitehat.sh reuses the build cache for fast incremental rebuilds, and since
# compose_build's Layer 3 it also drops the cache each build ORPHANS, so the
# WhiteHat-driven growth is already bounded. This ceiling is the second line of
# defence: it covers cache the daemon accumulates outside those builds (other
# projects, manual `docker build`) and caps the total regardless of what wrote
# it. DOCKER_BUILD_CACHE_MAX_GB makes the daemon auto-GC to that size.
# Blank -> leave Docker's default.
bootstrap_docker_build_cache() {
  local gb="${DOCKER_BUILD_CACHE_MAX_GB:-}"
  [[ -z "${gb}" ]] && return 0
  gb="${gb//[^0-9]/}"                     # digits only
  [[ -z "${gb}" || "${gb}" -eq 0 ]] && return 0
  step "Host bootstrap: BuildKit cache cap (${gb}GB)"
  local current="{}"
  [[ -f /etc/docker/daemon.json ]] && current=$(run_sudo cat /etc/docker/daemon.json 2>/dev/null || echo '{}')
  if [[ "$(printf '%s' "${current}" | jq -r '.builder.gc.defaultKeepStorage // empty' 2>/dev/null)" == "${gb}GB" ]]; then
    info "daemon.json already caps build cache at ${gb}GB -- leaving as-is"
    return 0
  fi
  run_sudo mkdir -p /etc/docker
  printf '%s' "${current}" \
    | jq --arg ks "${gb}GB" '.builder.gc.enabled = true | .builder.gc.defaultKeepStorage = $ks' \
    | run_sudo_tee /etc/docker/daemon.json
  run_sudo systemctl restart docker
  success "BuildKit cache capped at ${gb}GB (daemon auto-GC)"
}

# --- 13. inotify limits (small-host safety for 15+ containers) ---
bootstrap_inotify_limits() {
  local want_instances=1024 want_watches=524288
  local cur_i cur_w
  cur_i=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo 0)
  cur_w=$(sysctl -n fs.inotify.max_user_watches 2>/dev/null || echo 0)
  if [[ "${cur_i}" -ge "${want_instances}" && "${cur_w}" -ge "${want_watches}" ]]; then
    return 0
  fi
  step "Host bootstrap: raising inotify limits"
  echo "fs.inotify.max_user_instances = ${want_instances}
fs.inotify.max_user_watches = ${want_watches}" | run_sudo_tee /etc/sysctl.d/99-whitehat.conf
  run_sudo sysctl --system >/dev/null 2>&1 || true
  success "inotify limits raised"
}

# Orchestrates the full matrix in dependency order.
host_bootstrap() {
  bootstrap_base_packages
  bootstrap_docker
  bootstrap_docker_service
  bootstrap_nginx
  bootstrap_certbot
  bootstrap_ufw
  bootstrap_fail2ban
  bootstrap_unattended_upgrades
  bootstrap_swap
  bootstrap_docker_dns
  bootstrap_docker_build_cache
  bootstrap_inotify_limits
  success "Host bootstrap complete"
}
