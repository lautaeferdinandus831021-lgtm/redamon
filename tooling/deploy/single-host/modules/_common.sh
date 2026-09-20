#!/usr/bin/env bash
# Common helpers shared by every WhiteHat deploy module (sourced on the remote host).
# Depends on: SUDO_PASSWORD (optional, exported by deploy.sh for password-auth sudo).

# ---- logging (no colour: output is streamed over SSH and captured to logs) ----
log()     { echo "• $*"; }
info()    { echo "• $*"; }
warn()    { echo "⚠️  $*" >&2; }
err()     { echo "✖ $*" >&2; }
success() { echo "✅ $*"; }
step()    { echo; echo "==== $* ===="; }

# ---- privileged execution (works under both key-sudo and password-sudo) ----
# Password mode uses SUDO_ASKPASS (`sudo -A`), NOT `echo pw | sudo -S`. The latter
# hijacks stdin, so any caller that pipes data (`curl ... | run_sudo gpg`,
# `printf ... | run_sudo_tee`) would feed the command an EMPTY stdin and write a blank
# file. -A feeds the password out-of-band via a helper, leaving the data pipe intact.
_setup_askpass() {
  [[ -n "${SUDO_PASSWORD:-}" ]] || return 0
  [[ -n "${_ASKPASS:-}" && -f "${_ASKPASS:-}" ]] && return 0
  _ASKPASS="$(mktemp)"
  { printf '#!/bin/sh\n'; printf 'printf "%%s\\n" %q\n' "${SUDO_PASSWORD}"; } > "${_ASKPASS}"
  chmod 700 "${_ASKPASS}"
  export _ASKPASS
}

run_sudo() {
  if [[ -n "${SUDO_PASSWORD:-}" ]]; then
    _setup_askpass; SUDO_ASKPASS="${_ASKPASS}" sudo -A "$@"
  else
    sudo "$@"
  fi
}

# sudo tee helper for writing root-owned files from a heredoc/pipe (stdin = the data).
# Accepts an optional leading -a (append) flag: `run_sudo_tee -a /path`. Without this,
# callers passing `-a` had it swallowed as the path, so `tee -a` (no file) wrote the data
# to /dev/null -- silently dropping sshd_config directives and the swap fstab line.
run_sudo_tee() {
  local append=""
  [[ "$1" == "-a" ]] && { append="-a"; shift; }
  local path="$1"
  if [[ -n "${SUDO_PASSWORD:-}" ]]; then
    _setup_askpass; SUDO_ASKPASS="${_ASKPASS}" sudo -A tee ${append} "$path" >/dev/null
  else
    sudo tee ${append} "$path" >/dev/null
  fi
}

# ---- idempotent apt install (present -> skip; missing -> install) ----
# A single `apt-get update` is cached per shell via _APT_UPDATED.
_APT_UPDATED=""
apt_update_once() {
  [[ -n "${_APT_UPDATED}" ]] && return 0
  run_sudo apt-get update -qq
  _APT_UPDATED=1
}

install_if_missing() {
  local missing=()
  local pkg
  for pkg in "$@"; do
    dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
  done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  info "Installing: ${missing[*]}"
  apt_update_once
  run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

# ---- predicates ----
have()          { command -v "$1" &>/dev/null; }
pkg_installed() { dpkg -s "$1" &>/dev/null; }

# lowercase a value (for parsing "true"/"True"/"TRUE" flags)
lc() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }
is_true() { [[ "$(lc "${1:-}")" == "true" || "${1:-}" == "1" ]]; }
