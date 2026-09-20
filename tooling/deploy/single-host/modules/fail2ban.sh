#!/usr/bin/env bash
# fail2ban.sh -- sshd + nginx jails (§10). Repointed from the example: the Django
# [django-auth] jail is dropped (no such log here). Reads ENABLE_FAIL2BAN. Requires
# _common.sh. Also reads MCP_SERVER_ENABLED (adds the MCP auth jail).

setup_fail2ban() {
  if ! is_true "${ENABLE_FAIL2BAN:-true}"; then
    disable_fail2ban
    return 0
  fi
  step "fail2ban (sshd + nginx jails)"
  local _MCP_JAIL_ENABLED=false
  is_true "${MCP_SERVER_ENABLED:-false}" && _MCP_JAIL_ENABLED=true
  install_if_missing fail2ban
  run_sudo mkdir -p /etc/fail2ban/jail.d

  # NOTE: backend is set PER JAIL, not in [DEFAULT]. A global `backend = systemd` makes
  # the nginx jails read the journal and IGNORE their file `logpath`, so they never fire.
  # sshd uses systemd (journald auth), nginx jails use auto (file/inotify).
  cat <<F2B | run_sudo_tee /etc/fail2ban/jail.d/whitehat.conf
# WhiteHat fail2ban jails: SSH brute-force + nginx auth/badbots/rate-limit.

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled  = true
port     = ${SSH_PORT:-22}
filter   = sshd
backend  = systemd
maxretry = 3
bantime  = 7200
findtime = 600

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

[nginx-badbots]
enabled  = true
port     = http,https
filter   = nginx-badbots
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 86400

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime  = 600

# Repeated MCP auth failures. This is the threshold signal for a token brute
# force or a replayed revoked token, and it is deliberately SEPARATE from
# nginx-limit-req: that jail bans on RATE, which an MCP client legitimately
# trips while bursting, whereas eleven 401s in two minutes is never legitimate.
# The MCP location sets \`limit_req_log_level warn\`, so its rate-limit lines no
# longer reach the [error]-anchored nginx-limit-req filter at all.
[whitehat-mcp-auth]
enabled  = ${_MCP_JAIL_ENABLED}
port     = http,https
filter   = whitehat-mcp-auth
logpath  = /var/log/nginx/access.log
maxretry = 10
findtime = 120
bantime  = 1800
F2B

  # The filter the jail above references. 401 is the ONLY code matched: the route
  # returns 401 for every credential failure (missing, invalid, revoked, expired)
  # and distinct codes for everything else, so this cannot fire on a healthy
  # client that is merely rate-limited (429) or on a disabled server (404).
  #
  # The path is bounded by ` HTTP/` or a query string rather than left open, so
  # it matches this endpoint and not everything sharing its prefix: an open
  # `[^"]*` tail would also ban on a 401 from a future /api/mcp-server-<x>
  # route. tests/deploy_mcp_fail2ban_test.sh runs the corpus this was tuned on.
  cat <<'F2BFILTER' | run_sudo_tee /etc/fail2ban/filter.d/whitehat-mcp-auth.conf
# WhiteHat: repeated credential failures against the inbound MCP endpoint.
[Definition]
failregex = ^<HOST> .* "(?:POST|GET) /api/mcp-server(?:\?[^"]*)? HTTP/[^"]+" 401
ignoreregex =
F2BFILTER

  run_sudo touch /var/log/auth.log 2>/dev/null || true
  run_sudo systemctl enable fail2ban >/dev/null 2>&1 || true
  run_sudo systemctl restart fail2ban || true
  sleep 2
  if run_sudo systemctl is-active --quiet fail2ban; then
    success "fail2ban active"
    run_sudo fail2ban-client status 2>/dev/null | grep -i "jail list" || true
  else
    warn "fail2ban failed to start"
    run_sudo journalctl -u fail2ban -n 20 --no-pager 2>/dev/null || true
  fi
}

disable_fail2ban() {
  info "fail2ban DISABLED (ENABLE_FAIL2BAN=false)"
  if systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban.service'; then
    run_sudo systemctl stop fail2ban 2>/dev/null || true
    run_sudo systemctl disable fail2ban 2>/dev/null || true
  fi
}
