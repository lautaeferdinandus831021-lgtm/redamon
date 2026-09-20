#!/usr/bin/env bash
# =============================================================================
# Issue #175: the browser -> agent WebSocket routing hint must survive a
# PRODUCTION build and reach the browser.
#
# app/layout.tsx injects window.__WHITEHAT_WS__ from process.env (AGENT_WS_MODE /
# AGENT_WS_PORT / AGENT_WS_PUBLIC_URL). Every page under it is a 'use client'
# shell, so unless the layout forces dynamic rendering Next prerenders them into
# static .next/server/app/*.html at build time - where those vars do not exist -
# and the hint is silently absent from every page a real user loads. The browser
# then falls back to same-origin ws://<host>:3000, which runs no WebSocket
# server, so the AI Agent, Kali terminal and both cypherfix sockets hang with
# NOTHING in the agent's log.
#
# The vitest guard (webapp/src/app/layout.test.ts) asserts the source contract;
# this asserts the shipped artifact, which is the thing that actually broke.
#
# Needs a running webapp container. Run:  bash tests/ws_runtime_hint_live.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose unavailable — skipping (not failing)."
    exit 0
fi
if ! docker compose ps --status running --services 2>/dev/null | grep -qx webapp; then
    echo "webapp container not running — skipping (not failing)."
    exit 0
fi

WS_MODE="$(docker compose exec -T webapp printenv AGENT_WS_MODE 2>/dev/null | tr -d '\r')"
WS_URL="$(docker compose exec -T webapp printenv AGENT_WS_PUBLIC_URL 2>/dev/null | tr -d '\r')"
if [[ -z "$WS_MODE" && -z "$WS_URL" ]]; then
    echo "webapp declares no browser->agent WS hint (reverse-proxy posture) — skipping."
    exit 0
fi

PORT="${WEBAPP_PORT:-3000}"
# /login renders the same root layout and needs no session, so it is the cheapest
# page that proves the head injection reached a real HTTP response.
HTML="$(curl -fsS --max-time 10 "http://127.0.0.1:${PORT}/login" 2>/dev/null)"
if [[ -z "$HTML" ]]; then
    echo "could not fetch http://127.0.0.1:${PORT}/login — skipping."
    exit 0
fi

if grep -qF '__WHITEHAT_WS__' <<<"$HTML"; then
    pass "served HTML carries window.__WHITEHAT_WS__"
else
    fail "served HTML has NO window.__WHITEHAT_WS__ (layout was prerendered at build time; issue #175)"
fi

# The hint is worthless if it does not carry the value the container is running
# with: a stale prerender would still be caught above, a wrong mapping here.
if [[ -n "$WS_URL" ]]; then
    grep -qF "$WS_URL" <<<"$HTML" \
        && pass "hint carries AGENT_WS_PUBLIC_URL" \
        || fail "hint does not carry AGENT_WS_PUBLIC_URL ($WS_URL)"
elif [[ "$WS_MODE" == "agent-port" ]]; then
    WS_PORT="$(docker compose exec -T webapp printenv AGENT_WS_PORT 2>/dev/null | tr -d '\r')"
    WS_PORT="${WS_PORT:-8090}"
    grep -qF "\"port\":\"${WS_PORT}\"" <<<"$HTML" \
        && pass "hint carries agent port ${WS_PORT}" \
        || fail "hint does not carry agent port ${WS_PORT}"
fi

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
