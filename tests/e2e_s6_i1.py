"""Live E2E: S6 (WS ticket auth + hijack) and I1 (cross-tenant read) against the
running stack. Runs INSIDE the agent container (internal network).
  webapp: http://webapp:3000   agent WS: ws://localhost:8080/ws/agent
"""
import asyncio
import base64
import json
import os
import secrets
import sys

import requests
import websockets

WEB = "http://webapp:3000"
WS = "ws://localhost:8080/ws/agent"
IKEY = os.environ["INTERNAL_API_KEY"]
VICTIM_ID = "cmnxhb92m0000qp01u89ic4x5"  # existing 'standard' user (owns real data)

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS" if ok else "FAIL") + f"  {name}  -  {detail}", flush=True)

def H(**extra):
    h = {"Content-Type": "application/json"}
    h.update(extra)
    return h

def b64d(x):
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))


s = requests.Session()
# S2/E2 (commit 135c077) removed the internal-key bypass on POST /api/users, so
# the fresh STANDARD user is seeded directly in the DB by the shell wrapper
# (tests/test_e2e_security_live.sh) and its credentials are handed in via env.
# This test then only exercises the security surface (login, ws-ticket, I1).
EMAIL = os.environ["E2E_EMAIL"]
PW = os.environ.get("E2E_PW", "Test1234!")
check("fixture user seeded (standard)", bool(EMAIL), f"email={EMAIL}")

lg = s.post(f"{WEB}/api/auth/login", headers=H(),
            data=json.dumps({"email": EMAIL, "password": PW}))
check("login sets session cookie", lg.status_code == 200 and "whitehat-auth" in s.cookies.get_dict(),
      f"status {lg.status_code}")
uid = lg.json().get("id")
check("have authenticated userId", bool(uid), f"uid={uid}")

pid = os.environ.get("E2E_PID", "e2e-project")  # a project the seeded user owns
sid = "e2e-" + secrets.token_hex(8)

tk = s.post(f"{WEB}/api/agent/ws-ticket", headers=H(), data=json.dumps({"projectId": pid, "sessionId": sid}))
ticket = tk.json().get("ticket")
check("ws-ticket minted (cookie)", bool(ticket), f"status {tk.status_code}")

# Identity binding: ticket sub == authenticated user (cannot spoof another user).
claims = json.loads(b64d(ticket.split(".")[1]))
check("ticket sub bound to authenticated user (not spoofable)",
      claims.get("sub") == uid and claims.get("pid") == pid and claims.get("sid") == sid,
      f"sub={claims.get('sub')} pid={claims.get('pid')} sid={claims.get('sid')}")

# Attacker (no cookie) cannot mint a ticket at all.
am = requests.post(f"{WEB}/api/agent/ws-ticket", headers=H(), data=json.dumps({"projectId": pid, "sessionId": sid}))
check("attacker without cookie cannot mint ticket", am.status_code == 401, f"status {am.status_code}")


async def ws_init(ticket_val, user_id, project_id, session_id):
    """Returns ('frame', msg) or ('closed', code) or ('err', repr)."""
    try:
        async with websockets.connect(WS, open_timeout=10, close_timeout=5) as ws:
            payload = {"user_id": user_id, "project_id": project_id, "session_id": session_id}
            if ticket_val is not None:
                payload["ticket"] = ticket_val
            await ws.send(json.dumps({"type": "init", "payload": payload}))
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            return ("frame", msg)
    except websockets.exceptions.ConnectionClosed as e:
        return ("closed", e.code)
    except Exception as e:  # noqa
        return ("err", repr(e))


def is_rejected(kind, val):
    return (kind == "closed" and val in (1008, 1011)) or (kind == "frame" and val.get("type") == "error")


async def main():
    # Positive: valid ticket -> CONNECTED.
    kind, val = await ws_init(ticket, uid, pid, sid)
    ok = kind == "frame" and val.get("type") == "connected" and val.get("payload", {}).get("protocol_version") == 2
    check("S6 valid ticket -> CONNECTED (protocol v2)", ok, f"{kind}:{val if kind != 'frame' else val.get('type')}")

    # Negative: no ticket -> rejected.
    kind, val = await ws_init(None, uid, pid, sid + "-n")
    check("S6 missing ticket -> rejected", is_rejected(kind, val), f"{kind}:{val if kind != 'frame' else val.get('payload')}")

    # Negative: forged ticket -> rejected.
    kind, val = await ws_init("aaa.bbb.ccc", uid, pid, sid + "-f")
    check("S6 forged ticket -> rejected", is_rejected(kind, val), f"{kind}:{val if kind != 'frame' else val.get('payload')}")

    # HIJACK: establish a live victim session, then an unauthenticated attacker
    # tries to seize the same session key. Attacker must be rejected AND the
    # victim must survive (no eviction, no task transfer).
    vsid = "victim-" + secrets.token_hex(8)
    vtk = s.post(f"{WEB}/api/agent/ws-ticket", headers=H(),
                 data=json.dumps({"projectId": pid, "sessionId": vsid})).json()["ticket"]
    async with websockets.connect(WS, open_timeout=10) as victim:
        await victim.send(json.dumps({"type": "init",
                                      "payload": {"user_id": uid, "project_id": pid, "session_id": vsid, "ticket": vtk}}))
        vmsg = json.loads(await asyncio.wait_for(victim.recv(), timeout=10))
        check("hijack: victim session established", vmsg.get("type") == "connected", vmsg.get("type"))

        kind, val = await ws_init(None, uid, pid, vsid)  # attacker, same key, no ticket
        check("hijack: attacker REJECTED (no eviction path)", is_rejected(kind, val),
              f"{kind}:{val if kind != 'frame' else val.get('payload')}")

        try:
            pong_waiter = await victim.ping()
            await asyncio.wait_for(pong_waiter, timeout=5)
            check("hijack: victim SURVIVED (still connected)", True, "protocol pong received")
        except Exception as e:  # noqa
            check("hijack: victim SURVIVED (still connected)", False, f"victim dead: {e!r}")

asyncio.run(main())

# ---- I1: cross-tenant unmasked read ----
r = s.get(f"{WEB}/api/users/{VICTIM_ID}/llm-providers?internal=true")  # attacker cookie, no key
check("I1 cross-tenant ?internal=true BLOCKED (403)", r.status_code == 403, f"status {r.status_code}")
r = s.get(f"{WEB}/api/users/{uid}/llm-providers?internal=true")  # own account
check("I1 own read allowed (masked 200)", r.status_code == 200, f"status {r.status_code}")
r = requests.get(f"{WEB}/api/users/{VICTIM_ID}/llm-providers?internal=true", headers={"x-internal-key": IKEY})
check("I1 agent internal-key path still works (200)", r.status_code == 200, f"status {r.status_code}")

# The throwaway user is torn down by the shell wrapper (it was seeded there);
# S2/E2 removed the internal-key DELETE bypass this used to rely on.

passed = sum(results)
print(f"\n=== E2E S6+I1 SUMMARY: {passed}/{len(results)} passed ===", flush=True)
sys.exit(0 if passed == len(results) else 1)
