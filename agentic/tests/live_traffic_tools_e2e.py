"""
COMPREHENSIVE end-to-end probe for ALL 10 Phase-4 agent tools, run inside the
agent container against the real DB. Seeds rich multi-tenant data and drives
every tool with many parameter variations + edge cases, asserting results AND
tenant isolation. The 2 active tools are driven through the real _run_active_proxy
orchestration (fetch origin -> build mutated request -> sign replay tag -> invoke
execute_curl) with execute_curl mocked (the real send+capture is proved by the
separate proxy live test).

Run: docker exec whitehat-agent python /app/tests/live_traffic_tools_e2e.py
Exits non-zero on any failure; self-cleans.
"""
import asyncio
import json
import os
import sys

_A = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _A not in sys.path:
    sys.path.insert(0, _A)

import psycopg
from agent_context import set_tenant_context, set_phase_context
import traffic_tools as tt
import whitehat_ctx

DSN = os.environ["DATABASE_URL"]
INTERNAL = os.environ.get("INTERNAL_API_KEY", "")
PASS = 0
FAIL = 0
UUID = "550e8400-e29b-41d4-a716-446655440000"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig"
B64 = "SGVsbG9Xb3JsZFRlc3REYXRh"


def ok(n):
    global PASS; print(f"  PASS: {n}"); PASS += 1
def bad(n, extra=""):
    global FAIL; print(f"  FAIL: {n}  {extra}"); FAIL += 1
def check(n, cond, extra=""):
    ok(n) if cond else bad(n, extra)


def seed():
    with psycopg.connect(DSN, autocommit=True) as c:
        pr = c.execute("SELECT id, user_id FROM projects LIMIT 2").fetchall()
        if len(pr) < 2:
            print("need >=2 projects"); sys.exit(1)
        (pa, ua), (pb, ub) = pr
        ins = ("INSERT INTO captured_http_transactions "
               "(id,project_id,user_id,source,run_id,session_id,tool,phase,method,scheme,host,port,path,query,"
               "req_headers,resp_headers,req_body,resp_body,resp_body_ref,resp_body_size,status_code,response_time_ms,"
               "had_auth,has_set_cookie,reflected_params,is_replay,origin_id,started_at) VALUES "
               "(%s,%s,%s,%s,'r1','s1',%s,%s,%s,'https',%s,443,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())")
        rows = [
            # tenant A: rich variety
            ('e1', pa, ua, 'recon', 'httpx', 'informational', 'GET', 'shop.test', '/item', '?id=42',
             '{}', '{"server":"nginx"}', None, '<html>ok item</html>', None, 20, 200, 55, False, True, False, False, None),
            ('e2', pa, ua, 'agent', 'curl', 'exploitation', 'GET', 'shop.test', '/admin', '?id=99',
             '{"Cookie":"sid=alice","Authorization":"Bearer AAA","User-Agent":"UA"}',
             '{"content-type":"text/html"}', None,
             'aws_key=AKIAIOSFODNN7EXAMPLE java.lang.NullPointerException stack trace', None, 55, 500, 120,
             True, False, True, False, None),
            ('e3', pa, ua, 'recon', 'katana', 'informational', 'POST', 'api.test', '/login', f'?token={JWT}&uuid={UUID}&data={B64}',
             '{}', '{}', 'username=x', 'welcome nothing special', None, 22, 301, 30, False, False, False, False, None),
            ('e4', pa, ua, 'agent', 'curl', 'exploitation', 'DELETE', 'api.test', '/item', '?id=7',
             '{}', '{}', None, None, 'a'*64, 200000, 404, 500, False, False, False, False, None),  # offloaded body
            ('e5', pa, ua, 'agent', 'proxy_replay', 'exploitation', 'GET', 'shop.test', '/admin', '?id=99',
             '{}', '{}', None, 'replayed body', None, 13, 200, 40, False, False, False, True, 'e2'),  # replay row
            # tenant B (isolation)
            ('eb1', pb, ub, 'agent', 'curl', 'exploitation', 'GET', 'secret.test', '/x', '?id=1',
             '{}', '{}', None, 'AKIAIOSFODNN7EXAMPLE tenant B leak', None, 30, 200, 20, False, False, False, False, None),
        ]
        for r in rows:
            c.execute(ins, r)
        return pa, ua, pb, ub


def cleanup():
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DELETE FROM captured_http_transactions WHERE id IN "
                  "('e1','e2','e3','e4','e5','eb1')")


class MockCurl:
    """Stand-in for the kali execute_curl MCP tool: records the args it was called
    with (so we can assert the built request + replay tag) and returns a canned response."""
    def __init__(self):
        self.calls = []
    async def ainvoke(self, args):
        self.calls.append(args)
        return "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"


async def test_read_tools(pa, ua, pb, ub):
    print("\n== READ TOOLS ==")
    set_tenant_context(ua, pa)
    set_phase_context("exploitation")

    # --- proxy_search: many filters + edges ---
    r = await tt.proxy_search.ainvoke({"filters": ""})
    check("search empty filter returns A's 5 rows", r.count("\n") >= 5 and "e1" in r and "eb1" not in r)
    check("search never leaks bodies", "AKIA" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"host":"api.test"}'})
    check("search host filter", "e3" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"method":"delete"}'})
    check("search method filter (case-insensitive)", "e4" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"statusClass":"5xx"}'})
    check("search statusClass 5xx (e2=500 only; e4=404, e1=200 excluded)", "e2" in r and "/admin" in r and "/item" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"only5xx":true}'})
    check("search only5xx", "e2" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"hasAuth":true}'})
    check("search hasAuth", "e2" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"reflected":true}'})
    check("search reflected", "e2" in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"tool":"katana"}'})
    check("search tool filter", "e3" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"source":"recon"}'})
    # (assert on the /admin path — the agent row e2 — since the seeded UUID contains 'e2')
    check("search source filter (recon only; agent e2 excluded)", "/item" in r and "/login" in r and "/admin" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"status":404}'})
    check("search exact status", "e4" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"q":"admin"}'})
    check("search q (url substring)", "e2" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"bodyq":"NullPointer"}'})
    check("search bodyq (body substring)", "e2" in r and "e1" not in r)
    r = await tt.proxy_search.ainvoke({"filters": '{"limit":1}'})
    check("search limit=1 caps output", r.count("shop") + r.count("api") <= 2)
    r = await tt.proxy_search.ainvoke({"filters": "not json"})
    check("search bad JSON -> error", "Error" in r)

    # --- proxy_get: parts + offloaded + isolation ---
    r = await tt.proxy_get.ainvoke({"id": "e2", "part": "response"})
    check("get response body on demand", "AKIA" in r and "stack trace" in r)
    r = await tt.proxy_get.ainvoke({"id": "e2", "part": "request"})
    check("get request headers", "Authorization" in r or "Bearer" in r)
    r = await tt.proxy_get.ainvoke({"id": "e2", "part": "both"})
    check("get both", "Request" in r and "Response" in r)
    r = await tt.proxy_get.ainvoke({"id": "e4"})
    check("get offloaded body -> notes offload", "offloaded" in r.lower())
    r = await tt.proxy_get.ainvoke({"id": "eb1"})
    check("get cannot fetch tenant B", "Not found" in r)
    r = await tt.proxy_get.ainvoke({"id": "nope"})
    check("get nonexistent id", "Not found" in r)

    # --- proxy_sitemap ---
    r = await tt.proxy_sitemap.ainvoke({})
    check("sitemap lists A endpoints", "/admin" in r and "/login" in r)
    check("sitemap excludes B", "secret.test" not in r)

    # --- proxy_params: classification ---
    r = await tt.proxy_params.ainvoke({})
    check("params: id -> sequential-id", "id" in r and "sequential-id" in r)
    check("params: uuid -> uuid", "uuid" in r)
    check("params: token -> jwt", "jwt" in r)
    check("params: data -> base64", "base64" in r)

    # --- proxy_grep ---
    r = await tt.proxy_grep.ainvoke({"pattern": "AKIA"})
    check("grep finds secret in A", "e2" in r and "eb1" not in r)
    r = await tt.proxy_grep.ainvoke({"pattern": "NullPointerException"})
    check("grep finds identifier", "e2" in r)
    r = await tt.proxy_grep.ainvoke({"pattern": "zzznotpresent"})
    check("grep no match", "No response bodies" in r)
    r = await tt.proxy_grep.ainvoke({"pattern": ""})
    check("grep empty pattern -> error", "Error" in r)

    # --- proxy_diff ---
    r = await tt.proxy_diff.ainvoke({"id_a": "e1", "id_b": "e2"})
    check("diff shows status change 200 vs 500", "200" in r and "500" in r)
    r = await tt.proxy_diff.ainvoke({"id_a": "e1", "id_b": "eb1"})
    check("diff cross-tenant -> not found", "not found" in r.lower())
    r = await tt.proxy_diff.ainvoke({"id_a": "e1", "id_b": "nope"})
    check("diff nonexistent -> not found", "not found" in r.lower())

    # --- proxy_to_curl ---
    r = await tt.proxy_to_curl.ainvoke({"id": "e2"})
    check("to_curl renders headers+method", r.startswith("curl") and "shop.test" in r and "-X GET" in r)
    check("to_curl includes captured auth header", "Authorization" in r)
    r = await tt.proxy_to_curl.ainvoke({"id": "eb1"})
    check("to_curl cannot render B's request", "Not found" in r)

    # --- proxy_query: builder power + injection guards ---
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"agg":"count"}]}'})
    check("query count = A's 5 rows", "5" in r)
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"host"},{"agg":"count","as":"n"}],"group_by":["host"],"order_by":[{"as":"n","dir":"desc"}]}'})
    check("query group_by host + order", "shop.test" in r and "api.test" in r)
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"agg":"max","col":"response_time_ms"}]}'})
    check("query max aggregation (e4=500 is the max)", "500" in r)
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"host"}],"where":[{"col":"status_code","op":">=","val":500}]}'})
    check("query where >= 500", "shop.test" in r or "api.test" in r)
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"user_id"}]}'})
    check("query rejects tenant column", "not allowed" in r.lower())
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"host"}],"where":[{"col":"host","op":"; DROP","val":"x"}]}'})
    check("query rejects bad op", "not allowed" in r.lower())
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"resp_body"}]}'})
    check("query rejects body column", "not allowed" in r.lower())
    r = await tt.proxy_query.ainvoke({"spec": 'not json'})
    check("query bad JSON -> error", "Error" in r)
    r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"host"}],"where":[{"col":"host","op":"=","val":"nope.test"}]}'})
    check("query empty result", "No results" in r)


async def test_active_tools(pa, ua):
    print("\n== ACTIVE TOOLS (proxy_replay / proxy_fuzz via _run_active_proxy) ==")
    from tools import PhaseAwareToolExecutor
    set_tenant_context(ua, pa)
    set_phase_context("exploitation")
    ex = PhaseAwareToolExecutor(None, None)
    mock = MockCurl()
    ex._all_tools["execute_curl"] = mock

    def last_args():
        return mock.calls[-1]["args"] if mock.calls else ""

    def last_tag():
        return whitehat_ctx.verify_tag(mock.calls[-1].get("_whitehat_ctx", ""), {"recon": "x", "agent": INTERNAL}) if mock.calls else None

    # proxy_replay: param mutation
    r = await ex._run_active_proxy("proxy_replay", {"id": "e2", "mutate": '{"param":{"id":"1"}}'})
    check("replay param mutation builds id=1", "id=1" in last_args() and "id=99" not in last_args())
    tag = last_tag()
    check("replay tag is_replay + origin_id + tenant", bool(tag) and tag.get("is_replay") is True and tag.get("origin_id") == "e2" and tag.get("user_id") == ua)
    check("replay host pinned to origin (shop.test)", "shop.test" in last_args())

    # proxy_replay: auth-context swap (drop Cookie+Authorization)
    await ex._run_active_proxy("proxy_replay", {"id": "e2", "mutate": '{"dropHeaders":["Cookie","Authorization"]}'})
    check("replay auth-swap drops Cookie", "sid=alice" not in last_args())
    check("replay auth-swap drops Authorization", "Bearer AAA" not in last_args())

    # proxy_replay: cookie replace + method override
    await ex._run_active_proxy("proxy_replay", {"id": "e2", "mutate": '{"cookie":"sid=bob","method":"post"}'})
    check("replay cookie replace", "sid=bob" in last_args() and "sid=alice" not in last_args())
    check("replay method override", "-X POST" in last_args())

    # proxy_replay: Host-swap attempt is ignored (scope safety)
    await ex._run_active_proxy("proxy_replay", {"id": "e2", "mutate": '{"headers":{"Host":"evil.test"}}'})
    check("replay Host-swap is IGNORED (stays origin host)", "shop.test" in last_args() and "evil.test" not in last_args())

    # proxy_replay: edge cases
    r = await ex._run_active_proxy("proxy_replay", {"id": "eb1", "mutate": "{}"})
    check("replay cross-tenant origin -> not found", "not found" in r.lower())
    r = await ex._run_active_proxy("proxy_replay", {"id": "e2", "mutate": "not json"})
    check("replay bad mutate JSON -> error", "Error" in r)
    r = await ex._run_active_proxy("proxy_replay", {"mutate": "{}"})
    check("replay missing id -> error", "required" in r.lower())

    # proxy_fuzz: iterate payloads over a param
    n_before = len(mock.calls)
    r = await ex._run_active_proxy("proxy_fuzz", {"id": "e2", "insertion_point": "id", "payloads": '["1","2","\' OR 1=1"]'})
    sent = len(mock.calls) - n_before
    check("fuzz sends one request per payload (3)", sent == 3)
    check("fuzz each request host-pinned", all("shop.test" in c["args"] for c in mock.calls[n_before:]))
    check("fuzz summary reports 3 payloads", r.count("id=") >= 3 or "3 sent" in r)

    # proxy_fuzz: cap at 50
    n_before = len(mock.calls)
    await ex._run_active_proxy("proxy_fuzz", {"id": "e2", "insertion_point": "id", "payloads": json.dumps([str(i) for i in range(200)])})
    check("fuzz caps payloads at 50", len(mock.calls) - n_before == 50)

    # proxy_fuzz: edge cases
    r = await ex._run_active_proxy("proxy_fuzz", {"id": "e2", "insertion_point": "", "payloads": '["a"]'})
    check("fuzz missing insertion_point -> error", "Error" in r)
    r = await ex._run_active_proxy("proxy_fuzz", {"id": "e2", "insertion_point": "id", "payloads": "not json"})
    check("fuzz bad payloads -> error", "Error" in r)


async def main():
    pa, ua, pb, ub = seed()
    try:
        await test_read_tools(pa, ua, pb, ub)
        await test_active_tools(pa, ua)
    finally:
        cleanup()
    print(f"\n== RESULT: {PASS} passed, {FAIL} failed ==")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    asyncio.run(main())
