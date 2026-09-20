"""
Live end-to-end probe for the captured-traffic read tools (Phase 4), run INSIDE
the agent container against the real DB. Bypasses the LLM: it seeds rows in two
tenants, sets the ContextVars, calls each tool via .ainvoke(), and asserts both
the results AND tenant isolation (tenant A never sees tenant B's rows).

Run: docker exec whitehat-agent python /app/agentic/tests/live_traffic_tools_probe.py
(or with the agentic dir on sys.path). Exits non-zero on any failure. Self-cleans.
"""
import asyncio
import os
import sys

_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENTIC not in sys.path:
    sys.path.insert(0, _AGENTIC)

import psycopg
from agent_context import set_tenant_context
import traffic_tools as tt

DSN = os.environ["DATABASE_URL"]
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        print(f"  PASS: {name}"); PASS += 1
    else:
        print(f"  FAIL: {name}"); FAIL += 1


def seed():
    with psycopg.connect(DSN, autocommit=True) as conn:
        # two distinct tenants (project+owner) from the existing rows
        rows = conn.execute("SELECT id, user_id FROM projects LIMIT 2").fetchall()
        if len(rows) < 2:
            print("need >=2 projects to test isolation"); sys.exit(1)
        (pa, ua), (pb, ub) = rows
        base = ("INSERT INTO captured_http_transactions "
                "(id,project_id,user_id,source,method,scheme,host,port,path,query,"
                "req_headers,resp_headers,resp_body,resp_body_size,status_code,"
                "had_auth,reflected_params,started_at) VALUES "
                "(%s,%s,%s,'agent',%s,'https',%s,443,%s,%s,'{}','{}',%s,%s,%s,%s,false,now())")
        conn.execute(base, ('pt-a1', pa, ua, 'GET', 'shop.test', '/item', '?id=42',
                            'ok body', 7, 200, True))
        conn.execute(base, ('pt-a2', pa, ua, 'GET', 'shop.test', '/admin', '?id=99',
                            'aws_key=AKIAX leaked stack trace', 30, 500, False))
        conn.execute(base, ('pt-b1', pb, ub, 'GET', 'other.test', '/secret', '?id=7',
                            'AKIAX also here but tenant B', 27, 200, False))
        return pa, ua, pb, ub


def cleanup():
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DELETE FROM captured_http_transactions WHERE id IN ('pt-a1','pt-a2','pt-b1')")


async def main():
    pa, ua, pb, ub = seed()
    try:
        set_tenant_context(ua, pa)   # act as tenant A

        r = await tt.proxy_search.ainvoke({"filters": "{}"})
        check("proxy_search returns A's rows", 'pt-a1' in r and 'pt-a2' in r)
        check("proxy_search does NOT leak B's row", 'pt-b1' not in r)
        check("proxy_search never includes bodies", 'AKIAX' not in r)

        r = await tt.proxy_search.ainvoke({"filters": '{"only5xx": true}'})
        check("proxy_search filter only5xx -> just the 500", 'pt-a2' in r and 'pt-a1' not in r)

        r = await tt.proxy_get.ainvoke({"id": "pt-a2", "part": "response"})
        check("proxy_get fetches the body on demand", 'AKIAX leaked' in r)
        r = await tt.proxy_get.ainvoke({"id": "pt-b1"})
        check("proxy_get cannot fetch B's row", 'Not found' in r)

        r = await tt.proxy_grep.ainvoke({"pattern": "AKIAX"})
        check("proxy_grep finds the secret in A", 'pt-a2' in r)
        check("proxy_grep does NOT find B's row", 'pt-b1' not in r)

        r = await tt.proxy_sitemap.ainvoke({})
        check("proxy_sitemap lists A's endpoints", '/admin' in r and 'other.test' not in r)

        r = await tt.proxy_params.ainvoke({})
        check("proxy_params classifies id as sequential-id", 'id' in r and 'sequential-id' in r)

        r = await tt.proxy_diff.ainvoke({"id_a": "pt-a1", "id_b": "pt-a2"})
        check("proxy_diff shows status change", '200' in r and '500' in r)

        r = await tt.proxy_to_curl.ainvoke({"id": "pt-a1"})
        check("proxy_to_curl renders a curl for A", r.startswith('curl') and 'shop.test' in r)

        r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"agg":"count"}]}'})
        check("proxy_query count = A's 2 rows (tenant-scoped)", '2' in r)
        r = await tt.proxy_query.ainvoke({"spec": '{"select":[{"col":"user_id"}]}'})
        check("proxy_query rejects non-allowlisted (tenant) column", 'not allowed' in r.lower())
    finally:
        cleanup()

    print(f"\n== RESULT: {PASS} passed, {FAIL} failed ==")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    asyncio.run(main())
