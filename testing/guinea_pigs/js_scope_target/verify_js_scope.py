"""Assert what a JS scope lab run left in Neo4j. Exit 0 only if every check holds.

    docker run --rm --network host -v "$PWD:/repo:ro" -w /repo --entrypoint python \\
        whitehat-agent:latest testing/guinea_pigs/js_scope_target/verify_js_scope.py \\
        --project-id <id> [--expect-partial]

Case ids match static/app.js, uploads/scope-lab-upload.js and README.md.
"""
import argparse
import os
import sys

from neo4j import GraphDatabase

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TARGET = "http://192.88.97.10"

# (case, baseurl, path, method): must exist, be owned by its BaseURL, and be
# linked from the JS file that named it.
IN_SCOPE = [
    ("E1 relative path", TARGET, "/api/users", "GET"),
    ("E2 absolute on target", TARGET, "/api/orders", "GET"),
    ("E3 unprobed port 8080", "http://192.88.97.10:8080", "/api/admin", "GET"),
    ("E4 schema API, relative", TARGET, "/graphql", "POST"),
    ("E5 websocket", TARGET, "/socket", "WS"),
    ("U2 absolute in uploaded JS", TARGET, "/api/from-upload", "GET"),
]
PARTIAL_IN_SCOPE = [
    ("P1 partial run, user URL on :8080", "http://192.88.97.10:8080", "/api/partial-only", "GET"),
]
FOREIGN_HOSTS = ["api.payments-vendor.test", "192.88.97.20", "cms.vendor-content.test",
                 "push.vendor-realtime.test"]


def _password() -> str:
    with open(os.path.join(REPO, ".env")) as f:
        for line in f:
            if line.startswith("NEO4J_PASSWORD="):
                return line.split("=", 1)[1].strip().strip("'\"")
    raise SystemExit("NEO4J_PASSWORD not found in .env")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--uri", default="bolt://localhost:7687")
    ap.add_argument("--expect-partial", action="store_true")
    ap.add_argument("--expect-legacy", action="store_true",
                    help="a seeded pre-fix endpoint (see README) must still be intact")
    args = ap.parse_args()
    pid = args.project_id

    drv = GraphDatabase.driver(args.uri, auth=("neo4j", _password()))
    failures = []

    def q(cypher, **p):
        with drv.session() as s:
            return [r.data() for r in s.run(cypher, pid=pid, **p)]

    def check(ok, label, detail=""):
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + detail) if detail else ''}")
        if not ok:
            failures.append(label)

    uid_rows = q("MATCH (p:Domain {project_id: $pid}) RETURN DISTINCT p.user_id AS uid "
                 "UNION MATCH (b:BaseURL {project_id: $pid}) RETURN DISTINCT b.user_id AS uid")
    uids = sorted({r["uid"] for r in uid_rows if r["uid"]})
    check(len(uids) == 1, "one owner for every node of the project", str(uids))
    uid = uids[0] if uids else ""

    print("\nEndpoints in the project:")
    for r in q("""
        MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
        OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e)
        OPTIONAL MATCH (f:JsReconFinding {finding_type: 'js_file', user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e)
        RETURN e.baseurl AS baseurl, e.path AS path, e.method AS method, e.source AS source,
               collect(DISTINCT b.url) AS owners, collect(DISTINCT f.source_url) AS js_files
        ORDER BY baseurl, path""", uid=uid):
        print(f"    {r['method']:5} {r['baseurl']}{r['path']:<22} source={r['source']:<14} "
              f"owners={r['owners']} js={r['js_files']}")

    print("\nIn-scope cases:")
    cases = IN_SCOPE + (PARTIAL_IN_SCOPE if args.expect_partial else [])
    for label, base, path, method in cases:
        rows = q("""
            MATCH (e:Endpoint {baseurl: $base, path: $path, method: $method, user_id: $uid, project_id: $pid})
            OPTIONAL MATCH (b:BaseURL {url: $base, user_id: $uid, project_id: $pid})-[o:HAS_ENDPOINT]->(e)
            OPTIONAL MATCH (f:JsReconFinding {finding_type: 'js_file', user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e)
            RETURN count(DISTINCT e) AS n, count(DISTINCT o) AS owners, count(DISTINCT f) AS files""",
                 base=base, path=path, method=method, uid=uid)
        r = rows[0]
        check(r["n"] == 1 and r["owners"] == 1 and r["files"] >= 1,
              f"{label}: {method} {base}{path}",
              f"endpoint={r['n']} owner_edges={r['owners']} js_file_links={r['files']}")

    r = q("""MATCH (b:BaseURL {url: 'http://192.88.97.10:8080', user_id: $uid, project_id: $pid})
             RETURN b.source AS source""", uid=uid)
    check(len(r) == 1, "E3 BaseURL http://192.88.97.10:8080 exists, minted from JS",
          f"source={r[0]['source'] if r else None}")

    r = q("""MATCH (e:Endpoint {baseurl: 'upload', path: '/api/upload-only', user_id: $uid, project_id: $pid})
             OPTIONAL MATCH (b:BaseURL)-[:HAS_ENDPOINT]->(e)
             RETURN count(DISTINCT e) AS n, count(b) AS owners""", uid=uid)[0]
    check(r["n"] == 1 and r["owners"] == 0, "U1 uploaded relative path under 'upload', no BaseURL",
          f"endpoint={r['n']} owners={r['owners']}")

    print("\nOut-of-scope cases:")
    for host in FOREIGN_HOSTS:
        r = q("""
            OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
              WHERE e.baseurl CONTAINS $host OR e.path CONTAINS $host
            WITH count(e) AS eps
            OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid}) WHERE b.url CONTAINS $host
            RETURN eps, count(b) AS baseurls""", host=host, uid=uid)[0]
        check(r["eps"] == 0 and r["baseurls"] == 0, f"no Endpoint/BaseURL for {host}",
              f"endpoints={r['eps']} baseurls={r['baseurls']}")

    # Only http(s) URLs feed JS recon's external-domain list; the WebSocket and
    # the whole-URL-in-path hosts are dropped from the graph without a record.
    r = q("""MATCH (x:ExternalDomain {user_id: $uid, project_id: $pid})
             RETURN x.domain AS domain, x.sources AS sources ORDER BY domain""", uid=uid)
    recorded = {row["domain"]: row["sources"] for row in r}
    wanted = {"api.payments-vendor.test", "192.88.97.20"}
    check(wanted <= set(recorded) and all("js_recon" in recorded[d] for d in wanted)
          and "192.88.97.10" not in recorded,
          "third parties recorded as ExternalDomain (source js_recon), the target IP not",
          str(recorded))

    print("\nGraph invariants:")
    r = q("""MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WHERE e.path STARTS WITH 'http' OR e.path STARTS WITH 'ws' OR e.path STARTS WITH '//'
             RETURN count(e) AS n""", uid=uid)[0]
    check(r["n"] == 0, "no Endpoint carries a whole URL in its path", f"n={r['n']}")

    r = q("""MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
             WHERE e.baseurl <> 'upload' AND NOT EXISTS {
               MATCH (:BaseURL {url: e.baseurl, user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e) }
             RETURN collect(e.baseurl + e.path) AS orphans""", uid=uid)[0]
    if args.expect_legacy:
        r["orphans"] = [o for o in r["orphans"] if o != "https://legacy-vendor.test/graphql"]
    check(not r["orphans"], "every network Endpoint (any tool) hangs off its BaseURL",
          f"orphans={r['orphans']}")

    r = q("""MATCH (b:BaseURL {project_id: $pid})-[rel:HAS_ENDPOINT]->(e:Endpoint)
             WITH b, e, count(rel) AS n WHERE n > 1 RETURN count(*) AS dup""")[0]
    check(r["dup"] == 0, "no duplicate BaseURL->Endpoint edge", f"dup={r['dup']}")

    r = q("""MATCH (a)-[rel]-(b) WHERE a.project_id = $pid AND b.project_id IS NOT NULL
               AND b.project_id <> $pid RETURN count(rel) AS n""")[0]
    check(r["n"] == 0, "no relationship crosses into another project", f"n={r['n']}")

    r = q("""MATCH (b:BaseURL {project_id: $pid}) WHERE b.user_id IS NULL RETURN count(b) AS n""")[0]
    check(r["n"] == 0, "every BaseURL carries the tenant key", f"n={r['n']}")

    if args.expect_legacy:
        print("\nPre-existing data (seeded before the rescan):")
        r = q("""
            MATCH (e:Endpoint {baseurl: 'https://legacy-vendor.test', path: '/graphql', user_id: $uid, project_id: $pid})
            OPTIONAL MATCH (v:Vulnerability:Muted {user_id: $uid, project_id: $pid})-[:FOUND_AT]->(e)
            OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
            OPTIONAL MATCH (c:ChainFinding {user_id: $uid, project_id: $pid})-[:FINDING_AFFECTS_ENDPOINT]->(e)
            RETURN count(DISTINCT e) AS e, count(DISTINCT v) AS v, count(DISTINCT p) AS p, count(DISTINCT c) AS c""",
                 uid=uid)
        r = r[0] if r else {"e": 0, "v": 0, "p": 0, "c": 0}
        check(r == {"e": 1, "v": 1, "p": 1, "c": 1},
              "legacy endpoint and its muted vuln, parameter and chain finding untouched", str(r))

    drv.close()
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
