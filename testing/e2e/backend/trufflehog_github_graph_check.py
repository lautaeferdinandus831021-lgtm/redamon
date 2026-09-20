#!/usr/bin/env python3
"""Verify what a Secret Multiscanner `github` run actually wrote to the graph.

The parameter matrix proves the SCAN is right by reading the published artifact.
That file is the scan container's own output, though, and the graph is written by
a separate clean step in the orchestrator (`update_graph_from_trufflehog`). A
correct artifact and an empty, orphaned or mislabelled graph is a state the
matrix cannot see, and it is the graph that the /graph page and the Red Zone
table actually read.

So this compares the two: it runs one deliberately RICH scan (several repos, a
gist, issue/PR/gist comments, so every node label and edge is exercised), then
asserts the graph against the artifact finding by finding.

What is checked:

  nodes         one MultiscannerScan, one MultiscannerRepository per asset, one
                MultiscannerFinding per deduplicated artifact finding
  edges         (Domain)-[:HAS_MULTISCANNER_SCAN]->(scan)
                (scan)-[:HAS_ASSET]->(asset)
                (asset)-[:HAS_FINDING]->(finding)
  attributes    every property the ingest promises, with the values the artifact
                actually carried - not merely present, but equal
  tenancy       every node carries user_id AND project_id (a MERGE that loses the
                tenant key silently merges one project's data into another's)
  orphans       no finding without an incoming HAS_FINDING, no asset without a
                scan
  id stability  ids are a sha1 digest, not the process-randomised builtin hash();
                --twice re-runs the same scan and asserts the ids do not move

Run:  python3 testing/e2e/backend/trufflehog_github_graph_check.py
      python3 testing/e2e/backend/trufflehog_github_graph_check.py --twice
      python3 testing/e2e/backend/trufflehog_github_graph_check.py --no-scan
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY,
      GITHUB_FIXTURE_TOKEN (else _local/gh_fixture_token)
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PROJECT = os.environ.get("WHITEHAT_PROJECT", "e651f859c3114faf94196ab02")
USER = os.environ.get("WHITEHAT_USER", "cmrzlj3xk0000ob3vo67o3igg")
ORCH = os.environ.get("ORCH_URL", "http://127.0.0.1:8010")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ARTIFACT = os.path.join(
    REPO_ROOT, "scanners", "trufflehog_scan", "output",
    f"trufflehog_{PROJECT}_github.json")
MANIFEST = os.path.join(REPO_ROOT, "_local", "github_fixtures.json")

VALIDATION_STATUSES = {"validated", "unvalidated", "verify_error", "unverified"}


def _read(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _token() -> str:
    tok = os.environ.get("GITHUB_FIXTURE_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with open(os.path.join(REPO_ROOT, "_local", "gh_fixture_token")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


MF = _read(MANIFEST)
# No fallback: the account comes from the manifest the builder wrote, so this
# file carries no one's GitHub login. main() refuses to run without it.
OWNER = MF.get("owner", "")
PREFIX = MF.get("prefix", "whitehat-th")
GIST = MF.get("gist", "")
TOKEN = _token()

# Rich on purpose: several repositories AND a gist AND the comment sources, so
# the check covers an asset set with more than one member and findings whose
# `link` points somewhere other than a file.
SCAN_CONFIG = {
    "orgs": [OWNER],
    "includeRepos": [f"{OWNER}/{PREFIX}-*"] + ([f"*{GIST}*"] if GIST else []),
    "issueComments": True,
    "prComments": True,
    "gistComments": True,
}


def orchestrator_key() -> str:
    key = os.environ.get("ORCHESTRATOR_API_KEY", "").strip()
    if key:
        return key
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "recon-orchestrator",
         "printenv", "ORCHESTRATOR_API_KEY"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    return out.stdout.strip()


KEY = orchestrator_key()
HEADERS = {"Content-Type": "application/json", "X-Orchestrator-Key": KEY}


def start_scan() -> tuple[int, dict]:
    body = json.dumps({
        "project_id": PROJECT, "user_id": USER,
        "webapp_api_url": "http://webapp:3000",
        "source": "github", "config": SCAN_CONFIG, "common": {},
        "secrets": {"trufflehogGithubToken": TOKEN},
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(timeout: float = 600.0) -> dict:
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/github/status", headers=HEADERS)
    deadline = time.time() + timeout
    state: dict = {}
    while time.time() < deadline:
        time.sleep(3)
        try:
            state = json.loads(urllib.request.urlopen(req, timeout=20).read())
        except Exception:
            continue
        if state.get("status") not in ("running", "starting", "stopping"):
            return state
    return state


# ---------------------------------------------------------------------------
# Graph access. The agent image is the one place that already holds the Neo4j
# driver AND the credentials; the host has neither, and the scan container is
# denied both by design.
# ---------------------------------------------------------------------------

PROBE = r'''
import json, os, sys
from neo4j import GraphDatabase

uid, pid = sys.argv[1], sys.argv[2]
drv = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=(os.environ.get("NEO4J_USER") or os.environ["NEO4J_USERNAME"],
          os.environ["NEO4J_PASSWORD"]))
out = {}
with drv.session() as s:
    out["scans"] = [dict(r["ts"]) for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p, source:'github'}) "
        "RETURN ts", u=uid, p=pid)]
    out["assets"] = [dict(r["ta"]) | {"labels": r["labels"]} for r in s.run(
        "MATCH (ta {user_id:$u, project_id:$p, source:'github'}) "
        "WHERE any(l IN labels(ta) WHERE l STARTS WITH 'Multiscanner') "
        "  AND NOT ta:MultiscannerScan AND NOT ta:MultiscannerFinding "
        "RETURN ta, labels(ta) AS labels", u=uid, p=pid)]
    out["findings"] = [dict(r["tf"]) for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p, source:'github'}) "
        "RETURN tf", u=uid, p=pid)]
    out["domain_edges"] = s.run(
        "MATCH (d:Domain {user_id:$u, project_id:$p})-[:HAS_MULTISCANNER_SCAN]->"
        "(ts:MultiscannerScan {source:'github'}) RETURN count(*) AS n",
        u=uid, p=pid).single()["n"]
    out["has_asset"] = [[r["scan"], r["asset"]] for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p, source:'github'})"
        "-[:HAS_ASSET]->(ta) RETURN ts.id AS scan, ta.id AS asset", u=uid, p=pid)]
    out["has_finding"] = [[r["asset"], r["finding"]] for r in s.run(
        "MATCH (ta)-[:HAS_FINDING]->(tf:MultiscannerFinding "
        "{user_id:$u, project_id:$p, source:'github'}) "
        "RETURN ta.id AS asset, tf.id AS finding", u=uid, p=pid)]
    out["orphan_findings"] = [r["id"] for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p, source:'github'}) "
        "WHERE NOT ()-[:HAS_FINDING]->(tf) RETURN tf.id AS id", u=uid, p=pid)]
    # Tenant leak probe: a github Multiscanner node that carries no tenant key,
    # or carries another project's. Written as a scan of ALL Multiscanner nodes
    # on purpose - the bug this guards is a MERGE that dropped the key, and such
    # a node would not come back from a tenant-filtered query.
    out["untenanted"] = [r["id"] for r in s.run(
        "MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Multiscanner') "
        "AND (n.user_id IS NULL OR n.project_id IS NULL) RETURN n.id AS id")]
# default=str: every node carries an `updated_at` the driver returns as a
# neo4j DateTime, which json cannot encode.
print(json.dumps(out, default=str))
'''


def graph_state() -> dict:
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "agent", "python", "-", USER, PROJECT],
        cwd=REPO_ROOT, input=PROBE, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"graph probe failed: {out.stderr[-500:]}")
    return json.loads(out.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def dedup_key(f: dict) -> str:
    return (f"github:{f.get('asset') or ''}:{f.get('location') or ''}:"
            f"{f.get('line', 0)}:{f.get('detector_name', '')}")


class Report:
    def __init__(self):
        self.rows: list[tuple[bool, str, str]] = []

    def check(self, ok: bool, name: str, detail: str = "") -> None:
        self.rows.append((bool(ok), name, detail))

    def failed(self) -> list:
        return [r for r in self.rows if not r[0]]

    def render(self) -> int:
        for ok, name, detail in self.rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
            if detail:
                print(f"        {detail}")
        bad = self.failed()
        print(f"\n{len(self.rows) - len(bad)}/{len(self.rows)} graph checks passed")
        return 1 if bad else 0


def verify(art: dict, g: dict, rep: Report) -> None:
    findings = [f for f in (art.get("findings") or []) if f.get("detector_name")]
    # The ingest deduplicates on (source, asset, location, line, detector); the
    # graph is compared against the deduplicated set, not the raw one, or a
    # legitimately collapsed pair reads as a missing node.
    by_key = {dedup_key(f): f for f in findings}
    art_assets = {f.get("asset") for f in findings if f.get("asset")}

    # -- the scan node -------------------------------------------------------
    scans = g["scans"]
    rep.check(len(scans) == 1, "exactly one MultiscannerScan for source=github",
              f"found {len(scans)}: {[s.get('id') for s in scans]}")
    if not scans:
        return
    scan = scans[0]
    stats = art.get("statistics") or {}

    rep.check(scan.get("source") == "github", "scan.source is 'github'",
              f"got {scan.get('source')!r}")
    rep.check(scan.get("target") == art.get("target"),
              "scan.target matches the artifact",
              f"graph={scan.get('target')!r} artifact={art.get('target')!r}")
    rep.check(scan.get("status") == art.get("status"),
              "scan.status matches the artifact",
              f"graph={scan.get('status')!r} artifact={art.get('status')!r}")
    rep.check(int(scan.get("total_findings", -1)) == int(stats.get("total_findings", -2)),
              "scan.total_findings matches the artifact statistics",
              f"graph={scan.get('total_findings')} artifact={stats.get('total_findings')}")
    rep.check(int(scan.get("assets_scanned", -1)) == int(stats.get("assets_scanned", -2)),
              "scan.assets_scanned matches the artifact statistics",
              f"graph={scan.get('assets_scanned')} artifact={stats.get('assets_scanned')}")
    rep.check(scan.get("verification_enabled") is not None,
              "scan.verification_enabled is recorded",
              f"got {scan.get('verification_enabled')!r}")
    for key in ("scan_start_time", "scan_end_time", "run_id", "source_label"):
        rep.check(bool(str(scan.get(key) or "")), f"scan.{key} is populated",
                  f"got {scan.get(key)!r}")
    rep.check(g["domain_edges"] >= 1,
              "(Domain)-[:HAS_MULTISCANNER_SCAN]->(scan) exists",
              f"{g['domain_edges']} edges")

    # -- assets --------------------------------------------------------------
    assets = g["assets"]
    graph_asset_names = {a.get("name") for a in assets}
    rep.check(graph_asset_names == art_assets,
              "one asset node per artifact asset",
              f"graph={sorted(x or '' for x in graph_asset_names)} "
              f"artifact={sorted(x or '' for x in art_assets)}")
    rep.check(all("MultiscannerRepository" in a["labels"] for a in assets),
              "every github asset is labelled MultiscannerRepository",
              f"labels={sorted({l for a in assets for l in a['labels']})}")
    rep.check(all(a.get("asset_kind") == "repository" for a in assets),
              "every asset carries asset_kind='repository'",
              f"kinds={sorted({str(a.get('asset_kind')) for a in assets})}")
    rep.check(all(a.get("scan_id") == scan.get("id") for a in assets),
              "every asset points back at this scan via scan_id")
    # One repository must be ONE node. TruffleHog reports `repository` as a
    # clone URL for a file finding but as a bare `owner/repo` slug for an
    # issue/PR comment, and findings.py passes both through verbatim - so the
    # same repository arrives under two identities and the ingest faithfully
    # creates two MultiscannerRepository nodes for it. The graph then shows a
    # duplicate node, inflates assets_scanned, and splits one repository's
    # findings across two assets, so "everything found in <repo>" returns half.
    def canonical(name: str) -> str:
        n = str(name or "").split("://", 1)[-1].removesuffix(".git").strip("/")
        parts = n.split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else n

    groups: dict[str, set] = {}
    for a in assets:
        groups.setdefault(canonical(a.get("name")), set()).add(a.get("name"))
    split = {k: sorted(v) for k, v in groups.items() if len(v) > 1}
    rep.check(not split, "one node per repository (no slug / clone-URL split)",
              "; ".join(f"{k} -> {v}" for k, v in split.items()))

    linked_assets = {a for _, a in g["has_asset"]}
    rep.check(linked_assets == {a.get("id") for a in assets},
              "(scan)-[:HAS_ASSET]->(asset) covers every asset",
              f"{len(linked_assets)} linked of {len(assets)}")

    # -- findings ------------------------------------------------------------
    gf = g["findings"]
    rep.check(len(gf) == len(by_key),
              "one MultiscannerFinding per deduplicated artifact finding",
              f"graph={len(gf)} artifact_deduped={len(by_key)} raw={len(findings)}")

    graph_by_id = {f.get("id"): f for f in gf}
    rep.check(len(graph_by_id) == len(gf), "finding ids are unique")

    missing_props, wrong_status, empty_detector, mismatched = [], [], [], []
    for f in gf:
        if not f.get("detector_name"):
            empty_detector.append(f.get("id"))
        if f.get("validation_status") not in VALIDATION_STATUSES:
            wrong_status.append(f"{f.get('id')}={f.get('validation_status')!r}")
        for prop in ("user_id", "project_id", "source", "scan_id", "detector_name",
                     "asset", "validation_status", "finding_kind"):
            if f.get(prop) in (None, ""):
                missing_props.append(f"{f.get('id')}.{prop}")
        # The graph value must EQUAL the artifact's, not merely exist: the
        # deprecated aliases (repository/file) are written from the same source
        # values and a divergence there is a silent reporting bug.
        if f.get("repository") != f.get("asset") or f.get("file") != f.get("location"):
            mismatched.append(f.get("id"))

    rep.check(not empty_detector, "every finding has a detector_name",
              f"{len(empty_detector)} without one")
    rep.check(not wrong_status,
              "every validation_status is in the documented vocabulary",
              "; ".join(wrong_status[:4]))
    rep.check(not missing_props, "every finding carries the required properties",
              "; ".join(missing_props[:6]))
    rep.check(not mismatched,
              "the deprecated repository/file aliases equal asset/location",
              f"{len(mismatched)} divergent")

    # Value-level equality against the artifact, on the fields a report renders.
    art_by_key = {dedup_key(f): f for f in findings}
    graph_by_key = {}
    for f in gf:
        graph_by_key[f"github:{f.get('asset')}:{f.get('location')}:"
                     f"{f.get('line', 0)}:{f.get('detector_name')}"] = f
    common = set(art_by_key) & set(graph_by_key)
    rep.check(len(common) == len(by_key),
              "every artifact finding is findable in the graph by its identity",
              f"matched {len(common)} of {len(by_key)}")
    drift = []
    for k in sorted(common):
        a, b = art_by_key[k], graph_by_key[k]
        for prop in ("detector_name", "validation_status", "redacted", "link",
                     "commit", "location"):
            if str(a.get(prop) or "") != str(b.get(prop) or ""):
                drift.append(f"{prop}: artifact={a.get(prop)!r} graph={b.get(prop)!r}")
    rep.check(not drift, "finding attributes equal the artifact's values",
              "; ".join(drift[:4]))

    linked_findings = {f for _, f in g["has_finding"]}
    rep.check(linked_findings == set(graph_by_id),
              "(asset)-[:HAS_FINDING]->(finding) covers every finding",
              f"{len(linked_findings)} linked of {len(gf)}")
    rep.check(not g["orphan_findings"], "no orphaned findings",
              f"{len(g['orphan_findings'])} orphans")
    rep.check(not g["untenanted"],
              "every Multiscanner node carries user_id and project_id",
              f"{len(g['untenanted'])} untenanted: {g['untenanted'][:4]}")

    # -- the sources the rich config was chosen to exercise -------------------
    links = [str(f.get("link") or "") for f in gf]
    rep.check(any("gist.github.com" in str(a or "") for a in art_assets),
              "a gist asset reached the graph",
              f"assets={sorted(str(a) for a in art_assets)}")
    rep.check(any("/issues/" in ln or "issuecomment" in ln for ln in links),
              "a comment finding reached the graph with its link intact",
              f"sample links={links[:3]}")


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    if not TOKEN:
        print("no GitHub token", file=sys.stderr)
        return 2
    if not OWNER:
        print(f"no fixture manifest at {MANIFEST}; run build_github_fixtures.sh first",
              file=sys.stderr)
        return 2

    runs = 2 if "--twice" in sys.argv else 1
    ids_seen: list[tuple[set, set]] = []

    for run in range(runs):
        if "--no-scan" not in sys.argv:
            print(f"[run {run + 1}/{runs}] starting a rich github scan "
                  f"({', '.join(sorted(SCAN_CONFIG))}) ...")
            code, resp = start_scan()
            if code != 200:
                print(f"start refused: HTTP {code} {resp.get('detail', '')}",
                      file=sys.stderr)
                return 2
            state = wait_settled()
            print(f"           run settled: status={state.get('status')!r} "
                  f"error={str(state.get('error') or '')[:100]}")
            # The ingest runs after the container exits; give it a moment to land.
            time.sleep(5)

        art = _read(ARTIFACT)
        if not art:
            print(f"no artifact at {ARTIFACT}", file=sys.stderr)
            return 2
        g = graph_state()
        print(f"\n[run {run + 1}] artifact: {len(art.get('findings') or [])} findings, "
              f"status={art.get('status')!r}")
        print(f"[run {run + 1}] graph: {len(g['scans'])} scan, {len(g['assets'])} assets, "
              f"{len(g['findings'])} findings\n")

        rep = Report()
        verify(art, g, rep)
        rc = rep.render()
        ids_seen.append(({a["id"] for a in g["assets"]},
                         {f["id"] for f in g["findings"]}))
        if rc and runs == 1:
            return rc
        if rc:
            print("  (continuing to the id-stability run anyway)")

    if runs > 1:
        same_assets = ids_seen[0][0] == ids_seen[1][0]
        same_findings = ids_seen[0][1] == ids_seen[1][1]
        print("\nid stability across two identical runs:")
        print(f"  {'PASS' if same_assets else 'FAIL'}  asset ids are stable")
        print(f"  {'PASS' if same_findings else 'FAIL'}  finding ids are stable")
        if not (same_assets and same_findings):
            print("  a moving id means the digest is process-dependent again, "
                  "which leaves orphans behind every re-scan")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
