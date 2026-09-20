#!/usr/bin/env python3
"""Verify what a Secret Multiscanner `gitlab` run actually wrote to the graph.

The parameter matrix proves the SCAN is right by reading the published artifact.
That file is the scan container's own output, though, and the graph is written by
a separate clean step in the orchestrator (`update_graph_from_trufflehog`). A
correct artifact and an empty, orphaned or mislabelled graph is a state the
matrix cannot see, and it is the graph that the /graph page and the Red Zone
table actually read.

So this compares the two: it runs one deliberately RICH scan (the whole fixture
group, so several assets and several detectors are exercised), then asserts the
graph against the artifact finding by finding.

What is checked, beyond the generic contract:

  identity      ONE MultiscannerRepository per project. `_META_SPECS['gitlab']`
                reads the asset from ("repository", "link", "project"), three
                keys that need not agree in shape. The github source had exactly
                this bug: a clone URL from a file finding and a bare `owner/repo`
                from a comment finding built TWO nodes for one repository and
                inflated assets_scanned. This check groups asset names by their
                canonical `group/project` and fails if any group holds more
                than one spelling.
  host          the asset name keeps the endpoint's host. A self-hosted GitLab
                rewritten to gitlab.com would silently merge two different
                instances' projects of the same path.
  target        MultiscannerScan.target equals describe_target('gitlab', cfg),
                asserted as an exact string for TWO different configs (a repo
                list, and a group id).
  coexistence   a second source's scan node survives the gitlab ingest. The
                pre-clear at the head of update_graph_from_trufflehog is
                SOURCE-SCOPED on purpose; a blanket clear would wipe every other
                source's findings on every run.
  id stability  ids are a sha1 digest, not the process-randomised builtin
                hash(); --twice re-runs the same scan and asserts the ids do not
                move, across an intervening scan with a different config.

Run:  python3 testing/e2e/backend/trufflehog_gitlab_graph_check.py
      python3 testing/e2e/backend/trufflehog_gitlab_graph_check.py --twice
      python3 testing/e2e/backend/trufflehog_gitlab_graph_check.py --no-scan
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY,
      GITLAB_FIXTURE_TOKEN (else _local/gitlab_fixture_token)
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
    f"trufflehog_{PROJECT}_gitlab.json")
MANIFEST = os.path.join(REPO_ROOT, "_local", "gitlab_fixtures.json")

SETTINGS_KEY = "trufflehogGitlabToken"
VALIDATION_STATUSES = {"validated", "unvalidated", "verify_error", "unverified"}

# The coexistence partner. `filesystem` needs NO credential and no network, so
# the source-scoping proof costs nothing and cannot fail for a reason unrelated
# to what it measures.
COEXIST_SOURCE = "filesystem"
COEXIST_DIR = os.path.join(REPO_ROOT, "scanners", "scan_targets", "filesystem")
COEXIST_FILE = os.path.join(COEXIST_DIR, "whitehat_th_coexist.env")
# Synthetic, and deliberately a detector NO gitlab fixture carries, so "the
# other source's findings survived" is a question about one detector name.
COEXIST_CONTENT = "NPM_TOKEN=npm_iEDPP1TudBqvzVpBrIcHFJDVbrGwiC0dbfmL\n"
COEXIST_DETECTOR = "NpmToken"


def _read(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _token() -> str:
    tok = os.environ.get("GITLAB_FIXTURE_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with open(os.path.join(REPO_ROOT, "_local", "gitlab_fixture_token")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


MF = _read(MANIFEST)
# No fallback: the account and group come from the manifest the builder wrote,
# so this file carries no one's GitLab login. main() refuses to run without it.
HOST = MF.get("host", "https://gitlab.com")
GROUP = MF.get("group", "")
GROUP_ID = str(MF.get("groupId", "") or "")
ALPHA_URL = MF.get("alpha", "")
FIXTURE_PATHS = {MF.get("alphaPath", ""), MF.get("betaPath", ""), MF.get("gammaPath", "")}
TOKEN = _token()
HOST_NAME = HOST.split("://", 1)[-1].strip("/")

# Rich on purpose: a group scan enumerates all three projects, so the check
# covers an asset set with more than one member.
RICH_CONFIG = {"groupIds": [GROUP_ID]}
RICH_TARGET = f"group:{GROUP_ID}"
# The second config, purely to pin describe_target's other branch.
REPOS_CONFIG = {"repos": [ALPHA_URL]}
REPOS_TARGET = ALPHA_URL


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


def start_scan(source: str, config: dict, secrets: dict) -> tuple[int, dict]:
    body = json.dumps({
        "project_id": PROJECT, "user_id": USER,
        "webapp_api_url": "http://webapp:3000",
        "source": source, "config": config, "common": {}, "secrets": secrets,
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(source: str, timeout: float = 600.0) -> dict:
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/{source}/status", headers=HEADERS)
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


def run_gitlab(config: dict) -> dict:
    try:
        os.remove(ARTIFACT)
    except OSError:
        pass
    code, resp = start_scan("gitlab", config, {SETTINGS_KEY: TOKEN})
    if code != 200:
        raise RuntimeError(f"gitlab start refused: HTTP {code} {resp.get('detail','')}")
    state = wait_settled("gitlab")
    # The ingest runs after the container exits; give it a moment to land.
    time.sleep(5)
    return state


def run_coexist_partner() -> tuple[bool, str]:
    """Scan a second source so the gitlab ingest has something to NOT wipe."""
    try:
        os.makedirs(COEXIST_DIR, exist_ok=True)
        with open(COEXIST_FILE, "w") as fh:
            fh.write(COEXIST_CONTENT)
        os.chmod(COEXIST_FILE, 0o644)   # the scan container runs as a non-root uid
    except OSError as e:
        return False, f"could not write the filesystem fixture: {e}"
    code, resp = start_scan(COEXIST_SOURCE, {}, {})
    if code != 200:
        return False, f"HTTP {code} {resp.get('detail','')}"
    state = wait_settled(COEXIST_SOURCE)
    time.sleep(5)
    return state.get("status") == "completed", f"status={state.get('status')!r}"


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
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p, source:'gitlab'}) "
        "RETURN ts", u=uid, p=pid)]
    out["assets"] = [dict(r["ta"]) | {"labels": r["labels"]} for r in s.run(
        "MATCH (ta {user_id:$u, project_id:$p, source:'gitlab'}) "
        "WHERE any(l IN labels(ta) WHERE l STARTS WITH 'Multiscanner') "
        "  AND NOT ta:MultiscannerScan AND NOT ta:MultiscannerFinding "
        "RETURN ta, labels(ta) AS labels", u=uid, p=pid)]
    out["findings"] = [dict(r["tf"]) for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p, source:'gitlab'}) "
        "RETURN tf", u=uid, p=pid)]
    out["domain_edges"] = s.run(
        "MATCH (d:Domain {user_id:$u, project_id:$p})-[:HAS_MULTISCANNER_SCAN]->"
        "(ts:MultiscannerScan {source:'gitlab'}) RETURN count(*) AS n",
        u=uid, p=pid).single()["n"]
    out["has_asset"] = [[r["scan"], r["asset"]] for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p, source:'gitlab'})"
        "-[:HAS_ASSET]->(ta) RETURN ts.id AS scan, ta.id AS asset", u=uid, p=pid)]
    out["has_finding"] = [[r["asset"], r["finding"]] for r in s.run(
        "MATCH (ta)-[:HAS_FINDING]->(tf:MultiscannerFinding "
        "{user_id:$u, project_id:$p, source:'gitlab'}) "
        "RETURN ta.id AS asset, tf.id AS finding", u=uid, p=pid)]
    out["orphan_findings"] = [r["id"] for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p, source:'gitlab'}) "
        "WHERE NOT ()-[:HAS_FINDING]->(tf) RETURN tf.id AS id", u=uid, p=pid)]
    # Tenant leak probe: a Multiscanner node that carries no tenant key. Written
    # as a scan of ALL Multiscanner nodes on purpose - the bug this guards is a
    # MERGE that dropped the key, and such a node would not come back from a
    # tenant-filtered query.
    out["untenanted"] = [r["id"] for r in s.run(
        "MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Multiscanner') "
        "AND (n.user_id IS NULL OR n.project_id IS NULL) RETURN n.id AS id")]
    # Every OTHER source's scan node, for the source-scoped-clear proof.
    out["other_scans"] = [[r["src"], r["n"]] for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p}) "
        "WHERE ts.source <> 'gitlab' "
        "OPTIONAL MATCH (ts)-[:HAS_ASSET]->()-[:HAS_FINDING]->(tf) "
        "RETURN ts.source AS src, count(tf) AS n", u=uid, p=pid)]
    out["other_detectors"] = [r["d"] for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p}) "
        "WHERE tf.source <> 'gitlab' RETURN DISTINCT tf.detector_name AS d",
        u=uid, p=pid)]
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
    return (f"gitlab:{f.get('asset') or ''}:{f.get('location') or ''}:"
            f"{f.get('line', 0)}:{f.get('detector_name', '')}")


def canonical(name: str) -> str:
    """`group/project` for an asset name, whatever shape it arrived in.

    Two spellings of one project MUST collapse to the same string here; that is
    what makes the duplicate-node check meaningful.
    """
    n = str(name or "").strip()
    if "://" in n:
        n = n.split("://", 1)[1]
        n = n.split("/", 1)[1] if "/" in n else ""
    if n.endswith(".git"):
        n = n[:-4]
    return n.strip("/")


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


def verify(art: dict, g: dict, rep: Report, expect_target: str,
           coexist_ok: bool, coexist_note: str) -> None:
    findings = [f for f in (art.get("findings") or []) if f.get("detector_name")]
    # The ingest deduplicates on (source, asset, location, line, detector); the
    # graph is compared against the deduplicated set, not the raw one, or a
    # legitimately collapsed pair reads as a missing node.
    by_key = {dedup_key(f): f for f in findings}
    art_assets = {f.get("asset") for f in findings if f.get("asset")}

    # -- the scan node -------------------------------------------------------
    scans = g["scans"]
    rep.check(len(scans) == 1, "exactly one MultiscannerScan for source=gitlab",
              f"found {len(scans)}: {[s.get('id') for s in scans]}")
    if not scans:
        return
    scan = scans[0]
    stats = art.get("statistics") or {}

    rep.check(scan.get("source") == "gitlab", "scan.source is 'gitlab'",
              f"got {scan.get('source')!r}")
    rep.check(scan.get("target") == art.get("target"),
              "scan.target matches the artifact",
              f"graph={scan.get('target')!r} artifact={art.get('target')!r}")
    # The exact string describe_target('gitlab', cfg) promises for THIS config.
    rep.check(scan.get("target") == expect_target,
              f"scan.target is exactly {expect_target!r}",
              f"got {scan.get('target')!r}")
    rep.check(scan.get("status") == art.get("status"),
              "scan.status matches the artifact",
              f"graph={scan.get('status')!r} artifact={art.get('status')!r}")
    rep.check(int(scan.get("total_findings", -1)) == int(stats.get("total_findings", -2)),
              "scan.total_findings matches the artifact statistics",
              f"graph={scan.get('total_findings')} artifact={stats.get('total_findings')}")
    rep.check(int(scan.get("assets_scanned", -1)) == int(stats.get("assets_scanned", -2)),
              "scan.assets_scanned matches the artifact statistics",
              f"graph={scan.get('assets_scanned')} artifact={stats.get('assets_scanned')}")
    rep.check(int(scan.get("validated_findings", -1)) == int(stats.get("validated", -2)),
              "scan.validated_findings matches the artifact statistics",
              f"graph={scan.get('validated_findings')} artifact={stats.get('validated')}")
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
    rep.check(bool(assets) and all("MultiscannerRepository" in a["labels"] for a in assets),
              "every gitlab asset is labelled MultiscannerRepository",
              f"labels={sorted({l for a in assets for l in a['labels']})}")
    rep.check(bool(assets) and all(a.get("asset_kind") == "repository" for a in assets),
              "every asset carries asset_kind='repository'",
              f"kinds={sorted({str(a.get('asset_kind')) for a in assets})}")
    rep.check(all(a.get("scan_id") == scan.get("id") for a in assets),
              "every asset points back at this scan via scan_id")

    # One project must be ONE node. `_META_SPECS['gitlab']` reads the asset from
    # ("repository", "link", "project") - three keys that need not agree in
    # shape. If two of a project's findings pick different keys, the ingest
    # faithfully creates two MultiscannerRepository nodes for it: the graph then
    # shows a duplicate, inflates assets_scanned, and splits one project's
    # findings across two assets, so "everything found in <project>" returns
    # half. This is the exact bug the github source had.
    groups: dict[str, set] = {}
    for a in assets:
        groups.setdefault(canonical(a.get("name")), set()).add(a.get("name"))
    split = {k: sorted(v) for k, v in groups.items() if len(v) > 1}
    rep.check(not split, "one node per project (no slug / clone-URL split)",
              "; ".join(f"{k} -> {v}" for k, v in split.items()))

    # A self-hosted endpoint must not be rewritten to gitlab.com. Asserted on
    # the host actually configured, so this stays honest on a self-hosted run.
    wrong_host = [a.get("name") for a in assets
                  if "://" in str(a.get("name") or "")
                  and HOST_NAME not in str(a.get("name"))]
    rep.check(not wrong_host,
              f"every asset name keeps the configured host ({HOST_NAME})",
              f"rewritten: {wrong_host[:4]}")

    rep.check(FIXTURE_PATHS <= {canonical(n) for n in graph_asset_names},
              "all three fixture projects reached the graph",
              f"graph={sorted(canonical(n) for n in graph_asset_names)} "
              f"expected>={sorted(FIXTURE_PATHS)}")

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
        graph_by_key[f"gitlab:{f.get('asset')}:{f.get('location')}:"
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
    rep.check(not TOKEN or not any(TOKEN in json.dumps(n, default=str)
                                   for n in (g["scans"] + g["assets"] + g["findings"])),
              "the token appears in no graph node")

    # -- the pre-clear is source-scoped -------------------------------------
    if coexist_ok:
        others = {src for src, _ in g["other_scans"]}
        rep.check(COEXIST_SOURCE in others,
                  f"the {COEXIST_SOURCE} scan node survived the gitlab ingest",
                  f"other sources in the graph: {sorted(others)}")
        rep.check(COEXIST_DETECTOR in set(g["other_detectors"]),
                  f"the {COEXIST_SOURCE} findings survived too "
                  f"({COEXIST_DETECTOR} is in no gitlab fixture)",
                  f"other sources' detectors: {sorted(set(g['other_detectors']))}")
    else:
        print(f"  SKIP  source-scoped-clear proof ({coexist_note})")


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    if not TOKEN:
        print("no GitLab token", file=sys.stderr)
        return 2
    if not GROUP_ID or not ALPHA_URL:
        print(f"no usable fixture manifest at {MANIFEST}; "
              f"run build_gitlab_fixtures.sh first", file=sys.stderr)
        return 2

    live = "--no-scan" not in sys.argv
    runs = 2 if "--twice" in sys.argv else 1

    # First, and only once: a second source's scan, so the gitlab ingest has
    # something it must NOT wipe.
    coexist_ok, coexist_note = False, "skipped (--no-scan)"
    if live:
        print(f"[coexist] running a {COEXIST_SOURCE} scan first ...")
        coexist_ok, coexist_note = run_coexist_partner()
        print(f"           {'ok' if coexist_ok else 'FAILED'}: {coexist_note}")

    ids_seen: list[tuple[set, set]] = []
    rc_total = 0

    for run in range(runs):
        if live:
            print(f"\n[run {run + 1}/{runs}] rich gitlab scan {RICH_CONFIG} ...")
            state = run_gitlab(RICH_CONFIG)
            print(f"           settled: status={state.get('status')!r} "
                  f"error={str(state.get('error') or '')[:100]}")

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
        verify(art, g, rep, RICH_TARGET, coexist_ok, coexist_note)
        rc = rep.render()
        rc_total |= rc
        ids_seen.append(({a["id"] for a in g["assets"]},
                         {f["id"] for f in g["findings"]}))
        if rc and runs == 1:
            return rc
        if rc:
            print("  (continuing to the id-stability run anyway)")

        # Between the two identical runs, a DIFFERENT config runs: it pins
        # describe_target's other branch, and it means the id-stability claim
        # survives an intervening scan rather than only a back-to-back repeat.
        if live and run == 0:
            print(f"\n[target] second config {REPOS_CONFIG} ...")
            run_gitlab(REPOS_CONFIG)
            art2 = _read(ARTIFACT)
            g2 = graph_state()
            rep2 = Report()
            scan2 = (g2["scans"] or [{}])[0]
            rep2.check(scan2.get("target") == REPOS_TARGET,
                       f"scan.target is exactly {REPOS_TARGET!r} for a repos config",
                       f"got {scan2.get('target')!r}")
            rep2.check(scan2.get("target") == art2.get("target"),
                       "scan.target still matches the artifact",
                       f"graph={scan2.get('target')!r} artifact={art2.get('target')!r}")
            rep2.check(len(g2["scans"]) == 1,
                       "still exactly one MultiscannerScan after a second config",
                       f"found {len(g2['scans'])}")
            rc_total |= rep2.render()

    if runs > 1:
        same_assets = ids_seen[0][0] == ids_seen[1][0]
        same_findings = ids_seen[0][1] == ids_seen[1][1]
        print("\nid stability across two identical runs "
              "(with a different config in between):")
        print(f"  {'PASS' if same_assets else 'FAIL'}  asset ids are stable")
        print(f"  {'PASS' if same_findings else 'FAIL'}  finding ids are stable")
        if not (same_assets and same_findings):
            print("  a moving id means the digest is process-dependent again, "
                  "which leaves orphans behind every re-scan")
            return 1
    return rc_total


if __name__ == "__main__":
    sys.exit(main())
