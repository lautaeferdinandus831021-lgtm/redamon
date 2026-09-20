#!/usr/bin/env python3
"""Verify what a `github_experimental` run actually wrote to the graph.

The parameter matrix proves the SCAN is right by reading the published artifact.
That file is the scan container's own output, though, and the graph is written by
a separate clean step in the orchestrator (`update_graph_from_trufflehog`). A
correct artifact and an empty, orphaned or mislabelled graph is a state the
matrix cannot see, and it is the graph that the /graph page and the Red Zone
table actually read.

Beyond the generic node/edge/tenancy contract this shares with the `github`
check, three things are specific to this source and are the reason the file
exists:

  run key       MultiscannerScan.id and run_id are keyed on the SOURCE. This
                source reports its findings under the `Github` METADATA key
                (SOURCE_META_KEYS['github_experimental'] == 'github'), so a
                run-key that followed the metadata instead of the source id
                would make the two GitHub sources overwrite each other's scan
                node - one operator's deleted-commit findings silently replaced
                by the other's.
  coexistence   `github` and `github_experimental` pointed at the SAME repo must
                leave two scan nodes standing, each with its own findings. Dedup
                is source-scoped (`{source}:{asset}:{location}:{line}:{detector}`)
                precisely so one secret found by two sources stays two findings.
  scoped clear  re-running this source must not reap the other's data.
                clear_trufflehog_data(..., source=...) is what guarantees it, and
                a regression there is invisible in the artifact.

Findings here have no live file path, so `location` may legitimately be empty.
That is asserted rather than tolerated: an empty location is fine, an empty
ASSET is not, because the ingest skips the HAS_FINDING edge without one and the
finding becomes an orphan the Red Zone still lists.

Run:  python3 testing/e2e/backend/trufflehog_github_experimental_graph_check.py
      python3 testing/e2e/backend/trufflehog_github_experimental_graph_check.py --twice
      python3 testing/e2e/backend/trufflehog_github_experimental_graph_check.py --no-scan
      ... --skip-coexist        (the generic half only; much faster)
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY,
      GHX_SCAN_TIMEOUT, GITHUB_FIXTURE_TOKEN (else _local/gh_fixture_token)
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
OUTPUT_DIR = os.path.join(REPO_ROOT, "scanners", "trufflehog_scan", "output")
MANIFEST = os.path.join(REPO_ROOT, "_local", "github_experimental_fixtures.json")

SOURCE = "github_experimental"
OTHER = "github"
SCAN_TIMEOUT = float(os.environ.get("GHX_SCAN_TIMEOUT", "2400"))
VALIDATION_STATUSES = {"validated", "unvalidated", "verify_error", "unverified"}

# Every property the ingest PROMISES on each node type. Checked for presence as
# a contract, separately from the value comparisons below: a property silently
# dropped from update_graph_from_trufflehog would still let every value-equality
# assertion pass (they only compare what is there), and the loss would surface
# much later as an empty column in a report.
SCAN_PROPS = (
    "id", "user_id", "project_id", "source", "source_label", "run_id", "target",
    "verification_enabled", "scan_start_time", "scan_end_time",
    "duration_seconds", "status", "total_findings", "verified_findings",
    "unverified_findings", "validated_findings", "assets_scanned",
    "repositories_scanned", "updated_at",
)
ASSET_PROPS = ("id", "name", "source", "asset_kind", "scan_id", "user_id",
               "project_id", "updated_at")
FINDING_PROPS = (
    "id", "user_id", "project_id", "source", "scan_id", "detector_name",
    "detector_description", "verified", "validation_status", "finding_kind",
    "redacted", "asset", "location", "repository", "file", "commit", "line",
    "link", "timestamp", "extra_data", "updated_at",
)


def artifact_path(source: str) -> str:
    return os.path.join(OUTPUT_DIR, f"trufflehog_{PROJECT}_{source}.json")


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
DANGLING = MF.get("dangling", "")
LIVE = MF.get("live", "")
DANGLING_SHA = MF.get("danglingSha", "")
TOKEN = _token()

# The rich scan. There is only one target field, so "rich" here means the repo
# that actually has a hidden object: it is the only configuration that produces
# an asset, a finding, a commit and a link all at once.
SCAN_CONFIG = {"repo": DANGLING}

# The coexistence repo, where BOTH sources are pointed. The live-tree fixture by
# default: the ordinary `github` source is guaranteed to find its Mailgun key
# there, which is what gives the "each with its own findings" half something to
# assert. Overridable, because whether object discovery ALSO reports a live tree
# is the binary's choice and is recorded, not assumed.
COEXIST_REPO = os.environ.get("GHX_COEXIST_REPO", LIVE)


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


def start_scan(source: str, config: dict) -> tuple[int, dict]:
    body = json.dumps({
        "project_id": PROJECT, "user_id": USER,
        "webapp_api_url": "http://webapp:3000",
        "source": source, "config": config, "common": {},
        "secrets": {"trufflehogGithubToken": TOKEN},
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(source: str, timeout: float = None) -> dict:
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/{source}/status", headers=HEADERS)
    deadline = time.time() + (SCAN_TIMEOUT if timeout is None else timeout)
    state: dict = {}
    while time.time() < deadline:
        time.sleep(5)
        try:
            state = json.loads(urllib.request.urlopen(req, timeout=20).read())
        except Exception:
            continue
        if state.get("status") not in ("running", "starting", "stopping"):
            return state
    return {**state, "timed_out": True}


def run_scan(source: str, config: dict, label: str) -> dict:
    print(f"  starting {label} ({source} -> {config.get('repo') or config.get('repos')}) ...")
    code, resp = start_scan(source, config)
    if code != 200:
        raise RuntimeError(f"start refused: HTTP {code} {resp.get('detail', '')}")
    state = wait_settled(source)
    print(f"  settled: status={state.get('status')!r} "
          f"timed_out={state.get('timed_out', False)} "
          f"error={str(state.get('error') or '')[:100]}")
    # The ingest runs after the container exits; give it a moment to land.
    time.sleep(6)
    return state


# ---------------------------------------------------------------------------
# Graph access. The agent image is the one place that already holds the Neo4j
# driver AND the credentials; the host has neither, and the scan container is
# denied both by design.
# ---------------------------------------------------------------------------

PROBE = r'''
import json, os, sys
from neo4j import GraphDatabase

uid, pid, src = sys.argv[1], sys.argv[2], sys.argv[3]
drv = GraphDatabase.driver(
    os.environ["NEO4J_URI"],
    auth=(os.environ.get("NEO4J_USER") or os.environ["NEO4J_USERNAME"],
          os.environ["NEO4J_PASSWORD"]))
out = {}
with drv.session() as s:
    out["scans"] = [dict(r["ts"]) for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p, source:$s}) "
        "RETURN ts", u=uid, p=pid, s=src)]
    out["assets"] = [dict(r["ta"]) | {"labels": r["labels"]} for r in s.run(
        "MATCH (ta {user_id:$u, project_id:$p, source:$s}) "
        "WHERE any(l IN labels(ta) WHERE l STARTS WITH 'Multiscanner') "
        "  AND NOT ta:MultiscannerScan AND NOT ta:MultiscannerFinding "
        "RETURN ta, labels(ta) AS labels", u=uid, p=pid, s=src)]
    out["findings"] = [dict(r["tf"]) for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p, source:$s}) "
        "RETURN tf", u=uid, p=pid, s=src)]
    out["domain_nodes"] = s.run(
        "MATCH (d:Domain {user_id:$u, project_id:$p}) RETURN count(d) AS n",
        u=uid, p=pid).single()["n"]
    out["domain_edges"] = s.run(
        "MATCH (d:Domain {user_id:$u, project_id:$p})-[:HAS_MULTISCANNER_SCAN]->"
        "(ts:MultiscannerScan {source:$s}) RETURN count(*) AS n",
        u=uid, p=pid, s=src).single()["n"]
    out["has_asset"] = [[r["scan"], r["asset"]] for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p, source:$s})"
        "-[:HAS_ASSET]->(ta) RETURN ts.id AS scan, ta.id AS asset",
        u=uid, p=pid, s=src)]
    out["has_finding"] = [[r["asset"], r["finding"]] for r in s.run(
        "MATCH (ta)-[:HAS_FINDING]->(tf:MultiscannerFinding "
        "{user_id:$u, project_id:$p, source:$s}) "
        "RETURN ta.id AS asset, tf.id AS finding", u=uid, p=pid, s=src)]
    out["orphan_findings"] = [r["id"] for r in s.run(
        "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p, source:$s}) "
        "WHERE NOT ()-[:HAS_FINDING]->(tf) RETURN tf.id AS id", u=uid, p=pid, s=src)]
    # Tenant leak probe: a Multiscanner node that carries no tenant key. Written
    # as a scan of ALL Multiscanner nodes on purpose - the bug this guards is a
    # MERGE that dropped the key, and such a node would not come back from a
    # tenant-filtered query.
    out["untenanted"] = [r["id"] for r in s.run(
        "MATCH (n) WHERE any(l IN labels(n) WHERE l STARTS WITH 'Multiscanner') "
        "AND (n.user_id IS NULL OR n.project_id IS NULL) RETURN n.id AS id")]
    # Every Multiscanner scan in the project, whatever its source: the
    # coexistence half needs to see the OTHER source's subgraph too.
    out["all_scans"] = [dict(r["ts"]) for r in s.run(
        "MATCH (ts:MultiscannerScan {user_id:$u, project_id:$p}) RETURN ts",
        u=uid, p=pid)]
    out["all_findings"] = [
        {"id": r["id"], "source": r["source"], "asset": r["asset"],
         "detector_name": r["det"], "location": r["loc"], "line": r["line"]}
        for r in s.run(
            "MATCH (tf:MultiscannerFinding {user_id:$u, project_id:$p}) "
            "RETURN tf.id AS id, tf.source AS source, tf.asset AS asset, "
            "tf.detector_name AS det, tf.location AS loc, tf.line AS line",
            u=uid, p=pid)]
# default=str: every node carries an `updated_at` the driver returns as a
# neo4j DateTime, which json cannot encode.
print(json.dumps(out, default=str))
'''


def graph_state(source: str = SOURCE) -> dict:
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "agent", "python", "-",
         USER, PROJECT, source],
        cwd=REPO_ROOT, input=PROBE, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"graph probe failed: {out.stderr[-500:]}")
    return json.loads(out.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def dedup_key(f: dict, source: str = SOURCE) -> str:
    return (f"{source}:{f.get('asset') or ''}:{f.get('location') or ''}:"
            f"{f.get('line', 0)}:{f.get('detector_name', '')}")


class Report:
    def __init__(self):
        self.rows: list[tuple[bool, str, str]] = []
        self.notes: list[str] = []

    def check(self, ok: bool, name: str, detail: str = "") -> None:
        self.rows.append((bool(ok), name, detail))

    def unproven(self, name: str, why: str) -> None:
        """Not a pass and not a failure: something the fixture could not put in
        a position to be observed. Printed loudly so it is never read as green."""
        self.notes.append(f"{name}: {why}")

    def failed(self) -> list:
        return [r for r in self.rows if not r[0]]

    def render(self) -> int:
        for ok, name, detail in self.rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
            if detail:
                print(f"        {detail}")
        for note in self.notes:
            print(f"  UNPROVEN  {note}")
        bad = self.failed()
        print(f"\n{len(self.rows) - len(bad)}/{len(self.rows)} graph checks passed"
              + (f", {len(self.notes)} unproven" if self.notes else ""))
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
    rep.check(len(scans) == 1, f"exactly one MultiscannerScan for source={SOURCE}",
              f"found {len(scans)}: {[s.get('id') for s in scans]}")
    if not scans:
        return
    scan = scans[0]
    stats = art.get("statistics") or {}

    rep.check(scan.get("source") == SOURCE, f"scan.source is {SOURCE!r}",
              f"got {scan.get('source')!r}")
    # The run key follows the SOURCE, not the metadata key this source reports
    # under. If it followed the metadata, both GitHub sources would key on
    # 'github' and the second run would overwrite the first's scan node.
    rep.check(scan.get("run_id") == SOURCE,
              f"scan.run_id is {SOURCE!r}, not {OTHER!r}",
              f"got {scan.get('run_id')!r}")
    rep.check(SOURCE in str(scan.get("id") or ""),
              "scan.id is keyed on the source id",
              f"got {scan.get('id')!r}")
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
    rep.check(int(scan.get("validated_findings", -1)) == int(stats.get("validated", -2)),
              "scan.validated_findings matches the artifact statistics",
              f"graph={scan.get('validated_findings')} artifact={stats.get('validated')}")
    rep.check(scan.get("verification_enabled") is not None,
              "scan.verification_enabled is recorded",
              f"got {scan.get('verification_enabled')!r}")
    for key in ("scan_start_time", "scan_end_time", "source_label"):
        rep.check(bool(str(scan.get(key) or "")), f"scan.{key} is populated",
                  f"got {scan.get(key)!r}")
    missing_scan_props = [k for k in SCAN_PROPS if k not in scan]
    rep.check(not missing_scan_props,
              "the scan node carries every documented property",
              f"absent: {missing_scan_props}")
    # The deprecated alias must track its replacement or a report reading the old
    # name silently diverges from one reading the new.
    rep.check(scan.get("repositories_scanned") == scan.get("assets_scanned"),
              "repositories_scanned still mirrors assets_scanned",
              f"{scan.get('repositories_scanned')} vs {scan.get('assets_scanned')}")

    # A project with no Domain node cannot have the edge, and that is a property
    # of the project rather than of the ingest - so it is reported, not failed.
    if g.get("domain_nodes", 1):
        rep.check(g["domain_edges"] >= 1,
                  "(Domain)-[:HAS_MULTISCANNER_SCAN]->(scan) exists",
                  f"{g['domain_edges']} edges")
    else:
        rep.unproven("(Domain)-[:HAS_MULTISCANNER_SCAN]->(scan)",
                     "the project has no Domain node, so the ingest correctly "
                     "skipped the link; run a recon scan first to cover it")

    # -- assets --------------------------------------------------------------
    assets = g["assets"]
    graph_asset_names = {a.get("name") for a in assets}
    rep.check(graph_asset_names == art_assets,
              "one asset node per artifact asset, no more and no fewer",
              f"graph={sorted(x or '' for x in graph_asset_names)} "
              f"artifact={sorted(x or '' for x in art_assets)}")
    rep.check(assets and all("MultiscannerRepository" in a["labels"] for a in assets),
              "every asset is labelled MultiscannerRepository",
              f"labels={sorted({l for a in assets for l in a['labels']})}")
    rep.check(assets and all(a.get("asset_kind") == "repository" for a in assets),
              "every asset carries asset_kind='repository'",
              f"kinds={sorted({str(a.get('asset_kind')) for a in assets})}")
    rep.check(all(a.get("scan_id") == scan.get("id") for a in assets),
              "every asset points back at this scan via scan_id")
    missing_asset_props = sorted({k for a in assets for k in ASSET_PROPS if k not in a})
    rep.check(not missing_asset_props,
              "every asset node carries the documented properties",
              f"absent: {missing_asset_props}")

    # One repository must be ONE node. TruffleHog reports `repository` as a clone
    # URL for a file finding and as a bare `owner/repo` slug elsewhere, and both
    # pass through verbatim - so the same repository can arrive under two
    # identities and the ingest faithfully builds two nodes for it.
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
    empty_asset = []
    for f in gf:
        if not f.get("detector_name"):
            empty_detector.append(f.get("id"))
        if f.get("validation_status") not in VALIDATION_STATUSES:
            wrong_status.append(f"{f.get('id')}={f.get('validation_status')!r}")
        # `location` is deliberately NOT in this list: a deleted-commit finding
        # has no live file path and an empty location is correct here.
        for prop in ("user_id", "project_id", "source", "scan_id", "detector_name",
                     "asset", "validation_status", "finding_kind"):
            if f.get(prop) in (None, ""):
                missing_props.append(f"{f.get('id')}.{prop}")
        if not str(f.get("asset") or ""):
            empty_asset.append(f.get("id"))
        # The graph value must EQUAL the artifact's, not merely exist: the
        # deprecated aliases are written from the same source values and a
        # divergence there is a silent reporting bug.
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
    missing_finding_props = sorted({k for f in gf for k in FINDING_PROPS if k not in f})
    rep.check(not missing_finding_props,
              "every finding node carries the documented properties",
              f"absent: {missing_finding_props}")
    # The one that matters for this source: an empty location is fine, an empty
    # asset is not - the ingest skips the HAS_FINDING edge without one and the
    # finding becomes an orphan the Red Zone still lists.
    rep.check(not empty_asset,
              "no finding has an empty asset (the HAS_FINDING edge depends on it)",
              f"{len(empty_asset)} with none: {empty_asset[:3]}")

    no_location = [f for f in gf if not str(f.get("location") or "")]
    rep.check(all(str(f.get("commit") or "") for f in gf),
              "every finding carries a commit",
              f"{sum(1 for f in gf if not f.get('commit'))} without one")
    rep.check(all(str(f.get("link") or "") for f in gf),
              "every finding carries a link",
              f"{sum(1 for f in gf if not f.get('link'))} without one")
    print(f"        note: {len(no_location)}/{len(gf)} findings have an empty "
          f"`location` (expected: a deleted commit has no live file path)")

    if DANGLING_SHA:
        commits = {str(f.get("commit") or "") for f in gf}
        hit = [c for c in commits if c and (DANGLING_SHA.startswith(c) or c.startswith(DANGLING_SHA))]
        rep.check(bool(hit),
                  "a graph finding carries the force-pushed commit",
                  f"want {DANGLING_SHA[:12]}, graph commits={sorted(commits)}")

    # Value-level equality against the artifact, on the fields a report renders.
    art_by_key = {dedup_key(f): f for f in findings}
    graph_by_key = {dedup_key(f): f for f in gf}
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


def verify_coexistence(g: dict, rep: Report, before: dict | None) -> None:
    """Both GitHub sources, same repository, both still standing.

    `before` is the graph as it looked after the OTHER source ran and before this
    source's second run, so the scoped-clear assertion compares like with like.
    None means no such snapshot exists (--no-scan), in which case that one
    assertion is reported unproven instead of passing on identical inputs.
    """
    scans = {s.get("source"): s for s in g["all_scans"]}
    rep.check(SOURCE in scans and OTHER in scans,
              "both GitHub scan nodes coexist in one project",
              f"sources present: {sorted(scans)}")
    if SOURCE not in scans or OTHER not in scans:
        return
    rep.check(scans[SOURCE].get("id") != scans[OTHER].get("id"),
              "the two scan nodes have distinct ids",
              f"{scans[SOURCE].get('id')} vs {scans[OTHER].get('id')}")
    rep.check(scans[SOURCE].get("run_id") != scans[OTHER].get("run_id"),
              "the two scan nodes have distinct run_ids",
              f"{scans[SOURCE].get('run_id')!r} vs {scans[OTHER].get('run_id')!r}")

    by_source: dict[str, list] = {}
    for f in g["all_findings"]:
        by_source.setdefault(f.get("source"), []).append(f)
    mine, theirs = by_source.get(SOURCE, []), by_source.get(OTHER, [])

    # The scoped clear is the assertion that matters: this source ran LAST, and
    # the other source's findings must be exactly where they were. Skipped, not
    # faked, when there is no genuine "before" to compare against.
    if before is not None:
        was = {f["id"] for f in before.get("all_findings", [])
               if f.get("source") == OTHER}
        now = {f["id"] for f in theirs}
        rep.check(bool(was) and was == now,
                  f"re-running {SOURCE} left every {OTHER} finding intact",
                  f"before={len(was)} after={len(now)} lost={sorted(was - now)[:3]}")

    shared = ({f["asset"] for f in mine if f.get("asset")}
              & {f["asset"] for f in theirs if f.get("asset")})
    if mine and theirs and shared:
        pairs = 0
        for a in shared:
            m = {(f["detector_name"], f["location"], f["line"]) for f in mine
                 if f["asset"] == a}
            t = {(f["detector_name"], f["location"], f["line"]) for f in theirs
                 if f["asset"] == a}
            pairs += len(m & t)
        rep.check(pairs > 0,
                  "the same secret found by both sources is TWO findings, "
                  "not one (dedup is source-scoped)",
                  f"{pairs} identical (detector, location, line) pairs on "
                  f"{sorted(shared)}")
    else:
        rep.unproven(
            "one secret found by BOTH sources stays two findings",
            f"the fixture never put one secret in both sources' reach: "
            f"{SOURCE} reported {len(mine)} findings, {OTHER} reported "
            f"{len(theirs)}, shared assets={sorted(shared)}. The scan nodes and "
            f"the scoped clear are still proven above; only the shared-finding "
            f"half of the dedup contract is not. Point GHX_COEXIST_REPO at a "
            f"repo where both sources find something to close it.")


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    if not TOKEN:
        print("no GitHub token", file=sys.stderr)
        return 2
    if not OWNER or not DANGLING:
        print(f"no fixture manifest at {MANIFEST}; run "
              "build_github_experimental_fixtures.sh first", file=sys.stderr)
        return 2

    no_scan = "--no-scan" in sys.argv
    runs = 2 if "--twice" in sys.argv else 1
    if no_scan and runs > 1:
        # Same trap as the scoped-clear check: with no scan in between, both
        # "runs" read one unchanged graph, the ids are identical by
        # construction, and the assertion passes without being able to fail.
        # The bug it exists to catch is a PROCESS-dependent id, which only a
        # second ingest can expose.
        print("--twice needs real re-runs: with --no-scan both passes read the "
              "same graph and id stability would pass trivially. Refusing.",
              file=sys.stderr)
        return 2
    ids_seen: list[tuple[set, set]] = []
    rc = 0

    for run in range(runs):
        if not no_scan:
            print(f"[run {run + 1}/{runs}] the rich scan")
            run_scan(SOURCE, SCAN_CONFIG, "github_experimental on the dangling repo")

        art = _read(artifact_path(SOURCE))
        if not art:
            print(f"no artifact at {artifact_path(SOURCE)}", file=sys.stderr)
            return 2
        g = graph_state(SOURCE)
        print(f"\n[run {run + 1}] artifact: {len(art.get('findings') or [])} findings, "
              f"status={art.get('status')!r}")
        print(f"[run {run + 1}] graph: {len(g['scans'])} scan, {len(g['assets'])} assets, "
              f"{len(g['findings'])} findings\n")

        rep = Report()
        verify(art, g, rep)
        rc = rep.render()
        ids_seen.append(({a["id"] for a in g["assets"]},
                         {f["id"] for f in g["findings"]}))
        if rc:
            print("  (continuing; the remaining phases still report)")

    if runs > 1:
        same_assets = ids_seen[0][0] == ids_seen[1][0]
        same_findings = ids_seen[0][1] == ids_seen[1][1]
        print("\nid stability across two identical runs:")
        print(f"  {'PASS' if same_assets else 'FAIL'}  asset ids are stable")
        print(f"  {'PASS' if same_findings else 'FAIL'}  finding ids are stable")
        if not (same_assets and same_findings):
            print("  a moving id means the digest is process-dependent again, "
                  "which leaves orphans behind every re-scan")
            rc = 1

    if "--skip-coexist" not in sys.argv:
        print(f"\n=== coexistence: both GitHub sources on {COEXIST_REPO} ===")
        crep = Report()
        if no_scan:
            # --no-scan cannot prove the scoped clear: with no run in between,
            # "before" and "after" are the same snapshot and the assertion would
            # be trivially true. A pass that cannot fail is worse than no pass.
            crep.unproven(
                "re-running this source leaves the other's findings intact",
                "--no-scan takes one snapshot, so before == after and the "
                "comparison could not detect a blanket clear. Re-run without "
                "--no-scan to prove it.")
            verify_coexistence(graph_state(SOURCE), crep, before=None)
        else:
            run_scan(OTHER, {"repos": [COEXIST_REPO]}, "github on the shared repo")
            before = graph_state(SOURCE)
            run_scan(SOURCE, {"repo": COEXIST_REPO}, "github_experimental on the same repo")
            verify_coexistence(graph_state(SOURCE), crep, before)
        rc = crep.render() or rc

    return rc


if __name__ == "__main__":
    sys.exit(main())
