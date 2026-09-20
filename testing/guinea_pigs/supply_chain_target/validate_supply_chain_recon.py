"""End-to-end validation of EVERY L2 (Supply-Chain recon) feature.

Runs AFTER a real recon scan of the guinea pig and diffs the resulting Neo4j
state against expected_results.yaml. No mocks: it asserts on what the real
pipeline actually wrote.

Prerequisites:
  1. Target up:   cd guinea_pigs/supply_chain_target && docker compose up -d --build
  2. Project configured with jsReconEnabled + supplyChainReconEnabled = true,
     target http://192.88.99.10
  3. Full recon scan (or the SupplyChainRecon partial tool) completed

Run:
    ./guinea_pigs/supply_chain_target/run_validation.sh <USER_ID> <PROJECT_ID>

Add --deep to REQUIRE the GuardDog deep-analysis assertions (only meaningful
when the scan ran with supplyChainReconDeepAnalysisEnabled). Without it, the
deep-analysis block is asserted if suspicious findings exist and skipped with a
note if they do not, so a default run is not penalised for an opt-in feature.

Exit 0 == every L2 feature proven.
"""

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import yaml  # noqa: E402
from neo4j import GraphDatabase  # noqa: E402

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

_results = []


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    print("  %-4s %s%s" % ("PASS" if cond else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    return bool(cond)


# Sources that mean "the live target actually served this". Anything else
# (osv/sbom/lockfile/dir) came from a file an operator uploaded and has no
# BaseURL to hang off. Mirrors _SOURCE_RANK in graph_db/mixins/supply_chain_mixin.py.
_LIVE_TARGET_SOURCES = {"retirejs", "wappalyzer", "sourcemap", "import"}


class Graph:
    def __init__(self, uid, pid):
        self.uid, self.pid = uid, pid
        self.drv = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    def close(self):
        self.drv.close()

    def q(self, cypher, **kw):
        with self.drv.session() as s:
            return [r.data() for r in s.run(cypher, uid=self.uid, pid=self.pid, **kw)]

    def packages(self):
        rows = self.q("MATCH (p:Package {user_id:$uid, project_id:$pid}) "
                      "RETURN p.purl AS purl, p.name AS name, p.version AS version, "
                      "p.source AS source, p.ecosystem AS ecosystem, "
                      "p.first_seen AS first_seen, p.last_seen AS last_seen")
        return {r["purl"]: r for r in rows}

    def findings(self):
        return self.q(
            "MATCH (p:Package {user_id:$uid, project_id:$pid})-[:FLAGGED_AS]->"
            "(f:MalPackageFinding {user_id:$uid, project_id:$pid}) "
            "RETURN p.purl AS purl, f.finding_id AS finding_id, f.verdict AS verdict, "
            "f.advisory_id AS advisory_id, f.source_tool AS source_tool, "
            "f.severity AS severity, f.title AS title")

    def vulnerabilities(self):
        """CVE/GHSA verdicts. These are Vulnerability nodes, NOT
        MalPackageFinding - the two verdict classes are kept apart on purpose,
        so that "malicious" keeps meaning a MAL- advisory and nothing else."""
        return self.q(
            "MATCH (p:Package {user_id:$uid, project_id:$pid})-[:HAS_VULNERABILITY]->"
            "(v:Vulnerability {user_id:$uid, project_id:$pid}) "
            "RETURN p.purl AS purl, v.id AS id, v.severity AS severity, "
            "v.source AS source, v.cvss_metrics AS cvss")

    def orphan_findings(self):
        return self.q(
            "MATCH (f:MalPackageFinding {user_id:$uid, project_id:$pid}) "
            "WHERE NOT ( ()-[:FLAGGED_AS]->(f) ) RETURN f.finding_id AS finding_id")

    def anchored_purls(self, base_url):
        rows = self.q(
            "MATCH (b:BaseURL {url:$burl, user_id:$uid, project_id:$pid})"
            "-[:DEPENDS_ON]->(p:Package) RETURN p.purl AS purl", burl=base_url)
        return {r["purl"] for r in rows}

    def base_url_exists(self, base_url):
        rows = self.q("MATCH (b:BaseURL {url:$burl, user_id:$uid, project_id:$pid}) "
                      "RETURN count(b) AS c", burl=base_url)
        return bool(rows and rows[0]["c"])


def main():
    argv = [a for a in sys.argv[1:] if a != "--deep"]
    deep_required = "--deep" in sys.argv
    if len(argv) < 2:
        print(__doc__)
        print("usage: validate_supply_chain_recon.py <USER_ID> <PROJECT_ID> [--deep]")
        return 2
    uid, pid = argv[0], argv[1]

    exp = yaml.safe_load((HERE / "expected_results.yaml").read_text())
    base_url = exp["target"]["base_url_node"]

    g = Graph(uid, pid)
    try:
        pkgs = g.packages()
        finds = g.findings()

        print("\n=== L2 SUPPLY-CHAIN RECON VALIDATION ===")
        print("user=%s project=%s  packages=%d findings=%d\n" % (uid, pid, len(pkgs), len(finds)))

        # Guard: on an empty graph every negative control ("this purl must be
        # absent") passes vacuously, so a project that was never scanned would
        # report a healthy-looking partial score. Refuse to run instead.
        if not pkgs:
            print("ABORT: no Package nodes for this user/project.\n")
            print("  The negative controls would all pass vacuously, so this run")
            print("  would prove nothing. Check that:")
            print("    - the recon scan actually completed for THIS project id")
            print("    - jsReconEnabled = true AND supplyChainReconEnabled = true")
            print("    - the target was http://192.88.99.10 and it was reachable")
            print("    - the offline OSV DB is populated "
                  "(./whitehat.sh supply-chain-sync npm)")
            return 1

        # -- Path A: technologies -> purl -------------------------------------
        print("[Path A] technologies -> purl (the only version-bearing source)")
        for e in exp["packages_from_technologies"]:
            purl = e["purl"]
            row = pkgs.get(purl)
            if not check("tech package %s" % purl, row is not None):
                continue
            check("  source=wappalyzer for %s" % purl,
                  row["source"] == e["source"], "got %r" % row["source"])
            # The version is what actually drives the OSV match, so assert it
            # rather than trusting that it is embedded in the purl string.
            check("  version=%r for %s" % (e["version"], purl),
                  row["version"] == e["version"], "got %r" % row["version"])

        print("\n[Path A] non-alias technologies must NOT become packages")
        # Exact match on Package.name, not a substring sweep over purls: a
        # substring test would pass vacuously (and could false-fail the day a
        # real package name happens to contain "php" or "node.js").
        names = {(r["name"] or "").lower() for r in pkgs.values()}
        for tech in exp["technologies_detected_but_dropped"]:
            display = tech.split(":")[0]
            check("dropped non-alias %s" % tech, display.lower() not in names,
                  "a Package named %r exists" % display)

        # -- Path B: source-map mining ----------------------------------------
        print("\n[Path B] source-map mining")
        for e in exp["packages_from_sourcemaps"]:
            purl = e["purl"]
            row = pkgs.get(purl)
            if not check("sourcemap package %s" % purl, row is not None):
                continue
            check("  source=sourcemap for %s" % purl,
                  row["source"] == e["source"], "got %r" % row["source"])
            check("  no version for %s" % purl, not row["version"],
                  "source maps never carry versions")

        fp = exp["filler_packages"]
        fillers = [p for p in pkgs if p.startswith(fp["prefix"])]
        check("filler packages == %d (source_files[:100] cap)" % fp["count"],
              len(fillers) == fp["count"], "got %d" % len(fillers))

        # -- Path C: retire.js -------------------------------------------------
        print("\n[Path C] retire.js (name AND version, out of the served bytes)")
        vulns_by_purl = {}
        for v in g.vulnerabilities():
            vulns_by_purl.setdefault(v["purl"], set()).add(v["id"])
        for e in exp.get("packages_from_retirejs") or []:
            purl = e["purl"]
            row = pkgs.get(purl)
            if not check("retire.js package %s" % purl, row is not None,
                         "served at %s" % e["served_at"]):
                continue
            check("  source=retirejs for %s" % purl,
                  row["source"] == e["source"], "got %r" % row["source"])
            # The version is the entire point of this path - a name alone is
            # unverdictable, which is what the other two sources give us.
            check("  version=%r for %s" % (e["version"], purl),
                  row["version"] == e["version"], "got %r" % row["version"])
            got = len(vulns_by_purl.get(purl, ()))
            check("  %d CVE/GHSA advisories for %s" % (e["vulnerable_count"], purl),
                  got == e["vulnerable_count"], "got %d" % got)

        # -- Negative controls -------------------------------------------------
        print("\n[Negative controls] these must NOT exist")
        for e in exp["must_not_exist"]:
            why = e["why"].strip().splitlines()[0]
            check("absent purl %s" % e["purl"], e["purl"] not in pkgs, why)
            # A purl-only check is not enough for the hostile names: if
            # sanitize_name were loosened, build_purl would percent-encode the
            # survivor and the purl would no longer match. Assert the raw name.
            if e.get("name") is not None:
                check("absent name %r" % e["name"],
                      e["name"].lower() not in names, why)

        # -- Verdicts ----------------------------------------------------------
        print("\n[Verdicts]")
        mf = exp["graph"]["malicious_finding"]
        mal = [f for f in finds if f["verdict"] == "malicious"]
        check("exactly %d malicious finding" % exp["totals"]["malicious_findings"],
              len(mal) == exp["totals"]["malicious_findings"], "got %d" % len(mal))
        if mal:
            f = mal[0]
            check("advisory is %s" % mf["advisory_id"],
                  f["advisory_id"] == mf["advisory_id"], "got %r" % f["advisory_id"])
            check("source_tool is osv", f["source_tool"] == mf["source_tool"])
            check("FLAGGED_AS attaches to %s" % mf["attached_to_purl"],
                  f["purl"] == mf["attached_to_purl"], "got %r" % f["purl"])

        # The two verdict classes must stay apart. A CVE/GHSA is NOT a malicious
        # package - it is a known-vulnerable one - so it must never appear as a
        # MalPackageFinding, or "malicious" stops meaning "a MAL- advisory".
        ghsa_nodes = [f for f in finds if (f["advisory_id"] or "").startswith(("GHSA-", "CVE-"))]
        check("no CVE/GHSA masquerading as a MalPackageFinding",
              not ghsa_nodes, "got %d" % len(ghsa_nodes))

        # ...they land on Vulnerability instead, linked by HAS_VULNERABILITY.
        vulns = g.vulnerabilities()
        vuln_ids = {v["id"] for v in vulns}
        check("CVE/GHSA become Vulnerability nodes (>= %d)"
              % exp["totals"]["vulnerability_nodes_min"],
              len(vuln_ids) >= exp["totals"]["vulnerability_nodes_min"],
              "got %d distinct advisories over %d edges" % (len(vuln_ids), len(vulns)))
        check("every Vulnerability carries source=osv",
              all(v["source"] == "osv" for v in vulns),
              "sources: %s" % sorted({v["source"] for v in vulns}))
        # An unknown severity means _vuln_severity fell through, which is how a
        # critical advisory quietly renders as low-priority in the UI.
        bad_sev = [v["id"] for v in vulns
                   if v["severity"] not in ("critical", "high", "medium",
                                            "low", "info")]
        check("every Vulnerability has a real severity", not bad_sev,
              "unranked: %s" % bad_sev[:5])

        check("no orphaned MalPackageFinding", not g.orphan_findings())

        # -- Deep behavioural analysis (GuardDog) ------------------------------
        dexp = exp["graph"]["deep_analysis"]
        susp = [f for f in finds if f["verdict"] == "suspicious"]
        if not deep_required and not susp:
            print("\n[Deep analysis] skipped -- no suspicious findings present.")
            print("       Enable supplyChainReconDeepAnalysisEnabled and re-run")
            print("       with --deep to assert the GuardDog path.")
        else:
            print("\n[Deep analysis] GuardDog")
            check("suspicious findings present", bool(susp),
                  "%d found" % len(susp))
            check("suspicious >= %d" % dexp["min_suspicious_findings"],
                  len(susp) >= dexp["min_suspicious_findings"],
                  "got %d" % len(susp))
            scanned = {f["purl"] for f in susp}
            check("deep analysis covered %d packages" % dexp["scanned_packages"],
                  len(scanned) == dexp["scanned_packages"],
                  "got %d: %s" % (len(scanned), sorted(scanned)))
            # The HIGH tier only exists through severity_for_rule's
            # "steganography" marker; without a case for it the mapping is
            # only ever proven for low and medium.
            tiers = {f["severity"] for f in susp}
            check("all three severity tiers present",
                  {"low", "medium", "high"} <= tiers, "got %s" % sorted(tiers))
            check("all suspicious carry source_tool=guarddog",
                  all(f["source_tool"] == dexp["source_tool"] for f in susp),
                  "got %s" % sorted({f["source_tool"] for f in susp}))

            by_purl = {}
            for f in susp:
                by_purl.setdefault(f["purl"], {})[f["advisory_id"]] = f
            for entry in dexp["findings"]:
                got = by_purl.get(entry["purl"], {})
                for r in entry["rules"]:
                    f = got.get(r["rule"])
                    if not check("%s -> %s" % (entry["purl"], r["rule"]),
                                 f is not None):
                        continue
                    check("  severity=%s" % r["severity"],
                          f["severity"] == r["severity"],
                          "got %r" % f["severity"])

            # A GuardDog hit is NEVER a terminal malicious verdict.
            check("no GuardDog finding claims verdict=malicious",
                  not [f for f in finds
                       if f["source_tool"] == "guarddog" and f["verdict"] == "malicious"])

            # The purl fix: findings must land on the versioned Package.
            for purl in dexp["no_versionless_duplicates"]:
                check("no versionless duplicate %s" % purl, purl not in pkgs,
                      "add_guarddog_findings must pass a purl")

        # -- Graph shape -------------------------------------------------------
        print("\n[Graph shape]")
        dep = exp["graph"]["depends_on"]
        # Every BaseURL the scan produced must anchor the full package set:
        # update_graph_from_supply_chain_recon loops over base_urls and MERGEs
        # DEPENDS_ON from each, so a second surface is not decoration - it is
        # the only way that loop is exercised at all.
        for burl in [base_url] + list(dep.get("also_anchored_from") or []):
            if not check("BaseURL node %s exists" % burl, g.base_url_exists(burl)):
                continue
            anchored = g.anchored_purls(burl)
            check("  DEPENDS_ON edges from %s" % burl, len(anchored) > 0,
                  "%d anchored" % len(anchored))
            if dep["expect_all_packages_anchored"]:
                # Only packages the LIVE TARGET served must be anchored. A
                # package that arrived via an L1 upload (an SBOM or lockfile
                # someone supplied) has no BaseURL parent and floats by
                # design - see the mixin docstring. L1 and L2 dedup into one
                # node set per project, so once both have run this check must
                # look at provenance rather than assume every node came from
                # the crawl.
                live = {purl for purl, row in pkgs.items()
                        if row.get("source") in _LIVE_TARGET_SOURCES}
                missing = live - anchored
                check("  every live-target Package anchored to %s" % burl,
                      not missing,
                      "%d unanchored: %s" % (len(missing), sorted(missing)[:3]))

        check("total packages >= %d" % exp["totals"]["packages_min"],
              len(pkgs) >= exp["totals"]["packages_min"], "got %d" % len(pkgs))

        # -- MERGE semantics ---------------------------------------------------
        print("\n[MERGE semantics] (meaningful only after a SECOND scan)")
        dupes = g.q("MATCH (p:Package {user_id:$uid, project_id:$pid}) "
                    "WITH p.purl AS purl, count(*) AS c WHERE c > 1 "
                    "RETURN purl, c")
        check("no duplicate Package per purl", not dupes,
              "dupes: %s" % dupes[:3])
        moved = g.q("MATCH (p:Package {user_id:$uid, project_id:$pid}) "
                    "WHERE p.last_seen > p.first_seen RETURN count(p) AS c")
        print("       (packages enriched by a re-scan: %d)"
              % (moved[0]["c"] if moved else 0))

        # -- Tenant isolation --------------------------------------------------
        # A query against a project_id that never existed is vacuously empty and
        # proves nothing. What IS falsifiable: if the writer ever dropped the
        # tenant keys from a MERGE, nodes would appear without them, and the
        # same purl would be shared across projects instead of duplicated.
        print("\n[Tenant isolation] (S10)")
        untagged = g.q(
            "MATCH (p:Package) WHERE p.user_id IS NULL OR p.project_id IS NULL "
            "RETURN count(p) AS c")
        check("no Package lacks user_id/project_id",
              untagged and untagged[0]["c"] == 0,
              "found %d untagged" % (untagged[0]["c"] if untagged else -1))

        untagged_f = g.q(
            "MATCH (f:MalPackageFinding) "
            "WHERE f.user_id IS NULL OR f.project_id IS NULL RETURN count(f) AS c")
        check("no MalPackageFinding lacks user_id/project_id",
              untagged_f and untagged_f[0]["c"] == 0,
              "found %d untagged" % (untagged_f[0]["c"] if untagged_f else -1))

        # Cross-tenant leakage: our purls must not be reachable under a
        # different tenant. Only meaningful once a second project has scanned
        # the same target; reported either way so it is never a silent pass.
        leaked = g.q(
            "MATCH (p:Package) WHERE p.purl IN $purls AND "
            "(p.user_id <> $uid OR p.project_id <> $pid) "
            "RETURN p.user_id AS user_id, p.project_id AS project_id, "
            "count(*) AS c", purls=list(pkgs))
        if leaked:
            print("       (same purls also present under: %s -- expected only if "
                  "another project scanned this target)"
                  % [(r["user_id"], r["project_id"], r["c"]) for r in leaked])
        else:
            print("       (no other tenant holds these purls; run a second "
                  "project against the same target for a positive isolation proof)")

    finally:
        g.close()

    passed = sum(1 for _, ok, _ in _results if ok)
    total = len(_results)
    print("\n%s  %d/%d checks passed" % ("OK" if passed == total else "FAILED", passed, total))
    if passed != total:
        print("\nfailures:")
        for name, ok, detail in _results:
            if not ok:
                print("  - %s %s" % (name, ("(%s)" % detail) if detail else ""))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
