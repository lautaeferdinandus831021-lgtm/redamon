"""Strategy rows 2, 3, 4 (L4, real Neo4j): the MCP analytics Cypher, executed.

The TypeScript tests for these tools assert the query TEXT. They cannot prove
Neo4j agrees, and the difference is not academic: the stale-exploit predicate
sat in the wrong CLAUSE for a whole release while a test asserting it was
PRESENT passed. A `WITH ... WHERE` drops the row, and the row carries the CVE,
so every CVE whose only exploit record had been superseded vanished from two
security rankings - with a 200, a rendered view and no error anywhere.

So each query is run here against a real database holding a deliberately awkward
tenant: a fresh exploit, a superseded one, a suppressed one, and findings in
every state the census claims to exclude.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network whitehat-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://whitehat-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    whitehat-agent python -m unittest tests.test_mcp_analytics_graph_live -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown,
so it is safe against a populated database.
"""
import importlib.util
import os
import sys
import unittest
import uuid
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# The queries live in TypeScript; row 1 owns extracting them, and this reuses it
# so the two rows can never drift onto different text.
from tests.test_mcp_cypher_scoping import _queries  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "tenant_filter", Path(_REPO) / "graph_db/tenant_filter.py")
tf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tf)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")

if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveMcpAnalyticsCase(unittest.TestCase):
    """A tenant built to break the queries if their predicates are misplaced."""

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"mcpan-{run}"
        self.pid = f"MCPAN_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.queries = _queries()

        # CVE nodes are GLOBAL: no tenant properties, by design. That is exactly
        # why a re-reference that loses its exemption matches nothing.
        with self.driver.session() as s:
            s.run(
                """
                MERGE (cKev:CVE {id: $kev})   SET cKev.cvss = '9.8', cKev.severity = 'critical'
                MERGE (cStale:CVE {id: $stale}) SET cStale.cvss = '7.5', cStale.severity = 'high'
                MERGE (cMuted:CVE {id: $muted}) SET cMuted.cvss = '5.0', cMuted.severity = 'medium'
                MERGE (m:MitreData {cwe_id: 'CWE-79'}) SET m.cwe_name = 'XSS'

                CREATE (t:Technology {name: $tech, version: '1.0',
                                      user_id: $uid, project_id: $pid})
                CREATE (bu:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                CREATE (bu)-[:USES_TECHNOLOGY]->(t)
                CREATE (t)-[:HAS_KNOWN_CVE]->(cKev)
                CREATE (t)-[:HAS_KNOWN_CVE]->(cStale)
                CREATE (t)-[:HAS_KNOWN_CVE]->(cMuted)
                CREATE (cKev)-[:HAS_CWE]->(m)

                // A LIVE exploit: must count.
                CREATE (exLive:ExploitGvm {id: $exLive, user_id: $uid, project_id: $pid})
                CREATE (exLive)-[:EXPLOITED_CVE]->(cKev)

                // SUPERSEDED: a later scan stopped reporting it, and a human had
                // touched it so prune stamped stale_since instead of deleting.
                // It must not count as an exploit AND must not take its CVE away.
                CREATE (exStale:ExploitGvm {id: $exStale, stale_since: datetime(),
                                            triage_source: 'human',
                                            user_id: $uid, project_id: $pid})
                CREATE (exStale)-[:EXPLOITED_CVE]->(cStale)

                // SUPPRESSED by a person: invisible to every read here.
                CREATE (exMuted:ExploitGvm:Muted {id: $exMuted, user_id: $uid, project_id: $pid})
                CREATE (exMuted)-[:EXPLOITED_CVE]->(cMuted)

                // Census fodder: one of each state the counts claim to separate.
                CREATE (:Vulnerability {id: $vLive, severity: 'critical',
                                        user_id: $uid, project_id: $pid})
                CREATE (:Vulnerability {id: $vStale, severity: 'critical',
                                        stale_since: datetime(),
                                        user_id: $uid, project_id: $pid})
                CREATE (:Vulnerability:Muted {id: $vMuted, severity: 'critical',
                                              user_id: $uid, project_id: $pid})
                CREATE (:Secret {id: $sStale, stale_since: datetime(),
                                 user_id: $uid, project_id: $pid})
                CREATE (:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                """,
                uid=self.uid, pid=self.pid,
                kev=f"CVE-{run}-KEV", stale=f"CVE-{run}-STALE", muted=f"CVE-{run}-MUTED",
                tech=f"tech-{run}", url=f"https://{run}.invalid",
                exLive=f"ex-live-{run}", exStale=f"ex-stale-{run}", exMuted=f"ex-muted-{run}",
                vLive=f"v-live-{run}", vStale=f"v-stale-{run}", vMuted=f"v-muted-{run}",
                sStale=f"s-stale-{run}", sub=f"{run}.invalid",
            )
        self.run_id = run

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {project_id: $pid}) DETACH DELETE n", pid=self.pid)
            # The global CVE/MitreData nodes are shared, so only the ones this
            # run minted are removed, and MitreData is left alone entirely.
            s.run("MATCH (c:CVE) WHERE c.id STARTS WITH $p DETACH DELETE c",
                  p=f"CVE-{self.run_id}-")
        self.driver.close()

    # --- helper ---------------------------------------------------------------

    def _run(self, name):
        """Scope the query exactly as /graph/exec does, then execute it."""
        final = tf.scope_query(self.queries[name], self.uid, self.pid)
        with self.driver.session() as s:
            return [dict(r) for r in s.run(
                final, tenant_user_id=self.uid, tenant_project_id=self.pid)]

    # --- ROW 2: a superseded exploit must not delete its CVE -------------------

    def test_a_stale_exploit_leaves_its_CVE_counted_with_zero(self):
        # THE REGRESSION. With the predicate on a `WITH`, the row carrying
        # CVE-STALE was dropped entirely and the CVE disappeared from the
        # ranking, taking its CVSS out of maxCvss with it.
        rows = self._run("blast_radius")
        self.assertEqual(len(rows), 1, "the technology must still be ranked")
        row = rows[0]
        # Three CVEs hang off the technology; the muted one is filtered by the
        # injected !Muted on the EXPLOIT, not on the CVE, so all three count.
        self.assertEqual(row["cveCount"], 3)
        # Only the live exploit counts as an exploit.
        self.assertEqual(row["knownExploitCount"], 1)
        # And the stale CVE's score is still in the maximum.
        self.assertAlmostEqual(float(row["maxCvss"]), 9.8, places=2)

    def test_the_stale_CVE_is_present_in_the_exploit_path_list(self):
        rows = self._run("exploit_paths")
        cves = {r["cve"]: r for r in rows}
        stale_id = f"CVE-{self.run_id}-STALE"
        self.assertIn(stale_id, cves, "a superseded exploit removed its CVE from the list")
        # Present, and correctly NOT flagged as having a known exploit.
        self.assertFalse(cves[stale_id]["cisaKev"])

    def test_a_live_exploit_is_still_flagged(self):
        # The other direction: the fix must not have disabled the signal.
        rows = self._run("exploit_paths")
        kev = next(r for r in rows if r["cve"] == f"CVE-{self.run_id}-KEV")
        self.assertTrue(kev["cisaKev"])

    def test_the_global_reference_join_still_resolves(self):
        # The exemption trap: `(c)` instead of `(c:CVE)` makes this permanently
        # null while the query still returns 200.
        rows = self._run("exploit_paths")
        kev = next(r for r in rows if r["cve"] == f"CVE-{self.run_id}-KEV")
        self.assertEqual(kev["cweIds"], ["CWE-79"])

    def test_a_suppressed_exploit_is_never_counted(self):
        rows = self._run("blast_radius")
        self.assertEqual(rows[0]["knownExploitCount"], 1)

    # --- ROW 3: the census separates the states it claims to ------------------

    def test_muted_and_stale_findings_are_excluded_and_fresh_ones_counted(self):
        # Three critical Vulnerabilities exist: live, stale, muted. Only the live
        # one may be counted, and the two exclusions come from DIFFERENT places -
        # `!Muted` is injected by the tenant filter, `stale_since` is written by
        # hand - so a regression in either shows up here.
        rows = self._run("attack_surface")
        self.assertEqual(len(rows), 1)
        surface = rows[0]
        self.assertEqual(surface["criticalVulnerabilities"], 1)
        self.assertEqual(surface["exposedSecrets"], 0, "a stale Secret was counted")
        self.assertEqual(surface["knownExploits"], 1, "a stale or muted exploit was counted")
        self.assertEqual(surface["subdomains"], 1)

    def test_the_census_answers_for_an_empty_project(self):
        # OPTIONAL MATCH, not MATCH: a plain MATCH that finds nothing takes the
        # whole chained aggregation to zero rows, so a project whose first label
        # is empty would get no answer at all rather than zeros.
        final = tf.scope_query(self.queries["attack_surface"], "nobody", "NO_SUCH_PROJECT")
        with self.driver.session() as s:
            rows = [dict(r) for r in s.run(
                final, tenant_user_id="nobody", tenant_project_id="NO_SUCH_PROJECT")]
        self.assertEqual(len(rows), 1, "an empty project must still get one row of zeros")
        self.assertEqual(rows[0]["subdomains"], 0)

    def test_the_census_cannot_see_another_tenant(self):
        # scope_query is the SOLE isolation boundary for these tools: they
        # project scalars, which the outbound post-validation cannot check.
        final = tf.scope_query(self.queries["attack_surface"], "someone-else", self.pid)
        with self.driver.session() as s:
            rows = [dict(r) for r in s.run(
                final, tenant_user_id="someone-else", tenant_project_id=self.pid)]
        self.assertEqual(rows[0]["criticalVulnerabilities"], 0)
        self.assertEqual(rows[0]["subdomains"], 0)

    # --- ROW 4: the stale count is a real number ------------------------------

    def test_the_stale_count_is_present_and_numeric(self):
        # `graph_summary` reads this with `typeof n === 'number'` and OMITS the
        # key when it is anything else. If the driver returned a wrapper object
        # the field would be silently absent forever, and the discrepancy it
        # exists to explain would go back to being unexplained.
        rows = self._run("stale_findings")
        self.assertEqual(len(rows), 1)
        stale = rows[0]["stale"]
        self.assertIsInstance(stale, int, f"not a plain int: {type(stale)}")
        self.assertNotIsInstance(stale, bool)
        # One stale Vulnerability + one stale Secret. The stale ExploitGvm counts
        # too: it is muteable, not muted.
        self.assertEqual(stale, 3)

    def test_the_stale_count_excludes_suppressed_findings(self):
        # A muted finding is hidden from the census AND from this number, which
        # is why the muted total is deliberately a separate tool.
        rows = self._run("stale_findings")
        self.assertEqual(rows[0]["stale"], 3, "a muted finding leaked into the stale count")


if __name__ == "__main__":
    unittest.main()
