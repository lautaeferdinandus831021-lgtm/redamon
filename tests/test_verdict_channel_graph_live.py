"""Strategy rows 5, 6 (L4, real Neo4j): verdict provenance, and the muted cap.

ROW 5. A verdict delegated through an access token is written as `'human'`,
deliberately, because `triage_source` is a closed two-value set that four other
behaviours branch on - a third value makes the finding prune-eligible, lets a
later AI run overwrite it, stops `likely_noise` meaning false-positive, and
renders as "Not reviewed". The provenance therefore lives on two SEPARATE
properties, and the fake-session tests can only prove the Cypher mentions them.
Whether Neo4j actually persists them, and whether they survive being read back,
is provable only here.

ROW 6. `list_muted` had no bound at all, so the MCP path pulled every suppressed
finding across the wire on every call. The bound it gained has to be optional:
the Muted table in the UI counts the rows it receives, so a default cap would
silently change an operator-visible number. Both halves are proved against a
real database.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network whitehat-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://whitehat-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    whitehat-agent python -m unittest tests.test_verdict_channel_graph_live -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""
import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

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
class LiveVerdictChannelCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"vchan-{run}"
        self.pid = f"VCHAN_{run}"
        self.run_id = run
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)

        with self.driver.session() as s:
            s.run(
                """
                CREATE (:Vulnerability {id: $v1, name: 'Exposed .git', severity: 'high',
                                        source: 'nuclei', user_id: $uid, project_id: $pid})
                """,
                v1=f"v-{run}", uid=self.uid, pid=self.pid)
            # Enough muted rows to prove a cap actually bites.
            for i in range(7):
                s.run(
                    """
                    CREATE (:Vulnerability:Muted {id: $id, name: 'noisy', severity: 'low',
                                                  source: 'nuclei', muted_at: datetime(),
                                                  muted_by: $uid, muted_reason: 'accepted risk',
                                                  user_id: $uid, project_id: $pid})
                    """,
                    id=f"m-{run}-{i}", uid=self.uid, pid=self.pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {project_id: $pid}) DETACH DELETE n", pid=self.pid)
        self.driver.close()

    def _props(self, node_id):
        with self.driver.session() as s:
            rec = s.run(
                "MATCH (n {id: $id, user_id: $uid, project_id: $pid}) RETURN properties(n) AS p",
                id=node_id, uid=self.uid, pid=self.pid).single()
        return dict(rec["p"]) if rec else {}

    # --- ROW 5: the verdict's channel and actor are persisted ------------------

    def test_a_delegated_verdict_persists_its_channel_and_actor(self):
        out = self.client.set_human_verdict(
            self.uid, self.pid, f"v-{self.run_id}", "confirmed",
            "checked against the live host", channel="mcp", verdict_by="alice")
        self.assertTrue(out["updated"])
        self.assertEqual(out["label"], "Vulnerability")

        p = self._props(f"v-{self.run_id}")
        self.assertEqual(p["triage_verdict_channel"], "mcp")
        self.assertEqual(p["triage_verdict_by"], "alice")

    def test_the_verdict_itself_is_still_human(self):
        # The whole point of the split. A third `triage_source` value would make
        # this finding prune-eligible, so the next scan would DELETE it rather
        # than stamp stale_since.
        self.client.set_human_verdict(
            self.uid, self.pid, f"v-{self.run_id}", "confirmed", "", channel="mcp")
        p = self._props(f"v-{self.run_id}")
        self.assertEqual(p["triage_source"], "human")
        self.assertEqual(p["triage_status"], "confirmed")
        self.assertEqual(p["triage_confidence"], 1.0)

    def test_a_UI_verdict_records_the_app_channel_and_the_tenant(self):
        self.client.set_human_verdict(
            self.uid, self.pid, f"v-{self.run_id}", "likely_noise", "duplicate")
        p = self._props(f"v-{self.run_id}")
        self.assertEqual(p["triage_verdict_channel"], "app")
        self.assertEqual(p["triage_verdict_by"], self.uid)

    def test_a_later_verdict_overwrites_the_channel(self):
        # A finding judged in the app and then re-judged over MCP must not keep
        # claiming it was judged in the app.
        self.client.set_human_verdict(self.uid, self.pid, f"v-{self.run_id}", "confirmed", "")
        self.client.set_human_verdict(
            self.uid, self.pid, f"v-{self.run_id}", "unreviewed", "", channel="mcp",
            verdict_by="bob")
        p = self._props(f"v-{self.run_id}")
        self.assertEqual(p["triage_verdict_channel"], "mcp")
        self.assertEqual(p["triage_verdict_by"], "bob")
        self.assertEqual(p["triage_status"], "unreviewed")

    def test_a_verdict_cannot_reach_another_tenant(self):
        out = self.client.set_human_verdict(
            "someone-else", self.pid, f"v-{self.run_id}", "confirmed", "", channel="mcp")
        self.assertFalse(out["updated"])
        self.assertNotIn("triage_verdict_channel", self._props(f"v-{self.run_id}"))

    def test_a_verdict_on_a_muted_finding_does_not_unmute_it(self):
        # Nothing on the MCP surface can unmute, and a verdict must not do it by
        # accident: that would reverse a human's suppression decision, which is
        # the one power the model-driven path is denied.
        target = f"m-{self.run_id}-0"
        self.client.set_human_verdict(
            self.uid, self.pid, target, "confirmed", "", channel="mcp")
        with self.driver.session() as s:
            labels = s.run(
                "MATCH (n {id: $id, project_id: $pid}) RETURN labels(n) AS l",
                id=target, pid=self.pid).single()["l"]
        self.assertIn("Muted", labels)

    # --- ROW 6: the muted cap is opt-in ---------------------------------------

    def test_list_muted_with_no_limit_returns_every_row(self):
        # The UI counts what it receives, so a default cap would silently change
        # an operator-visible number.
        rows = self.client.list_muted(self.uid, self.pid)
        self.assertEqual(len(rows), 7)

    def test_list_muted_honours_a_limit(self):
        self.assertEqual(len(self.client.list_muted(self.uid, self.pid, limit=3)), 3)
        self.assertEqual(len(self.client.list_muted(self.uid, self.pid, limit=1)), 1)

    def test_a_limit_larger_than_the_data_returns_what_exists(self):
        self.assertEqual(len(self.client.list_muted(self.uid, self.pid, limit=500)), 7)

    def test_the_limited_read_is_still_tenant_scoped(self):
        self.assertEqual(self.client.list_muted("someone-else", self.pid, limit=500), [])

    def test_the_limited_read_returns_the_same_shape(self):
        # A capped read must not also be a narrower one: the grouping in
        # list_muted_findings reads label, severity and muted_reason off it.
        rows = self.client.list_muted(self.uid, self.pid, limit=2)
        for row in rows:
            self.assertEqual(row["label"], "Vulnerability")
            self.assertEqual(row["severity"], "low")
            self.assertEqual(row["muted_reason"], "accepted risk")
            self.assertNotIn("matched_text", row)


if __name__ == "__main__":
    unittest.main()
