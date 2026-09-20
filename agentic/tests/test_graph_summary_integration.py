"""L4 — `op: "summary"` against a REAL Neo4j.

The unit tests for this op use a fake driver, so they prove the SHAPE of the
result and nothing about the Cypher. A syntax error, a mis-spelled property or
a filter that does not actually filter would pass every one of them.

What only a real database can answer:

  * does the census Cypher parse and run at all
  * does `NOT n:Muted AND n.stale_since IS NULL` really exclude those nodes
  * does the tenant predicate really exclude another tenant's nodes

Tier: integration (the `_integration` suffix auto-marks it), so it is NOT in
the unit gate and self-skips when Neo4j is unreachable.

Run:  ./whitehat.sh test integration
  or: docker run --network host ... python -m pytest agentic/tests/test_graph_summary_integration.py
"""
import os
import sys
import unittest
import unittest.mock
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _candidate_uris():
    """Neo4j publishes on host loopback and answers to `neo4j` on the compose
    network; a test container may be on either, or neither."""
    explicit = os.environ.get("NEO4J_URI")
    if explicit:
        yield explicit
    yield "bolt://neo4j:7687"
    yield "bolt://localhost:7687"
    yield "bolt://host.docker.internal:7687"


def _connect():
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return None
    auth = (
        os.environ.get("NEO4J_USER", "neo4j"),
        os.environ.get("NEO4J_PASSWORD", "password"),
    )
    for uri in _candidate_uris():
        try:
            driver = GraphDatabase.driver(uri, auth=auth, connection_timeout=3)
            driver.verify_connectivity()
            return driver
        except Exception:
            continue
    return None


_DRIVER = _connect()

MINE_U, MINE_P = f"itu_{uuid.uuid4().hex[:8]}", f"itp_{uuid.uuid4().hex[:8]}"
OTHER_U, OTHER_P = f"itu_{uuid.uuid4().hex[:8]}", f"itp_{uuid.uuid4().hex[:8]}"


@unittest.skipIf(_DRIVER is None, "Neo4j not reachable (integration tier)")
class GraphSummaryIntegrationTests(unittest.TestCase):
    """Fixtures are labelled with a run-unique tenant so a live graph is safe."""

    @classmethod
    def setUpClass(cls):
        import api

        cls.api = api
        with _DRIVER.session() as s:
            # Mine: 2 live IPs, 1 muted IP, 1 stale IP, 1 Host + a relationship.
            s.run(
                """
                CREATE (a:IP {user_id:$u, project_id:$p, address:'10.0.0.1'})
                CREATE (b:IP {user_id:$u, project_id:$p, address:'10.0.0.2'})
                CREATE (m:IP:Muted {user_id:$u, project_id:$p, address:'10.0.0.3'})
                CREATE (st:IP {user_id:$u, project_id:$p, address:'10.0.0.4',
                               stale_since:'2026-01-01'})
                CREATE (h:Host {user_id:$u, project_id:$p, name:'mine.test'})
                CREATE (h)-[:RESOLVES_TO {user_id:$u, project_id:$p}]->(a)
                """,
                u=MINE_U, p=MINE_P,
            )
            # Another tenant: same labels, must never be counted.
            s.run(
                """
                CREATE (x:IP {user_id:$u, project_id:$p, address:'192.168.9.9'})
                CREATE (y:Secret {user_id:$u, project_id:$p, value:'do-not-leak'})
                CREATE (z:Host {user_id:$u, project_id:$p, name:'theirs.test'})
                CREATE (z)-[:RESOLVES_TO {user_id:$u, project_id:$p}]->(x)
                """,
                u=OTHER_U, p=OTHER_P,
            )

    @classmethod
    def tearDownClass(cls):
        if _DRIVER is None:
            return
        with _DRIVER.session() as s:
            for u, p in ((MINE_U, MINE_P), (OTHER_U, OTHER_P)):
                s.run(
                    "MATCH (n) WHERE n.user_id=$u AND n.project_id=$p DETACH DELETE n",
                    u=u, p=p,
                )
        _DRIVER.close()

    def _summary(self, user_id=MINE_U, project_id=MINE_P):
        import json

        with unittest.mock.patch.object(
            self.api, "_graph_exec_get_driver", return_value=_DRIVER
        ):
            resp = self.api._graph_exec_summary(
                {"tenant_user_id": user_id, "tenant_project_id": project_id}
            )
        self.assertEqual(resp.status_code, 200, bytes(resp.body).decode()[:200])
        return json.loads(bytes(resp.body).decode())

    def _counts(self, body):
        return {r["label"]: r["count"] for r in body["nodes"]}

    # --- the Cypher actually runs ------------------------------------------

    def test_the_census_cypher_parses_and_runs(self):
        body = self._summary()
        self.assertIn("nodes", body)
        self.assertIn("relationships", body)

    def test_it_counts_this_tenant_live_nodes(self):
        counts = self._counts(self._summary())
        # 2 live IPs: the muted and the stale one are excluded.
        self.assertEqual(counts.get("IP"), 2, f"got {counts}")
        self.assertEqual(counts.get("Host"), 1, f"got {counts}")

    def test_a_muted_node_is_NOT_counted(self):
        counts = self._counts(self._summary())
        # `Muted` must not appear as a label either: the only nodes carrying it
        # are the ones the filter drops.
        self.assertNotIn("Muted", counts)

    def test_a_stale_node_is_NOT_counted(self):
        # Since ingest-then-prune a finding a scanner stopped reporting is KEPT
        # and stamped. Counting it would report resolved findings as live.
        self.assertEqual(self._counts(self._summary()).get("IP"), 2)

    # --- tenant isolation ---------------------------------------------------

    def test_another_tenant_nodes_are_absent(self):
        counts = self._counts(self._summary())
        # The other tenant has a Secret; mine does not. Its presence would mean
        # the tenant predicate is not filtering.
        self.assertNotIn("Secret", counts, "another tenant's label leaked into the census")

    def test_the_other_tenant_sees_ITS_OWN_nodes_only(self):
        counts = self._counts(self._summary(OTHER_U, OTHER_P))
        self.assertEqual(counts.get("IP"), 1)
        self.assertEqual(counts.get("Secret"), 1)
        # And not mine: mine has 2 IPs, so a leak would show 3.
        self.assertNotEqual(counts.get("IP"), 3)

    def test_a_tenant_with_no_nodes_gets_an_EMPTY_census_not_an_error(self):
        body = self._summary("nobody-user", "nobody-project")
        self.assertEqual(body["nodes"], [])
        self.assertEqual(body["relationships"], [])

    def test_user_id_alone_does_not_match(self):
        # The tenant key is BOTH fields; matching on one would cross projects.
        self.assertEqual(self._counts(self._summary(MINE_U, "some-other-project")), {})

    def test_project_id_alone_does_not_match(self):
        self.assertEqual(self._counts(self._summary("some-other-user", MINE_P)), {})

    # --- relationships -------------------------------------------------------

    def test_relationship_types_are_counted_for_this_tenant(self):
        rels = {r["type"]: r["count"] for r in self._summary()["relationships"]}
        self.assertEqual(rels.get("RESOLVES_TO"), 1, f"got {rels}")

    def test_the_relationship_census_does_not_count_another_tenant_edges(self):
        # Both tenants have exactly one RESOLVES_TO; seeing 2 means the predicate
        # covers only one endpoint or neither.
        rels = {r["type"]: r["count"] for r in self._summary()["relationships"]}
        self.assertNotEqual(rels.get("RESOLVES_TO"), 2)


if __name__ == "__main__":
    import unittest.mock  # noqa: F401  (imported lazily above)

    unittest.main()
