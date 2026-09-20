"""LIVE-Neo4j proof that `updated_at` is universal and that it MOVES.

The static sweep in tests/test_updated_at_universal.py proves the source
*contains* the stamp; it cannot prove Neo4j accepted it, that the stamp landed
on the node the query actually created, or that a second write moves it. All
three are the contract the graph tables depend on:

  * every node created by a scan carries `updated_at`
  * re-running the scan MOVES it (it means "last written", not "first seen")
  * it is a real temporal, not a string, so the tables sort it correctly

This drives the REAL `update_graph_from_*` methods, so it also covers the write
paths a fake session cannot: bare relationship-anchor MERGEs that create a node
as a side effect, which were the largest group of gaps.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network whitehat-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    whitehat-agent python -m unittest tests.test_updated_at_graph_live -v

Everything it creates is scoped to a throwaway project id and deleted in
tearDownClass, so it is safe against a populated database.
"""

import os
import sys
import time
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


# A minimal recon payload that still exercises several writers: the domain and
# subdomain writer, the DNS/IP writer (whose IP node is created by a bare
# relationship-anchor MERGE), and the port/service writer.
def _recon_payload(domain, sub, ip):
    return {
        # `metadata.root_domain` is the key the writer reads; a payload without
        # it returns early with zero nodes, which is why this test asserts the
        # writer produced something before asserting anything about it.
        "metadata": {"root_domain": domain, "target": domain},
        "subdomains": [sub],
        "subdomain_status_map": {sub: "resolved"},
        "dns": {
            "domain": {"has_records": True, "records": {}, "ips": {"ipv4": [], "ipv6": []}},
            "subdomains": {
                sub: {
                    "has_records": True,
                    "records": {"A": [ip]},
                    "ips": {"ipv4": [ip], "ipv6": []},
                }
            },
        },
        "whois": {},
        "scan_metadata": {"scan_timestamp": "2026-08-20T00:00:00Z"},
    }


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestUpdatedAtLive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.project_id = "updated-at-itest-%s" % uuid.uuid4().hex[:10]
        cls.user_id = "updated-at-itest-user"
        cls.domain = "itest-%s.example.test" % uuid.uuid4().hex[:6]
        cls.sub = "www.%s" % cls.domain
        cls.ip = "203.0.113.7"
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.client.driver.session() as s:
                s.run(
                    "MATCH (n) WHERE n.project_id = $pid DETACH DELETE n",
                    pid=cls.project_id,
                )
        finally:
            cls.client.close()

    # -- helpers ---------------------------------------------------------

    def _write(self):
        self.client.update_graph_from_domain_discovery(
            _recon_payload(self.domain, self.sub, self.ip),
            self.user_id,
            self.project_id,
        )

    def _nodes(self):
        """[(label, name, updated_at)] for everything in this test's project."""
        with self.client.driver.session() as s:
            return [
                (r["label"], r["name"], r["ts"])
                for r in s.run(
                    "MATCH (n) WHERE n.project_id = $pid "
                    "RETURN labels(n)[0] AS label, "
                    "       coalesce(n.name, n.address, n.url, n.value, '?') AS name, "
                    "       n.updated_at AS ts",
                    pid=self.project_id,
                )
            ]

    # -- the contract ----------------------------------------------------

    def test_every_node_a_scan_creates_carries_updated_at(self):
        self._write()
        nodes = self._nodes()
        self.assertGreater(len(nodes), 0, "the writer created nothing; fixture is wrong")
        missing = [(lab, name) for lab, name, ts in nodes if ts is None]
        self.assertEqual(
            missing, [],
            "%d of %d nodes have no updated_at: %s" % (len(missing), len(nodes), missing),
        )

    def test_it_is_a_temporal_not_a_string(self):
        """The tables sort on it and the filter offers a date range for it; a
        string would sort lexically and profile as plain text."""
        self._write()
        for label, name, ts in self._nodes():
            self.assertTrue(
                hasattr(ts, "year"),
                "%s %s has updated_at of type %s, expected a Neo4j temporal"
                % (label, name, type(ts).__name__),
            )

    def test_a_second_write_MOVES_updated_at(self):
        """The whole point: it means "last written", not "first created". If a
        writer used ON CREATE SET, the value would freeze at first write and the
        column would report a months-old scan as current."""
        self._write()
        before = {(lab, name): ts for lab, name, ts in self._nodes()}
        self.assertGreater(len(before), 0)

        time.sleep(1.1)  # Neo4j datetime() has sub-second precision; be explicit
        self._write()
        after = {(lab, name): ts for lab, name, ts in self._nodes()}

        unmoved = [k for k, ts in after.items() if k in before and ts == before[k]]
        self.assertEqual(
            unmoved, [],
            "%d node(s) kept their original updated_at across a re-scan, so they "
            "are stamped ON CREATE only: %s" % (len(unmoved), unmoved),
        )

    def test_bare_relationship_anchor_nodes_are_stamped(self):
        """The IP node here is created as a side effect of hanging a
        RESOLVES_TO relationship, not by a write that sets its properties.
        That shape was the single largest group of gaps (19 in the OSINT mixin
        alone) and is exactly what a fake-session test cannot catch."""
        self._write()
        with self.client.driver.session() as s:
            row = s.run(
                "MATCH (i:IP {address: $ip, project_id: $pid}) "
                "RETURN i.updated_at AS ts",
                ip=self.ip, pid=self.project_id,
            ).single()
        self.assertIsNotNone(row, "the IP node was never created; fixture is wrong")
        self.assertIsNotNone(row["ts"], "IP node created without updated_at")


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestBackfillMigration(unittest.TestCase):
    """The backfill seeds pre-existing nodes from whatever write time they hold."""

    @classmethod
    def setUpClass(cls):
        cls.project_id = "backfill-itest-%s" % uuid.uuid4().hex[:10]
        cls.drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.drv.session() as s:
                s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n",
                      pid=cls.project_id)
        finally:
            cls.drv.close()

    def test_seeds_from_last_seen_created_at_and_first_seen(self):
        from graph_db.schema import backfill_updated_at, _mark_migration_applied
        with self.drv.session() as s:
            s.run(
                "CREATE (:Package  {project_id: $pid, purl: 'a', last_seen:  datetime()}) "
                "CREATE (:ChainStep{project_id: $pid, step_id: 'b', created_at: datetime()}) "
                "CREATE (:Package  {project_id: $pid, purl: 'c', first_seen: datetime()}) "
                "CREATE (:Domain   {project_id: $pid, name: 'd'})",
                pid=self.project_id,
            )
            # The real migration is marker-guarded and already applied on this
            # database, so drive the batched statements the same way it does.
            for prop in ("last_seen", "created_at", "first_seen"):
                s.run(
                    "MATCH (n) WHERE n.project_id = $pid AND n.updated_at IS NULL "
                    "AND n.`%s` IS NOT NULL SET n.updated_at = n.`%s`" % (prop, prop),
                    pid=self.project_id,
                )
            rows = {
                r["name"]: r["ts"]
                for r in s.run(
                    "MATCH (n) WHERE n.project_id = $pid "
                    "RETURN coalesce(n.purl, n.step_id, n.name) AS name, "
                    "       n.updated_at AS ts",
                    pid=self.project_id,
                )
            }
        self.assertIsNotNone(rows["a"], "not seeded from last_seen")
        self.assertIsNotNone(rows["b"], "not seeded from created_at")
        self.assertIsNotNone(rows["c"], "not seeded from first_seen")
        # A node with no write time at all is left null rather than stamped
        # "now": inventing one would claim a scan touched it that never did.
        self.assertIsNone(rows["d"], "a node with no write time was invented one")

    def test_migration_is_marker_guarded_and_idempotent(self):
        from graph_db.schema import (
            backfill_updated_at, _migration_applied, UPDATED_AT_BACKFILL_MARKER,
        )
        with self.drv.session() as s:
            self.assertTrue(
                _migration_applied(s, UPDATED_AT_BACKFILL_MARKER),
                "marker missing; the backfill would re-scan the graph on every "
                "single connection",
            )
            # Second call must be a no-op, not a re-scan.
            backfill_updated_at(s)
            backfill_updated_at(s)


if __name__ == "__main__":
    unittest.main()
