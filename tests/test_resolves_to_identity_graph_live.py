"""LIVE-Neo4j proof that a Subdomain -> IP pair is ONE RESOLVES_TO edge.

  * every writer (IP recon, domain discovery, partial discovery, Shodan reverse
    DNS and DNS records, OTX passive DNS, vhost/SNI) run against the same pair,
    in the order that used to stack parallel edges, leaves exactly one;
  * the edge carries each writer's properties: record_type (AAAA for an IPv6
    reverse-DNS hit), the passive-DNS window, and vhost provenance only when
    vhost/SNI created it;
  * the one-time fold collapses edges stored before the fix into one carrying
    every property, deletes no node, never touches another project, and is
    idempotent.

Self-skips unless the neo4j driver imports AND a database answers. Everything
it writes is under a random tenant and is deleted afterwards. To run it:

  docker run --rm --network whitehat-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    whitehat-agent python -m pytest tests/test_resolves_to_identity_graph_live.py -v
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
_V4 = "192.0.2.10"
_V6 = "2001:db8::10"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestResolvesToIdentityLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"rtid-{run}", f"RTID_{run}"
        self.uid2, self.pid2 = f"rtid2-{run}", f"RTID2_{run}"
        self.domain = f"example-{run}.test"
        self.sub = f"www.{self.domain}"

    def tearDown(self):
        self._q("MATCH (n) WHERE n.user_id IN [$u, $u2] DETACH DELETE n",
                u=self.uid, u2=self.uid2)

    def _q(self, cypher, **params):
        with self.client.driver.session() as s:
            return [r.data() for r in s.run(cypher, **params)]

    def _edges(self, ip=_V4, uid=None, pid=None, sub=None):
        return [row["p"] for row in self._q(
            """
            MATCH (s:Subdomain {name: $sub, user_id: $u, project_id: $p})
                  -[r:RESOLVES_TO]->(i:IP {address: $ip, user_id: $u, project_id: $p})
            RETURN properties(r) AS p
            """,
            sub=sub or self.sub, ip=ip, u=uid or self.uid, p=pid or self.pid)]

    # -- the real writers ----------------------------------------------------

    def _tenant(self, uid, pid):
        return (uid or self.uid, pid or self.pid)

    def _ip_recon(self, ip=_V4, uid=None, pid=None):
        uid, pid = self._tenant(uid, pid)
        self.client.update_graph_from_ip_recon({
            "metadata": {"root_domain": self.domain},
            "subdomains": [self.sub],
            "dns": {"subdomains": {self.sub: {"has_records": True,
                                               "ips": {"ipv4": [ip], "ipv6": []}}}},
        }, uid, pid)

    def _domain_discovery(self, ipv4=(_V4,), ipv6=(), uid=None, pid=None):
        uid, pid = self._tenant(uid, pid)
        stats = self.client.update_graph_from_domain_discovery({
            "metadata": {"root_domain": self.domain, "target": self.domain},
            "subdomains": [self.sub],
            "dns": {"subdomains": {self.sub: {
                "records": {"A": list(ipv4), "AAAA": list(ipv6)},
                "ips": {"ipv4": list(ipv4), "ipv6": list(ipv6)}}}},
        }, uid, pid)
        self.assertEqual(stats["errors"], [])

    def _partial_discovery(self, ip=_V4):
        self.client.update_graph_from_partial_discovery({
            "domain": self.domain,
            "subdomains": [self.sub],
            "dns": {"subdomains": {self.sub: {"has_records": True,
                                               "ips": {"ipv4": [ip], "ipv6": []}}}},
        }, self.uid, self.pid)

    def _shodan(self, reverse_dns_ip=None, dns_record_ip=None):
        data = {"hosts": [], "reverse_dns": {}, "domain_dns": {"subdomains": [], "records": []}}
        if reverse_dns_ip:
            data["reverse_dns"] = {reverse_dns_ip: [self.sub]}
        if dns_record_ip:
            data["domain_dns"] = {"subdomains": ["www"],
                                  "records": [{"type": "A", "value": dns_record_ip,
                                               "subdomain": "www"}]}
        self.client.update_graph_from_shodan(
            {"domain": self.domain, "shodan": data}, self.uid, self.pid)

    def _otx(self, first, last, ip=_V4):
        self.client.update_graph_from_otx({"domain": self.domain, "otx": {"ip_reports": [{
            "ip": ip,
            "passive_dns": [{"hostname": self.sub, "first": first, "last": last,
                             "record_type": "A"}],
        }]}}, self.uid, self.pid)

    def _vhost(self, ip=_V4):
        self._q("MERGE (:IP {address: $ip, user_id: $u, project_id: $p})",
                ip=ip, u=self.uid, p=self.pid)
        self.client.update_graph_from_vhost_sni({"domain": self.domain, "vhost_sni": {
            "by_ip": {}, "discovered_baseurls": [],
            "findings": [{
                "id": f"vhost_sni_{uuid.uuid4().hex[:6]}", "name": f"Hidden Virtual Host: {self.sub}",
                "type": "hidden_vhost", "severity": "medium", "source": "vhost_sni_enum",
                "hostname": self.sub, "ip": ip, "port": 443, "layer": "L7",
                "discovered_at": "2026-04-25T14:00:00Z",
            }],
        }}, self.uid, self.pid)

    # -- write time ----------------------------------------------------------

    def test_every_writer_on_one_pair_leaves_one_edge(self):
        # Plain edge first, then every writer that put a property in its MERGE
        # pattern: on the old writers this stacked a parallel edge per spelling.
        self._ip_recon()
        self._domain_discovery()
        self._shodan(reverse_dns_ip=_V4, dns_record_ip=_V4)
        self._otx("2021-03-01T00:00:00", "2025-06-01T00:00:00")
        self._vhost()
        self._partial_discovery()

        edges = self._edges()
        self.assertEqual(len(edges), 1, edges)
        edge = edges[0]
        self.assertEqual(edge["record_type"], "A")
        self.assertEqual(edge["first_seen"], "2021-03-01T00:00:00")
        self.assertEqual(edge["last_seen"], "2025-06-01T00:00:00")
        self.assertIn("last_seen_at", edge)
        self.assertNotIn("discovered_via", edge, "vhost/SNI did not create this edge")

    def test_vhost_first_keeps_its_provenance_and_gains_the_record_type(self):
        self._vhost()
        self._domain_discovery()

        edges = self._edges()
        self.assertEqual(len(edges), 1, edges)
        self.assertEqual(edges[0]["discovered_via"], "vhost_sni_enum")
        self.assertEqual(edges[0]["record_type"], "A")

    def test_ipv6_reverse_dns_is_labelled_aaaa_and_shares_the_dns_edge(self):
        self._shodan(reverse_dns_ip=_V6)
        self._domain_discovery(ipv4=(), ipv6=(_V6,))

        edges = self._edges(ip=_V6)
        self.assertEqual(len(edges), 1, edges)
        self.assertEqual(edges[0]["record_type"], "AAAA")

    def test_passive_dns_widens_the_window_and_empty_dates_erase_nothing(self):
        self._domain_discovery()
        self._otx("2021-01-01T00:00:00", "2023-01-01T00:00:00")
        self._otx("2019-05-05T00:00:00", "2022-01-01T00:00:00")
        self._otx("", "")

        edges = self._edges()
        self.assertEqual(len(edges), 1, edges)
        self.assertEqual(edges[0]["first_seen"], "2019-05-05T00:00:00")
        self.assertEqual(edges[0]["last_seen"], "2023-01-01T00:00:00")

    def test_writers_never_touch_another_project(self):
        self._ip_recon(uid=self.uid2, pid=self.pid2)
        before = self._edges(uid=self.uid2, pid=self.pid2)

        self._ip_recon()
        self._domain_discovery()
        self._vhost()

        self.assertEqual(len(self._edges()), 1)
        self.assertEqual(self._edges(uid=self.uid2, pid=self.pid2), before)

    # -- the one-time fold -----------------------------------------------------

    def _fold(self, uid=None, pid=None):
        from graph_db.resolves_to_identity import fold_resolves_to_duplicates
        with self.client.driver.session() as s:
            return fold_resolves_to_duplicates(s, uid or self.uid, pid or self.pid)

    def _seed_old_parallel_edges(self, uid, pid, sub):
        # The spellings the old writers stored side by side for one DNS fact.
        self._q(
            """
            MERGE (s:Subdomain {name: $sub, user_id: $u, project_id: $p})
            MERGE (i:IP {address: $ip, user_id: $u, project_id: $p})
            CREATE (s)-[:RESOLVES_TO]->(i)
            CREATE (s)-[:RESOLVES_TO {record_type: 'A',
                                      timestamp: datetime('2026-03-01T00:00:00Z'),
                                      last_seen_at: datetime('2026-03-05T00:00:00Z')}]->(i)
            CREATE (s)-[:RESOLVES_TO {record_type: 'A',
                                      timestamp: datetime('2026-01-01T00:00:00Z'),
                                      first_seen: '2020-02-02T00:00:00',
                                      last_seen: '2024-04-04T00:00:00'}]->(i)
            CREATE (s)-[:RESOLVES_TO {discovered_via: 'vhost_sni_enum'}]->(i)
            """,
            sub=sub, ip=_V4, u=uid, p=pid)

    def _node_count(self, uid):
        return self._q("MATCH (n {user_id: $u}) RETURN count(n) AS c", u=uid)[0]["c"]

    def test_fold_collapses_old_parallel_edges_keeping_every_property(self):
        self._seed_old_parallel_edges(self.uid, self.pid, self.sub)
        nodes_before = self._node_count(self.uid)

        stats = self._fold()

        edges = self._edges()
        self.assertEqual(len(edges), 1, edges)
        edge = edges[0]
        self.assertEqual(edge["record_type"], "A")
        self.assertEqual(edge["discovered_via"], "vhost_sni_enum")
        self.assertEqual(edge["first_seen"], "2020-02-02T00:00:00")
        self.assertEqual(edge["last_seen"], "2024-04-04T00:00:00")
        self.assertEqual(edge["timestamp"].iso_format()[:10], "2026-01-01", "earliest creation")
        self.assertEqual(edge["last_seen_at"].iso_format()[:10], "2026-03-05")
        self.assertEqual(stats, {"folded": 3, "pairs": 1})
        self.assertEqual(self._node_count(self.uid), nodes_before, "a fold deletes no node")

    def test_fold_never_touches_another_project(self):
        self._seed_old_parallel_edges(self.uid, self.pid, self.sub)
        self._seed_old_parallel_edges(self.uid2, self.pid2, self.sub)

        self._fold()

        self.assertEqual(len(self._edges()), 1)
        self.assertEqual(len(self._edges(uid=self.uid2, pid=self.pid2)), 4)

    def test_fold_is_idempotent(self):
        self._seed_old_parallel_edges(self.uid, self.pid, self.sub)
        self._fold()
        folded_once = self._edges()

        self.assertEqual(self._fold(), {"folded": 0, "pairs": 0})
        self.assertEqual(self._edges(), folded_once)

    def test_writers_after_the_fold_do_not_bring_a_duplicate_back(self):
        self._seed_old_parallel_edges(self.uid, self.pid, self.sub)
        self._fold()

        self._domain_discovery()
        self._shodan(reverse_dns_ip=_V4)
        self._otx("2018-01-01T00:00:00", "2026-01-01T00:00:00")
        self._vhost()
        self._ip_recon()

        edges = self._edges()
        self.assertEqual(len(edges), 1, edges)
        self.assertEqual(edges[0]["first_seen"], "2018-01-01T00:00:00")
        self.assertEqual(edges[0]["last_seen"], "2026-01-01T00:00:00")


if __name__ == "__main__":
    unittest.main()
