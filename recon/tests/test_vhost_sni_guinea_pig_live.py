"""End-to-end VHost/SNI against the vhost_target guinea pig and a real Neo4j.

Everything here is real: curl probes a live nginx that serves three virtual
hosts on one address, the module classifies what comes back, and the graph
mixin writes the result. Nothing is mocked, so this is what catches a break
between "the module found it" and "the graph says something true about it".

Start the lab and point the test at it:

    cd testing/guinea_pigs/vhost_target && docker compose up -d --build
    VHOST_LAB_IP=$(docker inspect -f \
      '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
      whitehat-vhost-target)

then run this file from a container attached to whitehat-vhostlab with
VHOST_LAB_IP and the NEO4J_* variables set. It skips when either is missing.
"""

from __future__ import annotations

import os
import sys
import unittest
import uuid

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
for _p in (_project_root, _recon_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

LAB_IP = os.getenv("VHOST_LAB_IP", "").strip()
LAB_APEX = "vhostlab.test"

# In scope and never in DNS: the finding the tool exists to produce.
HIDDEN_HOST = f"admin.{LAB_APEX}"
# A second hidden panel, used where a test needs the node to exist beforehand.
SEEDED_HOST = f"jenkins.{LAB_APEX}"
# Somebody else's name on the same frontend.
COHOSTED_HOST = "partner.cohost.test"
# Configured on neither vhost, so the lab answers the baseline for all of them.
ABSENT_HOSTS = [f"www.{LAB_APEX}", f"mail.{LAB_APEX}", f"dev.{LAB_APEX}"]


def _lab_reachable() -> bool:
    if not LAB_IP:
        return False
    import socket
    try:
        with socket.create_connection((LAB_IP, 80), timeout=3):
            return True
    except OSError:
        return False


def _neo4j_available() -> bool:
    try:
        import neo4j  # noqa: F401
        from graph_db import Neo4jClient
        with Neo4jClient() as c:
            return c.verify_connection()
    except Exception:
        return False


LAB_OK = _lab_reachable()
NEO4J_OK = _neo4j_available()


@unittest.skipUnless(LAB_OK, "vhost_target guinea pig not reachable (set VHOST_LAB_IP)")
@unittest.skipUnless(NEO4J_OK, "Neo4j not reachable")
class TestVhostSniAgainstGuineaPig(unittest.TestCase):
    """One scan of the lab, then every assertion reads the graph it produced."""

    @classmethod
    def setUpClass(cls):
        from graph_db import Neo4jClient
        from recon.main_recon_modules.vhost_sni_enum import run_vhost_sni_enrichment

        cls.uid = f"test-user-{uuid.uuid4()}"
        cls.pid = f"test-project-{uuid.uuid4()}"
        cls.client = Neo4jClient()

        with cls.client.driver.session() as session:
            session.run(
                """
                MERGE (d:Domain {name: $apex, user_id: $uid, project_id: $pid})
                MERGE (i:IP {address: $lab, user_id: $uid, project_id: $pid})
                MERGE (svc:Service {ip_address: $lab, port_number: 443,
                                    user_id: $uid, project_id: $pid})
                  ON CREATE SET svc.name = 'https'
                MERGE (svc80:Service {ip_address: $lab, port_number: 80,
                                      user_id: $uid, project_id: $pid})
                  ON CREATE SET svc80.name = 'http'
                MERGE (other:IP {address: '203.0.113.77', user_id: $uid, project_id: $pid})
                MERGE (www:Subdomain {name: $www, user_id: $uid, project_id: $pid})
                  ON CREATE SET www.has_dns_records = true, www.status = 'resolved'
                MERGE (www)-[r:RESOLVES_TO]->(other)
                  ON CREATE SET r.record_type = 'A'
                """,
                apex=LAB_APEX, lab=LAB_IP, www=ABSENT_HOSTS[0],
                uid=cls.uid, pid=cls.pid,
            )
            # An edge an earlier release would have written for this very pair.
            session.run(
                """
                MERGE (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                WITH s
                MATCH (i:IP {address: $lab, user_id: $uid, project_id: $pid})
                MERGE (s)-[r:RESOLVES_TO]->(i)
                  SET r.discovered_via = 'vhost_sni_enum'
                """,
                host=SEEDED_HOST, lab=LAB_IP, uid=cls.uid, pid=cls.pid,
            )

        combined = {
            "domain": LAB_APEX,
            "metadata": {"target": LAB_APEX},
            "port_scan": {
                "by_host": {
                    LAB_IP: {
                        "ip": LAB_IP,
                        "ports": [
                            {"port": 80, "scheme": "http"},
                            {"port": 443, "scheme": "https"},
                        ],
                    }
                }
            },
        }
        settings = {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_TEST_L7": True,
            "VHOST_SNI_TEST_L4": True,
            # A fixed candidate list keeps the run quick and the assertions exact;
            # the 2400-entry default wordlist is exercised by the module's own tests.
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_CUSTOM_WORDLIST": "\n".join(
                [HIDDEN_HOST, SEEDED_HOST, COHOSTED_HOST] + ABSENT_HOSTS
            ),
            "VHOST_SNI_INJECT_DISCOVERED": True,
            "VHOST_SNI_TIMEOUT": 5,
        }

        run_vhost_sni_enrichment(combined, settings=settings)
        cls.result = combined.get("vhost_sni") or {}
        cls.findings = cls.result.get("findings") or []
        cls.stats = cls.client.update_graph_from_vhost_sni(combined, cls.uid, cls.pid)

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.client.driver.session() as session:
                session.run(
                    "MATCH (n {user_id: $uid, project_id: $pid}) DETACH DELETE n",
                    uid=cls.uid, pid=cls.pid,
                )
        finally:
            cls.client.close()

    def _one(self, cypher, **kw):
        with self.client.driver.session() as session:
            return session.run(cypher, uid=self.uid, pid=self.pid, **kw).single()

    # -- what the probe itself found -------------------------------------
    def test_the_hidden_vhost_is_discovered(self):
        hosts = {f.get("hostname") for f in self.findings}
        self.assertIn(HIDDEN_HOST, hosts, f"probe returned: {sorted(hosts)}")

    def test_hosts_the_lab_does_not_serve_are_not_reported(self):
        hosts = {f.get("hostname") for f in self.findings}
        for absent in ABSENT_HOSTS:
            self.assertNotIn(absent, hosts, "baseline responses must not become findings")

    # -- the DNS claim this change is about ------------------------------
    def test_no_dns_edge_is_invented_for_the_hidden_vhost(self):
        rec = self._one(
            """
            MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                  -[r:RESOLVES_TO]->(:IP {address: $lab})
            RETURN count(r) AS c
            """,
            host=HIDDEN_HOST, lab=LAB_IP,
        )
        self.assertEqual(rec["c"], 0, "answering a Host header is not a DNS record")

    def test_the_edge_an_earlier_release_wrote_is_repaired(self):
        self.assertGreaterEqual(self.stats["stale_dns_edges_removed"], 1)

    def test_a_real_dns_edge_is_left_alone(self):
        rec = self._one(
            """
            MATCH (s:Subdomain {name: $www, user_id: $uid, project_id: $pid})
                  -[r:RESOLVES_TO]->(i:IP)
            RETURN collect(i.address) AS ips, collect(r.record_type) AS types
            """,
            www=ABSENT_HOSTS[0],
        )
        self.assertEqual(rec["ips"], ["203.0.113.77"])
        self.assertEqual(rec["types"], ["A"])

    # -- the finding still has to be reachable ---------------------------
    def test_in_scope_hidden_vhost_owns_its_finding_and_is_flagged_unconfirmed(self):
        rec = self._one(
            """
            MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                  -[:HAS_VULNERABILITY]->(v:Vulnerability {source: 'vhost_sni_enum'})
            RETURN s.has_dns_records AS dns, s.vhost_hidden AS hidden,
                   v.severity AS severity, count(v) AS c
            """,
            host=HIDDEN_HOST,
        )
        self.assertIsNotNone(rec, "the hidden vhost finding is unreachable in the graph")
        self.assertIs(rec["dns"], False)
        self.assertIs(rec["hidden"], True)
        self.assertGreaterEqual(rec["c"], 1)

    def test_in_scope_hidden_vhost_hangs_under_its_domain(self):
        rec = self._one(
            """
            MATCH (:Domain {name: $apex, user_id: $uid, project_id: $pid})
                  -[:HAS_SUBDOMAIN]->(s:Subdomain {name: $host})
            RETURN count(s) AS c
            """,
            apex=LAB_APEX, host=HIDDEN_HOST,
        )
        self.assertEqual(rec["c"], 1)

    def test_documented_hidden_admin_panel_query_finds_it(self):
        rec = self._one(
            """
            MATCH (s:Subdomain {user_id: $uid, project_id: $pid})
                  -[:HAS_VULNERABILITY]->(v:Vulnerability {source: 'vhost_sni_enum'})
            WHERE v.internal_pattern_match IS NOT NULL
            RETURN collect(DISTINCT s.name) AS hosts
            """
        )
        self.assertIn(HIDDEN_HOST, rec["hosts"])

    # -- the co-hosted third party ---------------------------------------
    def test_cohosted_name_is_not_added_to_our_inventory(self):
        rec = self._one(
            """
            MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
            RETURN count(s) AS c
            """,
            host=COHOSTED_HOST,
        )
        self.assertEqual(rec["c"], 0)

    def test_cohosted_finding_still_hangs_off_the_ip(self):
        rec = self._one(
            """
            MATCH (:IP {address: $lab, user_id: $uid, project_id: $pid})
                  -[:HAS_VULNERABILITY]->(v:Vulnerability {source: 'vhost_sni_enum'})
            WHERE v.hostname = $host
            RETURN count(v) AS c
            """,
            lab=LAB_IP, host=COHOSTED_HOST,
        )
        self.assertGreaterEqual(rec["c"], 1, "a finding nothing points at is lost")

    # -- nothing is left floating ----------------------------------------
    def test_no_vhost_node_is_left_without_an_owner(self):
        rec = self._one(
            """
            MATCH (n {user_id: $uid, project_id: $pid})
            WHERE (n:Vulnerability AND n.source = 'vhost_sni_enum')
               OR (n:BaseURL AND n.discovery_source = 'vhost_sni_enum')
            WITH n WHERE NOT ()-->(n)
            RETURN collect(coalesce(n.url, n.id)) AS orphans
            """
        )
        self.assertEqual(rec["orphans"], [], "every finding must be reachable")

    def test_discovered_baseurl_is_owned_by_the_hidden_vhost(self):
        rec = self._one(
            """
            MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                  -[:HAS_BASE_URL]->(b:BaseURL)
            RETURN collect(b.url) AS urls
            """,
            host=HIDDEN_HOST,
        )
        self.assertTrue(rec["urls"], "downstream tools reach the vhost through this URL")

    # -- re-running must not drift ---------------------------------------
    def test_second_run_is_idempotent(self):
        before = self._one(
            """
            MATCH (n {user_id: $uid, project_id: $pid})
            OPTIONAL MATCH (n)-[r]->()
            RETURN count(DISTINCT n) AS nodes, count(r) AS rels
            """
        )
        self.client.update_graph_from_vhost_sni(
            {"domain": LAB_APEX, "vhost_sni": self.result}, self.uid, self.pid,
        )
        after = self._one(
            """
            MATCH (n {user_id: $uid, project_id: $pid})
            OPTIONAL MATCH (n)-[r]->()
            RETURN count(DISTINCT n) AS nodes, count(r) AS rels
            """
        )
        self.assertEqual((before["nodes"], before["rels"]), (after["nodes"], after["rels"]))


if __name__ == "__main__":
    unittest.main()
