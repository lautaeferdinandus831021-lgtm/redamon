"""LIVE-Neo4j proof that one product is one Technology node, and that folding
two nodes into one never costs another scanner's findings.

  * httpx and Wappalyzer spelling a product differently land on one node;
  * the AI write paths no longer create a NULL-version node;
  * folding keeps every edge with its properties and unions detected_by, so a
    GVM rescan (clear_gvm_data) afterwards still spares what httpx/nmap found;
  * a fold never touches another project and never bumps updated_at.

Self-skips unless the neo4j driver imports AND a database answers. Everything
it writes is under a random tenant and is deleted afterwards. To run it:

  docker run --rm --network whitehat-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    whitehat-agent python -m pytest tests/test_technology_identity_graph_live.py -v
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
_URL = "https://app.example.test/"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestTechnologyIdentityLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        from graph_db import technology_identity
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.identity = technology_identity

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"techid-{run}", f"TECHID_{run}"
        self.uid2, self.pid2 = f"techid2-{run}", f"TECHID2_{run}"
        self.cve = f"CVE-2099-{run}"

    def tearDown(self):
        self._q("MATCH (n) WHERE n.user_id IN [$u, $u2] DETACH DELETE n",
                u=self.uid, u2=self.uid2)
        self._q("MATCH (c:CVE {id: $cve}) DETACH DELETE c", cve=self.cve)

    def _q(self, cypher, **params):
        with self.client.driver.session() as s:
            return [r.data() for r in s.run(cypher, **params)]

    def _techs(self, uid=None, pid=None):
        return self._q(
            """
            MATCH (t:Technology {user_id: $u, project_id: $p})
            RETURN t.name AS name, t.version AS version, t.detected_by AS detected_by,
                   t.category AS category, t.updated_at AS updated_at,
                   COUNT { (t)--() } AS degree
            ORDER BY name
            """,
            u=uid or self.uid, p=pid or self.pid)

    def _fold(self, uid=None, pid=None):
        with self.client.driver.session() as s:
            return self.identity.fold_technology_duplicates(
                s, uid or self.uid, pid or self.pid)

    def _seed_gvm_and_httpx_nginx(self):
        # GVM's cpe_resolver title-case fallback vs httpx's spelling.
        self._q(
            """
            CREATE (ip:IP {address: '10.0.0.7', user_id: $u, project_id: $p})
            CREATE (b:BaseURL {url: 'https://c.example.test', user_id: $u, project_id: $p})
            CREATE (g:Technology {name: 'Nginx', version: '', user_id: $u, project_id: $p,
                                  detected_by: 'gvm', cpe: 'cpe:/a:f5:nginx'})
            CREATE (h:Technology {name: 'nginx', version: '', user_id: $u, project_id: $p,
                                  detected_by: 'httpx'})
            CREATE (ip)-[:USES_TECHNOLOGY {detected_by: 'gvm'}]->(g)
            CREATE (b)-[:USES_TECHNOLOGY {detected_by: 'httpx'}]->(h)
            MERGE (c:CVE {id: $cve})
            CREATE (h)-[:HAS_KNOWN_CVE]->(c)
            CREATE (g)-[:HAS_KNOWN_CVE]->(c)
            WITH g
            UNWIND range(1, 3) AS i
            CREATE (v:Vulnerability {id: $u + '-v' + i, source: 'gvm',
                                     user_id: $u, project_id: $p})
            CREATE (g)-[:HAS_VULNERABILITY]->(v)
            """,
            u=self.uid, p=self.pid, cve=self.cve)

    # -- write time ----------------------------------------------------------

    def test_resolve_name_reuses_this_projects_spelling_only(self):
        self._q("CREATE (:Technology {name: 'Amazon CloudFront', version: '', "
                "user_id: $u, project_id: $p})", u=self.uid, p=self.pid)
        with self.client.driver.session() as s:
            here = self.identity.resolve_tech_name(s, " amazon cloudfront", self.uid, self.pid)
            there = self.identity.resolve_tech_name(s, "Amazon Cloudfront", self.uid2, self.pid2)
        self.assertEqual(here, "Amazon CloudFront")
        self.assertEqual(there, "Amazon Cloudfront", "another project's spelling leaked in")

    def test_httpx_and_wappalyzer_spellings_land_on_one_node(self):
        recon = {"http_probe": {
            "by_url": {_URL: {"host": "app.example.test", "status_code": 200,
                              "technologies": ["Amazon CloudFront"]}},
            "wappalyzer": {"by_url": {_URL: [{"name": "Amazon Cloudfront", "version": None}]},
                           "all_technologies": {}},
        }}
        stats = self.client.update_graph_from_http_probe(recon, self.uid, self.pid)
        self.assertEqual(stats["errors"], [])
        # A second scan where Wappalyzer's spelling arrives first on its own.
        recon["http_probe"]["by_url"][_URL]["technologies"] = []
        self.client.update_graph_from_http_probe(recon, self.uid, self.pid)

        techs = self._techs()
        self.assertEqual([t["name"] for t in techs], ["Amazon CloudFront"])
        self.assertEqual(techs[0]["version"], "")

    def test_ai_detection_writes_a_version(self):
        recon = {"http_probe": {
            "by_url": {_URL: {"host": "app.example.test", "status_code": 200,
                              "ai_framework_name": "Ollama",
                              "ai_framework_category": "ai-llm",
                              "is_ai_framework_detected": True}},
            "wappalyzer": {},
        }}
        stats = self.client.update_graph_from_http_probe(recon, self.uid, self.pid)
        self.assertEqual(stats["errors"], [])
        techs = self._techs()
        self.assertEqual(len(techs), 1)
        self.assertEqual(techs[0]["version"], "",
                         "a NULL version escapes the uniqueness constraint")
        self.assertEqual(techs[0]["category"], "ai-llm")

    def test_versioned_detection_absorbs_twin_with_its_edge_properties(self):
        self._q(
            """
            CREATE (p:Port {number: 443, protocol: 'tcp', ip_address: '10.0.0.8',
                            user_id: $u, project_id: $p})
            CREATE (t:Technology {name: 'nginx', version: '', user_id: $u, project_id: $p})
            CREATE (p)-[:USES_TECHNOLOGY {detected_by: 'nmap', confidence: 90}]->(t)
            """, u=self.uid, p=self.pid)
        with self.client.driver.session() as s:
            self.identity.resolve_tech_version(s, "nginx", "1.24.0", self.uid, self.pid)
        edges = self._q(
            "MATCH (:Port {user_id: $u})-[r:USES_TECHNOLOGY]->(t:Technology) "
            "RETURN t.version AS version, properties(r) AS props", u=self.uid)
        self.assertEqual(edges, [{"version": "1.24.0",
                                  "props": {"detected_by": "nmap", "confidence": 90}}])

    # -- folding existing duplicates -----------------------------------------

    def test_fold_keeps_edges_and_a_gvm_rescan_spares_httpx(self):
        self._seed_gvm_and_httpx_nginx()
        before = {t["name"]: t["updated_at"] for t in self._techs()}
        self.assertEqual(self._fold()["folded"], 1)

        techs = self._techs()
        self.assertEqual(len(techs), 1)
        survivor = techs[0]
        self.assertEqual(survivor["detected_by"], "httpx,gvm")
        self.assertEqual(survivor["updated_at"], before[survivor["name"]],
                         "a fold is not a sighting")
        # 3 vulns + IP edge + BaseURL edge + ONE CVE link (the two were identical)
        self.assertEqual(survivor["degree"], 6)

        self.client.clear_gvm_data(self.uid, self.pid)
        after = self._q(
            """
            MATCH (t:Technology {user_id: $u, project_id: $p})
            RETURN t.detected_by AS detected_by, t.cpe AS cpe,
                   [(b:BaseURL)-[:USES_TECHNOLOGY]->(t) | b.url] AS baseurls,
                   [(t)-[:HAS_KNOWN_CVE]->(c) | c.id] AS cves,
                   [(i:IP)-[:USES_TECHNOLOGY]->(t) | i.address] AS gvm_ips
            """, u=self.uid, p=self.pid)
        self.assertEqual(after, [{"detected_by": "httpx", "cpe": None,
                                  "baseurls": ["https://c.example.test"],
                                  "cves": [self.cve], "gvm_ips": []}])

    def test_fold_keeps_parallel_edges_that_differ_in_provenance(self):
        self._q(
            """
            CREATE (p:Port {number: 443, protocol: 'tcp', ip_address: '10.0.0.8',
                            user_id: $u, project_id: $p})
            CREATE (h:Technology {name: 'OpenSSL', version: '', user_id: $u,
                                  project_id: $p, detected_by: 'httpx'})
            CREATE (g:Technology {name: 'Openssl', version: '', user_id: $u,
                                  project_id: $p, detected_by: 'gvm'})
            CREATE (p)-[:USES_TECHNOLOGY {detected_by: 'nmap', confidence: 90}]->(h)
            CREATE (p)-[:USES_TECHNOLOGY {detected_by: 'gvm'}]->(g)
            """, u=self.uid, p=self.pid)
        self._fold()
        self.client.clear_gvm_data(self.uid, self.pid)
        edges = self._q(
            "MATCH (:Port {user_id: $u})-[r:USES_TECHNOLOGY]->(:Technology) "
            "RETURN properties(r) AS props", u=self.uid)
        self.assertEqual(edges, [{"props": {"detected_by": "nmap", "confidence": 90}}])

    def test_fold_turns_a_null_version_into_empty_and_merges_its_twin(self):
        self._q(
            """
            CREATE (a:Technology {name: 'Ollama', user_id: $u, project_id: $p,
                                  category: 'ai-llm'})
            CREATE (b:Technology {name: 'Ollama', version: '', user_id: $u, project_id: $p})
            CREATE (:Port {number: 11434, user_id: $u, project_id: $p})-[:HAS_TECHNOLOGY]->(a)
            CREATE (:Endpoint {path: '/', user_id: $u, project_id: $p})-[:USES_TECHNOLOGY]->(b)
            CREATE (:Technology {name: 'Qdrant', user_id: $u, project_id: $p})
            """, u=self.uid, p=self.pid)
        stats = self._fold()
        self.assertEqual(stats, {"folded": 1, "versioned": 1})
        techs = self._techs()
        self.assertEqual([(t["name"], t["version"], t["degree"]) for t in techs],
                         [("Ollama", "", 2), ("Qdrant", "", 0)])
        self.assertEqual(techs[0]["category"], "ai-llm", "a property only the folded node had")

    def test_fold_never_touches_another_project(self):
        # Same user, two projects: the project-less fold below then groups
        # across projects without reaching any data this test did not write.
        for pid in (self.pid, self.pid2):
            self._q(
                """
                CREATE (e:Endpoint {path: '/', user_id: $u, project_id: $p})
                CREATE (a:Technology {name: 'Amazon CloudFront', version: '', user_id: $u, project_id: $p})
                CREATE (b:Technology {name: 'Amazon Cloudfront', version: '', user_id: $u, project_id: $p})
                CREATE (e)-[:USES_TECHNOLOGY]->(a)
                CREATE (e)-[:USES_TECHNOLOGY {detected_by: 'wappalyzer'}]->(b)
                """, u=self.uid, p=pid)
        self._fold()
        self.assertEqual(len(self._techs()), 1)
        self.assertEqual(len(self._techs(self.uid, self.pid2)), 2)

        with self.client.driver.session() as s:
            self.identity.fold_technology_duplicates(s, user_id=self.uid)
        self.assertEqual(len(self._techs(self.uid, self.pid2)), 1)
        crossing = self._q(
            """
            MATCH (a {user_id: $u})-[r]-(b {user_id: $u})
            WHERE a.project_id <> b.project_id
            RETURN count(r) AS n
            """, u=self.uid)
        self.assertEqual(crossing, [{"n": 0}])

    def test_fold_is_idempotent(self):
        self._seed_gvm_and_httpx_nginx()
        self._fold()
        self.assertEqual(self._fold(), {"folded": 0, "versioned": 0})


if __name__ == "__main__":
    unittest.main()
