"""Technology identity: write-time resolution and the one-time duplicate fold.

The behaviour against a real database (edges and provenance surviving a fold,
a GVM rescan sparing httpx's edges, tenant isolation) is proven in
tests/test_technology_identity_graph_live.py. These cover the logic around the
Cypher and the invariants every writer must keep.

Run: python -m pytest tests/test_technology_identity.py
"""

import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db import schema, technology_identity  # noqa: E402
from graph_db.technology_identity import (  # noqa: E402
    fold_technology_duplicates, resolve_tech_name, tech_name_key,
)


class FakeResult:
    def __init__(self, single=None, rows=None):
        self._single = single
        self._rows = rows or []

    def single(self):
        return self._single

    def data(self):
        return self._rows


class FakeSession:
    """Answers each query by the first `(marker, result)` whose marker it contains."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.queries = []

    def run(self, query, **params):
        self.queries.append((query, params))
        for marker, result in self.answers:
            if marker in query:
                return result
        return FakeResult()


class TestResolveTechName(unittest.TestCase):
    def test_returns_the_spelling_already_in_the_project(self):
        session = FakeSession([("AS name", FakeResult({"name": "Amazon CloudFront"}))])
        self.assertEqual(resolve_tech_name(session, "Amazon Cloudfront", "u1", "p1"),
                         "Amazon CloudFront")

    def test_a_new_product_keeps_its_own_name(self):
        self.assertEqual(resolve_tech_name(FakeSession(), "Qdrant", "u1", "p1"), "Qdrant")

    def test_an_empty_name_queries_nothing(self):
        session = FakeSession()
        self.assertEqual(resolve_tech_name(session, "", "u1", "p1"), "")
        self.assertEqual(session.queries, [])

    def test_lookup_is_scoped_to_the_tenant_and_prefers_an_exact_match(self):
        session = FakeSession()
        resolve_tech_name(session, " Nginx ", "u1", "p1")
        query, params = session.queries[0]
        self.assertIn("{user_id: $uid, project_id: $pid}", query)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))
        self.assertEqual(params["key"], "nginx")
        self.assertIn("ORDER BY t.name = $name DESC", query)

    def test_key_ignores_case_and_surrounding_space(self):
        self.assertEqual(tech_name_key("  Amazon CloudFront "), tech_name_key("amazon cloudfront"))
        self.assertEqual(tech_name_key(None), "")


class TestFoldTechnologyDuplicates(unittest.TestCase):
    def _fold(self, groups, **scope):
        session = FakeSession([("RETURN uid, pid, name_key, ids", FakeResult(rows=groups)),
                               ("AS c", FakeResult({"c": 0}))])
        with patch.object(technology_identity, "absorb_technology",
                          return_value=True) as absorb:
            stats = fold_technology_duplicates(session, **scope)
        return session, absorb, stats

    def test_every_other_node_folds_into_the_first_within_its_own_tenant(self):
        groups = [{"uid": "u1", "pid": "p1", "name_key": "nginx", "ids": ["a", "b", "c"]},
                  {"uid": "u2", "pid": "p2", "name_key": "nginx", "ids": ["d", "e"]}]
        session, absorb, stats = self._fold(groups)
        self.assertEqual([c.args[1:5] for c in absorb.call_args_list],
                         [("b", "a", "u1", "p1"), ("c", "a", "u1", "p1"),
                          ("e", "d", "u2", "p2")])
        self.assertEqual(stats, {"folded": 3, "versioned": 0})

    def test_groups_are_keyed_by_tenant_and_prefer_a_versioned_survivor(self):
        session, _, _ = self._fold([])
        query = session.queries[0][0]
        self.assertIn("WITH uid, pid, name_key, version, collect(elementId(t))", query)
        self.assertIn("ORDER BY t.version IS NULL, COUNT { (t)--() } DESC", query)

    def test_scope_reaches_both_queries(self):
        session, _, _ = self._fold([], user_id="u1", project_id="p1")
        for query, params in session.queries:
            self.assertIn("$uid IS NULL OR t.user_id = $uid", query)
            self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))


class TestConsolidationMigration(unittest.TestCase):
    def test_a_marked_database_is_left_alone(self):
        session = FakeSession([("WhiteHatSchemaMigration {id: $id}) RETURN", FakeResult({"c": 1}))])
        with patch.object(technology_identity, "fold_technology_duplicates") as fold:
            schema.consolidate_technology_identity(session)
        fold.assert_not_called()

    def test_a_failed_fold_leaves_the_marker_unwritten_so_it_retries(self):
        session = FakeSession([("RETURN count(m)", FakeResult({"c": 0}))])
        with patch.object(technology_identity, "fold_technology_duplicates",
                          side_effect=RuntimeError("boom")):
            schema.consolidate_technology_identity(session)
        self.assertFalse([q for q, _ in session.queries if q.startswith("MERGE (m:WhiteHatSchemaMigration")])

    def test_a_clean_fold_writes_the_marker(self):
        session = FakeSession([("RETURN count(m)", FakeResult({"c": 0}))])
        with patch.object(technology_identity, "fold_technology_duplicates",
                          return_value={"folded": 0, "versioned": 0}):
            schema.consolidate_technology_identity(session)
        marks = [p for q, p in session.queries if q.startswith("MERGE (m:WhiteHatSchemaMigration")]
        self.assertEqual(marks, [{"id": schema.TECH_IDENTITY_MARKER}])


class TestAbsorbQueries(unittest.TestCase):
    def _queries(self):
        session = FakeSession([("AS absorbed", FakeResult({"absorbed": 1}))])
        technology_identity.absorb_technology(session, "old", "new", "u1", "p1")
        return [q for q, _ in session.queries]

    def test_gvm_is_listed_last_in_the_folded_detected_by(self):
        # clear_gvm_data strips ',gvm'; a leading 'gvm,' would survive it.
        fold = next(q for q in self._queries() if "new.detected_by" in q)
        self.assertIn("[d IN seen WHERE d <> 'gvm'] + [d IN seen WHERE d = 'gvm']", fold)

    def test_a_fold_never_stamps_updated_at(self):
        for query in self._queries():
            self.assertNotIn("updated_at = datetime()", query)


_TECH_MERGE = re.compile(r"MERGE \(\w+:Technology \{([^}]*)\}")


class TestEveryWriterKeysTheFullIdentity(unittest.TestCase):
    """A MERGE without `version` creates a NULL-version node the uniqueness
    constraint ignores; one without the tenant keys merges across projects."""

    def test_every_technology_merge_names_version_and_both_tenant_keys(self):
        merges = []
        for path in (Path(_REPO) / "graph_db").rglob("*.py"):
            for match in _TECH_MERGE.finditer(path.read_text()):
                merges.append((path.name, match.group(1)))
        self.assertGreater(len(merges), 5, "the scan found no writers - pattern broken?")
        for name, body in merges:
            self.assertIn("version:", body, f"{name}: MERGE (:Technology {{{body}}})")
            self.assertRegex(body, r"user_id:", name)
            self.assertRegex(body, r"project_id:", name)


if __name__ == "__main__":
    unittest.main()
