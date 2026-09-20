"""RESOLVES_TO identity: one edge per Subdomain -> IP pair.

The behaviour against a real database (every writer landing on one edge, the
fold keeping every property, tenant isolation) is proven in
tests/test_resolves_to_identity_graph_live.py. These cover the property-merge
rules, the fold loop, the migration marker, and the invariant every writer in
the repo must keep.

Run: python -m pytest tests/test_resolves_to_identity.py
"""

import os
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db import schema, resolves_to_identity  # noqa: E402
from graph_db.resolves_to_identity import (  # noqa: E402
    fold_resolves_to_duplicates, merge_edge_properties,
)


def _dt(day):
    return datetime(2026, 1, day, tzinfo=timezone.utc)


class TestMergeEdgeProperties(unittest.TestCase):
    def test_keeps_the_union_of_every_edges_properties(self):
        merged = merge_edge_properties([
            {"record_type": "A"},
            {"discovered_via": "vhost_sni_enum"},
            {"first_seen": "2021-03-01T00:00:00", "last_seen": "2025-06-01T00:00:00"},
        ])
        self.assertEqual(merged, {
            "record_type": "A", "discovered_via": "vhost_sni_enum",
            "first_seen": "2021-03-01T00:00:00", "last_seen": "2025-06-01T00:00:00",
        })

    def test_creation_and_first_sighting_take_the_earliest(self):
        merged = merge_edge_properties([
            {"timestamp": _dt(9), "first_seen": "2022-01-01T00:00:00"},
            {"timestamp": _dt(2), "first_seen": "2020-05-05T00:00:00"},
        ])
        self.assertEqual(merged["timestamp"], _dt(2))
        self.assertEqual(merged["first_seen"], "2020-05-05T00:00:00")

    def test_last_sighting_takes_the_latest(self):
        merged = merge_edge_properties([
            {"last_seen_at": _dt(20), "last_seen": "2025-01-01T00:00:00"},
            {"last_seen_at": _dt(3), "last_seen": "2026-02-02T00:00:00"},
        ])
        self.assertEqual(merged["last_seen_at"], _dt(20))
        self.assertEqual(merged["last_seen"], "2026-02-02T00:00:00")

    def test_an_empty_date_never_replaces_a_real_one(self):
        merged = merge_edge_properties([
            {"first_seen": "", "last_seen": ""},
            {"first_seen": "2021-01-01T00:00:00", "last_seen": "2024-01-01T00:00:00"},
            {"first_seen": "", "last_seen": ""},
        ])
        self.assertEqual(merged["first_seen"], "2021-01-01T00:00:00")
        self.assertEqual(merged["last_seen"], "2024-01-01T00:00:00")

    def test_an_empty_value_is_replaced_by_a_later_real_one(self):
        merged = merge_edge_properties([{"discovered_via": ""},
                                        {"discovered_via": "vhost_sni_enum"}])
        self.assertEqual(merged["discovered_via"], "vhost_sni_enum")

    def test_other_keys_keep_their_first_present_value(self):
        merged = merge_edge_properties([{"note": "one"}, {"note": "two"}])
        self.assertEqual(merged["note"], "one")

    def test_incomparable_values_keep_the_first(self):
        merged = merge_edge_properties([{"timestamp": _dt(5)}, {"timestamp": "2020-01-01"}])
        self.assertEqual(merged["timestamp"], _dt(5))

    def test_a_record_type_conflict_is_settled_by_the_address_family(self):
        edges = [{"record_type": "A"}, {"record_type": "AAAA"}]
        self.assertEqual(merge_edge_properties(edges, "2001:db8::10")["record_type"], "AAAA")
        self.assertEqual(merge_edge_properties(list(reversed(edges)), "192.0.2.10")["record_type"], "A")

    def test_edges_with_no_properties_merge_to_nothing(self):
        self.assertEqual(merge_edge_properties([{}, {}]), {})
        self.assertEqual(merge_edge_properties([{"first_seen": None}, None]), {})


class _Result:
    def __init__(self, rows=None, single=None):
        self._rows, self._single = rows or [], single

    def data(self):
        return self._rows

    def single(self):
        return self._single


class _FoldSession:
    """Serves `rounds` of duplicate groups, then none; the delete query reports
    how many edges it removed."""

    def __init__(self, rounds, deleted=None):
        self.rounds = list(rounds)
        self.deleted = deleted
        self.queries = []

    def run(self, query, **params):
        self.queries.append((query, params))
        if "UNWIND $work" in query:
            removed = self.deleted if self.deleted is not None else sum(
                len(w["extras"]) for w in params["work"])
            return _Result(single={"c": removed})
        return _Result(rows=self.rounds.pop(0) if self.rounds else [])


_GROUP = {"address": "192.0.2.10", "ids": ["e1", "e2", "e3"],
          "props": [{"record_type": "A"}, {}, {"discovered_via": "vhost_sni_enum"}]}


class TestFoldResolvesToDuplicates(unittest.TestCase):
    def test_the_first_edge_survives_with_the_merged_properties(self):
        session = _FoldSession([[_GROUP]])
        stats = fold_resolves_to_duplicates(session)

        work = next(p["work"] for q, p in session.queries if "UNWIND $work" in q)
        self.assertEqual(work, [{"keep": "e1", "extras": ["e2", "e3"],
                                 "props": {"record_type": "A",
                                           "discovered_via": "vhost_sni_enum"}}])
        self.assertEqual(stats, {"folded": 2, "pairs": 1})

    def test_groups_are_one_subdomain_and_one_ip(self):
        session = _FoldSession([])
        fold_resolves_to_duplicates(session)
        group_query = session.queries[0][0]
        self.assertIn("WITH s, i, collect(r) AS rels", group_query)
        self.assertIn("WHERE size(rels) > 1", group_query)

    def test_only_edges_are_deleted_never_nodes(self):
        session = _FoldSession([[_GROUP]])
        fold_resolves_to_duplicates(session)
        delete_query = next(q for q, _ in session.queries if "UNWIND $work" in q)
        self.assertIn("DELETE x", delete_query)
        self.assertNotIn("DETACH", delete_query)

    def test_scope_reaches_the_group_query(self):
        session = _FoldSession([])
        fold_resolves_to_duplicates(session, "u1", "p1")
        self.assertEqual(session.queries[0][1]["uid"], "u1")
        self.assertEqual(session.queries[0][1]["pid"], "p1")

    def test_it_loops_until_no_group_is_left(self):
        session = _FoldSession([[_GROUP], [_GROUP]])
        stats = fold_resolves_to_duplicates(session)
        self.assertEqual(stats, {"folded": 4, "pairs": 2})

    def test_a_round_that_deletes_nothing_raises_instead_of_spinning(self):
        session = _FoldSession([[_GROUP]] * 5, deleted=0)
        with self.assertRaises(RuntimeError):
            fold_resolves_to_duplicates(session)


class TestConsolidationMigration(unittest.TestCase):
    def test_a_marked_database_is_left_alone(self):
        with patch.object(schema, "_migration_applied", return_value=True), \
             patch.object(resolves_to_identity, "fold_resolves_to_duplicates") as fold:
            schema.consolidate_resolves_to_identity(MagicMock())
        fold.assert_not_called()

    def test_a_failed_fold_leaves_the_marker_unwritten_so_it_retries(self):
        with patch.object(schema, "_migration_applied", return_value=False), \
             patch.object(schema, "_mark_migration_applied") as mark, \
             patch.object(resolves_to_identity, "fold_resolves_to_duplicates",
                          side_effect=RuntimeError("boom")):
            schema.consolidate_resolves_to_identity(MagicMock())
        mark.assert_not_called()

    def test_a_clean_fold_writes_the_marker(self):
        with patch.object(schema, "_migration_applied", return_value=False), \
             patch.object(schema, "_mark_migration_applied") as mark, \
             patch.object(resolves_to_identity, "fold_resolves_to_duplicates",
                          return_value={"folded": 3, "pairs": 2}):
            schema.consolidate_resolves_to_identity(MagicMock())
        mark.assert_called_once()
        self.assertEqual(mark.call_args[0][1], schema.RESOLVES_TO_IDENTITY_MARKER)

    def test_init_schema_runs_the_consolidation(self):
        with patch.object(schema, "consolidate_resolves_to_identity") as consolidate, \
             patch.object(schema, "migrate_legacy_labels"), \
             patch.object(schema, "backfill_updated_at"), \
             patch.object(schema, "strip_reference_node_tenant"), \
             patch.object(schema, "backfill_cert_key"), \
             patch.object(schema, "consolidate_technology_identity"):
            schema.init_schema(MagicMock())
        consolidate.assert_called_once()


# A relationship pattern opening a Cypher line: `MERGE (s)-[r:RESOLVES_TO {...}]->`.
_WRITE = re.compile(
    r"^\s*(?P<verb>MERGE|CREATE)\b[^\n]*?-\[\s*\w*\s*:RESOLVES_TO\s*(?P<props>\{[^}]*\})?\s*\]",
    re.MULTILINE)
_SKIP_DIRS = {"tests", "node_modules", "_local", ".next", ".git", "whitehat.wiki"}


def _writers():
    found = []
    for root, dirs, files in os.walk(_REPO):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if not name.endswith((".py", ".ts", ".tsx")) or name.startswith("test_") \
                    or ".test." in name:
                continue
            path = Path(root) / name
            text = path.read_text(errors="ignore")
            for match in _WRITE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                found.append((f"{path.relative_to(_REPO)}:{line}",
                              match.group("verb"), match.group("props")))
    return found


class TestEveryWriterMergesTheBarePattern(unittest.TestCase):
    """A property in the MERGE pattern makes the property part of the edge's
    identity, so a writer spelling it differently adds a parallel edge."""

    @classmethod
    def setUpClass(cls):
        cls.writers = _writers()

    def test_the_scan_finds_the_writers(self):
        self.assertGreaterEqual(len(self.writers), 20,
                                f"found only {self.writers} - pattern broken?")

    def test_no_resolves_to_merge_carries_a_property_map(self):
        offenders = [w for w in self.writers if w[2]]
        self.assertEqual(offenders, [], "set RESOLVES_TO properties after the MERGE, "
                                        "never inside its pattern")

    def test_no_writer_creates_a_resolves_to_edge_unconditionally(self):
        creates = [w for w in self.writers if w[1] == "CREATE"]
        self.assertEqual(creates, [], "CREATE adds a parallel edge every run; MERGE it")


if __name__ == "__main__":
    unittest.main()
