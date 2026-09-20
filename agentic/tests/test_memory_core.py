"""The memory core: store, scoring/lifecycle, hybrid search, entities, timeline.

What is pinned here is the behaviour the memory subsystem is worth having for:

* a repeat of the same observation REINFORCES one memory instead of piling up
  near-duplicates (the failure mode that makes a memory store useless after a
  few sessions);
* memory is project-scoped on every read and every write - one engagement's
  findings must never surface in another's prompt;
* confidence is earned and spent, not a boolean;
* a recall can reach a memory that shares no keyword with the query, but ONLY
  through a real graph edge - never by guessing;
* the timeline is append-only and keeps what the current text no longer shows.

Stdlib only: this file must run without the agent's third-party deps.
"""
import os
import sys
import tempfile
import time
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from memory import entities, scoring, search, timeline  # noqa: E402
from memory.models import (  # noqa: E402
    EVENT_DECAYED,
    EVENT_REINFORCED,
    KIND_LESSON,
    KIND_OBSERVATION,
    STATE_ACTIVE,
    STATE_ARCHIVED,
    STATE_CANDIDATE,
)
from memory.store import MemoryStore, dedup_key  # noqa: E402


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self._tmp.name, "memory.db")
        self.store = MemoryStore(self.db)

    def tearDown(self):
        self._tmp.cleanup()


class StoreWriteTests(_StoreCase):
    def test_a_new_observation_is_created_once(self):
        rec, created = self.store.upsert(
            project_id="p1", kind=KIND_OBSERVATION, text="nmap found port 8080 open",
        )
        self.assertTrue(created)
        self.assertEqual(rec.uses, 0)
        self.assertEqual(rec.state, STATE_CANDIDATE)
        self.assertEqual(self.store.stats("p1")["memories"], 1)

    def test_a_repeat_reinforces_instead_of_duplicating(self):
        first, _ = self.store.upsert(
            project_id="p1", kind=KIND_OBSERVATION, text="nmap found port 8080 open",
        )
        second, created = self.store.upsert(
            # Differing only in whitespace case: still the SAME memory.
            project_id="p1", kind=KIND_OBSERVATION, text="  Nmap   found port 8080 open ",
        )
        self.assertFalse(created)
        self.assertEqual(second.memory_id, first.memory_id)
        # `seen` counts re-observations, `uses` counts recalls: a repeat is
        # evidence that the outcome happened again, not that it was recalled.
        self.assertEqual(second.seen, 1)
        self.assertEqual(second.uses, 0)
        self.assertGreater(second.confidence, first.confidence)
        self.assertEqual(self.store.stats("p1")["memories"], 1)

        events = self.store.events("p1", memory_id=first.memory_id)
        self.assertIn(EVENT_REINFORCED, [e.event_type for e in events])

    def test_different_projects_never_share_a_memory(self):
        self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="admin panel at /admin")
        self.store.upsert(project_id="p2", kind=KIND_OBSERVATION, text="admin panel at /admin")

        p1 = self.store.candidates("p1")
        p2 = self.store.candidates("p2")
        self.assertEqual(len(p1), 1)
        self.assertEqual(len(p2), 1)
        # Same text, different rows: the dedup key is scoped by project.
        self.assertNotEqual(p1[0].memory_id, p2[0].memory_id)
        self.assertEqual(dedup_key("x", "y"), dedup_key("x", "y"))

    def test_project_id_is_mandatory(self):
        with self.assertRaises(ValueError):
            self.store.upsert(project_id="", kind=KIND_OBSERVATION, text="orphan")
        with self.assertRaises(ValueError):
            self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="   ")

    def test_an_archived_memory_returns_as_a_candidate_when_seen_again(self):
        rec, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="WAF blocks POST")
        self.store.set_state(rec, STATE_ARCHIVED, "archived", detail="decayed")
        again, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="WAF blocks POST")
        # Evidence that it was archived too early: it gets to earn its place again.
        self.assertNotEqual(again.state, STATE_ARCHIVED)

    def test_touch_raises_confidence_and_promotes(self):
        rec, _ = self.store.upsert(
            project_id="p1", kind=KIND_LESSON, text="Use the legacy KEX flag on the jump host",
        )
        before = rec.confidence
        for _ in range(3):
            self.store.touch(rec)
        self.assertGreater(rec.confidence, before)
        self.assertEqual(rec.uses, 3)
        self.assertEqual(rec.state, STATE_ACTIVE)

    def test_confidence_and_state_changes_are_evented(self):
        rec, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="timeout on /slow")
        self.store.set_confidence(rec, 0.05, EVENT_DECAYED, detail="idle 90d")
        self.assertEqual(rec.state, STATE_ARCHIVED)
        kinds = [e.event_type for e in self.store.events("p1", memory_id=rec.memory_id)]
        self.assertIn(EVENT_DECAYED, kinds)

    def test_edges_link_only_within_the_project(self):
        a, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="host A open")
        b, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="host B open")
        self.store.add_edge("p1", a.memory_id, b.memory_id, "shares_entity", 2.0)
        self.store.add_edge("p1", a.memory_id, b.memory_id, "shares_entity", 1.0)

        neighbours = self.store.neighbors("p1", [a.memory_id, b.memory_id])
        self.assertEqual(neighbours[a.memory_id][0][0], b.memory_id)
        # Repeated evidence accumulates weight rather than adding a parallel edge.
        self.assertEqual(neighbours[a.memory_id][0][1], 3.0)
        self.assertEqual(self.store.neighbors("p2", [a.memory_id]), {})

    def test_no_self_edges(self):
        a, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="solo")
        self.store.add_edge("p1", a.memory_id, a.memory_id)
        self.assertEqual(self.store.stats("p1")["edges"], 0)


class ScoringTests(unittest.TestCase):
    def test_reinforcement_is_bounded_and_asymptotic(self):
        self.assertLess(scoring.reinforce(0.9, 0.15), 1.0)
        self.assertGreater(scoring.reinforce(0.9, 0.15), 0.9)
        self.assertEqual(scoring.reinforce(1.0, 0.15), 1.0)

    def test_decay_halves_over_one_half_life(self):
        self.assertAlmostEqual(scoring.decay(1.0, 30.0, 30.0), 0.5, places=6)
        self.assertAlmostEqual(scoring.decay(1.0, 60.0, 30.0), 0.25, places=6)
        # No idle time, no decay.
        self.assertEqual(scoring.decay(0.4, 0.0, 30.0), 0.4)

    def test_decay_never_reaches_zero(self):
        self.assertGreaterEqual(scoring.confidence_after_decay(0.1, 10_000.0), 0.01)

    def test_a_distilled_lesson_starts_above_a_raw_observation(self):
        lesson = scoring.initial_confidence(KIND_LESSON, "heuristic", "nuclei is unreliable here")
        observation = scoring.initial_confidence(KIND_OBSERVATION, "redamon", "nuclei ran")
        self.assertGreater(lesson, observation)

    def test_an_empty_memory_starts_weaker(self):
        self.assertLess(
            scoring.initial_confidence(KIND_OBSERVATION, "redamon", "hi"),
            scoring.initial_confidence(KIND_OBSERVATION, "redamon", "a real observation"),
        )

    def test_weak_memory_is_archived_and_used_memory_becomes_active(self):
        self.assertEqual(
            scoring.next_state(0.05, 0, 0.0, archive_max_confidence=0.15), STATE_ARCHIVED,
        )
        self.assertEqual(
            scoring.next_state(0.6, 2, 0.0, active_min_confidence=0.35), STATE_ACTIVE,
        )
        self.assertEqual(
            scoring.next_state(0.5, 0, 0.0, active_min_confidence=0.35), STATE_CANDIDATE,
        )


class SearchTests(unittest.TestCase):
    def _records(self):
        store = MemoryStore(os.path.join(tempfile.mkdtemp(), "m.db"))
        a, _ = store.upsert(
            project_id="p1", kind=KIND_OBSERVATION,
            text="nuclei returned 403 on the login endpoint behind the WAF",
            entities=("nuclei", "login.example.com"),
        )
        b, _ = store.upsert(
            project_id="p1", kind=KIND_OBSERVATION,
            text="the edge rewrites unusual user agents before serving",
            entities=("nuclei",),
            confidence=0.5,
        )
        c, _ = store.upsert(
            project_id="p1", kind=KIND_OBSERVATION, text="unrelated note about DNS records",
        )
        return store, a, b, c

    def test_keyword_recall_finds_the_matching_memory(self):
        _store, a, b, _c = self._records()
        hits = search.search([a, b], "nuclei 403 login", limit=5)
        self.assertTrue(hits)
        self.assertEqual(hits[0].record.memory_id, a.memory_id)

    def test_an_empty_query_ranks_by_confidence(self):
        _store, a, b, _c = self._records()
        hits = search.search([a, b], "", limit=5)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0].why, "ranked by confidence")

    def test_no_keyword_overlap_means_no_result(self):
        _store, a, _b, _c = self._records()
        self.assertEqual(search.search([a], "kerberoasting ldap", limit=5), [])

    def test_archived_memories_are_not_recalled_by_default(self):
        store, a, _b, _c = self._records()
        store.set_state(a, STATE_ARCHIVED, "archived", detail="superseded")
        self.assertEqual(search.search([a], "nuclei 403 login", limit=5), [])

    def test_confidence_breaks_a_tie_between_equal_matches(self):
        store = MemoryStore(os.path.join(tempfile.mkdtemp(), "m.db"))
        strong, _ = store.upsert(
            project_id="p1", kind=KIND_OBSERVATION,
            text="nuclei run reported 403 on the login endpoint",
        )
        weak, _ = store.upsert(
            project_id="p1", kind=KIND_OBSERVATION,
            text="nuclei run reported 403 on the login endpoint too",
        )
        # Identical token overlap, so only confidence can decide the order.
        strong.confidence, weak.confidence = 0.9, 0.2
        hits = search.search([weak, strong], "nuclei 403 login", limit=5)
        self.assertEqual(hits[0].record.memory_id, strong.memory_id)

    def test_high_confidence_cannot_invent_a_match(self):
        store = MemoryStore(os.path.join(tempfile.mkdtemp(), "m.db"))
        strong, _ = store.upsert(
            project_id="p1", kind=KIND_OBSERVATION, text="the edge rewrites user agents",
        )
        strong.confidence = 1.0
        self.assertEqual(search.search([strong], "kerberoasting ldap", limit=5), [])

    def test_graph_fusion_reaches_a_memory_with_no_keyword_overlap(self):
        _store, a, b, _c = self._records()
        without = search.smart_search([a, b], "nuclei 403 login", limit=5)
        self.assertNotIn(b.memory_id, [s.record.memory_id for s in without])

        with_graph = search.smart_search(
            [a, b], "nuclei 403 login", limit=5,
            neighbors={a.memory_id: [(b.memory_id, 1.0)]},
        )
        self.assertIn(b.memory_id, [s.record.memory_id for s in with_graph])

    def test_entity_bias_pulls_in_a_named_host(self):
        _store, a, b, _c = self._records()
        hits = search.smart_search(
            [a, b], "completely different words", limit=5, entities=("nuclei",),
        )
        self.assertEqual({s.record.memory_id for s in hits}, {a.memory_id, b.memory_id})

    def test_empty_pool_is_not_an_error(self):
        self.assertEqual(search.search([], "anything", limit=5), [])
        self.assertEqual(search.smart_search([], "anything", limit=5), [])


class EntityTests(unittest.TestCase):
    def test_it_pulls_facts_and_tool_names(self):
        found = entities.extract_entities(
            "10.0.0.5:8443 and api.example.com both hit CVE-2024-1234 via nuclei (HTTP/1.1 403)"
        )
        self.assertIn("10.0.0.5", found)
        self.assertIn("api.example.com", found)
        self.assertIn("CVE-2024-1234", found)
        self.assertIn("nuclei", found)
        self.assertIn("http:403", found)

    def test_asset_filenames_are_not_hostnames(self):
        self.assertEqual(entities.extract_entities("edited config.yaml and app.js"), ())

    def test_credentials_never_become_entities(self):
        # An entity is injected back into prompts and used as a join key, so a
        # header value or a token must not survive extraction.
        found = entities.extract_entities(
            "Cookie: session=eyJhbGciOiJIUzI1NiJ9 sent to app.example.com"
        )
        self.assertIn("app.example.com", found)
        self.assertNotIn("session=eyJhbGciOiJIUzI1NiJ9", found)

    def test_it_is_bounded_and_deduped(self):
        text = " ".join(f"host{i}.example.com" for i in range(40))
        found = entities.extract_entities(text)
        self.assertLessEqual(len(found), 12)
        self.assertEqual(len(found), len(set(found)))

    def test_shared_entities_counts_intersections(self):
        self.assertEqual(entities.shared_entities(("a", "b"), ("B", "c")), 1)


class TimelineTests(_StoreCase):
    def test_the_timeline_is_chronological_and_keeps_history(self):
        rec, _ = self.store.upsert(
            project_id="p1", kind=KIND_OBSERVATION, text="curl showed a 500 on /api/users",
        )
        self.store.set_confidence(rec, 0.9, EVENT_REINFORCED, detail="confirmed twice")
        self.store.set_confidence(rec, 0.04, EVENT_DECAYED, detail="idle 120d")

        out = timeline.project_timeline(self.store, "p1", hours=24)
        self.assertIn("Memory timeline", out)
        self.assertIn("created", out)
        # The reversal is visible even though the memory's text never changed.
        self.assertIn("decayed", out)
        self.assertIn("summary:", out)

    def test_memory_history_reads_forwards_from_the_id_prefix(self):
        rec, _ = self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="first sighting")
        # Real clock gap between the two events: the ordering assertion below is
        # only meaningful if they are not timestamped in the same microsecond.
        time.sleep(0.01)
        self.store.set_confidence(rec, 0.8, EVENT_REINFORCED, detail="seen again")
        out = timeline.memory_history(self.store, "p1", rec.memory_id[:8])
        self.assertIn("history", out)
        self.assertIn("first sighting", out)
        self.assertLess(out.index("created"), out.index("reinforced"))

    def test_an_unknown_memory_is_an_error_not_an_empty_history(self):
        out = timeline.memory_history(self.store, "p1", "deadbeef")
        self.assertTrue(out.startswith("Error"))

    def test_a_missing_project_refuses_to_read(self):
        self.assertIn("Error", timeline.project_timeline(self.store, ""))

    def test_an_empty_window_says_so(self):
        out = timeline.project_timeline(self.store, "p1", hours=1)
        self.assertIn("no events recorded yet", out)
        self.assertEqual(timeline.summarize([]), "no memory events in this window")

    def test_truncation_says_what_it_dropped(self):
        for i in range(30):
            self.store.upsert(
                project_id="p1", kind=KIND_OBSERVATION, text=f"observation number {i} of many",
            )
        out = timeline.render(
            self.store.events("p1", limit=60), max_chars=400, header="T",
        )
        self.assertIn("older event(s) omitted", out)

    def test_events_are_project_scoped(self):
        self.store.upsert(project_id="p1", kind=KIND_OBSERVATION, text="only in p1")
        self.assertEqual(self.store.events("p2"), [])
        self.assertEqual(self.store.stats("p2")["memories"], 0)


class ConfigTests(unittest.TestCase):
    def test_env_is_read_at_call_time(self):
        from memory.config import load_config

        old = os.environ.get("MEMORY_ENABLED")
        try:
            os.environ["MEMORY_ENABLED"] = "false"
            self.assertFalse(load_config().enabled)
            os.environ["MEMORY_ENABLED"] = "true"
            self.assertTrue(load_config().enabled)
        finally:
            if old is None:
                os.environ.pop("MEMORY_ENABLED", None)
            else:
                os.environ["MEMORY_ENABLED"] = old

    def test_the_mirror_is_off_without_a_url(self):
        from memory.config import MemoryConfig

        self.assertFalse(MemoryConfig(agentmemory_url="").mirror_enabled)
        self.assertTrue(MemoryConfig(agentmemory_url="http://agentmemory:3111").mirror_enabled)

    def test_the_db_path_can_be_pinned(self):
        old = os.environ.get("MEMORY_DB_PATH")
        try:
            os.environ["MEMORY_DB_PATH"] = "/tmp/redamon-memory-test.db"
            from memory.config import load_config
            self.assertEqual(load_config().db_path, "/tmp/redamon-memory-test.db")
        finally:
            if old is None:
                os.environ.pop("MEMORY_DB_PATH", None)
            else:
                os.environ["MEMORY_DB_PATH"] = old


if __name__ == "__main__":
    unittest.main()
