"""The self-improvement pass: distil, promote, resolve contradictions, mark the timeline.

The behaviour worth pinning is that the pass only ever says something the store
can back up, and that it changes memory by MOVING it (promote / archive), never
by deleting it. An archived lesson still has to appear on the timeline: that is
how a reversal stays auditable.

Stdlib only, like the memory core it exercises.
"""
import os
import sys
import tempfile
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from memory import self_improve  # noqa: E402
from memory.models import (  # noqa: E402
    EVENT_PROMOTED,
    EVENT_SELF_IMPROVE,
    KIND_LESSON,
    KIND_NOTE,
    KIND_PLAYBOOK,
    KIND_TOOL_OUTCOME,
    STATE_ARCHIVED,
)
from memory.store import MemoryStore  # noqa: E402

TOOL = "execute_nuclei"


def _outcome(store, project_id, tool, ok):
    """One call whose text is UNIQUE, i.e. one store row per call."""
    return store.upsert(
        project_id=project_id,
        kind=KIND_TOOL_OUTCOME,
        text=f"{tool} call number {store.stats(project_id)['memories']} "
             f"{'succeeded' if ok else 'failed'} against the target",
        tags=(f"tool:{tool}", "ok" if ok else "fail"),
        entities=(tool,),
    )[0]


def _repeat(store, project_id, tool, ok):
    """One call whose text is IDENTICAL to the last, i.e. a deduped row."""
    return store.upsert(
        project_id=project_id,
        kind=KIND_TOOL_OUTCOME,
        text=f"{tool} run against the target",
        tags=(f"tool:{tool}", "ok" if ok else "fail"),
        entities=(tool,),
    )[0]


class ReflectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = MemoryStore(os.path.join(self._tmp.name, "memory.db"))
        self.project = "proj-a"

    def tearDown(self):
        self._tmp.cleanup()

    def _lesson_for(self, key):
        return [
            r for r in self.store.candidates(
                self.project, kinds=(KIND_LESSON, KIND_PLAYBOOK), include_archived=True, limit=500,
            )
            if f"lesson_key:{key}" in r.tags
        ]

    def test_an_unreliable_tool_becomes_a_labelled_lesson(self):
        for ok in (False, False, True, False):
            _outcome(self.store, self.project, TOOL, ok)

        report = self_improve.reflect(self.store, self.project)

        self.assertEqual(report.observations_seen, 4)
        self.assertEqual(report.lessons_added, 1)
        lesson = self._lesson_for(f"tool_reliability:{TOOL}")[0]
        self.assertIn("failed 3/4", lesson.text)
        self.assertIn("negative", lesson.tags)
        self.assertGreater(lesson.confidence, 0.35)

    def test_a_reliable_tool_earns_a_positive_lesson(self):
        # 4/5 = 0.2, i.e. exactly at the reliable threshold; 3/4 would sit in
        # the deliberately silent middle band.
        for ok in (True, True, True, True, False):
            _outcome(self.store, self.project, TOOL, ok)

        self_improve.reflect(self.store, self.project)

        lesson = self._lesson_for(f"tool_reliability:{TOOL}")[0]
        self.assertIn("positive", lesson.tags)
        self.assertIn("4/5", lesson.text)

    def test_repeated_identical_failures_still_count_as_attempts(self):
        # The store dedups identical outcomes into ONE reinforced row. Reading
        # the row count alone would report "failed 1/1" and stay silent - i.e.
        # the pass would go blind exactly when a tool keeps failing the same way.
        for _ in range(4):
            _repeat(self.store, self.project, TOOL, False)

        self.assertEqual(self.store.stats(self.project)["memories"], 1)
        report = self_improve.reflect(self.store, self.project)

        self.assertEqual(report.observations_seen, 1)
        self.assertEqual(report.lessons_added, 1)
        lesson = self._lesson_for(f"tool_reliability:{TOOL}")[0]
        self.assertIn("failed 4/4", lesson.text)

    def test_a_recall_does_not_count_as_a_call(self):
        # `uses` rises on every recall; if the pass read it as evidence, merely
        # looking at the tool history would make a tool look more exercised.
        row = _repeat(self.store, self.project, TOOL, False)
        for _ in range(4):
            self.store.touch(row)

        stats = self_improve._tool_stats(
            self.store.candidates(self.project, kinds=(KIND_TOOL_OUTCOME,), limit=100),
        )
        self.assertEqual(stats[TOOL]["attempts"], 1)

    def test_too_few_calls_is_not_a_conclusion(self):
        for ok in (False, False):
            _outcome(self.store, self.project, TOOL, ok)

        report = self_improve.reflect(self.store, self.project)

        self.assertEqual(report.lessons_added, 0)
        self.assertEqual(self._lesson_for(f"tool_reliability:{TOOL}"), [])

    def test_a_mixed_record_stays_silent(self):
        # Half and half is not a lesson, it is noise.
        for ok in (True, False, True, False):
            _outcome(self.store, self.project, TOOL, ok)

        report = self_improve.reflect(self.store, self.project)

        self.assertEqual(report.lessons_added, 0)

    def test_a_second_pass_reinforces_rather_than_duplicating(self):
        for ok in (False, False, False, True):
            _outcome(self.store, self.project, TOOL, ok)
        first = self_improve.reflect(self.store, self.project)
        second = self_improve.reflect(self.store, self.project)

        self.assertEqual(first.lessons_added, 1)
        self.assertEqual(second.lessons_added, 0)
        self.assertGreaterEqual(second.lessons_reinforced, 1)
        self.assertEqual(len(self._lesson_for(f"tool_reliability:{TOOL}")), 1)

    def test_opposite_lessons_archive_the_weaker_one_instead_of_deleting_it(self):
        self.store.upsert(
            project_id=self.project, kind=KIND_LESSON,
            text="execute_nuclei is dependable here.",
            tags=("tool:execute_nuclei", "positive", "lesson_key:tool_reliability:execute_nuclei"),
            confidence=0.9,
        )
        loser, _ = self.store.upsert(
            project_id=self.project, kind=KIND_LESSON,
            text="execute_nuclei fails here; use the alternative.",
            tags=("tool:execute_nuclei", "negative", "lesson_key:tool_reliability:execute_nuclei"),
            confidence=0.4,
        )

        report = self_improve.reflect(self.store, self.project)

        self.assertEqual(report.contradictions_resolved, 1)
        self.assertEqual(report.archived, 1)
        # Still present, still readable, just no longer live.
        after = loser.with_confidence(loser.confidence)
        self.assertEqual(self.store.get(loser.memory_id, self.project).state, STATE_ARCHIVED)
        self.assertTrue(after.text)

    def test_earned_memories_graduate_to_the_playbook(self):
        note, _ = self.store.upsert(
            project_id=self.project, kind=KIND_NOTE,
            text="Confirm scope in writing before touching the third-party API.",
        )
        for _ in range(3):
            self.store.touch(note)

        report = self_improve.reflect(self.store, self.project)

        self.assertEqual(report.promoted, 1)
        promoted = self.store.get(note.memory_id, self.project)
        self.assertEqual(promoted.kind, KIND_PLAYBOOK)
        kinds = [e.event_type for e in self.store.events(self.project, memory_id=note.memory_id)]
        self.assertIn(EVENT_PROMOTED, kinds)

    def test_an_unused_memory_is_not_promoted(self):
        self.store.upsert(
            project_id=self.project, kind=KIND_NOTE, text="Something never recalled again.",
        )
        report = self_improve.reflect(self.store, self.project)
        self.assertEqual(report.promoted, 0)

    def test_the_pass_marks_the_timeline(self):
        _outcome(self.store, self.project, TOOL, False)
        report = self_improve.reflect(self.store, self.project)

        events = self.store.events(
            self.project, event_types=(EVENT_SELF_IMPROVE,), limit=10,
        )
        self.assertEqual(len(events), 1)
        self.assertIn(report.summary(), events[0].detail)

    def test_the_playbook_digest_is_injectable_and_bounded(self):
        note, _ = self.store.upsert(
            project_id=self.project, kind=KIND_NOTE,
            text="The operator wants findings numbered, never bulleted.",
        )
        for _ in range(3):
            self.store.touch(note)
        self_improve.reflect(self.store, self.project)

        digest = self_improve.playbook_digest(self.store, self.project, max_chars=400)
        self.assertIn("Playbook", digest)
        self.assertIn("numbered", digest)
        self.assertLessEqual(len(digest), 400 + 80)

    def test_an_empty_project_has_no_digest(self):
        self.assertEqual(self_improve.playbook_digest(self.store, self.project), "")

    def test_nothing_is_learned_across_projects(self):
        for ok in (False, False, False):
            _outcome(self.store, self.project, TOOL, ok)

        other = self_improve.reflect(self.store, "proj-b")

        self.assertEqual(other.observations_seen, 0)
        self.assertEqual(other.lessons_added, 0)
        self.assertEqual(
            self.store.candidates("proj-b", kinds=(KIND_LESSON,), include_archived=True), [],
        )

    def test_no_project_is_a_noop(self):
        report = self_improve.reflect(self.store, "")
        self.assertEqual(report.observations_seen, 0)
        self.assertEqual(report.summary().startswith("self-improvement:"), True)


if __name__ == "__main__":
    unittest.main()
