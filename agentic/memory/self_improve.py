"""Self-improvement: the agent reviewing its own record and distilling lessons.

WHAT THIS IS (AND IS NOT)
-------------------------
This is a deterministic reflection pass over the memory store, not an LLM call:

* no API key, no token cost, no latency on the agent's critical path, and
* no fabricated advice. Every lesson is a statement about counts the store
  actually holds ("execute_nuclei failed 4/5 recent calls here"), so a lesson can
  be audited against the timeline that produced it.

The pass does three things agentmemory's lifecycle does, in WhiteHat's terms:

1. **Distil** - tool-outcome observations become `lesson` memories about which
   tools are reliable here, replacing raw failure noise with a durable claim.
2. **Promote** - a `lesson`/`note` that keeps getting recalled (uses >= 3) is
   graduated to `playbook`, the tier that is injected into the next session.
3. **Resolve contradictions** - two lessons about the same subject with opposite
   polarity cannot both be true; the weaker one is ARCHIVED (never deleted), and
   the timeline keeps both so the reversal is visible.

Self-improvement is therefore a change to the memory store, and every change it
makes is an event in the timeline.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Sequence

from . import scoring
from .models import (
    EVENT_ARCHIVED,
    EVENT_PROMOTED,
    EVENT_REINFORCED,
    EVENT_SELF_IMPROVE,
    KIND_LESSON,
    KIND_NOTE,
    KIND_PLAYBOOK,
    KIND_TOOL_OUTCOME,
    MemoryRecord,
    STATE_ACTIVE,
    STATE_ARCHIVED,
)

logger = logging.getLogger(__name__)

# Minimum attempts before a tool's failure rate means anything. Two failures out
# of two calls is a transient, not a property of the tool in this project.
MIN_ATTEMPTS = 3

# Failure rates that justify a claim. The band between them stays silent on
# purpose: "succeeds about half the time" is not a lesson, it is noise.
UNRELIABLE_AT = 0.6
RELIABLE_AT = 0.2

PROMOTE_MIN_USES = 3
PROMOTE_MIN_CONFIDENCE = 0.5

LESSON_KEY_TAG = "lesson_key:"


@dataclass
class ReflectionReport:
    observations_seen: int = 0
    lessons_added: int = 0
    lessons_reinforced: int = 0
    promoted: int = 0
    archived: int = 0
    contradictions_resolved: int = 0
    playbook: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"self-improvement: {self.observations_seen} observations, "
            f"+{self.lessons_added} lesson(s), ^ {self.lessons_reinforced} reinforced, "
            f"* {self.promoted} promoted, x {self.archived} archived "
            f"({self.contradictions_resolved} contradiction(s) resolved)"
        )


def _lesson_key(record: MemoryRecord) -> str:
    for tag in record.tags:
        if tag.startswith(LESSON_KEY_TAG):
            return tag[len(LESSON_KEY_TAG):]
    return ""


def _polarity(record: MemoryRecord) -> str:
    return "positive" if "positive" in record.tags else "negative"


def _tool_stats(records: Sequence[MemoryRecord]) -> dict[str, dict[str, int]]:
    """Per-tool attempt/outcome counts from captured observations.

    Reads the tags the auto-updater stamps (`tool:<name>` + `ok`/`fail`), so a
    tool outcome is countable without parsing prose.

    Each observation weighs `seen + 1`, not 1: the store DEDUPLICATES identical
    outcomes ("nmap failed: connection refused" five times is one row reinforced
    four times), and a tool that repeatedly fails the same way is exactly the
    case this pass exists to catch. Counting rows would report "failed 1/1" and
    stay silent. `seen` and not `uses`: recalls inflate `uses`, and a recall is
    not a call.
    """
    stats: dict[str, dict[str, int]] = {}
    for rec in records:
        if rec.kind != KIND_TOOL_OUTCOME:
            continue
        tool = ""
        for tag in rec.tags:
            if tag.startswith("tool:"):
                tool = tag[5:]
                break
        if not tool:
            continue
        weight = max(1, rec.seen + 1)
        bucket = stats.setdefault(tool, {"attempts": 0, "fails": 0})
        bucket["attempts"] += weight
        if "fail" in rec.tags:
            bucket["fails"] += weight
    return stats


def reflect(
    store,
    project_id: str,
    *,
    session_id: str = "",
    min_confidence: float = 0.35,
) -> ReflectionReport:
    """Run one reflection pass over the project's memory."""
    report = ReflectionReport()
    if not project_id:
        return report

    records = store.candidates(
        project_id,
        kinds=(KIND_TOOL_OUTCOME, KIND_LESSON, KIND_NOTE, KIND_PLAYBOOK),
        include_archived=True,
        limit=2000,
    )
    outcomes = [r for r in records if r.kind == KIND_TOOL_OUTCOME]
    report.observations_seen = len(outcomes)

    # Index the existing lessons ONCE: distilling is per-tool, and re-querying
    # the store inside that loop is O(tools x memories) per pass.
    lesson_index: dict[str, list[MemoryRecord]] = {}
    for rec in records:
        key = _lesson_key(rec)
        if key and rec.kind in (KIND_LESSON, KIND_PLAYBOOK):
            lesson_index.setdefault(key, []).append(rec)

    _distil_tool_lessons(store, project_id, outcomes, report, lesson_index,
                         session_id=session_id)
    _promote_earned(store, project_id, records, report, session_id=session_id)
    _resolve_contradictions(store, project_id, lesson_index, report, session_id=session_id)
    _record_pass(store, project_id, report, session_id=session_id)

    report.playbook = [r.text for r in playbook_records(store, project_id)]
    return report


def _distil_tool_lessons(
    store,
    project_id: str,
    outcomes: Sequence[MemoryRecord],
    report: ReflectionReport,
    lesson_index: dict[str, list[MemoryRecord]],
    *,
    session_id: str = "",
) -> None:
    for tool, bucket in sorted(_tool_stats(outcomes).items()):
        attempts, fails = bucket["attempts"], bucket["fails"]
        if attempts < MIN_ATTEMPTS:
            continue
        rate = fails / attempts
        if rate >= UNRELIABLE_AT:
            text = (
                f"{tool} failed {fails}/{attempts} recent calls in this project. Treat a failure "
                f"from it as EXPECTED rather than as evidence about the target: confirm "
                f"connectivity, scope and credentials first, and prefer an alternative tool or a "
                f"lower-level command before retrying it."
            )
            key, tags, polarity, conf = f"tool_reliability:{tool}", ("negative",), "negative", 0.6
        elif rate <= RELIABLE_AT:
            text = (
                f"{tool} succeeded {attempts - fails}/{attempts} recent calls in this project. "
                f"It is dependable here — reach for it first for this kind of work rather than "
                f"re-deriving an equivalent command."
            )
            key, tags, polarity, conf = f"tool_reliability:{tool}", ("positive",), "positive", 0.6
        else:
            continue

        tag_set = (f"tool:{tool}", *tags, f"{LESSON_KEY_TAG}{key}", "self_improvement")
        existing = lesson_index.get(key, [])
        kept = next((r for r in existing
                     if _polarity(r) == polarity and r.state != STATE_ARCHIVED), None)
        if kept is not None:
            store.touch(kept, session_id=session_id)
            report.lessons_reinforced += 1
            continue

        record, created = store.upsert(
            project_id=project_id,
            kind=KIND_LESSON,
            text=text,
            session_id=session_id,
            entities=(tool,),
            tags=tag_set,
            confidence=conf,
            source="heuristic",
        )
        if created:
            store.set_confidence(record, conf, EVENT_REINFORCED,
                                 detail=f"distilled from {attempts} calls ({rate:.0%} failed)",
                                 session_id=session_id)
            report.lessons_added += 1
            # Visible to conflict resolution in THIS pass, not just the next one.
            lesson_index.setdefault(key, []).append(record)
        else:
            report.lessons_reinforced += 1


def _promote_earned(
    store,
    project_id: str,
    records: Sequence[MemoryRecord],
    report: ReflectionReport,
    *,
    session_id: str = "",
) -> None:
    """Graduate memories that proved themselves to the injected playbook tier."""
    for rec in records:
        if rec.kind not in (KIND_LESSON, KIND_NOTE):
            continue
        if rec.state == STATE_ARCHIVED:
            continue
        if rec.uses < PROMOTE_MIN_USES or rec.confidence < PROMOTE_MIN_CONFIDENCE:
            continue
        before = rec.kind
        store.set_confidence(
            rec, scoring.reinforce(rec.confidence, 0.1), EVENT_REINFORCED,
            detail=f"promotion boost (uses={rec.uses})", session_id=session_id,
        )
        store.set_kind(
            rec, KIND_PLAYBOOK, EVENT_PROMOTED,
            detail=f"{before} -> playbook (uses={rec.uses}, conf={rec.confidence:.2f})",
            session_id=session_id,
        )
        report.promoted += 1


def _resolve_contradictions(
    store,
    project_id: str,
    lesson_index: dict[str, list[MemoryRecord]],
    report: ReflectionReport,
    *,
    session_id: str = "",
) -> None:
    """Archive the weaker of two opposite-polarity lessons about one subject.

    Deletion is never the answer: an archived lesson still appears in the
    timeline, which is how an operator sees that the agent changed its mind and
    when.
    """
    for key, group in lesson_index.items():
        live = [r for r in group if r.state != STATE_ARCHIVED]
        polarities = {_polarity(r) for r in live}
        if len(polarities) < 2:
            continue
        # Newest wins ties: the store's most recent evidence should decide.
        winner = max(live, key=lambda r: (r.confidence, r.updated_at))
        for loser in live:
            if loser.memory_id == winner.memory_id:
                continue
            store.set_state(
                loser, STATE_ARCHIVED, EVENT_ARCHIVED,
                detail=f"superseded by {winner.memory_id[:8]} (conf {winner.confidence:.2f} "
                       f"> {loser.confidence:.2f})",
                session_id=session_id,
            )
            report.archived += 1
            report.contradictions_resolved += 1


def _record_pass(
    store,
    project_id: str,
    report: ReflectionReport,
    *,
    session_id: str = "",
) -> None:
    """Leave a marker in the timeline for the pass itself.

    Without it, a reader of the timeline sees lessons appearing from nowhere and
    cannot tell which run produced them.
    """
    record, _ = store.upsert(
        project_id=project_id,
        kind=KIND_NOTE,
        text=f"Self-improvement pass — {report.summary()}",
        session_id=session_id,
        tags=("self_improvement",),
        confidence=0.4,
        source="heuristic",
    )
    store.record_event(
        project_id=project_id,
        memory_id=record.memory_id,
        event_type=EVENT_SELF_IMPROVE,
        detail=report.summary(),
        confidence_after=record.confidence,
        session_id=session_id,
    )


def playbook_records(store, project_id: str, *, limit: int = 12) -> list[MemoryRecord]:
    """The memories worth injecting: the graduated playbook, then top lessons."""
    if not project_id:
        return []
    playbook = [
        r for r in store.candidates(project_id, kinds=(KIND_PLAYBOOK,), states=(STATE_ACTIVE,),
                                    limit=limit)
    ]
    if len(playbook) >= limit:
        return playbook[:limit]
    lessons = [
        r for r in store.candidates(project_id, kinds=(KIND_LESSON,), states=(STATE_ACTIVE,),
                                    limit=limit)
    ]
    merged = {r.memory_id: r for r in playbook}
    for rec in lessons:
        merged.setdefault(rec.memory_id, rec)
    return list(merged.values())[:limit]


def playbook_digest(
    store,
    project_id: str,
    *,
    max_chars: int = 1200,
    limit: int = 12,
) -> str:
    """Compact, injectable digest of what this project has learned so far."""
    records = playbook_records(store, project_id, limit=limit)
    if not records:
        return ""
    lines = ["Playbook (learned in this project, highest confidence first):"]
    used = len(lines[0])
    for rec in sorted(records, key=lambda r: -r.confidence):
        line = f"- [{rec.kind} conf={rec.confidence:.2f}] {rec.text}"
        if used + len(line) + 1 > max_chars:
            lines.append(f"... {len(records) - (len(lines) - 1)} more (use memory_recall)")
            break
        lines.append(line)
        used += len(line) + 1
    return "\n".join(lines)
