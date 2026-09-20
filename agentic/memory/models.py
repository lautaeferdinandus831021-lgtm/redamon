"""The memory record + timeline event model.

Shape follows agentmemory's observation model: a memory carries a confidence
score, a lifecycle state, usage counters and its own knowledge-graph edges, and
EVERY state change is appended to an event log. That log is what makes the
timeline a first-class view rather than a "sort by updated_at" guess - a memory
whose text never changed still has a rich history of reinforcements, promotions
and decays.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

# =============================================================================
# LIFECYCLE
# =============================================================================
# candidate -> active (confidence earned) -> archived (decayed / superseded).
# candidate -> archived directly when it never earns confidence.
STATE_CANDIDATE = "candidate"
STATE_ACTIVE = "active"
STATE_ARCHIVED = "archived"
STATES = (STATE_CANDIDATE, STATE_ACTIVE, STATE_ARCHIVED)

# =============================================================================
# EVENT TYPES (the timeline vocabulary)
# =============================================================================
EVENT_CREATED = "created"
EVENT_REINFORCED = "reinforced"
EVENT_DECAYED = "decayed"
EVENT_PROMOTED = "promoted"
EVENT_ARCHIVED = "archived"
EVENT_UPDATED = "updated"
EVENT_USED = "used"
EVENT_IMPORTED = "imported"
EVENT_MIRRORED = "mirrored"
EVENT_EDGE = "linked"
EVENT_SELF_IMPROVE = "self_improve"
EVENT_TYPES = (
    EVENT_CREATED, EVENT_REINFORCED, EVENT_DECAYED, EVENT_PROMOTED,
    EVENT_ARCHIVED, EVENT_UPDATED, EVENT_USED, EVENT_IMPORTED,
    EVENT_MIRRORED, EVENT_EDGE, EVENT_SELF_IMPROVE,
)

EVENT_MARKERS = {
    EVENT_CREATED: "+",
    EVENT_REINFORCED: "^",
    EVENT_DECAYED: "v",
    EVENT_PROMOTED: "*",
    EVENT_ARCHIVED: "x",
    EVENT_UPDATED: "~",
    EVENT_USED: ".",
    EVENT_IMPORTED: "<",
    EVENT_MIRRORED: ">",
    EVENT_EDGE: "=",
    EVENT_SELF_IMPROVE: "!",
}

# =============================================================================
# KINDS
# =============================================================================
KIND_OBSERVATION = "observation"
KIND_TARGET_FACT = "target_fact"
KIND_TOOL_OUTCOME = "tool_outcome"
KIND_LESSON = "lesson"
KIND_PLAYBOOK = "playbook"
KIND_NOTE = "note"

KINDS = (
    KIND_OBSERVATION, KIND_TARGET_FACT, KIND_TOOL_OUTCOME,
    KIND_LESSON, KIND_PLAYBOOK, KIND_NOTE,
)


@dataclass
class MemoryRecord:
    """One memory. `entities` back the knowledge graph, `confidence` its rank."""

    memory_id: str
    project_id: str
    kind: str = KIND_OBSERVATION
    text: str = ""
    user_id: str = ""
    session_id: str = ""
    entities: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    confidence: float = 0.5
    state: str = STATE_CANDIDATE
    # `seen` counts re-OBSERVATIONS (the same outcome happening again) and `uses`
    # counts RECALLS. They are deliberately separate: the self-improvement pass
    # reads `seen` as evidence weight per tool, and recalling a tool outcome
    # (which happens every time the agent inspects its tool history) must not
    # inflate that evidence.
    seen: int = 0
    uses: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_used_at: float = 0.0
    source: str = "whitehat"
    external_id: str = ""

    def with_confidence(self, confidence: float) -> "MemoryRecord":
        self.confidence = max(0.0, min(1.0, confidence))
        self.updated_at = time.time()
        return self

    def age_days(self, now: Optional[float] = None) -> float:
        return max(0.0, ((now if now is not None else time.time()) - self.created_at) / 86400.0)

    def idle_days(self, now: Optional[float] = None) -> float:
        # "Idle" = time since anything last happened to it, which is what decay
        # keys on. A never-used memory has been idle since creation.
        last = self.last_used_at or self.created_at
        return max(0.0, ((now if now is not None else time.time()) - last) / 86400.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "project_id": self.project_id,
            "kind": self.kind,
            "text": self.text,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "entities": list(self.entities),
            "tags": list(self.tags),
            "confidence": round(self.confidence, 4),
            "state": self.state,
            "seen": self.seen,
            "uses": self.uses,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_used_at": self.last_used_at,
            "source": self.source,
            "external_id": self.external_id,
        }


@dataclass
class MemoryEvent:
    """One timeline entry. Append-only; never rewritten, only added."""

    event_id: int
    project_id: str
    memory_id: str
    event_type: str
    at: float
    detail: str = ""
    session_id: str = ""
    confidence_after: Optional[float] = None
    kind: str = ""
    text: str = ""

    def marker(self) -> str:
        return EVENT_MARKERS.get(self.event_type, "?")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "project_id": self.project_id,
            "memory_id": self.memory_id,
            "event_type": self.event_type,
            "at": self.at,
            "detail": self.detail,
            "session_id": self.session_id,
            "confidence_after": self.confidence_after,
        }
