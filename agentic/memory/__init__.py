"""WhiteHat's agent memory: persistent, project-scoped, self-improving.

Follows agentmemory's model - observations with confidence scoring and a
lifecycle, a knowledge graph of entities, hybrid (keyword + graph) recall, and
auto-capture hooks - implemented agent-side (SQLite + in-process) so it needs no
new dependency in the baked agent image and no external service to work.

Layout:
    config              env-driven settings (read at call time)
    models              MemoryRecord / MemoryEvent + the timeline event vocabulary
    scoring             confidence priors, reinforcement, half-life decay, states
    store               SQLite store (project-scoped) + events + graph edges
    search              BM25 keyword recall + entity/graph fusion
    timeline            rendering of the event log (project / one memory / self-improve)
    self_improve        reflection pass: distil lessons, promote, resolve conflicts
    auto_update         capture -> reinforce -> decay -> reflect pipeline
    entities            entity extraction (graph nodes)
    agentmemory_client  optional best-effort mirror to an agentmemory server
"""
from .config import MemoryConfig, load_config  # noqa: F401
from .models import (  # noqa: F401
    MemoryEvent,
    MemoryRecord,
    STATES,
    STATE_ACTIVE,
    STATE_ARCHIVED,
    STATE_CANDIDATE,
    KIND_LESSON,
    KIND_NOTE,
    KIND_OBSERVATION,
    KIND_PLAYBOOK,
    KIND_TARGET_FACT,
    KIND_TOOL_OUTCOME,
)
from .store import MemoryStore, get_store  # noqa: F401
from . import entities, scoring, search, self_improve, timeline  # noqa: F401

__all__ = [
    "MemoryConfig",
    "MemoryEvent",
    "MemoryRecord",
    "MemoryStore",
    "load_config",
    "get_store",
    "entities",
    "scoring",
    "search",
    "self_improve",
    "timeline",
]
