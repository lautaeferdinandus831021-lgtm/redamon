"""Memory subsystem configuration.

Everything is read from the environment AT CALL TIME through
:func:`load_config`, never at import time. The agent image bakes this module, so
import-time reads would freeze whatever the container happened to start with and
make the whole subsystem untestable (a test cannot re-enable memory in a process
that already latched `enabled=False`).

Config lives in env vars rather than a Prisma project setting on purpose:
`fetch_agent_settings` REPLACES the stored TOOL_PHASE_MAP/settings blob, so a new
per-project key is invisible on every existing project until someone backfills
the jsonb row. Memory is agent infrastructure - it must work on the projects that
already exist, the moment this ships.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Default DB location. /workspace is the one writable volume mount the agent
# image has (./agentic/agent-workspace:/workspace); the built-in fallback keeps
# the subsystem usable in a bare checkout and in tests.
_DEFAULT_DB_DIRS = ("/workspace/.memory", "~/.whitehat/memory")

_TRUE = {"1", "true", "yes", "on"}


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in _TRUE


def _int(name: str, default: int) -> int:
    try:
        return int(float(os.environ.get(name, "").strip() or default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def _default_db_path() -> str:
    for d in _DEFAULT_DB_DIRS:
        path = os.path.join(os.path.expanduser(d), "memory.db")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            return path
        except OSError:
            continue
    return os.path.join(os.path.expanduser("~"), "whitehat-memory.db")


@dataclass(frozen=True)
class MemoryConfig:
    enabled: bool = True
    auto_update: bool = True
    self_improve: bool = True
    # Run a reflection pass every N captured observations (and once at session
    # end, which is wired separately). 0 turns the counter off but keeps the
    # session-end pass.
    self_improve_every: int = 10
    db_path: str = ""
    recall_limit: int = 8
    # Confidence half-life in days: a memory nobody re-uses loses half its
    # confidence over this window.
    decay_half_life_days: float = 30.0
    reinforce_boost: float = 0.15
    active_min_confidence: float = 0.35
    archive_max_confidence: float = 0.15
    archive_after_days: float = 120.0
    max_inject_chars: int = 3000
    observation_max_chars: int = 600
    tool_output_chars: int = 400
    # Optional mirror to a real agentmemory server (REST, port 3111). Off unless
    # a URL is configured - the local store is always the source of truth.
    agentmemory_url: str = ""

    @property
    def mirror_enabled(self) -> bool:
        return bool(self.agentmemory_url)


def load_config() -> MemoryConfig:
    """Resolve the effective config from the current environment."""
    return MemoryConfig(
        enabled=_flag("MEMORY_ENABLED", True),
        auto_update=_flag("MEMORY_AUTO_UPDATE", True),
        self_improve=_flag("MEMORY_SELF_IMPROVE", True),
        self_improve_every=_int("MEMORY_SELF_IMPROVE_EVERY", 10),
        db_path=(os.environ.get("MEMORY_DB_PATH", "").strip() or _default_db_path()),
        recall_limit=_int("MEMORY_RECALL_LIMIT", 8),
        decay_half_life_days=max(0.1, _float("MEMORY_DECAY_HALF_LIFE_DAYS", 30.0)),
        reinforce_boost=_float("MEMORY_REINFORCE_BOOST", 0.15),
        active_min_confidence=_float("MEMORY_ACTIVE_MIN_CONFIDENCE", 0.35),
        archive_max_confidence=_float("MEMORY_ARCHIVE_MAX_CONFIDENCE", 0.15),
        archive_after_days=_float("MEMORY_ARCHIVE_AFTER_DAYS", 120.0),
        max_inject_chars=_int("MEMORY_MAX_INJECT_CHARS", 3000),
        observation_max_chars=_int("MEMORY_OBSERVATION_MAX_CHARS", 600),
        tool_output_chars=_int("MEMORY_TOOL_OUTPUT_CHARS", 400),
        agentmemory_url=os.environ.get("AGENTMEMORY_URL", "").strip().rstrip("/"),
    )
