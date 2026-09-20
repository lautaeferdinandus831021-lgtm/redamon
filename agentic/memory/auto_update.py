"""Memory auto-update: capture, compress, reinforce, decay, reflect.

This is RedAmon's equivalent of agentmemory's auto hooks, wired to the one place
every agent tool call already passes through (`PhaseAwareToolExecutor.execute`),
so single-tool and parallel-plan execution both feed memory without touching
either node.

WHAT IT CAPTURES
----------------
Only the SHAPE of a call, never its raw payload: tool name, phase, success and a
COMPRESSED digest of the output. A full tool response can be megabytes of target
data; storing that would make memory a second copy of every scan and blow up the
prompt on recall. Compression keeps the signal (status codes, error lines, a
bounded head/tail) and drops the bulk.

WHAT IT DOES NOT CAPTURE
------------------------
Nothing from inside a target. Memory is RedAmon's own operational record - what
this project's tooling did and what it learned - so it stays black-box: no
inferred target internals, no white-box assumptions, no credentials.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any, Optional

from . import self_improve
from .agentmemory_client import encode_metadata, get_client
from .config import MemoryConfig, load_config
from .entities import extract_entities, shared_entities
from .models import (
    EVENT_DECAYED,
    EVENT_IMPORTED,
    EVENT_MIRRORED,
    KIND_OBSERVATION,
    KIND_TOOL_OUTCOME,
    MemoryRecord,
    STATE_ARCHIVED,
)
from .store import MemoryStore, get_store

logger = logging.getLogger(__name__)

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_WS = re.compile(r"[ \t]+")

# Output lines that are pure progress/spinner noise: they carry no outcome and
# would otherwise dominate the digest of a long scan.
_NOISE = re.compile(
    r"^\s*(?:\[\s*\d+%\]|\[[#=>.\s]+\]|[-\\|/]\s*$|\d+%\|)", re.M,
)

# Lines worth keeping verbatim even when they are deep in the output: the
# evidence of what happened, which a head/tail slice alone would drop.
_SIGNAL = re.compile(
    r"(error|failed|failure|denied|refused|timeout|timed out|forbidden|unauthorized|"
    r"not found|no such|vulnerab|critical|high|medium|found|discovered|cve-\d{4}|"
    r"cracked|password|success|complete|open port)",
    re.I,
)


def compress_output(text: str, max_chars: int = 400, signal_lines: int = 4) -> str:
    """Reduce a tool output to a bounded, signal-first digest."""
    if not text:
        return ""
    clean = _ANSI.sub("", str(text))
    clean = _NOISE.sub("", clean)
    lines = [_WS.sub(" ", ln).strip() for ln in clean.splitlines()]
    lines = [ln for ln in lines if ln]

    picked: list[str] = []
    for ln in lines:
        if _SIGNAL.search(ln):
            picked.append(ln)
            if len(picked) >= signal_lines:
                break

    head = lines[:2]
    tail = lines[-2:] if len(lines) > 2 else []

    ordered: list[str] = []
    for group in (head, picked, tail):
        for ln in group:
            if ln not in ordered:
                ordered.append(ln)

    out = " | ".join(ordered)
    if len(out) <= max_chars:
        return out
    return out[: max(1, max_chars - 3)].rstrip() + "..."


def build_observation_text(
    tool_name: str,
    phase: str,
    success: bool,
    digest: str,
    error: str = "",
) -> str:
    """The human/LLM-readable one-liner stored for one call."""
    outcome = "succeeded" if success else "failed"
    text = f"{tool_name} ({phase or 'unknown'} phase) {outcome}"
    if digest:
        text += f": {digest}"
    if error and not success:
        text += f" [error: {compress_output(error, 200, 2)}]"
    return text


class MemoryAutoUpdater:
    """Owns the capture -> reinforce -> decay -> reflect pipeline for one process."""

    def __init__(self, config: Optional[MemoryConfig] = None):
        self.config = config or load_config()
        self._counters: dict[str, int] = {}
        self._counter_lock = threading.Lock()

    # ------------------------------------------------------------------ accessors
    def store(self) -> Optional[MemoryStore]:
        if not self.config.enabled:
            return None
        return get_store(self.config.db_path)

    def client(self):
        return get_client(self.config.agentmemory_url)

    # ------------------------------------------------------------------ capture
    def observe_tool_result(
        self,
        *,
        project_id: str,
        tool_name: str,
        success: bool,
        phase: str = "",
        session_id: str = "",
        output: str = "",
        error: str = "",
        args: Optional[dict[str, Any]] = None,
    ) -> Optional[MemoryRecord]:
        """Record one tool call. Returns the memory, or None if it was skipped.

        Skips unsaveable calls (no project, no tool name) and the memory tools
        themselves: a `memory_recall` writing an observation about recalling
        would make the store's own traffic its dominant content.
        """
        if not (self.config.enabled and self.config.auto_update):
            return None
        if not project_id or not tool_name:
            return None
        if tool_name.startswith("memory_"):
            return None

        store = self.store()
        if store is None:
            return None

        digest = compress_output(output, self.config.tool_output_chars)
        text = build_observation_text(tool_name, phase, success, digest, error)
        text = text[: self.config.observation_max_chars]
        tags = (f"tool:{tool_name}", "ok" if success else "fail")
        if phase:
            tags = (*tags, f"phase:{phase}")

        entities = extract_entities(f"{tool_name} {phase} {digest}")

        try:
            record, _created = store.upsert(
                project_id=project_id,
                kind=KIND_TOOL_OUTCOME,
                text=text,
                session_id=session_id,
                entities=entities,
                tags=tags,
            )
            self._link_to_related(store, project_id, record)
        except Exception as e:  # noqa: BLE001 - memory must never break a tool call
            logger.warning(f"memory capture failed for {tool_name}: {e}")
            return None

        self._should_reflect(project_id, session_id)
        return record

    def save_memory(
        self,
        *,
        project_id: str,
        text: str,
        kind: str = KIND_OBSERVATION,
        session_id: str = "",
        entities: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
        confidence: Optional[float] = None,
    ) -> Optional[MemoryRecord]:
        store = self.store()
        if store is None or not project_id or not text.strip():
            return None
        merged_entities = entities or extract_entities(text)
        record, _created = store.upsert(
            project_id=project_id,
            kind=kind,
            text=text,
            session_id=session_id,
            entities=merged_entities,
            tags=tags,
            confidence=confidence,
        )
        self._link_to_related(store, project_id, record)
        return record

    def _link_to_related(self, store: MemoryStore, project_id: str, record: MemoryRecord) -> None:
        """Add graph edges to recent memories this one shares entities with.

        This is what makes `memory_smart_search` able to reach a memory whose
        wording differs from the query: the link is between ENTITIES, not text.
        """
        if not record.entities:
            return
        try:
            recent = store.recent(project_id, limit=120)
        except Exception:  # noqa: BLE001
            return
        linked = 0
        for other in recent:
            if other.memory_id == record.memory_id:
                continue
            weight = shared_entities(record.entities, other.entities)
            if weight <= 0:
                continue
            store.add_edge(project_id, record.memory_id, other.memory_id, "shares_entity", weight)
            linked += 1
            if linked >= 5:
                break

    # ------------------------------------------------------------------ reflection
    def _should_reflect(self, project_id: str, session_id: str) -> None:
        every = self.config.self_improve_every
        if not self.config.self_improve or every <= 0:
            return
        with self._counter_lock:
            self._counters[project_id] = self._counters.get(project_id, 0) + 1
            due = self._counters[project_id] >= every
            if due:
                self._counters[project_id] = 0
        if due:
            self.reflect(project_id, session_id=session_id)

    def reflect(self, project_id: str, *, session_id: str = "") -> Optional[self_improve.ReflectionReport]:
        """Run one self-improvement pass (also the explicit tool's entrypoint)."""
        if not (self.config.enabled and self.config.self_improve):
            return None
        store = self.store()
        if store is None:
            return None
        try:
            return self_improve.reflect(store, project_id, session_id=session_id)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"self-improvement pass failed for {project_id}: {e}")
            return None

    # ------------------------------------------------------------------ lifecycle
    def decay_sweep(self, project_id: str, *, session_id: str = "") -> int:
        """Apply half-life decay to idle memories. Returns how many changed."""
        if not (self.config.enabled and project_id):
            return 0
        store = self.store()
        if store is None:
            return 0
        from . import scoring

        changed = 0
        try:
            records = store.candidates(project_id, include_archived=True, limit=2000)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"decay sweep read failed: {e}")
            return 0

        now = time.time()
        for rec in records:
            idle = rec.idle_days(now)
            if idle < 1.0:
                continue  # same-day use: nothing has had time to go stale
            new_conf = scoring.confidence_after_decay(
                rec.confidence, idle, half_life_days=self.config.decay_half_life_days,
            )
            if rec.confidence - new_conf < 0.01:
                continue
            store.set_confidence(
                rec, new_conf, EVENT_DECAYED,
                detail=f"idle {idle:.0f}d (half-life {self.config.decay_half_life_days:.0f}d)",
                session_id=session_id,
            )
            changed += 1
            if rec.state == STATE_ARCHIVED:
                store.record_event(
                    project_id=project_id,
                    memory_id=rec.memory_id,
                    event_type="archived",
                    detail="decayed out of the active set",
                    confidence_after=rec.confidence,
                    session_id=session_id,
                )
        return changed

    def session_end(self, project_id: str, *, session_id: str = "") -> dict[str, Any]:
        """End-of-session pass: decay, then reflect, then mirror if configured."""
        result: dict[str, Any] = {"decayed": 0, "reflection": None}
        if not self.config.enabled or not project_id:
            return result
        result["decayed"] = self.decay_sweep(project_id, session_id=session_id)
        report = self.reflect(project_id, session_id=session_id)
        if report is not None:
            result["reflection"] = report.summary()
        return result

    def session_start_text(self, project_id: str) -> str:
        """What a fresh session should be told about this project's memory."""
        store = self.store()
        if store is None or not (project_id and self.config.auto_update):
            return ""
        try:
            return self_improve.playbook_digest(
                store, project_id, max_chars=self.config.max_inject_chars,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(f"playbook digest failed: {e}")
            return ""

    # ------------------------------------------------------------------ mirror
    async def mirror_records(self, project_id: str, records: list[MemoryRecord]) -> int:
        """Best-effort copy of local memories to an agentmemory server."""
        client = self.client()
        if client is None:
            return 0
        mirrored = 0
        store = self.store()
        for rec in records:
            if await client.save(text=rec.text, metadata=encode_metadata(rec)):
                mirrored += 1
                if store is not None:
                    store.record_event(
                        project_id=project_id,
                        memory_id=rec.memory_id,
                        event_type=EVENT_MIRRORED,
                        detail=f"mirrored to {client.base_url}",
                        confidence_after=rec.confidence,
                    )
        return mirrored

    def import_external(self, project_id: str, items: list[dict[str, Any]]) -> int:
        """Fold agentmemory search hits into the local store.

        Anything already joined by `redamon_memory_id` is skipped: importing a
        mirrored memory back over itself would inflate its use count on every
        recall and eventually pin it at confidence 1.0.
        """
        store = self.store()
        if store is None or not project_id or not items:
            return 0
        imported = 0
        for item in items:
            text = item.get("content") or item.get("text") or item.get("memory") or ""
            if not isinstance(text, str) or not text.strip():
                continue
            meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            foreign_id = str(meta.get("redamon_memory_id") or "")
            if foreign_id and store.by_external_id(project_id, foreign_id) is not None:
                continue
            record, created = store.upsert(
                project_id=project_id,
                kind=str(meta.get("kind") or KIND_OBSERVATION),
                text=text,
                entities=tuple(meta.get("entities") or ()) or extract_entities(text),
                tags=tuple(meta.get("tags") or ()) + ("agentmemory",),
                source="agentmemory",
                external_id=str(item.get("id") or foreign_id or ""),
            )
            if created:
                imported += 1
                store.record_event(
                    project_id=project_id,
                    memory_id=record.memory_id,
                    event_type=EVENT_IMPORTED,
                    detail="imported from agentmemory",
                    confidence_after=record.confidence,
                )
        return imported


_updater: Optional[MemoryAutoUpdater] = None
_updater_lock = threading.Lock()


def get_updater() -> MemoryAutoUpdater:
    """Process-wide auto-updater (config is re-read from env on each call)."""
    global _updater
    if _updater is None:
        with _updater_lock:
            if _updater is None:
                _updater = MemoryAutoUpdater(load_config())
    _updater.config = load_config()
    return _updater


def reset_updater() -> None:
    """Drop the cached updater (tests and env changes)."""
    global _updater
    with _updater_lock:
        _updater = None


def auto_update_tool_result(**kwargs) -> Optional[MemoryRecord]:
    """Fail-open entrypoint for the executor's post-execution hook."""
    try:
        return get_updater().observe_tool_result(**kwargs)
    except Exception as e:  # noqa: BLE001 - never break a tool call
        logger.warning(f"memory auto-update skipped: {e}")
        return None


__all__ = [
    "MemoryAutoUpdater",
    "auto_update_tool_result",
    "build_observation_text",
    "compress_output",
    "get_updater",
    "reset_updater",
]
