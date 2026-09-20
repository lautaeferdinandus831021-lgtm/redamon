"""SQLite-backed memory store.

WHY SQLITE, NO NEW DEPENDENCY
-----------------------------
The agent image is frozen at startup (`agentic/` is baked, not mounted) and an
import that is not already installed crash-loops the container, so this uses
`sqlite3` from the standard library. One file per deployment, WAL on, every
connection short-lived - the workload is a handful of writes per tool call from
a single asyncio loop, not a server.

TENANT ISOLATION
----------------
`project_id` is NOT optional decoration: every read filters on it and every
write stamps it. The tables are keyed (project_id, dedup_key) so two projects
placing the same text get two rows instead of sharing one, and no query in this
module can return another project's memory. Cross-project recall would leak one
engagement's findings into another engagement's prompt.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Optional, Sequence

from . import scoring
from .models import (
    EVENT_CREATED,
    EVENT_DECAYED,
    EVENT_EDGE,
    EVENT_REINFORCED,
    EVENT_UPDATED,
    KIND_OBSERVATION,
    MemoryEvent,
    MemoryRecord,
    STATES,
    STATE_ARCHIVED,
    STATE_CANDIDATE,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    memory_id    TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    dedup_key    TEXT NOT NULL,
    user_id      TEXT NOT NULL DEFAULT '',
    session_id   TEXT NOT NULL DEFAULT '',
    kind         TEXT NOT NULL,
    text         TEXT NOT NULL,
    entities     TEXT NOT NULL DEFAULT '[]',
    tags         TEXT NOT NULL DEFAULT '[]',
    confidence   REAL NOT NULL,
    state        TEXT NOT NULL,
    seen         INTEGER NOT NULL DEFAULT 0,
    uses         INTEGER NOT NULL DEFAULT 0,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    last_used_at REAL NOT NULL DEFAULT 0,
    source       TEXT NOT NULL DEFAULT 'whitehat',
    external_id  TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_dedup
    ON memories(project_id, dedup_key);
CREATE INDEX IF NOT EXISTS idx_memories_project
    ON memories(project_id, kind, state);
CREATE INDEX IF NOT EXISTS idx_memories_updated
    ON memories(project_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS memory_events (
    event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id       TEXT NOT NULL,
    memory_id        TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    at               REAL NOT NULL,
    detail           TEXT NOT NULL DEFAULT '',
    session_id       TEXT NOT NULL DEFAULT '',
    confidence_after REAL
);
CREATE INDEX IF NOT EXISTS idx_events_project
    ON memory_events(project_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_events_memory
    ON memory_events(project_id, memory_id, at DESC);

CREATE TABLE IF NOT EXISTS memory_edges (
    project_id TEXT NOT NULL,
    src_id     TEXT NOT NULL,
    dst_id     TEXT NOT NULL,
    relation   TEXT NOT NULL,
    weight     REAL NOT NULL DEFAULT 1.0,
    created_at REAL NOT NULL,
    PRIMARY KEY (project_id, src_id, dst_id, relation)
);
"""

_WS = re.compile(r"\s+")


def _now() -> float:
    return time.time()


def dedup_key(kind: str, text: str) -> str:
    """Stable identity for a memory: same kind + same normalized text.

    Case-folded and whitespace-collapsed so "Port 8080 open" and "port  8080
    open" reinforce one memory instead of accumulating near-duplicates - the
    failure mode that makes a memory store useless after a few sessions.
    """
    norm = _WS.sub(" ", (text or "").strip().lower())
    return hashlib.sha1(f"{kind}\x00{norm}".encode("utf-8", "replace")).hexdigest()[:16]


def _json_list(value: Sequence[str] | None) -> str:
    out = []
    for item in value or ():
        s = str(item).strip()
        if s:
            out.append(s)
    return json.dumps(out[:32])


def _load_list(raw: str) -> tuple[str, ...]:
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return ()
    if not isinstance(data, list):
        return ()
    return tuple(str(x) for x in data)


class MemoryStore:
    """Project-scoped memory: observations, confidence, events, edges."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        d = os.path.dirname(os.path.abspath(db_path))
        if d:
            os.makedirs(d, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Additive column upgrades for a store written by an earlier version.

        CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so without
        this an upgraded deployment would query columns that do not exist yet.
        """
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(memories)")}
        if "seen" not in columns:
            conn.execute(
                "ALTER TABLE memories ADD COLUMN seen INTEGER NOT NULL DEFAULT 0"
            )

    # ------------------------------------------------------------------ plumbing
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One short-lived connection: commit on success, ALWAYS close.

        `with sqlite3.connect(...)` commits but never closes, so a naive
        per-call connection leaks a file descriptor per memory operation. The
        explicit finally is the whole point of this wrapper.
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def close(self) -> None:
        # Connections are per-call; the method exists so callers (and tests) can
        # dispose of the handle by name.
        return None
    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            memory_id=row["memory_id"],
            project_id=row["project_id"],
            kind=row["kind"],
            text=row["text"],
            user_id=row["user_id"],
            session_id=row["session_id"],
            entities=_load_list(row["entities"]),
            tags=_load_list(row["tags"]),
            confidence=float(row["confidence"]),
            state=row["state"],
            seen=int(row["seen"]),
            uses=int(row["uses"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            last_used_at=float(row["last_used_at"]),
            source=row["source"],
            external_id=row["external_id"],
        )

    # ------------------------------------------------------------------ events
    def record_event(
        self,
        *,
        project_id: str,
        memory_id: str,
        event_type: str,
        detail: str = "",
        confidence_after: Optional[float] = None,
        session_id: str = "",
    ) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO memory_events "
                "(project_id, memory_id, event_type, at, detail, session_id, confidence_after) "
                "VALUES (?,?,?,?,?,?,?)",
                (project_id, memory_id, event_type, _now(), detail[:500],
                 session_id, confidence_after),
            )
            return int(cur.lastrowid or 0)

    # ------------------------------------------------------------------ writes
    def upsert(
        self,
        *,
        project_id: str,
        kind: str,
        text: str,
        user_id: str = "",
        session_id: str = "",
        entities: Iterable[str] = (),
        tags: Iterable[str] = (),
        confidence: Optional[float] = None,
        source: str = "whitehat",
        external_id: str = "",
    ) -> tuple[MemoryRecord, bool]:
        """Create or reinforce a memory. Returns (record, created).

        A repeat of the same (project, kind, text) is a REINFORCEMENT, not a new
        row: that is how the store learns which observations keep coming back.
        """
        if not project_id:
            raise ValueError("project_id is required (tenant isolation)")
        text = _WS.sub(" ", (text or "").strip())
        if not text:
            raise ValueError("text is required")

        key = dedup_key(kind, text)
        now = _now()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM memories WHERE project_id=? AND dedup_key=?",
                (project_id, key),
            ).fetchone()

            if row is None:
                record = MemoryRecord(
                    memory_id=uuid.uuid4().hex,
                    project_id=project_id,
                    kind=kind or KIND_OBSERVATION,
                    text=text,
                    user_id=user_id,
                    session_id=session_id,
                    entities=tuple(dict.fromkeys(entities or ())),
                    tags=tuple(dict.fromkeys(tags or ())),
                    confidence=(
                        scoring.initial_confidence(kind, source, text)
                        if confidence is None else max(0.0, min(1.0, confidence))
                    ),
                    state=STATE_CANDIDATE,
                    source=source or "whitehat",
                    external_id=external_id,
                )
                record.state = scoring.next_state(record.confidence, 0, 0.0)
                conn.execute(
                    "INSERT INTO memories (memory_id, project_id, dedup_key, user_id, "
                    "session_id, kind, text, entities, tags, confidence, state, seen, "
                    "uses, created_at, updated_at, last_used_at, source, external_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (record.memory_id, record.project_id, key, record.user_id,
                     record.session_id, record.kind, record.text,
                     _json_list(record.entities), _json_list(record.tags),
                     record.confidence, record.state, 0, 0, record.created_at,
                     record.updated_at, 0.0, record.source, record.external_id),
                )
                created = True
                event_type = EVENT_CREATED
                detail = f"{record.kind}: {text[:120]}"
            else:
                record = self._row_to_record(row)
                before = record.confidence
                record.confidence = scoring.reinforce(record.confidence, 0.15)
                record.seen += 1
                record.updated_at = now
                record.last_used_at = now
                # New entities may arrive with the repeat observation; union
                # rather than replace, or the graph loses earlier links.
                if entities:
                    record.entities = tuple(dict.fromkeys(list(record.entities) + list(entities)))
                if tags:
                    record.tags = tuple(dict.fromkeys(list(record.tags) + list(tags)))
                if record.state == STATE_ARCHIVED:
                    # A repeat of an archived memory is evidence it was archived
                    # too early; bring it back as a candidate to be re-earned.
                    record.state = STATE_CANDIDATE
                record.state = scoring.next_state(
                    record.confidence, record.uses, record.idle_days(), current_state=record.state,
                )
                conn.execute(
                    "UPDATE memories SET text=?, entities=?, tags=?, confidence=?, state=?, "
                    "seen=?, updated_at=?, last_used_at=? WHERE memory_id=? AND project_id=?",
                    (record.text, _json_list(record.entities), _json_list(record.tags),
                     record.confidence, record.state, record.seen, record.updated_at,
                     record.last_used_at, record.memory_id, project_id),
                )
                created = False
                event_type = EVENT_REINFORCED
                detail = f"seen again (seen={record.seen}, d={record.confidence - before:+.2f})"

            conn.execute(
                "INSERT INTO memory_events (project_id, memory_id, event_type, at, detail, "
                "session_id, confidence_after) VALUES (?,?,?,?,?,?,?)",
                (project_id, record.memory_id, event_type, now, detail[:500],
                 session_id, record.confidence),
            )
            return record, created

    def touch(self, record: MemoryRecord, session_id: str = "", boost: float = 0.15) -> MemoryRecord:
        """Record a recall (a memory that gets used earns confidence)."""
        record.confidence = scoring.reinforce(record.confidence, boost)
        record.uses += 1
        record.last_used_at = _now()
        record.updated_at = record.last_used_at
        record.state = scoring.next_state(
            record.confidence, record.uses, 0.0, current_state=record.state,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE memories SET confidence=?, state=?, uses=?, updated_at=?, "
                "last_used_at=? WHERE memory_id=? AND project_id=?",
                (record.confidence, record.state, record.uses, record.updated_at,
                 record.last_used_at, record.memory_id, record.project_id),
            )
        return record

    def set_confidence(
        self,
        record: MemoryRecord,
        confidence: float,
        event_type: str,
        detail: str = "",
        session_id: str = "",
    ) -> MemoryRecord:
        """Write a new confidence + the state it implies, and log the reason."""
        before = record.confidence
        record.confidence = max(0.0, min(1.0, confidence))
        record.updated_at = _now()
        record.state = scoring.next_state(
            record.confidence, record.uses, record.idle_days(), current_state=record.state,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE memories SET confidence=?, state=?, updated_at=? "
                "WHERE memory_id=? AND project_id=?",
                (record.confidence, record.state, record.updated_at,
                 record.memory_id, record.project_id),
            )
        self.record_event(
            project_id=record.project_id,
            memory_id=record.memory_id,
            event_type=event_type,
            detail=detail or f"confidence {before:.2f} -> {record.confidence:.2f}",
            confidence_after=record.confidence,
            session_id=session_id,
        )
        return record

    def set_state(
        self,
        record: MemoryRecord,
        state: str,
        event_type: str,
        detail: str = "",
        session_id: str = "",
    ) -> MemoryRecord:
        if state not in STATES:
            raise ValueError(f"unknown state: {state}")
        record.state = state
        record.updated_at = _now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE memories SET state=?, updated_at=? WHERE memory_id=? AND project_id=?",
                (state, record.updated_at, record.memory_id, record.project_id),
            )
        self.record_event(
            project_id=record.project_id,
            memory_id=record.memory_id,
            event_type=event_type,
            detail=detail or f"state -> {state}",
            confidence_after=record.confidence,
            session_id=session_id,
        )
        return record

    def set_kind(
        self,
        record: MemoryRecord,
        kind: str,
        event_type: str,
        detail: str = "",
        session_id: str = "",
    ) -> MemoryRecord:
        """Re-tier a memory (e.g. lesson -> playbook) and log the promotion."""
        before = record.kind
        record.kind = kind
        record.updated_at = _now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE memories SET kind=?, updated_at=? WHERE memory_id=? AND project_id=?",
                (kind, record.updated_at, record.memory_id, record.project_id),
            )
        self.record_event(
            project_id=record.project_id,
            memory_id=record.memory_id,
            event_type=event_type,
            detail=detail or f"kind {before} -> {kind}",
            confidence_after=record.confidence,
            session_id=session_id,
        )
        return record

    def add_edge(
        self,
        project_id: str,
        src_id: str,
        dst_id: str,
        relation: str = "related",
        weight: float = 1.0,
    ) -> None:
        """Knowledge-graph edge between two memories (mirrored from agentmemory)."""
        if not project_id or not src_id or not dst_id or src_id == dst_id:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO memory_edges (project_id, src_id, dst_id, relation, weight, "
                "created_at) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(project_id, src_id, dst_id, relation) DO UPDATE SET "
                "weight = memory_edges.weight + excluded.weight",
                (project_id, src_id, dst_id, relation, float(weight), _now()),
            )
        self.record_event(
            project_id=project_id,
            memory_id=src_id,
            event_type=EVENT_EDGE,
            detail=f"{relation} -> {dst_id}",
        )

    # ------------------------------------------------------------------ reads
    def get(self, memory_id: str, project_id: str) -> Optional[MemoryRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM memories WHERE memory_id=? AND project_id=?",
                (memory_id, project_id),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def by_external_id(self, project_id: str, external_id: str) -> Optional[MemoryRecord]:
        if not external_id:
            return None
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM memories WHERE project_id=? AND external_id=? LIMIT 1",
                (project_id, external_id),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def candidates(
        self,
        project_id: str,
        *,
        kinds: Optional[Sequence[str]] = None,
        states: Optional[Sequence[str]] = None,
        include_archived: bool = False,
        limit: int = 500,
    ) -> list[MemoryRecord]:
        """Every memory eligible for scoring/search in one project."""
        sql = "SELECT * FROM memories WHERE project_id=?"
        params: list[Any] = [project_id]
        if kinds:
            sql += f" AND kind IN ({','.join('?' * len(kinds))})"
            params.extend(kinds)
        if states:
            sql += f" AND state IN ({','.join('?' * len(states))})"
            params.extend(states)
        elif not include_archived:
            sql += f" AND state != '{STATE_ARCHIVED}'"
        sql += " ORDER BY confidence DESC, updated_at DESC LIMIT ?"
        params.append(int(limit))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_record(r) for r in rows]

    def recent(self, project_id: str, *, limit: int = 50, since: float = 0.0) -> list[MemoryRecord]:
        sql = "SELECT * FROM memories WHERE project_id=? AND updated_at >= ? "
        sql += "ORDER BY updated_at DESC LIMIT ?"
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, (project_id, float(since), int(limit))).fetchall()
        return [self._row_to_record(r) for r in rows]

    def events(
        self,
        project_id: str,
        *,
        memory_id: Optional[str] = None,
        since: float = 0.0,
        until: float = 0.0,
        event_types: Optional[Sequence[str]] = None,
        limit: int = 200,
    ) -> list[MemoryEvent]:
        """Timeline entries, newest first."""
        sql = (
            "SELECT e.*, COALESCE(m.kind,'') AS kind, COALESCE(m.text,'') AS text "
            "FROM memory_events e LEFT JOIN memories m "
            "ON m.memory_id = e.memory_id AND m.project_id = e.project_id "
            "WHERE e.project_id=? AND e.at >= ?"
        )
        params: list[Any] = [project_id, float(since)]
        if until:
            sql += " AND e.at <= ?"
            params.append(float(until))
        if memory_id:
            sql += " AND e.memory_id=?"
            params.append(memory_id)
        if event_types:
            sql += f" AND e.event_type IN ({','.join('?' * len(event_types))})"
            params.extend(event_types)
        sql += " ORDER BY e.at DESC, e.event_id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            MemoryEvent(
                event_id=int(r["event_id"]),
                project_id=r["project_id"],
                memory_id=r["memory_id"],
                event_type=r["event_type"],
                at=float(r["at"]),
                detail=r["detail"] or "",
                session_id=r["session_id"] or "",
                confidence_after=(
                    float(r["confidence_after"]) if r["confidence_after"] is not None else None
                ),
                kind=r["kind"] or "",
                text=r["text"] or "",
            )
            for r in rows
        ]

    def last_decay_at(self, project_id: str) -> dict[str, float]:
        """memory_id -> `at` of its most recent decayed event.

        A decay sweep needs this to apply only the time that no earlier sweep has
        already accounted for: `idle_days()` is measured from last use and keeps
        growing past a sweep, so two sweeps in one day would otherwise decay the
        same idleness twice.
        """
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT memory_id, MAX(at) AS last_at FROM memory_events "
                "WHERE project_id=? AND event_type=? GROUP BY memory_id",
                (project_id, EVENT_DECAYED),
            ).fetchall()
        return {r["memory_id"]: float(r["last_at"]) for r in rows}

    def event_counts(self, project_id: str, *, since: float = 0.0) -> dict[str, int]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT event_type, COUNT(*) AS n FROM memory_events "
                "WHERE project_id=? AND at >= ? GROUP BY event_type",
                (project_id, float(since)),
            ).fetchall()
        return {r["event_type"]: int(r["n"]) for r in rows}

    def neighbors(self, project_id: str, memory_ids: Sequence[str]) -> dict[str, list[tuple[str, float]]]:
        """Undirected adjacency for the given memories, for graph fusion."""
        ids = [m for m in dict.fromkeys(memory_ids) if m]
        if not ids:
            return {}
        ph = ",".join("?" * len(ids))
        sql = (
            "SELECT src_id, dst_id, weight FROM memory_edges "
            f"WHERE project_id=? AND (src_id IN ({ph}) OR dst_id IN ({ph}))"
        )
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, [project_id, *ids, *ids]).fetchall()
        out: dict[str, list[tuple[str, float]]] = {}
        id_set = set(ids)
        for r in rows:
            src, dst, w = r["src_id"], r["dst_id"], float(r["weight"])
            if src in id_set and dst in id_set:
                out.setdefault(src, []).append((dst, w))
                out.setdefault(dst, []).append((src, w))
        return out

    def stats(self, project_id: str) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            kind_rows = conn.execute(
                "SELECT kind, state, COUNT(*) AS n FROM memories WHERE project_id=? "
                "GROUP BY kind, state",
                (project_id,),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM memories WHERE project_id=?", (project_id,)
            ).fetchone()
            events = conn.execute(
                "SELECT COUNT(*) AS n FROM memory_events WHERE project_id=?", (project_id,)
            ).fetchone()
            edges = conn.execute(
                "SELECT COUNT(*) AS n FROM memory_edges WHERE project_id=?", (project_id,)
            ).fetchone()
        by_kind: dict[str, dict[str, int]] = {}
        for r in kind_rows:
            by_kind.setdefault(r["kind"], {})[r["state"]] = int(r["n"])
        return {
            "memories": int(total["n"] if total else 0),
            "events": int(events["n"] if events else 0),
            "edges": int(edges["n"] if edges else 0),
            "by_kind": by_kind,
        }


# ------------------------------------------------------------------ module handle
_store: Optional[MemoryStore] = None
_store_path: str = ""
_store_lock = threading.Lock()


def get_store(db_path: str) -> Optional[MemoryStore]:
    """Process-wide store for `db_path`, or None when it cannot be opened.

    Returns None instead of raising: memory is an enhancement on the agent's
    critical path, and a broken/unwritable DB must degrade the memory tools, not
    the tool call the agent was actually making.
    """
    global _store, _store_path
    with _store_lock:
        if _store is not None and _store_path == db_path:
            return _store
        try:
            _store = MemoryStore(db_path)
            _store_path = db_path
        except Exception as e:  # noqa: BLE001 - disk/permission/schema
            logger.error(f"memory store unavailable at {db_path}: {e}")
            _store = None
            _store_path = ""
        return _store
