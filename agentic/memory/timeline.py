"""The memory timeline: what changed, when, and why.

Every mutation in the store appends an event, so the timeline is the true history
of what the agent learned - including the changes the current text no longer
shows (a confidence that was once 0.9 and decayed, a lesson that was archived
when a contradicted one outranked it, a self-improvement pass and what it did).

Rendered oldest-first in the chronological modes, because a timeline read
backwards cannot show a drift.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Iterable, Optional, Sequence

from .models import EVENT_SELF_IMPROVE, MemoryEvent

_DAY = 86400.0


def _stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _ago(ts: float, now: Optional[float] = None) -> str:
    delta = max(0.0, (now if now is not None else time.time()) - ts)
    if delta < 90:
        return "just now"
    if delta < 5400:
        return f"{int(delta // 60)}m ago"
    if delta < 2 * _DAY:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // _DAY)}d ago"


def format_event(event: MemoryEvent, *, now: Optional[float] = None, with_text: bool = True) -> str:
    """One timeline line: `[stamp] (N d ago) ^ reinforced  <id> detail`."""
    bit = f"[{_stamp(event.at)}] ({_ago(event.at, now)}) {event.marker()} {event.event_type}"
    if event.confidence_after is not None:
        bit += f" conf={event.confidence_after:.2f}"
    if event.kind:
        bit += f" {event.kind}"
    bit += f" id={event.memory_id[:8]}"
    detail = (event.detail or "").strip()
    if detail:
        bit += f" :: {detail}"
    if with_text and event.text and event.event_type != "reinforced":
        snippet = event.text if len(event.text) <= 140 else event.text[:137] + "..."
        bit += f"\n      {snippet}"
    return bit


def summarize(events: Sequence[MemoryEvent], now: Optional[float] = None) -> str:
    """One-line census of a window, so a long timeline stays scannable."""
    if not events:
        return "no memory events in this window"
    counts: dict[str, int] = {}
    for e in events:
        counts[e.event_type] = counts.get(e.event_type, 0) + 1
    order = ("created", "reinforced", "used", "promoted", "decayed", "archived",
             "updated", "linked", "imported", "mirrored", "self_improve")
    parts = [f"{t} x{counts[t]}" for t in order if counts.get(t)]
    for t in sorted(k for k in counts if k not in order):
        parts.append(f"{t} x{counts[t]}")
    oldest = min(e.at for e in events)
    newest = max(e.at for e in events)
    return (
        f"{len(events)} events | {', '.join(parts)} | "
        f"spanning {_stamp(oldest)} -> {_stamp(newest)} ({_ago(oldest, now)} to {_ago(newest, now)})"
    )


def render(
    events: Iterable[MemoryEvent],
    *,
    header: str = "Memory timeline",
    now: Optional[float] = None,
    max_chars: int = 4000,
    newest_first: bool = True,
    with_text: bool = True,
) -> str:
    """Render events as text, bounded to `max_chars`.

    Truncation drops the OLDEST entries (not the newest) and says how many were
    cut: a silent truncation reads as "that is the whole history".
    """
    ordered = list(events)
    # `store.events()` yields newest-first; the caller may hand over oldest-first
    # instead (memory_history does), so normalise on the requested direction.
    body_order = sorted(ordered, key=lambda e: e.at, reverse=newest_first)

    lines: list[str] = []
    for e in body_order:
        lines.append(format_event(e, now=now, with_text=with_text))

    kept: list[str] = []
    used = 0
    dropped = 0
    for line in lines:
        if used + len(line) + 1 > max_chars and kept:
            dropped += 1
            continue
        kept.append(line)
        used += len(line) + 1

    if dropped:
        tail = "older" if newest_first else "newer"
        kept.append(f"... {dropped} {tail} event(s) omitted (increase `limit` to see them)")

    if not kept:
        return f"{header}\n{'=' * len(header)}\nno events recorded yet"

    return "\n".join([header, "=" * len(header), *kept])


def project_timeline(
    store,
    project_id: str,
    *,
    hours: float = 168.0,
    limit: int = 60,
    event_types: Optional[Sequence[str]] = None,
    max_chars: int = 4000,
    include_summary: bool = True,
) -> str:
    """The project's recent memory history (default: last 7 days)."""
    if not project_id:
        return "Error: missing project_id — memory is project-scoped, refusing to read."
    since = time.time() - (hours * 3600.0) if hours > 0 else 0.0
    events = store.events(
        project_id, since=since, limit=limit, event_types=event_types,
    )
    header = f"Memory timeline (last {int(hours)}h)" if hours > 0 else "Memory timeline (all)"
    out = render(events, header=header, max_chars=max_chars)
    if include_summary:
        out += f"\n\nsummary: {summarize(events)}"
    return out


def memory_history(
    store,
    project_id: str,
    memory_id: str,
    *,
    limit: int = 60,
    max_chars: int = 4000,
) -> str:
    """The full life of ONE memory, oldest first - how it earned its rank."""
    if not project_id:
        return "Error: missing project_id — memory is project-scoped, refusing to read."
    record = store.get(memory_id, project_id)
    if record is None:
        # Could be a shortened id, which is how ids appear in the timeline.
        matches = [r for r in store.recent(project_id, limit=500)
                   if r.memory_id.startswith(memory_id)]
        if len(matches) != 1:
            return (
                f"Error: no memory {memory_id} in this project "
                f"(memory ids are project-scoped)." if not matches else
                f"Error: {memory_id} is ambiguous ({len(matches)} matches) — use a longer id."
            )
        record = matches[0]

    events = store.events(project_id, memory_id=record.memory_id, limit=limit)
    header = (
        f"Memory {record.memory_id[:8]} history — {record.kind}/{record.state} "
        f"conf={record.confidence:.2f} uses={record.uses}"
    )
    body = render(
        events,
        header=header,
        max_chars=max_chars,
        with_text=False,
        newest_first=False,  # a life story reads forwards
    )
    return f"{body}\n\ntext: {record.text}\nsources: {record.source}" + (
        f" (external {record.external_id})" if record.external_id else ""
    )


def self_improvement_timeline(
    store,
    project_id: str,
    *,
    hours: float = 720.0,
    limit: int = 40,
    max_chars: int = 4000,
) -> str:
    """Just the self-improvement history: what the reflection passes changed."""
    if not project_id:
        return "Error: missing project_id — memory is project-scoped, refusing to read."
    since = time.time() - (hours * 3600.0) if hours > 0 else 0.0
    events = store.events(
        project_id, since=since, limit=limit,
        event_types=(EVENT_SELF_IMPROVE, "promoted", "archived"),
    )
    return render(events, header=f"Self-improvement timeline (last {int(hours)}h)",
                  max_chars=max_chars)
