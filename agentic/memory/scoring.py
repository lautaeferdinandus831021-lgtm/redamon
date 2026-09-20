"""Confidence scoring + lifecycle transitions.

Kept as pure functions with no I/O so the policy is testable on its own and the
store can apply it identically for auto-capture, recall reinforcement and the
self-improvement pass.

The model mirrors agentmemory's: confidence is not a boolean "relevant", it is a
score that is EARNED (a memory that keeps getting recalled rises), SPENT (idle
memories decay on a half-life), and drives the lifecycle state.
"""
from __future__ import annotations

import math

from .models import STATE_ACTIVE, STATE_ARCHIVED, STATE_CANDIDATE, KIND_LESSON, KIND_PLAYBOOK

# Priors by kind. A distilled lesson starts more trustworthy than a raw
# observation: it is the output of a reflection pass that already discarded
# noise, whereas an observation is whatever a tool happened to print.
_KIND_PRIOR = {
    KIND_PLAYBOOK: 0.8,
    KIND_LESSON: 0.65,
    "target_fact": 0.55,
    "tool_outcome": 0.45,
    "observation": 0.4,
    "note": 0.45,
}

# Captured-by looks-authoritative-but-is-not sources: an unattributed guess or a
# single-shot capture must not start above a distilled lesson.
_SOURCE_ADJUST = {
    "agentmemory": 0.05,   # mirrored from a server that already scored it
    "heuristic": 0.0,
    "inferred": -0.1,
}


def initial_confidence(kind: str, source: str = "whitehat", text: str = "") -> float:
    """Starting confidence for a freshly captured memory."""
    base = _KIND_PRIOR.get(kind, 0.4)
    base += _SOURCE_ADJUST.get(source, 0.0)
    # A memory with almost no content carries almost no information.
    if len((text or "").strip()) < 12:
        base -= 0.1
    return max(0.05, min(1.0, base))


def reinforce(confidence: float, boost: float = 0.15, times: int = 1) -> float:
    """Raise confidence on reuse, asymptotically bounded at 1.0.

    Proportional-to-remaining-headroom rather than a flat add: repeated
    reinforcement of a mediocre memory must not linear-ramp it to 1.0.
    """
    out = float(confidence)
    for _ in range(max(1, int(times))):
        out = out + (1.0 - out) * max(0.0, boost)
    return max(0.0, min(1.0, out))


def decay(confidence: float, idle_days: float, half_life_days: float = 30.0) -> float:
    """Apply half-life decay for `idle_days` of no use."""
    if idle_days <= 0:
        return max(0.0, min(1.0, float(confidence)))
    hl = max(0.1, float(half_life_days))
    return max(0.0, min(1.0, float(confidence) * math.pow(0.5, idle_days / hl)))


def next_state(
    confidence: float,
    uses: int = 0,
    idle_days: float = 0.0,
    *,
    current_state: str = STATE_CANDIDATE,
    active_min_confidence: float = 0.35,
    archive_max_confidence: float = 0.15,
    archive_after_days: float = 120.0,
) -> str:
    """Where a memory belongs after scoring.

    Archival wins over promotion: a memory old enough and weak enough is done,
    even if it was once active. An archived memory is never resurrected by a
    decay that happens to compute a healthy score - only an explicit
    reinforcement or a self-improvement pass moves it back.
    """
    if confidence <= archive_max_confidence:
        return STATE_ARCHIVED
    if idle_days >= archive_after_days and confidence < active_min_confidence:
        return STATE_ARCHIVED
    if confidence >= active_min_confidence and (uses > 0 or current_state == STATE_ACTIVE):
        return STATE_ACTIVE
    if uses > 0 and confidence >= archive_max_confidence:
        return STATE_ACTIVE
    return STATE_CANDIDATE


def confidence_after_decay(
    confidence: float,
    idle_days: float,
    *,
    half_life_days: float = 30.0,
) -> float:
    """One decay step, with a floor so a memory never silently hits exactly 0."""
    return max(0.01, decay(confidence, idle_days, half_life_days))
