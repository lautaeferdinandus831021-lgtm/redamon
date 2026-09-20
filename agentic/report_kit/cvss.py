"""CVSS 3.1 base scoring, and the metric-vs-evidence mismatch checks.

Two jobs:

1. **Score a base vector for real.** The official 3.1 base formula, so a report
   says 6.5 instead of a guessed number, and so the max-severity default
   ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" = 9.8) is visible as the default it is.
2. **Check each metric against what was verified.** Temporal and Environmental
   metrics are the reader's to weigh; setting them is an overclaim. `PR:N` on a
   gated feature, `UI:N` on a click, `S:C` without a trust boundary and `AC:L`
   on a non-guessable identifier are the four mismatches that show up most.
"""
from __future__ import annotations

import math
import re

from report_kit.slop import Flag

BASE_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Anything outside the base group. Environmental/Temporal metrics are the
# reader's context to weigh, not the reporter's.
EXTENDED_METRICS: tuple[str, ...] = (
    "E", "RL", "RC", "CR", "IR", "AR",
    "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
)

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    "S": {"U": 1.0, "C": 1.0},
}

# PR is the one metric whose weight depends on S (scope).
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}

SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "None"),
)

_VECTOR_RE = re.compile(r"(?:CVSS:3\.[01]/)?((?:[A-Za-z]{1,3}:[A-Za-z]{1,2}/)+[A-Za-z]{1,3}:[A-Za-z]{1,2})")

# The classic LLM default: every metric at its most severe, whatever the bug.
MAX_BASE_SCORE = 10.0
COMMON_MAX_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def parse_vector(text: str) -> dict[str, str] | None:
    """Parse a CVSS 3.x vector string into {metric: value}. None if unparseable.

    Unknown metric keys are dropped rather than guessed at, so a typo cannot
    silently turn into a scored metric.
    """
    if not text:
        return None
    match = _VECTOR_RE.search(str(text))
    if not match:
        return None
    parsed: dict[str, str] = {}
    for part in match.group(1).split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        value = value.strip().upper()
        if not key or not value:
            continue
        parsed[key] = value
    return parsed or None


def format_vector(parsed: dict[str, str]) -> str:
    """Render a parsed vector in standard order (base metrics, then the rest)."""
    order = list(BASE_METRICS) + [m for m in EXTENDED_METRICS if m in parsed]
    return "CVSS:3.1/" + "/".join(f"{m}:{parsed[m]}" for m in order if m in parsed)


def extended_metrics(parsed: dict[str, str] | None) -> tuple[str, ...]:
    """The non-base metrics present in a vector, in canonical order."""
    if not parsed:
        return ()
    return tuple(m for m in EXTENDED_METRICS if m in parsed)


def is_base_only(parsed: dict[str, str] | None) -> bool:
    return bool(parsed) and not extended_metrics(parsed)


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A roundup: ceil to one decimal, without float drift."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def base_score(vector) -> float | None:
    """CVSS 3.1 base score for a vector string or a parsed dict. None if incomplete.

    Incomplete is a refusal on purpose: scoring a vector with three metrics
    missing means inventing the other five.
    """
    parsed = vector if isinstance(vector, dict) else parse_vector(vector or "")
    if not parsed or any(m not in parsed for m in BASE_METRICS):
        return None

    scope_changed = parsed["S"] == "C"
    for metric, value in parsed.items():
        if metric == "PR":
            if value not in _PR["C" if scope_changed else "U"]:
                return None
        elif metric in _WEIGHTS and value not in _WEIGHTS[metric]:
            return None

    c, i, a = (parsed[m] for m in ("C", "I", "A"))
    iss = 1 - (1 - _WEIGHTS["C"][c]) * (1 - _WEIGHTS["I"][i]) * (1 - _WEIGHTS["A"][a])

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22
        * _WEIGHTS["AV"][parsed["AV"]]
        * _WEIGHTS["AC"][parsed["AC"]]
        * _PR["C" if scope_changed else "U"][parsed["PR"]]
        * _WEIGHTS["UI"][parsed["UI"]]
    )
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def severity(score: float | None) -> str:
    """CVSS 3.1 qualitative severity rating."""
    if score is None:
        return "unscored"
    for floor, label in SEVERITY_BANDS:
        if score >= floor:
            return label
    return "None"


def is_max_vector(parsed: dict[str, str] | None) -> bool:
    """True when every base metric sits at its most severe value."""
    if not parsed or not is_base_only(parsed):
        return False
    parsed_max = parse_vector(COMMON_MAX_VECTOR if parsed["S"] == "U"
                              else "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    return all(parsed.get(m) == parsed_max.get(m) for m in BASE_METRICS)


def metric_mismatch_flags(
    vector,
    *,
    auth_gate: bool = False,
    victim_interaction: bool = False,
    trust_boundary: bool = False,
    non_guessable_id: bool = False,
) -> list[Flag]:
    """Flags for base metrics that contradict the stated preconditions.

    Each keyword argument is a fact the reporter established, and each flag is
    that fact contradicting the vector - so the fix is to correct one or the
    other, never to adjust the score quietly.
    """
    parsed = vector if isinstance(vector, dict) else parse_vector(vector or "")
    if not parsed:
        return []

    flags: list[Flag] = []
    vector_str = format_vector(parsed)

    for metric in extended_metrics(parsed):
        flags.append(Flag(
            "strong",
            "cvss",
            f"{metric} set in {vector_str}",
            "Score CVSS 3.1 with base metrics only. Environmental/Temporal metrics "
            "are the reader's context to weigh - setting them inflates the score.",
        ))

    if auth_gate and parsed.get("PR") == "N":
        flags.append(Flag(
            "strong", "cvss", "PR:N claimed while a real auth gate exists",
            "A paid tier, admin invite or org membership is a privilege "
            "requirement: use PR:L (or PR:H) unless self-registration is open.",
        ))
    if victim_interaction and parsed.get("UI") == "N":
        flags.append(Flag(
            "strong", "cvss", "UI:N claimed while the victim must act",
            "If the victim must click, paste, or load something, the metric is UI:R.",
        ))
    if not trust_boundary and parsed.get("S") == "C":
        flags.append(Flag(
            "strong", "cvss", "S:C claimed without a trust-boundary crossing",
            "Scope-changed means the exploit crosses a security authority boundary "
            "(e.g. escapes a container/VM). If it stays inside the vulnerable "
            "component's authority, use S:U.",
        ))
    if non_guessable_id and parsed.get("AC") == "L":
        flags.append(Flag(
            "strong", "cvss", "AC:L claimed while the identifier is not enumerable",
            "A random UUIDv4 / long opaque token makes discovery of a victim's ID "
            "the hard part: score AC:H and state where such an ID would come from.",
        ))
    if is_max_vector(parsed):
        flags.append(Flag(
            "strong", "cvss", f"max-severity vector {vector_str}",
            "Every metric is at its most severe value. Re-derive each one from what "
            "was verified - this is the default an unverified score lands on.",
        ))
    return flags


__all__ = [
    "BASE_METRICS",
    "COMMON_MAX_VECTOR",
    "EXTENDED_METRICS",
    "MAX_BASE_SCORE",
    "SEVERITY_BANDS",
    "base_score",
    "extended_metrics",
    "format_vector",
    "is_base_only",
    "is_max_vector",
    "metric_mismatch_flags",
    "parse_vector",
    "severity",
]
