"""Report discipline for the agent: the evidence bar, the report structure, the
per-class gotchas, CVSS 3.1 base scoring, and a deterministic triage pass.

It follows the model of YesWeHack's claude-kit (always-on rules + write / triage
/ gotchas skills), implemented agent-side so it needs no new dependency and works
with no external service:

    report_kit/
      config.py     env-driven switches, read at CALL time
      rules.py      always-on discipline + the report structure
      gotchas.py    per-class minimum proof / common N/A / overclaim traps
      cvss.py       CVSS 3.1 base scoring + metric-vs-evidence mismatches
      slop.py       deterministic AI-slop detection
      triage.py     verdict + buckets, and the renderer

Three surfaces consume it:

* `DISCIPLINE_RULES` is injected into every think prompt, so the bar applies
  while the agent is still investigating, not only when it writes up.
* `build_report_block()` is appended to the final-report prompt: the structure
  plus the gotchas for the class actually being reported on.
* The `report_review` tool (see `agentic/report_tools.py`) lets the agent run
  triage / gotchas / structure / cvss on a draft mid-session.
"""
from __future__ import annotations

from report_kit.config import ReportKitConfig, load_config
from report_kit.cvss import (
    base_score,
    extended_metrics,
    is_base_only,
    metric_mismatch_flags,
    parse_vector,
    severity,
)
from report_kit.gotchas import (
    CLASSES,
    GOTCHAS,
    build_gotchas_block,
    classes_for_attack_path,
    detect_classes,
    resolve_class,
)
from report_kit.rules import (
    DISCIPLINE_RULES,
    OMIT_SECTIONS,
    PLATFORM_FIELDS,
    REPORT_SECTIONS,
    build_structure_block,
)
from report_kit.slop import Flag, scan_slop
from report_kit.triage import (
    TriageResult,
    render_triage,
    triage_draft,
)


def build_report_block(attack_path_type: str = "", vulnerability_class: str = "") -> str:
    """The report-time block: structure + the gotchas for the class in play.

    Returns "" when the layer is switched off, so callers can append it
    unconditionally.
    """
    if not load_config().report_block:
        return ""

    classes = list(classes_for_attack_path(attack_path_type))
    if vulnerability_class:
        classes.append(vulnerability_class)

    parts = [
        "## Report discipline (applies to this report)",
        "",
        build_structure_block(),
    ]
    gotchas = build_gotchas_block(classes)
    if gotchas:
        parts += ["", gotchas]
    else:
        parts += [
            "",
            "No class-specific reference applies to this session's technique: hold "
            "the report to the general evidence bar (a replayable PoC, impact only "
            "as demonstrated, base-metrics-only CVSS).",
        ]
    return "\n".join(parts)


def discipline_block() -> str:
    """The always-on rules, or "" when the layer is switched off."""
    if not load_config().enabled:
        return ""
    return DISCIPLINE_RULES


__all__ = [
    "CLASSES",
    "DISCIPLINE_RULES",
    "GOTCHAS",
    "Flag",
    "OMIT_SECTIONS",
    "PLATFORM_FIELDS",
    "REPORT_SECTIONS",
    "ReportKitConfig",
    "TriageResult",
    "base_score",
    "build_gotchas_block",
    "build_report_block",
    "build_structure_block",
    "classes_for_attack_path",
    "detect_classes",
    "discipline_block",
    "extended_metrics",
    "is_base_only",
    "load_config",
    "metric_mismatch_flags",
    "parse_vector",
    "render_triage",
    "resolve_class",
    "scan_slop",
    "severity",
    "triage_draft",
]
