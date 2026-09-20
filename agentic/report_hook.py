"""The report layer's seams into the agent loop.

Everything else in the report layer is self-contained; these are the only touch
points, kept together so the node files reference one implementation instead of
each growing its own:

* `report_discipline_block` - the always-on rules, prepended to the think
  prompt. The reference installs them at session start, so an unverified claim
  never gets written in the first place; injecting on every think step is the
  agent-loop equivalent.
* `report_prompt_block` - the report structure plus the class gotchas, appended
  to the final-report prompt.
* `self_check_appendix` - the machine triage of the generated report, appended
  only when it found something, so the reader sees which claims are unproven.
* `register_report_tools` - attach `report_review` to a
  `PhaseAwareToolExecutor`, where every other tool surface is wired.

All four are fail-open. The report layer reviews work; a bug in it must never
cost the agent its report or a turn.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# The self-check is a review of the report, so it must not become longer than
# what it reviews; this caps the flags rendered into the appendix.
_APPENDIX_MAX_FLAGS = 6


def report_discipline_block() -> str:
    """The always-on evidence/report rules. "" when the layer is off or broken."""
    try:
        from report_kit import discipline_block

        return discipline_block()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"report discipline unavailable: {e}")
        return ""


def report_prompt_block(attack_path_type: str = "", vulnerability_class: str = "") -> str:
    """Structure + class gotchas for the final-report prompt. "" when off/broken."""
    try:
        from report_kit import build_report_block

        return build_report_block(
            attack_path_type=attack_path_type,
            vulnerability_class=vulnerability_class,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"report prompt block unavailable: {e}")
        return ""


def self_check_appendix(report_text: str) -> str:
    """Triage the finished report; "" when clean, disabled, or broken."""
    try:
        from report_kit import load_config
        from report_kit.triage import render_triage, triage_draft

        if not load_config().autocheck:
            return ""
        if not report_text or not str(report_text).strip():
            return ""

        # require_scope=False: this pass has no access to the program's scope
        # list, and the RoE / scope guardrail is what gated the engagement. A
        # standing "scope unknown" flag here would fire on every report, which
        # is exactly how a review section stops being read.
        result = triage_draft(str(report_text), require_scope=False)
        if not (result.critical or result.major):
            return ""

        kept = render_triage(result, max_per_bucket=_APPENDIX_MAX_FLAGS)
        return (
            "\n\n---\n\n## Report self-check (machine review, not part of the finding)\n\n"
            "The claims below were checked against their own evidence. Items listed "
            "as unverified are unverified in THIS report - correct or remove them "
            "rather than submitting them as proven.\n\n"
            f"```\n{kept}\n```"
        )
    except Exception as e:  # noqa: BLE001 - never break the report
        logger.warning(f"report self-check skipped: {e}")
        return ""


def register_report_tools(tool_executor) -> int:
    """Attach the report tools to `tool_executor`. Returns how many were added."""
    try:
        from report_tools import build_report_tools

        tools = build_report_tools()
        tool_executor._all_tools.update(tools)  # noqa: SLF001 - executor-owned table
        return len(tools)
    except Exception as e:  # noqa: BLE001 - a broken review must not cost the agent its tools
        logger.warning(f"Failed to register report tools: {e}")
        return 0


__all__ = [
    "register_report_tools",
    "report_discipline_block",
    "report_prompt_block",
    "self_check_appendix",
]
