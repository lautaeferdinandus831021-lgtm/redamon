"""Report-discipline configuration.

Read from the environment AT CALL TIME through :func:`load_config`, never at
import time - same reason as `memory/config.py`: this module is baked into the
agent image, so an import-time read would freeze whatever the container started
with and make a test unable to re-enable the layer in a process that already
latched it off.

Config lives in env vars rather than a Prisma project setting because
`fetch_agent_settings` REPLACES the stored settings blob: a new per-project key
is invisible on every EXISTING project until someone backfills the jsonb row.
The agent service has an `env_file`, so a value set in `.env` reaches it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

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


@dataclass(frozen=True)
class ReportKitConfig:
    """What the report layer is allowed to do this turn."""

    enabled: bool
    """Master switch: always-on discipline rules in the think prompt."""

    report_block: bool
    """Append the report structure + class gotchas to the final-report prompt."""

    autocheck: bool
    """Machine-triage the generated report and append the flags it finds."""

    max_flags: int
    """Cap on flags rendered in the self-check appendix."""


def load_config() -> ReportKitConfig:
    return ReportKitConfig(
        enabled=_flag("WHITEHAT_REPORT_DISCIPLINE", True),
        report_block=_flag("WHITEHAT_REPORT_DISCIPLINE_REPORT_BLOCK", True),
        autocheck=_flag("WHITEHAT_REPORT_DISCIPLINE_AUTOCHECK", True),
        max_flags=max(1, _int("WHITEHAT_REPORT_DISCIPLINE_MAX_FLAGS", 12)),
    )


__all__ = ["ReportKitConfig", "load_config"]
