"""
Resolve one synthetic project row to the settings a scan would actually run with.

Shared by the golden-master test and the regeneration script, so the baseline
and the assertion are produced by exactly the same code path. If they were two
implementations, a bug in either would look like agreement.

The full path is run, not just `fetch_project_settings`: stealth, then the RoE
capper inside the fetch, then the AI-pipeline overrides, then the memory
governor. Ordering is load-bearing and documented in `project_settings.py`, and
a refactor that reorders the passes produces different effective settings with
nothing failing.

The memory governor reads live host memory, so it is disabled here: a baseline
that changes with the machine's free RAM would be a baseline nobody trusts. Its
ORDERING is asserted separately, by the runtime tests.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[2]
for p in (str(_REPO), str(_REPO / "recon")):
    if p not in sys.path:
        sys.path.insert(0, p)


class _FakeResponse:
    """The webapp API's answer. Both the project fetch and the user-settings
    fetch go through `requests.get`, so one payload serves both."""

    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def resolve(row: dict) -> dict:
    from recon import project_settings as ps

    payload = {"userId": "golden-user", **row}
    env = {
        "PROJECT_ID": "golden-project",
        "WEBAPP_API_URL": "http://mocked",
        # The governor is fail-open and reads live memory; a baseline that moved
        # with the host's free RAM would be worthless.
        "WHITEHAT_MEM_GOVERNOR": "0",
    }
    with patch.dict(os.environ, env, clear=False), patch("requests.get", return_value=_FakeResponse(payload)):
        settings = ps.fetch_project_settings("golden-project", "http://mocked")
        if settings.get("STEALTH_MODE"):
            settings = ps.apply_stealth_overrides(settings)
        settings = ps.apply_ai_pipeline_overrides(settings)
        settings = ps.apply_memory_governor(settings)

    # Key rotators and other callables are per-run objects with no stable
    # identity, so they are recorded by presence rather than by value.
    out: dict = {}
    for key, value in sorted(settings.items()):
        if callable(value) or key.endswith("_KEY_ROTATOR"):
            out[key] = f"<{type(value).__name__}>"
        else:
            out[key] = value
    return out
