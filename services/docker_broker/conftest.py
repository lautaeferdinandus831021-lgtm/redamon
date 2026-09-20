"""Shared pytest configuration for WhiteHat (auto-tiering + isolation rules).

This file is intentionally near-identical at every in-container test root
(agentic/, recon/, recon_orchestrator/, scanners/ai_attack_surface_scan/,
scanners/capture_proxy/, services/docker_broker/, and the repo root). Each container mounts only its own subtree,
so the config must be visible at each in-container rootdir; keep the copies in
sync.

TIERS (Part B) — every collected test is auto-marked by filename so we do not
have to edit ~350 files. Selection is then `pytest -m unit` (the fast, hermetic
gate), `-m 'unit or integration'` (coverage), or `-m live` (needs a stack):

  * ``integration`` — ``*_integration.py``, ``*_skill.py``, ``*_e2e*``
  * ``live``        — ``live_*``, ``*_live*``, ``*_smoke*`` (self-skip when a
                      stack/service is down; never hard-fail on a missing prereq)
  * ``unit``        — everything else (the default gate tier)

A file can override the auto-mark with an explicit ``@pytest.mark.{unit,
integration,live}`` marker (respected below).

ISOLATION RULE (Part C) — the make-or-break of a deterministic AI-run suite:
NEVER mutate global process state at import time. Do not overwrite
``sys.modules``, ``os.environ``, or the cwd at module scope and leave it
mutated; a later-collected test then imports the polluted module and silently
drops to 0% coverage (this is exactly the bug that hid `tradecraft_lookup.py`).
Use fixtures or ``mock.patch.dict(sys.modules, {...})`` / ``mock.patch.dict(
os.environ, {...})`` scoped to a single test, and restore in ``tearDownModule``
if you must shim at import time. See ``docs/readmes/README.TESTING.md``.

DETERMINISM AT THE GATE — a large body of these tests was written for the old
per-file ``python -m unittest tests.test_x`` runner, where every file was its
own process, so many stub langchain/langgraph into ``sys.modules`` at import
time and (worse) bake real tool objects against a fake decorator during import.
That is order-dependent in a single pytest process. The canonical gate
(``whitehat.sh test`` / ``run_tests.sh``) therefore runs each test FILE in its
own pytest subprocess (parallelized), which reproduces the isolation these tests
assume and makes the gate deterministic. Running ``pytest -m unit`` over the
whole tree in one process is intentionally NOT the gate for that reason — use it
only for a single file / node id while iterating. The ``-m unit`` path-scope
(``pytest_ignore_collect`` below) additionally keeps such a single-process run
from even importing the heavier integration/live files.
"""

import asyncio
import os

import pytest


@pytest.fixture(autouse=True)
def _ensure_event_loop():
    """Guarantee a usable current event loop for each test.

    Many suites drive coroutines with the classic
    ``asyncio.get_event_loop().run_until_complete(...)`` helper. Python's
    ``unittest.IsolatedAsyncioTestCase`` calls ``set_event_loop(None)`` on
    teardown, so any such test that runs AFTER an IsolatedAsyncioTestCase would
    otherwise hit "There is no current event loop in thread 'MainThread'". Under
    the old per-file `python -m unittest` runner each file was its own process,
    hiding this cross-file interaction; a single pytest process exposes it. This
    autouse fixture restores a loop when the previous test cleared it — a
    determinism fix, not a behavior change.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    yield


# Filename fragments that route a test file to a non-unit tier. Matched against
# the lowercased basename so this stays OS/path independent.
_INTEGRATION_MARKERS = ("_integration.py", "_skill.py", "_e2e")
_LIVE_MARKERS = ("live_", "_live", "_smoke", "smoke_")

_TIER_NAMES = {"unit", "integration", "live"}


def _auto_tier(basename: str) -> str:
    name = basename.lower()
    if any(frag in name for frag in _LIVE_MARKERS):
        return "live"
    if any(frag in name for frag in _INTEGRATION_MARKERS):
        return "integration"
    return "unit"


def pytest_ignore_collect(collection_path, config):
    """Make the `-m unit` gate hermetic by NOT importing non-unit files at all.

    pytest imports every *collected* module during collection — even under
    `-m unit`, because the tier marker is read only after import. Many
    integration/skill files stub or mutate shared modules at import time (e.g.
    they replace the real ``langchain_core.tools.tool`` decorator with a fake),
    which then breaks unit tests that build real tools. Marker selection alone
    cannot prevent that. So when the marker expression is exactly ``unit`` we
    skip collecting non-unit files entirely — the plan's path-scoped-collection
    fallback. Broader runs (`-m 'unit or integration'`, coverage) collect
    everything as usual (and run the heavier tiers with process isolation).
    """
    markexpr = (config.getoption("markexpr", default="") or "").replace(" ", "")
    if markexpr != "unit":
        return None
    p = collection_path
    if p.is_file() and p.suffix == ".py" and (
        p.name.startswith("test_") or p.name.endswith("_test.py")
    ):
        if _auto_tier(p.name) != "unit":
            return True
    return None


def pytest_collection_modifyitems(config, items):
    """Auto-mark each collected item into exactly one tier by filename.

    An explicit ``@pytest.mark.{unit,integration,live}`` in the file wins; only
    files with no tier marker get an inferred one.
    """
    for item in items:
        if _TIER_NAMES & {m.name for m in item.iter_markers()}:
            continue
        tier = _auto_tier(os.path.basename(str(item.fspath)))
        item.add_marker(tier)
