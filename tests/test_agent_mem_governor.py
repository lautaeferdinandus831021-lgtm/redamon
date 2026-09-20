"""Unit tests for agentic apply_memory_governor (Part 3).

Ratio-scales fireteam/plan concurrency to available RAM, emits [RESOURCE-CAP],
fail-open. Loaded via importlib under a unique name to avoid clashing with the
recon `project_settings` module in a shared test run.
Run: python3 -m unittest tests.test_agent_mem_governor
"""
import importlib.util
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(__file__), '..')
# graph_db on path so the governor's `import resource_governor` fallback resolves.
sys.path.insert(0, os.path.join(ROOT, 'graph_db'))
import resource_governor as rg

# Load agentic/project_settings.py under a distinct module name.
_spec = importlib.util.spec_from_file_location(
    'agent_project_settings', os.path.join(ROOT, 'agentic', 'project_settings.py'))
aps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aps)

GB = 1024 ** 3

# Force the lazy `import resource_governor` inside apply_memory_governor to
# happen NOW, so _all_governors() below can see whichever copy it resolved.
aps.apply_memory_governor({})


def _all_governors():
    """Every resource_governor copy currently loaded.

    There are two maintained copies and several test modules that each put a
    DIFFERENT directory on sys.path before `import resource_governor`, so
    whichever ran first owns the bare module name for the whole process. In a
    combined run this file's `rg` was therefore often NOT the object
    apply_memory_governor resolved: set_mem_override applied to the wrong module
    and these tests silently read REAL host RAM, passing alone and failing in a
    suite. Fan the override out to every copy so run order stops mattering.
    """
    return [m for name, m in list(sys.modules.items())
            if m is not None and name.split('.')[-1] == 'resource_governor'
            and hasattr(m, 'set_mem_override')]


def _set_mem(total, avail):
    for m in _all_governors():
        m.set_mem_override(total, avail)


def _reset_governors():
    for m in _all_governors():
        m.set_mem_override(None, None)
        m.reset_profile_cache()


class AgentGovTestBase(unittest.TestCase):
    def setUp(self):
        os.environ.pop('WHITEHAT_MEM_GOVERNOR', None)
        _reset_governors()

    def tearDown(self):
        _reset_governors()


class TestByteBudgetScaling(AgentGovTestBase):
    def test_reduces_under_pressure(self):
        # 2GB free x 0.5 fraction = 1GB budget. member=512MB -> 2, tool=400MB -> 2.
        _set_mem(32 * GB, 2 * GB)
        s = {'FIRETEAM_MAX_CONCURRENT': 5, 'FIRETEAM_MAX_MEMBERS': 5,
             'PLAN_MAX_PARALLEL_TOOLS': 10}
        out = aps.apply_memory_governor(s)
        self.assertEqual(out['FIRETEAM_MAX_CONCURRENT'], 2)
        self.assertEqual(out['PLAN_MAX_PARALLEL_TOOLS'], 2)
        # membership is NOT scaled (would truncate a planned fireteam across resume)
        self.assertEqual(out['FIRETEAM_MAX_MEMBERS'], 5)

    def test_small_host_moderate_pressure_still_throttles(self):
        # The ratio-model bug: 4GB total / 2GB free is ratio 0.5 -> ratio said no
        # throttle. Byte-budget still caps (1GB budget / 512MB = 2 members).
        _set_mem(4 * GB, 2 * GB)
        out = aps.apply_memory_governor({'FIRETEAM_MAX_CONCURRENT': 5})
        self.assertEqual(out['FIRETEAM_MAX_CONCURRENT'], 2)

    def test_unchanged_when_ample(self):
        _set_mem(64 * GB, 60 * GB)  # 30GB budget -> everything fits
        s = {'FIRETEAM_MAX_CONCURRENT': 5, 'PLAN_MAX_PARALLEL_TOOLS': 10}
        out = aps.apply_memory_governor(dict(s))
        self.assertEqual(out, s)

    def test_floor_never_zero(self):
        _set_mem(32 * GB, 256 * 1024 * 1024)  # tiny
        out = aps.apply_memory_governor({'FIRETEAM_MAX_CONCURRENT': 5})
        self.assertGreaterEqual(out['FIRETEAM_MAX_CONCURRENT'], 1)


class TestGuards(AgentGovTestBase):
    def test_governor_off(self):
        os.environ['WHITEHAT_MEM_GOVERNOR'] = 'false'
        _set_mem(32 * GB, 1 * GB)
        s = {'FIRETEAM_MAX_CONCURRENT': 5, 'PLAN_MAX_PARALLEL_TOOLS': 10}
        out = aps.apply_memory_governor(dict(s))
        self.assertEqual(out, s)

    def test_non_targeted_keys_untouched(self):
        _set_mem(32 * GB, 2 * GB)
        s = {'FIRETEAM_ENABLED': True, 'OPENAI_MODEL': 'claude', 'MAX_ITERATIONS': 100}
        out = aps.apply_memory_governor(s)
        self.assertIs(out['FIRETEAM_ENABLED'], True)
        self.assertEqual(out['OPENAI_MODEL'], 'claude')
        self.assertEqual(out['MAX_ITERATIONS'], 100)  # not in governor map


class TestCapLog(AgentGovTestBase):
    def test_emits_on_reduction(self):
        _set_mem(32 * GB, 2 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            aps.apply_memory_governor({'FIRETEAM_MAX_CONCURRENT': 5})
        out = buf.getvalue()
        self.assertIn('[RESOURCE-CAP]', out)
        self.assertIn('FIRETEAM_MAX_CONCURRENT', out)

    def test_silent_when_ample(self):
        _set_mem(32 * GB, 32 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            aps.apply_memory_governor({'PLAN_MAX_PARALLEL_TOOLS': 10})
        self.assertNotIn('[RESOURCE-CAP]', buf.getvalue())


if __name__ == "__main__":
    unittest.main()
