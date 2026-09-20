"""Unit tests for recon apply_memory_governor (Part 2).

Ratio-scales concurrency keys, byte-budgets *_MAX_* lists, emits [RESOURCE-CAP]
logs on reduction, fail-open. Deterministic via the governor mem override.
Run: python3 -m unittest tests.test_recon_mem_governor
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

# graph_db dir on path so apply_memory_governor's `import resource_governor`
# fallback resolves (graph_db/__init__ pulls neo4j, unavailable on host).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'graph_db'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon'))

import resource_governor as rg
import project_settings as ps

GB = 1024 ** 3

# Force the lazy `import resource_governor` inside apply_memory_governor to
# happen NOW, so _all_governors() below can see whichever copy it resolved.
ps.apply_memory_governor({})


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



class ReconGovTestBase(unittest.TestCase):
    def setUp(self):
        for k in ("WHITEHAT_MEM_GOVERNOR", "MEM_BUDGET_FRACTION", "RESOURCE_PROFILE_PATH"):
            os.environ.pop(k, None)
        _reset_governors()

    def tearDown(self):
        _reset_governors()


class TestRatioScaling(ReconGovTestBase):
    def test_reduces_concurrency_under_pressure(self):
        _set_mem(32 * GB, 2 * GB)  # scale -> floor 0.15
        s = {'NUCLEI_CONCURRENCY': 25, 'KATANA_PARALLELISM': 8, 'DNS_MAX_WORKERS': 80}
        out = ps.apply_memory_governor(s)
        self.assertEqual(out['NUCLEI_CONCURRENCY'], 4)   # round(3.75)
        self.assertEqual(out['KATANA_PARALLELISM'], 1)   # round(1.2) -> floor 1
        self.assertEqual(out['DNS_MAX_WORKERS'], 12)     # round(12.0)

    def test_unchanged_when_ample(self):
        _set_mem(32 * GB, 32 * GB)  # scale 1.0
        s = {'NUCLEI_CONCURRENCY': 25, 'KATANA_MAX_URLS': 300000}
        out = ps.apply_memory_governor(dict(s))
        self.assertEqual(out, s)

    def test_floor_respected(self):
        _set_mem(32 * GB, 1 * GB)  # very low
        s = {'NMAP_PARALLELISM': 5}
        out = ps.apply_memory_governor(s)
        self.assertEqual(out['NMAP_PARALLELISM'], 1)  # floor 1


class TestByteBudget(ReconGovTestBase):
    def test_caps_max_urls_when_tight(self):
        _set_mem(32 * GB, 256 * 1024 * 1024)  # 256MB free
        s = {'KATANA_MAX_URLS': 300000}
        out = ps.apply_memory_governor(s)
        self.assertLess(out['KATANA_MAX_URLS'], 300000)
        self.assertGreaterEqual(out['KATANA_MAX_URLS'], 1000)  # floor

    def test_max_urls_unchanged_when_ample(self):
        _set_mem(64 * GB, 60 * GB)
        s = {'KATANA_MAX_URLS': 300000}
        out = ps.apply_memory_governor(s)
        self.assertEqual(out['KATANA_MAX_URLS'], 300000)


class TestGuards(ReconGovTestBase):
    def test_governor_off_no_change(self):
        os.environ['WHITEHAT_MEM_GOVERNOR'] = 'false'
        _set_mem(32 * GB, 1 * GB)
        s = {'NUCLEI_CONCURRENCY': 25, 'KATANA_MAX_URLS': 300000}
        out = ps.apply_memory_governor(dict(s))
        self.assertEqual(out, s)

    def test_bools_and_non_ints_untouched(self):
        _set_mem(32 * GB, 2 * GB)
        s = {'GAU_ENABLED': True, 'HTTPX_THREADS': 50, 'SOME_STR': 'x'}
        out = ps.apply_memory_governor(s)
        self.assertIs(out['GAU_ENABLED'], True)   # bool not scaled
        self.assertEqual(out['SOME_STR'], 'x')
        self.assertLess(out['HTTPX_THREADS'], 50)  # the real int is scaled

    def test_missing_keys_ok(self):
        _set_mem(32 * GB, 2 * GB)
        out = ps.apply_memory_governor({'UNRELATED': 1})
        self.assertEqual(out, {'UNRELATED': 1})


class TestCapLog(ReconGovTestBase):
    def test_emits_resource_cap_on_reduction(self):
        _set_mem(32 * GB, 2 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            ps.apply_memory_governor({'NUCLEI_CONCURRENCY': 25})
        out = buf.getvalue()
        self.assertIn('[RESOURCE-CAP]', out)
        self.assertIn('NUCLEI_CONCURRENCY', out)

    def test_silent_when_no_reduction(self):
        _set_mem(32 * GB, 32 * GB)
        buf = io.StringIO()
        with redirect_stdout(buf):
            ps.apply_memory_governor({'NUCLEI_CONCURRENCY': 25})
        self.assertNotIn('[RESOURCE-CAP]', buf.getvalue())


if __name__ == "__main__":
    unittest.main()
