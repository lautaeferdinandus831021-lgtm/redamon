"""INTEGRATION: the supply-chain memory-governor chain, end to end in-process.

The unit tests in tests/test_supply_chain_mem_governor.py pin each helper in
isolation. These wire the real components together, because every bug this
subsystem has actually shipped lived in a SEAM, not in a function:

  * the value existed in one governor copy and not the other
  * the ceiling was computed by one spawner and hardcoded by the other two
  * the throttled setting was never read by the code it was meant to throttle
  * the reserved envelope was smaller than the container it was reserving for

So each test here spans at least two real modules with no mock in between.
`docker` and `httpx` are unavailable on the host, so the container-manager and
agent-tool halves live in recon_orchestrator/tests/test_supply_chain_admission.py
and agentic/tests/test_guarddog_admission_lane.py respectively.

Run: python3 -m unittest tests.test_supply_chain_governor_integration
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, os.path.join(ROOT, 'graph_db'))
sys.path.insert(0, os.path.join(ROOT, 'recon'))
sys.path.insert(0, ROOT)

import resource_governor as rg
from supply_chain_common import analyzer_dispatch as ad
from supply_chain_common.artifact import empty_artifact

# Load recon/project_settings.py by PATH: four files share that module name.
_spec = importlib.util.spec_from_file_location(
    'recon_project_settings_scint', os.path.join(ROOT, 'recon', 'project_settings.py'))
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)

from main_recon_modules import supply_chain_recon as scr   # noqa: E402

GB = 1024 ** 3

# Force lazy `import resource_governor` calls to resolve before we fan out.
ps.apply_memory_governor({})
ad._governed_mem()


def _all_governors():
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


class IntegrationBase(unittest.TestCase):
    ENV = ("WHITEHAT_MEM_GOVERNOR", "SUPPLY_CHAIN_ANALYZER_MEM", "MEM_BUDGET_FRACTION",
           "CONTAINER_CAP_HEADROOM", "PER_CONTAINER_MAX", "RESOURCE_PROFILE_PATH",
           "SUPPLY_CHAIN_IMPORT_MAX_FILES", "SUPPLY_CHAIN_IMPORT_MAX_BYTES")

    def setUp(self):
        for k in self.ENV:
            os.environ.pop(k, None)
        _reset_governors()

    def tearDown(self):
        for k in self.ENV:
            os.environ.pop(k, None)
        _reset_governors()

    def _js_dir(self, count=40, body="import 'lodash';\n"):
        d = tempfile.mkdtemp(prefix="scgov-js")
        self.addCleanup(shutil.rmtree, d, True)
        for i in range(count):
            with open(os.path.join(d, "a{}.js".format(i)), "w") as fh:
                fh.write(body)
        return {"js_recon": {"work_dir": d}}


# ---------------------------------------------------------------------------
# Seam 1: governor -> settings dict -> the code that consumes the setting.
# ---------------------------------------------------------------------------
class TestThrottleReachesTheMiner(IntegrationBase):
    """Registering a key as a budget key in the registry is only half the job. The original
    defect was that the miner read os.environ directly, so the governor could
    throttle the setting all day and the miner would never look at it."""

    def test_starved_host_makes_the_miner_read_fewer_files(self):
        combined = self._js_dir(count=40)
        _set_mem(32 * GB, 24 * GB)          # roomy: nothing throttled
        roomy = ps.apply_memory_governor(dict(ps.DEFAULT_SETTINGS))
        n_roomy = len(scr._read_js_contents(combined, roomy))

        _set_mem(32 * GB, 1 * 1024 ** 2)    # 1 MB free: hard throttle
        starved = ps.apply_memory_governor(dict(ps.DEFAULT_SETTINGS))
        n_starved = len(scr._read_js_contents(combined, starved))

        self.assertEqual(n_roomy, 40)
        self.assertLess(n_starved, n_roomy)
        self.assertGreaterEqual(n_starved, 1, "throttled to zero reads as 'no deps'")

    def test_governor_disabled_restores_full_reads(self):
        combined = self._js_dir(count=40)
        os.environ["WHITEHAT_MEM_GOVERNOR"] = "false"
        _set_mem(32 * GB, 1 * 1024 ** 2)
        s = ps.apply_memory_governor(dict(ps.DEFAULT_SETTINGS))
        self.assertEqual(len(scr._read_js_contents(combined, s)), 40)

    def test_byte_budget_also_bounds_total_bytes_read(self):
        # 40 files x ~1 MB. A file-count cap alone would not bound memory.
        combined = self._js_dir(count=40, body="x" * (1024 * 1024))
        _set_mem(32 * GB, 8 * 1024 ** 2)
        s = ps.apply_memory_governor(dict(ps.DEFAULT_SETTINGS))
        total = sum(len(c) for c in scr._read_js_contents(combined, s))
        self.assertLessEqual(total, s['SUPPLY_CHAIN_IMPORT_MAX_BYTES'] + 1024 * 1024)

    def test_defaults_alone_are_a_usable_budget(self):
        # A caller that never runs the governor must still get the shipped caps,
        # not zero: DEFAULT_SETTINGS is the contract for an ungoverned run.
        combined = self._js_dir(count=40)
        self.assertEqual(len(scr._read_js_contents(combined, dict(ps.DEFAULT_SETTINGS))), 40)


# ---------------------------------------------------------------------------
# Seam 2: governor -> analyzer_dispatch -> the actual spawn call.
# ---------------------------------------------------------------------------
class TestGovernedMemoryReachesTheSpawn(IntegrationBase):
    """analyzer_docker_argv is where the value is *computed*; run_analyzer_job is
    what production actually calls. Test the latter, or a refactor that stops
    passing the argv through would go unnoticed."""

    def _runner(self, seen):
        def run(argv, timeout=None):
            seen.append(argv)
            if argv[:2] == ["docker", "network"]:
                return {"exit_code": 0, "stdout": "", "stderr": "", "error": None}
            # Emulate the analyzer writing a valid artifact.
            out = os.path.join(self._work, "out.json")
            with open(out, "w") as fh:
                json.dump(empty_artifact("purls"), fh)
            return {"exit_code": 0, "stdout": "", "stderr": "", "error": None}
        return run

    def setUp(self):
        super().setUp()
        self._work = tempfile.mkdtemp(prefix="scgov-job")
        self.addCleanup(shutil.rmtree, self._work, True)

    def _spawn_argv(self, seen):
        return [a for a in seen if a[:2] == ["docker", "run"]][0]

    def test_run_analyzer_job_spawns_with_the_governed_ceiling(self):
        _set_mem(64 * GB, 32 * GB)
        seen = []
        res = ad.run_analyzer_job({"mode": "purls", "target": "/work"},
                                  self._work, "/host/sc_common",
                                  runner=self._runner(seen))
        self.assertIsNotNone(res["artifact"])
        argv = self._spawn_argv(seen)
        expected = rg.container_cap(rg.tool_container_envelope("supply_chain_analyzer"))
        self.assertEqual(argv[argv.index("--memory") + 1], str(expected))

    def test_the_ceiling_tracks_host_pressure_through_the_real_call(self):
        seen_big, seen_small = [], []
        _set_mem(64 * GB, 32 * GB)
        ad.run_analyzer_job({"mode": "purls", "target": "/work"}, self._work,
                            "/host/sc", runner=self._runner(seen_big))
        _set_mem(2 * GB, 128 * 1024 ** 2)
        ad.run_analyzer_job({"mode": "purls", "target": "/work"}, self._work,
                            "/host/sc", runner=self._runner(seen_small))
        big = int(self._spawn_argv(seen_big)[self._spawn_argv(seen_big).index("--memory") + 1])
        small = int(self._spawn_argv(seen_small)[self._spawn_argv(seen_small).index("--memory") + 1])
        self.assertLess(small, big)

    def test_hardening_survives_the_whole_path(self):
        """Memory sizing shares an argv with the security boundary. A regression
        that dropped --cap-drop while fixing memory would be catastrophic and
        silent, so assert the full posture at the real call site."""
        _set_mem(64 * GB, 32 * GB)
        seen = []
        ad.run_analyzer_job({"mode": "purls", "target": "/work"}, self._work,
                            "/host/sc", runner=self._runner(seen))
        argv = self._spawn_argv(seen)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertIn("--read-only", argv)
        self.assertIn("--rm", argv)
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "512")
        # No secrets may ride along into the dirty zone.
        joined = " ".join(argv)
        for secret in ("NEO4J_PASSWORD", "INTERNAL_API_KEY", "SCANNER_API_KEY",
                       "GITHUB_TOKEN", "ORCHESTRATOR_API_KEY"):
            self.assertNotIn(secret, joined)


# ---------------------------------------------------------------------------
# Seam 3: the profile layering that decides every number above.
# ---------------------------------------------------------------------------
class TestProfileLayeringForSupplyChain(IntegrationBase):
    def _profile(self, obj):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        os.environ["RESOURCE_PROFILE_PATH"] = fh.name
        _reset_governors()

    def test_measured_analyzer_envelope_flows_into_the_spawn_argv(self):
        """The whole point of calibration: a measured figure must change what
        docker is actually told, not just what a getter returns."""
        _set_mem(64 * GB, 32 * GB)
        self._profile({"tool_container_envelope_bytes": {"supply_chain_analyzer": 2 * GB}})
        _set_mem(64 * GB, 32 * GB)
        argv = ad.analyzer_docker_argv("/tmp/whitehat/j", "/host/sc")
        self.assertEqual(argv[argv.index("--memory") + 1], str(int(2 * GB * 1.5)))

    def test_partial_calibration_does_not_wipe_sibling_defaults(self):
        # A calibration run that only measured full_recon must leave every other
        # envelope intact, or one measurement silently degrades the whole table.
        self._profile({"scan_job_envelope_bytes": {"full_recon": 5 * GB}})
        self.assertEqual(rg.scan_job_envelope("full_recon"), 5 * GB)
        self.assertEqual(rg.scan_job_envelope("supply_chain"), 1_879_048_192)
        self.assertEqual(rg.tool_container_envelope("supply_chain_analyzer"), 1_073_741_824)

    def test_corrupt_profile_degrades_to_shipped_values(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        fh.write("{not json at all")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        os.environ["RESOURCE_PROFILE_PATH"] = fh.name
        _reset_governors()
        self.assertEqual(rg.scan_job_envelope("supply_chain"), 1_879_048_192)
        _set_mem(64 * GB, 32 * GB)
        self.assertIsNotNone(rg.container_cap(
            rg.tool_container_envelope("supply_chain_analyzer")))

    def test_zero_measurement_cannot_reserve_nothing(self):
        # A botched calibration writing 0 must not mean "this scan is free".
        self._profile({"scan_job_envelope_bytes": {"supply_chain": 0},
                       "tool_container_envelope_bytes": {"supply_chain_analyzer": 0}})
        self.assertGreater(rg.scan_job_envelope("supply_chain"), 0)
        self.assertGreater(rg.tool_container_envelope("supply_chain_analyzer"), 0)


# ---------------------------------------------------------------------------
# Seam 4: the invariant that ties admission to enforcement.
# ---------------------------------------------------------------------------
class TestReservationVersusCeilingInvariant(IntegrationBase):
    """Admission reserves an envelope; the kernel enforces a cap. If the cap for a
    unit is BELOW what was reserved for it, a normal run gets OOM-killed. If the
    reservation is below the cap of a container it is meant to cover, the host can
    be oversubscribed. Both directions matter, so assert the relationship."""

    UNITS = ("full_recon", "partial_recon", "partial_recon:SupplyChainRecon",
             "ai_attack", "gvm", "github_hunt", "trufflehog", "supply_chain")

    def test_every_scan_cap_is_at_least_its_reservation(self):
        _set_mem(64 * GB, 32 * GB)
        for kind in self.UNITS:
            env = rg.scan_job_envelope(kind)
            self.assertGreaterEqual(rg.container_cap(env), env, kind)

    def test_supply_chain_reservations_cover_the_analyzer_they_spawn(self):
        analyzer = rg.tool_container_envelope("supply_chain_analyzer")
        for kind in ("supply_chain", "partial_recon:SupplyChainRecon"):
            self.assertGreater(rg.scan_job_envelope(kind), analyzer, kind)

    def test_no_single_container_may_claim_the_whole_host(self):
        # 4 GB host: the DB and the app must survive any one scan container.
        _set_mem(4 * GB, 2 * GB)
        for kind in self.UNITS:
            cap = rg.container_cap(rg.scan_job_envelope(kind))
            self.assertLess(cap, 4 * GB, "{} could take the whole host".format(kind))


# ---------------------------------------------------------------------------
# Seam 5: the two analyzer spawn implementations, which live in packages that
# cannot import each other.
# ---------------------------------------------------------------------------
class TestSpawnPathParityContract(IntegrationBase):
    """`recon_orchestrator` cannot import `supply_chain_common` (not mounted) and
    the host cannot import `docker`, so no test can execute both resolvers in one
    process. Source inspection is the only place their agreement can be asserted
    at all - and it has to be asserted, because they have drifted twice:

      1. the broker side hardcoded a literal and ignored the governor
      2. fixing that made the SDK side ignore the operator's override

    Both bugs were invisible to every test that exercised only one side.
    """

    def _read(self, *parts):
        with open(os.path.join(ROOT, *parts)) as fh:
            return fh.read()

    def setUp(self):
        super().setUp()
        self.dispatch = self._read("scanners", "supply_chain_common", "analyzer_dispatch.py")
        self.manager = self._read("recon_orchestrator", "container_manager.py")

    def test_both_sides_read_the_same_override_variable(self):
        for src, who in ((self.dispatch, "analyzer_dispatch"),
                         (self.manager, "container_manager")):
            self.assertIn("SUPPLY_CHAIN_ANALYZER_MEM", src, who)

    def test_both_sides_read_the_same_tool_envelope_key(self):
        for src, who in ((self.dispatch, "analyzer_dispatch"),
                         (self.manager, "container_manager")):
            self.assertIn("supply_chain_analyzer", src, who)

    def test_both_sides_derive_the_cap_through_container_cap(self):
        # Not through a private clamp of their own: that is how they drifted.
        self.assertIn("container_cap(", self.dispatch)
        self.assertIn("container_cap(", self.manager)

    def _func_body(self, src, name):
        """Source of one def, up to the next top-level or method def."""
        start = src.find("def {}(".format(name))
        self.assertGreater(start, -1, "{} not found".format(name))
        rest = src[start:]
        nxt = rest.find("\n    def ", 1)
        end = nxt if nxt > 0 else len(rest)
        return rest[:end]

    def test_no_analyzer_spawn_site_hardcodes_a_memory_literal(self):
        """A size literal inline at a spawn site IS the original bug. Scoped to
        the analyzer's own spawn functions: other features have their own
        (separately governed or not) ceilings and are not this contract's
        business."""
        import re
        sites = [("analyzer_dispatch.analyzer_docker_argv",
                  self._func_body(self.dispatch, "analyzer_docker_argv")),
                 ("container_manager.run_supply_chain_analyzer",
                  self._func_body(self.manager, "run_supply_chain_analyzer")),
                 ("container_manager.run_guarddog_package",
                  self._func_body(self.manager, "run_guarddog_package"))]
        for who, body in sites:
            for m in re.finditer(r'["\']\d+(\.\d+)?[mMgG][bB]?["\']', body):
                context = body.splitlines()[body[:m.start()].count("\n")]
                self.assertNotIn("--memory", context, who)
                self.assertNotIn("mem_limit=", context, who)

    def test_each_analyzer_spawn_site_delegates_to_a_named_resolver(self):
        argv = self._func_body(self.dispatch, "analyzer_docker_argv")
        self.assertIn("_resolve_mem()", argv)
        for fn in ("run_supply_chain_analyzer", "run_guarddog_package"):
            self.assertIn("_analyzer_mem_limit()", self._func_body(self.manager, fn), fn)

    def test_the_dispatch_module_resolves_late_not_at_import(self):
        # A module-level os.environ read for the override is the exact shape of
        # the bug where a late-arriving operator value was silently dropped.
        head = self.dispatch.split("def analyzer_docker_argv")[0]
        self.assertNotIn('_DEFAULT_MEM = os.environ.get("SUPPLY_CHAIN_ANALYZER_MEM"', head)
        self.assertIn("def _resolve_mem", self.dispatch)

    def test_calibration_can_measure_the_analyzer(self):
        """Every byte figure the governor uses is meant to be measurable. The
        analyzer's was not: mem_calibrate maps sibling IMAGES to profile keys and
        had no hint for it, so a calibration run sampled the container and then
        discarded the number. A shipped estimate that can never be replaced by a
        measurement is a permanent guess."""
        cal = self._read("recon_orchestrator", "mem_calibrate.py")
        keys = cal[cal.find("TOOL_KEYS = {"):]
        keys = keys[:keys.find("}") + 1]
        self.assertIn("supply_chain_analyzer", keys)
        # The hint must actually match the real image name.
        hint = "supply-chain-analyzer"
        self.assertIn('"{}"'.format(hint), keys)
        self.assertIn(hint, "whitehat-supply-chain-analyzer:latest")

    def test_no_other_calibration_hint_collides_with_the_analyzer_image(self):
        # _tool_key does substring matching over an unordered dict, so a hint that
        # also appears in the analyzer's image name would make the key it resolves
        # to depend on iteration order.
        import re
        cal = self._read("recon_orchestrator", "mem_calibrate.py")
        block = cal[cal.find("TOOL_KEYS = {"):]
        block = block[:block.find("}") + 1]
        hints = re.findall(r'"([a-z0-9-]+)":\s*"', block)
        image = "whitehat-supply-chain-analyzer:latest"
        matching = [h for h in hints if h in image]
        self.assertEqual(matching, ["supply-chain-analyzer"],
                         "ambiguous calibration hints for the analyzer image")

    def test_the_governor_is_reached_fail_soft_from_the_dispatch_module(self):
        """The analyzer image mounts supply_chain_common but has no graph_db, so
        the import must be inside a function and guarded."""
        self.assertNotIn("\nfrom graph_db import resource_governor",
                         self.dispatch, "import must not be at module scope")
        block = self.dispatch[self.dispatch.find("def _governed_mem"):]
        block = block[:block.find("\ndef ", 10)]
        self.assertIn("except Exception", block)
        self.assertIn("return None", block)


if __name__ == '__main__':
    unittest.main()
