"""Integration + regression tests for per-scan-type memory envelopes.

Unlike tests/test_resource_governor.py (which unit-tests the governor) and
tests/test_admission_ledger.py (which unit-tests the ledger), this exercises the
LAYERS TOGETHER for the bug that was reported:

    profile layering -> envelope_for(kind) -> try_admit() -> container hard cap

on synthetic hosts of several sizes, for every scan type the orchestrator can
spawn. Deterministic: host memory is injected, no Docker and no /proc dependency.

Run: python3 -m unittest tests.test_scan_envelope_integration
"""
import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import unittest

_ORCH = os.path.join(os.path.dirname(__file__), '..', 'recon_orchestrator')


def _load(mod_name, filename):
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(_ORCH, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# Pin BOTH modules to the recon_orchestrator copies by path. Other test modules put
# graph_db (the governor twin) on sys.path, and whichever imports first wins the
# plain `resource_governor` slot for the whole process, so a bare import here would
# test the wrong copy depending on test ORDER. admission_ledger resolves its
# governor by name at exec time, so the slot is swapped just for that load and then
# restored, leaving other suites' bindings untouched.
rg = _load('_orch_rg_envelope_it', 'resource_governor.py')
_saved = sys.modules.get('resource_governor')
sys.modules['resource_governor'] = rg
try:
    al = _load('_orch_ledger_envelope_it', 'admission_ledger.py')
finally:
    if _saved is None:
        sys.modules.pop('resource_governor', None)
    else:
        sys.modules['resource_governor'] = _saved

GB = 1024 ** 3
MB = 1024 ** 2

# Every kind string passed to _admit_scan() in container_manager.py. Keep in sync:
# a new scan type with no envelope entry silently inherits `_default`.
SCAN_KINDS = ("full_recon", "partial_recon", "ai_attack", "gvm",
              "github_hunt", "trufflehog")

# Peaks observed by calibration on the dev host, in MiB. partial_recon is measured
# directly (_measured_scan_mb.job_envelope_peak); full_recon is derived from the
# 1.5 GiB envelope right-sized in 6.0.2 at MEM_SAFETY_TOLERANCE 0.25. An envelope
# BELOW its observed peak would under-reserve and risk the joint OOM the ledger
# exists to prevent.
OBSERVED_PEAK_MB = {"partial_recon": 153, "full_recon": 1229}

ENV_KNOBS = ("WHITEHAT_MEM_GOVERNOR", "OS_HEADROOM_MEM", "SERVICE_BASELINE_MEM",
             "RECON_JOB_ENVELOPE_MEM", "RECON_MAX_CONCURRENT_GLOBAL",
             "RECON_MAX_CONCURRENT_PER_USER", "RESOURCE_PROFILE_PATH",
             "RESOURCE_PROFILE_DEFAULT_PATH")


class EnvelopeIntegrationBase(unittest.IsolatedAsyncioTestCase):
    """Simulates a FRESH INSTALL: no host-specific (calibrated) profile on disk,
    so the shipped default + built-in fallback are what a real user gets."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ENV_KNOBS}
        for k in ENV_KNOBS:
            os.environ.pop(k, None)
        os.environ["RESOURCE_PROFILE_PATH"] = "/tmp/whitehat-no-such-profile.json"
        rg.reset_profile_cache()

    def tearDown(self):
        rg.set_mem_override(None, None)
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        rg.reset_profile_cache()

    def host(self, total_gb, free_gb):
        rg.set_mem_override(int(total_gb * GB), int(free_gb * GB))

    def container_cap(self, kind):
        """Mirror of container_manager._container_mem_limit() so the hard Docker
        ceiling derived from each envelope is asserted without importing the
        manager (which needs the docker SDK)."""
        led = al.ReservationLedger()
        envelope = led.envelope_for(kind)
        cap = int(envelope * rg._env_float("CONTAINER_CAP_HEADROOM", 1.5))
        per_max = rg.env_bytes("PER_CONTAINER_MAX", None)
        if per_max is None:
            mem = rg.read_mem()
            per_max = int(mem[0] * 0.55) if mem else cap
        return max(512 * MB, envelope, min(cap, per_max))


class TestWiring(unittest.TestCase):
    """If these fail, every other test in this file is exercising the wrong module
    and its passes mean nothing."""

    def test_ledger_and_test_share_one_governor_module(self):
        self.assertIs(al.rg, rg, "ledger bound a different resource_governor copy")

    def test_pinned_to_the_orchestrator_copies(self):
        self.assertIn(os.path.join('recon_orchestrator', 'resource_governor.py'),
                      rg.__file__)
        self.assertIn(os.path.join('recon_orchestrator', 'admission_ledger.py'),
                      al.__file__)

    def test_mem_override_reaches_the_ledger(self):
        rg.set_mem_override(7 * GB, 3 * GB)
        try:
            self.assertEqual(al.ReservationLedger().host_total(), 7 * GB)
        finally:
            rg.set_mem_override(None, None)


class TestEnvelopeSanity(EnvelopeIntegrationBase):
    def test_every_spawnable_kind_has_an_explicit_envelope(self):
        table = rg.load_profile()["scan_job_envelope_bytes"]
        for kind in SCAN_KINDS:
            self.assertIn(kind, table, f"{kind} would silently inherit _default")

    def test_no_envelope_is_below_its_observed_peak(self):
        led = al.ReservationLedger()
        for kind, peak_mb in OBSERVED_PEAK_MB.items():
            self.assertGreaterEqual(led.envelope_for(kind), peak_mb * MB,
                                    f"{kind} envelope under-reserves vs measured peak")

    def test_envelopes_are_ordered_by_real_workload_size(self):
        led = al.ReservationLedger()
        one_step = led.envelope_for("partial_recon")
        pipeline = led.envelope_for("full_recon")
        heaviest = led.envelope_for("gvm")
        self.assertLess(one_step, pipeline)
        self.assertLessEqual(pipeline, heaviest)


class TestSmallHostAdmission(EnvelopeIntegrationBase):
    """The reported failure: 8 GB Docker Desktop VM, services resident, RAM free."""

    async def test_partial_recon_admitted_on_8gb_host(self):
        self.host(8, 3.8)
        led = al.ReservationLedger()
        r = await led.try_admit("partial_recon:p1:r1", led.envelope_for("partial_recon"),
                                user_id="u1")
        self.assertTrue(r.admitted, r.detail)

    async def test_light_scan_types_all_admitted_on_8gb_host(self):
        self.host(8, 3.8)
        for kind in ("partial_recon", "github_hunt", "trufflehog", "ai_attack"):
            with self.subTest(kind=kind):
                led = al.ReservationLedger()
                r = await led.try_admit(f"{kind}:p1", led.envelope_for(kind), user_id="u1")
                self.assertTrue(r.admitted, f"{kind}: {r.detail}")

    async def test_every_kind_admitted_on_a_16gb_host(self):
        self.host(16, 11)
        for kind in SCAN_KINDS:
            with self.subTest(kind=kind):
                led = al.ReservationLedger()
                r = await led.try_admit(f"{kind}:p1", led.envelope_for(kind), user_id="u1")
                self.assertTrue(r.admitted, f"{kind}: {r.detail}")

    async def test_denial_is_still_possible_when_ram_really_is_gone(self):
        # The fix must not turn admission into a rubber stamp.
        self.host(8, 0.4)
        led = al.ReservationLedger()
        r = await led.try_admit("partial_recon:p1", led.envelope_for("partial_recon"),
                                user_id="u1")
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "ram")

    async def test_denial_payload_is_renderable_by_the_webapp(self):
        # webapp/src/lib/orchestratorError.ts reads these keys; a missing one
        # previously white-screened the app.
        self.host(8, 0.4)
        led = al.ReservationLedger()
        r = await led.try_admit("partial_recon:p1", led.envelope_for("partial_recon"))
        payload = r.payload()
        for key in ("admitted", "limitType", "resource", "current", "ceiling",
                    "settingName", "detail"):
            self.assertIn(key, payload)
        self.assertIsInstance(payload["detail"], str)
        self.assertTrue(payload["detail"])


class TestConcurrencyStillBounded(EnvelopeIntegrationBase):
    """Smaller envelopes must not break the OOM guarantee: N concurrent scans still
    have to fit the pool, and the sole-scan exemption must not leak into the 2nd."""

    async def test_pool_stops_admitting_before_the_pool_is_exceeded(self):
        # 32 GB host, explicit baseline -> pool = 32 - 2 - 6 = 24 GB.
        os.environ["OS_HEADROOM_MEM"] = "2g"
        os.environ["SERVICE_BASELINE_MEM"] = "6g"
        self.host(32, 30)
        led = al.ReservationLedger()
        envelope = led.envelope_for("partial_recon")   # 768 MB
        pool = led.scan_pool()
        admitted = 0
        for i in range(200):
            r = await led.try_admit(f"partial:{i}", envelope, user_id="u1")
            if not r.admitted:
                break
            admitted += 1
        self.assertGreater(admitted, 1, "must allow real concurrency")
        self.assertLessEqual(led.committed_bytes(), pool, "ledger overcommitted the pool")
        # Reservations are what bound it, so the count is pool/envelope (not the
        # per-user count cap, which defaults to 30 and would mask a pool bug).
        self.assertLessEqual(admitted, pool // envelope + 1)

    async def test_second_scan_on_a_zero_pool_host_is_refused(self):
        # 8 GB host, uncalibrated baseline (6 GB fallback) -> pool 0. The sole-scan
        # exemption lets ONE through; a second must be refused on budget grounds.
        self.host(8, 3.8)
        led = al.ReservationLedger()
        env = led.envelope_for("partial_recon")
        self.assertEqual(led.scan_pool(), 0)
        self.assertTrue((await led.try_admit("first", env, user_id="u1")).admitted)
        second = await led.try_admit("second", env, user_id="u1")
        self.assertFalse(second.admitted)
        self.assertEqual(second.limit_type, "ram")

    async def test_release_reopens_the_sole_scan_slot(self):
        self.host(8, 3.8)
        led = al.ReservationLedger()
        env = led.envelope_for("partial_recon")
        await led.try_admit("first", env, user_id="u1")
        self.assertFalse((await led.try_admit("second", env, user_id="u1")).admitted)
        led.reconcile(set())          # the scan finished / died
        self.assertTrue((await led.try_admit("second", env, user_id="u1")).admitted)


class TestContainerHardCap(EnvelopeIntegrationBase):
    """The Docker --memory ceiling is derived from the envelope, so shrinking
    envelopes must not start OOM-killing healthy scans."""

    def test_cap_stays_above_the_observed_peak(self):
        self.host(8, 3.8)
        for kind, peak_mb in OBSERVED_PEAK_MB.items():
            with self.subTest(kind=kind):
                self.assertGreater(self.container_cap(kind), peak_mb * MB * 1.5)

    def test_cap_is_never_below_the_reserved_envelope(self):
        self.host(8, 3.8)
        led = al.ReservationLedger()
        for kind in SCAN_KINDS:
            with self.subTest(kind=kind):
                self.assertGreaterEqual(self.container_cap(kind), led.envelope_for(kind))

    def test_cap_never_takes_the_whole_host(self):
        self.host(8, 3.8)
        for kind in SCAN_KINDS:
            with self.subTest(kind=kind):
                self.assertLess(self.container_cap(kind), 8 * GB)


class TestProfileLayeringEndToEnd(EnvelopeIntegrationBase):
    """The three layers, exercised through the ledger rather than the governor."""

    def _write(self, obj):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_calibrated_host_profile_beats_the_shipped_default(self):
        # What mem_calibrate.py actually writes: full_recon + _default, nothing else.
        path = self._write({"service_baseline_bytes": 4_798_940_160,
                            "scan_job_envelope_bytes": {"full_recon": 1_610_612_736,
                                                        "_default": 1_610_612_736}})
        os.environ["RESOURCE_PROFILE_PATH"] = path
        rg.reset_profile_cache()
        led = al.ReservationLedger()
        self.assertEqual(led.envelope_for("full_recon"), 1_610_612_736)  # measured wins
        # ...and the types calibration never measured keep the shipped defaults
        # instead of inheriting the (larger) measured _default.
        self.assertEqual(led.envelope_for("partial_recon"), 768 * MB)
        self.assertEqual(led.service_baseline(), 4_798_940_160)

    def test_env_override_beats_every_profile_layer(self):
        os.environ["RECON_JOB_ENVELOPE_MEM"] = "300m"
        rg.reset_profile_cache()
        led = al.ReservationLedger()
        for kind in SCAN_KINDS:
            self.assertEqual(led.envelope_for(kind), 300 * MB, kind)

    def test_shipped_default_is_what_a_fresh_clone_gets(self):
        # No RESOURCE_PROFILE_DEFAULT_PATH override: resolve the real shipped file.
        rg.reset_profile_cache()
        self.assertTrue(os.path.exists(rg._default_profile_path()),
                        "shipped profile missing from the repo/image")
        led = al.ReservationLedger()
        with open(rg._default_profile_path()) as fh:
            shipped = json.load(fh)["scan_job_envelope_bytes"]
        for kind in SCAN_KINDS:
            self.assertEqual(led.envelope_for(kind), shipped[kind], kind)


class TestGovernorDisabledPath(EnvelopeIntegrationBase):
    async def test_disabled_governor_admits_regardless_of_envelope(self):
        os.environ["WHITEHAT_MEM_GOVERNOR"] = "0"
        self.host(8, 0.1)
        led = al.ReservationLedger()
        r = await led.try_admit("partial_recon:p1", led.envelope_for("partial_recon"))
        self.assertTrue(r.admitted)

    async def test_unreadable_memory_fails_open(self):
        led = al.ReservationLedger(mem_reader=lambda: None, pressure_fn=lambda: "ok")
        r = await led.try_admit("partial_recon:p1", 768 * MB)
        self.assertTrue(r.admitted)


if __name__ == "__main__":
    unittest.main()
