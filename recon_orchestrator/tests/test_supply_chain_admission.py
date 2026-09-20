"""Memory admission for the supply-chain feature's two unaccounted paths.

Two holes this pins shut:

  * L3 GuardDog (`execute_guarddog`) spawned a real ~1.5 GB analyzer container
    and booked NOTHING. The agent could fire N in parallel while the ledger
    reported the host idle - precisely the sum-of-envelopes guarantee the
    governor exists to provide.
  * A supply-chain PARTIAL recon booked the generic 768 MB single-step envelope
    but also re-runs the JS fetch and spawns the analyzer, so it under-reserved
    by ~3x.

The second fix has a sharp edge worth testing directly: admission and the
reaper's _active_scan_keys must agree on the key FORMAT. If admission books
"partial_recon:SupplyChainRecon:pid:run" while _active_scan_keys reports
"partial_recon:pid:run", reconcile() sees an unknown committed key and frees a
live scan's reservation within 30 s.

Run: docker exec whitehat-recon-orchestrator sh -c 'cd /app && python -m unittest tests.test_supply_chain_admission -v'
"""

import asyncio
import os
import unittest
from unittest import mock

import resource_governor as rg
from admission_ledger import AdmissionError, AdmissionResult, ReservationLedger
import container_manager as cm
from container_manager import ContainerManager

GB = 1024 ** 3


def _mgr() -> ContainerManager:
    """A ContainerManager without __init__ (which calls docker.from_env)."""
    m = ContainerManager.__new__(ContainerManager)
    m.ledger = ReservationLedger()
    m.guarddog_jobs = set()
    m.running_states = {}
    m.partial_recon_states = {}
    m.ai_attack_states = {}
    m.gvm_states = {}
    m.github_hunt_states = {}
    m.trufflehog_states = {}
    m.supply_chain_states = {}
    # _active_scan_keys() walks this too (CodeFix sandboxes were brought under the
    # ledger in Phase 7); without it every reconcile test dies on AttributeError.
    m.codefix_sandboxes = {}
    return m


class TestPartialKindResolution(unittest.TestCase):
    def test_supply_chain_partial_is_tool_qualified(self):
        self.assertEqual(ContainerManager._partial_kind("SupplyChainRecon"),
                         "partial_recon:SupplyChainRecon")

    def test_missing_tool_id_degrades_to_the_plain_kind(self):
        self.assertEqual(ContainerManager._partial_kind(None), "partial_recon")
        self.assertEqual(ContainerManager._partial_kind(""), "partial_recon")

    def test_supply_chain_partial_reserves_more_than_a_plain_partial(self):
        ledger = ReservationLedger()
        self.assertGreater(
            ledger.envelope_for(ContainerManager._partial_kind("SupplyChainRecon")),
            ledger.envelope_for(ContainerManager._partial_kind("Naabu")))

    def test_other_partial_tools_keep_the_cheap_envelope(self):
        """Qualifying EVERY tool is only safe because an unknown qualified key
        falls back to its base kind. If it fell through to _default, every
        ordinary partial would jump from 768 MB to 2 GB and small hosts would
        stop admitting them."""
        ledger = ReservationLedger()
        self.assertEqual(ledger.envelope_for("partial_recon:Naabu"),
                         ledger.envelope_for("partial_recon"))


class TestPartialKeySymmetry(unittest.TestCase):
    """The reaper frees any committed key not in _active_scan_keys, so the two
    sides must build the SAME string."""

    def _state(self, tool_id, status):
        st = mock.MagicMock()
        st.tool_id = tool_id
        st.status = status
        return st

    def test_active_keys_use_the_same_qualified_kind_as_admission(self):
        from models import PartialReconStatus
        m = _mgr()
        m.partial_recon_states = {
            "proj1": {"run1": self._state("SupplyChainRecon", PartialReconStatus.RUNNING)}
        }
        admitted_key = m._scan_key(m._partial_kind("SupplyChainRecon"), "proj1", "run1")
        self.assertIn(admitted_key, m._active_scan_keys())

    def test_a_live_supply_chain_partial_survives_reconcile(self):
        """The end-to-end version of the above: book, reconcile, still booked."""
        from models import PartialReconStatus
        m = _mgr()
        rg.set_mem_override(64 * GB, 48 * GB)
        self.addCleanup(rg.set_mem_override, None, None)
        m.partial_recon_states = {
            "proj1": {"run1": self._state("SupplyChainRecon", PartialReconStatus.RUNNING)}
        }
        asyncio.run(m._admit_scan(m._partial_kind("SupplyChainRecon"), "proj1", "run1"))
        self.assertEqual(m.ledger.active_count(), 1)
        m.ledger.reconcile(m._active_scan_keys())
        self.assertEqual(m.ledger.active_count(), 1)

    def test_a_finished_partial_is_reconciled_free(self):
        m = _mgr()
        rg.set_mem_override(64 * GB, 48 * GB)
        self.addCleanup(rg.set_mem_override, None, None)
        asyncio.run(m._admit_scan(m._partial_kind("SupplyChainRecon"), "proj1", "run1"))
        m.partial_recon_states = {}          # scan gone
        m.ledger.reconcile(m._active_scan_keys())
        self.assertEqual(m.ledger.active_count(), 0)


class TestGuarddogAdmission(unittest.TestCase):
    def setUp(self):
        self.m = _mgr()
        rg.set_mem_override(64 * GB, 48 * GB)
        self.addCleanup(rg.set_mem_override, None, None)

    def _run(self, ok=True):
        self.m.run_guarddog_package = mock.MagicMock(
            return_value={"issues": 0, "rules_fired": [], "errors": [], "error": None})
        return asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))

    def test_a_job_books_the_analyzer_envelope(self):
        seen = {}

        def spy(*a, **kw):
            seen["committed"] = self.m.ledger.committed_bytes()
            seen["active"] = set(self.m._active_scan_keys())
            return {"issues": 0, "rules_fired": [], "errors": [], "error": None}

        self.m.run_guarddog_package = mock.MagicMock(side_effect=spy)
        asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(seen["committed"],
                         rg.tool_container_envelope("supply_chain_analyzer"))
        # In flight it must be listed as active, or the 30 s reaper frees a live job.
        self.assertEqual(len(seen["active"]), 1)

    def test_the_reservation_is_released_when_the_job_finishes(self):
        self._run()
        self.assertEqual(self.m.ledger.committed_bytes(), 0)
        self.assertEqual(self.m.guarddog_jobs, set())

    def test_the_reservation_is_released_when_the_job_raises(self):
        # A leaked reservation would permanently shrink the scan pool.
        self.m.run_guarddog_package = mock.MagicMock(side_effect=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(self.m.ledger.committed_bytes(), 0)
        self.assertEqual(self.m.guarddog_jobs, set())

    def test_concurrent_jobs_get_distinct_reservations(self):
        async def two():
            gate = asyncio.Event()
            seen = []

            def blocking(*a, **kw):
                seen.append(self.m.ledger.active_count())
                return {"issues": 0, "rules_fired": [], "errors": [], "error": None}

            self.m.run_guarddog_package = mock.MagicMock(side_effect=blocking)
            await asyncio.gather(
                self.m.run_guarddog_package_governed("npm", "a"),
                self.m.run_guarddog_package_governed("npm", "b"))
            return seen

        seen = asyncio.run(two())
        # Both ran; keys are uuid-based so neither collapsed onto the other's slot.
        self.assertEqual(len(seen), 2)
        self.assertEqual(self.m.ledger.committed_bytes(), 0)

    def test_a_refused_job_raises_admission_error_and_spawns_nothing(self):
        self.m.run_guarddog_package = mock.MagicMock()
        refuse = AdmissionResult(False, limit_type="ram", detail="host memory critically low")

        async def deny(*_a, **_kw):
            return refuse

        with mock.patch.object(self.m.ledger, "try_admit", side_effect=deny):
            with self.assertRaises(AdmissionError) as ctx:
                asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.m.run_guarddog_package.assert_not_called()
        self.assertEqual(ctx.exception.result.limit_type, "ram")
        self.assertEqual(self.m.guarddog_jobs, set())

    def test_refusal_payload_is_the_typed_limit_modal_shape(self):
        # api.py turns this into the 409 body the UI/agent branch on.
        refuse = AdmissionResult(False, limit_type="ram", detail="no room")
        payload = refuse.payload()
        self.assertEqual(payload["limitType"], "ram")
        self.assertIn("detail", payload)

    def test_fails_open_when_the_governor_is_disabled(self):
        with mock.patch.dict("os.environ", {"WHITEHAT_MEM_GOVERNOR": "false"}):
            out = self._run()
        self.assertEqual(out["issues"], 0)
        self.assertEqual(self.m.ledger.committed_bytes(), 0)


class TestMixedWorkloadReconcile(unittest.TestCase):
    """INTEGRATION: a realistic host running several kinds of work at once.

    Each scan type books through a different code path but they all share ONE
    ledger and ONE reaper, so the interesting failures are cross-type: a key
    format that only one type gets right, or a unit the reaper cannot see.
    """

    def setUp(self):
        self.m = _mgr()
        rg.set_mem_override(256 * GB, 200 * GB)   # roomy: nothing is refused
        self.addCleanup(rg.set_mem_override, None, None)

    def _partial(self, tool_id, status):
        st = mock.MagicMock()
        st.tool_id = tool_id
        st.status = status
        return st

    def _book_everything(self):
        from models import (PartialReconStatus, ReconStatus, SupplyChainStatus)
        run = asyncio.run
        run(self.m._admit_scan("full_recon", "p1"))
        run(self.m._admit_scan(self.m._partial_kind("SupplyChainRecon"), "p1", "r1"))
        run(self.m._admit_scan(self.m._partial_kind("Naabu"), "p1", "r2"))
        run(self.m._admit_scan("supply_chain", "p2"))

        full = mock.MagicMock()
        full.status = ReconStatus.RUNNING
        self.m.running_states = {"p1": full}
        self.m.partial_recon_states = {"p1": {
            "r1": self._partial("SupplyChainRecon", PartialReconStatus.RUNNING),
            "r2": self._partial("Naabu", PartialReconStatus.RUNNING)}}
        sc = mock.MagicMock()
        sc.status = SupplyChainStatus.RUNNING
        self.m.supply_chain_states = {"p2": sc}

    def test_all_four_survive_a_reconcile(self):
        self._book_everything()
        self.assertEqual(self.m.ledger.active_count(), 4)
        self.assertEqual(self.m.ledger.reconcile(self.m._active_scan_keys()), 0)
        self.assertEqual(self.m.ledger.active_count(), 4)

    def test_committed_total_is_the_sum_of_the_right_envelopes(self):
        self._book_everything()
        expected = (self.m.ledger.envelope_for("full_recon")
                    + self.m.ledger.envelope_for("partial_recon:SupplyChainRecon")
                    + self.m.ledger.envelope_for("partial_recon:Naabu")
                    + self.m.ledger.envelope_for("supply_chain"))
        self.assertEqual(self.m.ledger.committed_bytes(), expected)

    def test_an_l3_job_adds_on_top_of_running_scans_then_frees(self):
        self._book_everything()
        base = self.m.ledger.committed_bytes()
        peak = {}

        def spy(*a, **kw):
            peak["committed"] = self.m.ledger.committed_bytes()
            peak["released"] = self.m.ledger.reconcile(self.m._active_scan_keys())
            return {"issues": 0, "rules_fired": [], "errors": [], "error": None}

        self.m.run_guarddog_package = mock.MagicMock(side_effect=spy)
        asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(peak["committed"],
                         base + rg.tool_container_envelope("supply_chain_analyzer"))
        # A reaper tick DURING the job must not free the job or any scan.
        self.assertEqual(peak["released"], 0)
        self.assertEqual(self.m.ledger.committed_bytes(), base)

    def test_only_the_finished_scan_is_reclaimed(self):
        from models import PartialReconStatus
        self._book_everything()
        # The supply-chain partial ends; everything else keeps running.
        self.m.partial_recon_states["p1"]["r1"].status = PartialReconStatus.COMPLETED
        released = self.m.ledger.reconcile(self.m._active_scan_keys())
        self.assertEqual(released, 1)
        self.assertEqual(self.m.ledger.active_count(), 3)
        self.assertNotIn("partial_recon:SupplyChainRecon:p1:r1", self.m.ledger._committed)
        self.assertIn("partial_recon:Naabu:p1:r2", self.m.ledger._committed)


class TestL3LeakSafety(unittest.TestCase):
    """A reservation that leaks permanently shrinks the scan pool until restart,
    so every exit path from an L3 job must give the bytes back."""

    def setUp(self):
        self.m = _mgr()
        rg.set_mem_override(256 * GB, 200 * GB)
        self.addCleanup(rg.set_mem_override, None, None)

    def test_cancellation_mid_job_does_not_leak(self):
        """If the request is cancelled while the analyzer runs, the `finally`
        still has to await the ledger lock, which cancellation can interrupt. The
        key is removed from guarddog_jobs FIRST, so even in the worst case the
        reaper reclaims it on the next tick rather than leaking forever."""
        async def scenario():
            started = asyncio.Event()

            def block(*a, **kw):
                started.set()
                import time
                time.sleep(0.5)
                return {"issues": 0, "rules_fired": [], "errors": [], "error": None}

            self.m.run_guarddog_package = mock.MagicMock(side_effect=block)
            task = asyncio.create_task(
                self.m.run_guarddog_package_governed("npm", "left-pad"))
            await started.wait()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            # Whatever happened to the await in `finally`, the reaper can see it.
            return self.m.ledger.reconcile(self.m._active_scan_keys())

        asyncio.run(scenario())
        self.assertEqual(self.m.ledger.committed_bytes(), 0)
        self.assertEqual(self.m.guarddog_jobs, set())

    def test_many_sequential_jobs_leave_nothing_behind(self):
        self.m.run_guarddog_package = mock.MagicMock(
            return_value={"issues": 0, "rules_fired": [], "errors": [], "error": None})
        for i in range(25):
            asyncio.run(self.m.run_guarddog_package_governed("npm", "pkg{}".format(i)))
        self.assertEqual(self.m.ledger.committed_bytes(), 0)
        self.assertEqual(self.m.ledger.active_count(), 0)

    def test_a_refused_job_reserves_nothing(self):
        refuse = AdmissionResult(False, limit_type="ram", detail="no room")

        async def deny(*_a, **_kw):
            return refuse

        self.m.run_guarddog_package = mock.MagicMock()
        with mock.patch.object(self.m.ledger, "try_admit", side_effect=deny):
            for _ in range(5):
                with self.assertRaises(AdmissionError):
                    asyncio.run(self.m.run_guarddog_package_governed("npm", "x"))
        self.assertEqual(self.m.ledger.committed_bytes(), 0)


class TestSaturationBehaviour(unittest.TestCase):
    """The governor's whole promise is that the SUM cannot exceed the pool. These
    drive the ledger to its limit through the real admission path."""

    def setUp(self):
        self.m = _mgr()
        self.addCleanup(rg.set_mem_override, None, None)

    def test_l3_is_refused_under_critical_pressure(self):
        rg.set_mem_override(8 * GB, 256 * 1024 ** 2)   # ratio 0.03 -> critical
        self.m.run_guarddog_package = mock.MagicMock()
        with self.assertRaises(AdmissionError) as ctx:
            asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(ctx.exception.result.limit_type, "ram")
        self.m.run_guarddog_package.assert_not_called()

    def test_l3_is_admitted_again_once_memory_frees(self):
        rg.set_mem_override(8 * GB, 256 * 1024 ** 2)
        self.m.run_guarddog_package = mock.MagicMock(
            return_value={"issues": 0, "rules_fired": [], "errors": [], "error": None})
        with self.assertRaises(AdmissionError):
            asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        rg.set_mem_override(64 * GB, 48 * GB)          # a scan finished
        out = asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(out["issues"], 0)

    def test_the_global_count_cap_also_applies_to_l3(self):
        """L3 jobs are real containers, so they count against the concurrency
        ceiling like anything else. Documents the coupling deliberately: an agent
        on a saturated host is told to wait rather than piling on."""
        rg.set_mem_override(256 * GB, 200 * GB)
        self.m.run_guarddog_package = mock.MagicMock()
        with mock.patch.dict("os.environ", {"RECON_MAX_CONCURRENT_GLOBAL": "0"}):
            with self.assertRaises(AdmissionError) as ctx:
                asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(ctx.exception.result.limit_type, "hard")
        self.assertEqual(ctx.exception.result.setting_name, "RECON_MAX_CONCURRENT_GLOBAL")

    def test_supply_chain_scan_refused_on_a_host_too_small_for_it(self):
        # 3 GB host: 1.75 GB envelope + 2 GB OS headroom does not fit. Refusing is
        # correct; admitting would OOM the DB mid-scan.
        rg.set_mem_override(3 * GB, 2 * GB)
        with self.assertRaises(AdmissionError) as ctx:
            asyncio.run(self.m._admit_scan("supply_chain", "p1"))
        self.assertEqual(ctx.exception.result.limit_type, "ram")


class TestAnalyzerCapSource(unittest.TestCase):
    """The analyzer is a SIBLING TOOL, not a scan: it must be sized from the tool
    envelope. Sizing it from the L1 scan envelope meant an L3 call - which has no
    L1 scan anywhere near it - was capped by an unrelated number."""

    def setUp(self):
        rg.set_mem_override(64 * GB, 48 * GB)
        self.addCleanup(rg.set_mem_override, None, None)

    def test_tool_cap_matches_the_governor(self):
        m = _mgr()
        self.assertEqual(m._tool_container_mem_limit("supply_chain_analyzer"),
                         rg.container_cap(rg.tool_container_envelope("supply_chain_analyzer")))

    def test_tool_cap_differs_from_the_l1_scan_cap(self):
        m = _mgr()
        self.assertNotEqual(m._tool_container_mem_limit("supply_chain_analyzer"),
                            m._container_mem_limit("supply_chain"))

    def test_scan_cap_still_sits_above_its_admission_envelope(self):
        m = _mgr()
        self.assertGreaterEqual(m._container_mem_limit("supply_chain"),
                                m.ledger.envelope_for("supply_chain"))

    def test_fails_open_when_governor_disabled(self):
        m = _mgr()
        with mock.patch.dict("os.environ", {"WHITEHAT_MEM_GOVERNOR": "false"}):
            self.assertIsNone(m._tool_container_mem_limit("supply_chain_analyzer"))
            self.assertIsNone(m._container_mem_limit("supply_chain"))


class TestAnalyzerOverridePrecedence(unittest.TestCase):
    """The analyzer is spawned by the Docker SDK here and by `docker run` through
    the broker in recon/L1. supply_chain_common.analyzer_dispatch exists so those
    two never diverge. They have now diverged twice, in both directions:

      1. the broker side hardcoded "1500m" and ignored the governor
      2. fixing that made THIS side ignore the operator's explicit override

    Precedence is override > governor > caller default, on both sides."""

    def setUp(self):
        self.m = _mgr()
        self.m.supply_chain_analyzer_mem = "1500m"
        rg.set_mem_override(64 * GB, 48 * GB)
        self.addCleanup(rg.set_mem_override, None, None)

    def test_operator_override_wins_over_the_governor(self):
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "700m"}):
            self.assertEqual(self.m._analyzer_mem_limit(), "700m")

    def test_governor_is_used_when_no_override_is_set(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            os.environ.pop("SUPPLY_CHAIN_ANALYZER_MEM", None)
            self.assertEqual(
                self.m._analyzer_mem_limit(),
                rg.container_cap(rg.tool_container_envelope("supply_chain_analyzer")))

    def test_blank_override_is_treated_as_unset(self):
        # Compose emits `SUPPLY_CHAIN_ANALYZER_MEM=` for an unset variable.
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "  "}):
            self.assertNotEqual(self.m._analyzer_mem_limit(), "  ")
            self.assertIsInstance(self.m._analyzer_mem_limit(), int)

    def test_override_is_read_at_call_time_not_at_construction(self):
        # __init__ snapshots supply_chain_analyzer_mem; a var that arrives later
        # (or is changed) must still be honoured.
        self.assertIsInstance(self.m._analyzer_mem_limit(), int)
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "333m"}):
            self.assertEqual(self.m._analyzer_mem_limit(), "333m")

    def test_governor_disabled_falls_back_to_the_constructor_value(self):
        with mock.patch.dict("os.environ", {"WHITEHAT_MEM_GOVERNOR": "false"}):
            os.environ.pop("SUPPLY_CHAIN_ANALYZER_MEM", None)
            self.assertEqual(self.m._analyzer_mem_limit(), "1500m")

    def test_both_analyzer_spawn_sites_use_the_shared_resolver(self):
        """Source-level: two call sites, one resolver. A future edit that inlines
        a limit at one of them recreates the drift this class documents."""
        with open(os.path.join(os.path.dirname(__file__), "..",
                               "container_manager.py")) as fh:
            src = fh.read()
        self.assertEqual(src.count("mem_limit=self._analyzer_mem_limit()"), 2)
        self.assertNotIn('mem_limit=self._container_mem_limit("supply_chain") or', src)


class TestAnalyzerReservationTracksTheOverride(unittest.TestCase):
    """An override raises the hard cap without telling the ledger. If admission
    kept reserving the 1 GB envelope while the container was permitted 4 GB, the
    sum-of-envelopes guarantee would be quietly false."""

    def setUp(self):
        self.m = _mgr()
        rg.set_mem_override(256 * GB, 200 * GB)
        self.addCleanup(rg.set_mem_override, None, None)

    def test_a_larger_override_raises_the_reservation(self):
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "4g"}):
            self.assertEqual(self.m._analyzer_envelope(), 4 * GB)

    def test_a_smaller_override_does_not_lower_the_reservation(self):
        # Reserving less than the expected peak would under-count a normal run.
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "128m"}):
            self.assertEqual(self.m._analyzer_envelope(),
                             rg.tool_container_envelope("supply_chain_analyzer"))

    def test_an_unparseable_override_is_ignored(self):
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "banana"}):
            self.assertEqual(self.m._analyzer_envelope(),
                             rg.tool_container_envelope("supply_chain_analyzer"))

    def test_the_l3_job_books_the_override_aware_envelope(self):
        seen = {}

        def spy(*a, **kw):
            seen["committed"] = self.m.ledger.committed_bytes()
            return {"issues": 0, "rules_fired": [], "errors": [], "error": None}

        self.m.run_guarddog_package = mock.MagicMock(side_effect=spy)
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "4g"}):
            asyncio.run(self.m.run_guarddog_package_governed("npm", "left-pad"))
        self.assertEqual(seen["committed"], 4 * GB)
        self.assertEqual(self.m.ledger.committed_bytes(), 0)


class TestBlankEnvIsUnset(unittest.TestCase):
    """The orchestrator has NO env_file, so an optional knob only reaches it if
    compose lists it as ``VAR: ${VAR:-}``. That idiom delivers an EMPTY STRING
    when the operator set nothing - not a missing key - so every reader has to
    treat blank as unset. The analyzer knobs are read in __init__, where
    ``int("")`` is not a wrong value but a crash-loop of the whole service."""

    def test_blank_falls_back_to_default(self):
        with mock.patch.dict("os.environ", {"X_TEST_KNOB": ""}):
            self.assertEqual(cm._env_unset_if_blank("X_TEST_KNOB", "fallback"), "fallback")
        with mock.patch.dict("os.environ", {"X_TEST_KNOB": "   "}):
            self.assertEqual(cm._env_unset_if_blank("X_TEST_KNOB", "fallback"), "fallback")

    def test_missing_falls_back_to_default(self):
        env = dict(os.environ)
        env.pop("X_TEST_KNOB", None)
        with mock.patch.dict("os.environ", env, clear=True):
            self.assertEqual(cm._env_unset_if_blank("X_TEST_KNOB", "fallback"), "fallback")

    def test_set_value_wins_and_is_stripped(self):
        with mock.patch.dict("os.environ", {"X_TEST_KNOB": " 700m "}):
            self.assertEqual(cm._env_unset_if_blank("X_TEST_KNOB", "fallback"), "700m")

    def test_blank_numeric_knobs_do_not_raise(self):
        """The regression this guards: compose passing the PID/CPU knobs through
        empty made int() raise inside ContainerManager.__init__."""
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_PIDS": "",
                                            "SUPPLY_CHAIN_ANALYZER_NANOCPUS": ""}):
            self.assertEqual(int(cm._env_unset_if_blank("SUPPLY_CHAIN_ANALYZER_PIDS", "512")), 512)
            self.assertEqual(
                int(cm._env_unset_if_blank("SUPPLY_CHAIN_ANALYZER_NANOCPUS", str(2_000_000_000))),
                2_000_000_000)


class TestAnalyzerEnvPassthrough(unittest.TestCase):
    """The analyzer is spawned from three processes, but only this one reads the
    operator's .env. The recon (L2) and supply-chain (L1) containers run the
    OTHER implementation (supply_chain_common.analyzer_dispatch) and inherit
    nothing, so an override that is not forwarded at spawn applies to L3 alone -
    the same two-implementations-disagree failure the parity contract exists to
    prevent, just relocated to the process boundary."""

    def test_forwards_only_keys_the_operator_set(self):
        m = _mgr()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SUPPLY_CHAIN_ANALYZER_")}
        env["SUPPLY_CHAIN_ANALYZER_MEM"] = "700m"
        with mock.patch.dict("os.environ", env, clear=True):
            self.assertEqual(m._analyzer_env(), {"SUPPLY_CHAIN_ANALYZER_MEM": "700m"})

    def test_blank_knobs_are_not_forwarded(self):
        """A forwarded empty string would read as an explicit pin on the far
        side and defeat the governor there."""
        m = _mgr()
        with mock.patch.dict("os.environ", {"SUPPLY_CHAIN_ANALYZER_MEM": "",
                                            "SUPPLY_CHAIN_ANALYZER_PIDS": "  "}):
            self.assertEqual(m._analyzer_env(), {})

    def test_forwards_every_documented_knob(self):
        m = _mgr()
        pinned = {k: "1" for k in m._ANALYZER_PASSTHROUGH_ENV}
        with mock.patch.dict("os.environ", pinned):
            self.assertEqual(set(m._analyzer_env()), set(m._ANALYZER_PASSTHROUGH_ENV))

    def test_passthrough_list_covers_what_dispatch_reads(self):
        """Source-level parity: analyzer_dispatch resolves these from its own
        environment, so anything it reads must be forwarded or it silently
        falls back while the orchestrator uses the operator's value."""
        for knob in ("SUPPLY_CHAIN_ANALYZER_IMAGE", "SUPPLY_CHAIN_ANALYZER_NETWORK",
                     "SUPPLY_CHAIN_ANALYZER_MEM", "SUPPLY_CHAIN_ANALYZER_PIDS"):
            self.assertIn(knob, ContainerManager._ANALYZER_PASSTHROUGH_ENV)


if __name__ == "__main__":
    unittest.main()
