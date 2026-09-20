"""Unit tests for the DIRTY analyzer job pipeline (supply_chain_analyzer).

This is the single entry point for every hostile-byte operation: retire.js over
target-served JS, GuardDog over registry tarballs, osv-scanner over manifests.
Until now the whole pipeline had NO caller, so none of it was covered end to end
and `js-dir` mode silently produced packages with no verdicts.

Every regression test is named after the bug it pins.

No binaries, no network: the runners are injected.

Run: python -m pytest tests/test_supply_chain_analyzer_job.py
"""

import importlib.util
import json
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_spec = importlib.util.spec_from_file_location(
    "sc_analyzer_entrypoint",
    os.path.join(_REPO, "scanners", "supply_chain_analyzer", "entrypoint.py"))
ep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ep)

from supply_chain_common.security import validate_artifact  # noqa: E402


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------

class _FakeRetire:
    """Stands in for supply_chain_common.retire_runner."""

    def __init__(self, components=None, error=None, raise_on_purl=False):
        self.components = components or []
        self.error = error
        self.raise_on_purl = raise_on_purl
        self.scanned = []

    def scan_js_dir(self, target, **kw):
        self.scanned.append(target)
        return {"components": self.components, "vulnerabilities": [],
                "error": self.error}

    def to_purls(self, comps):
        if self.raise_on_purl:
            raise ValueError("hostile component")
        out = []
        for c in comps:
            if c.get("name") and c.get("version"):
                out.append("pkg:npm/{}@{}".format(c["name"], c["version"]))
        return out


class _FakeOsv:
    def __init__(self, parsed=None, error=None):
        self.parsed = parsed or {"packages": [], "malicious": [], "vulnerable": []}
        self.error = error
        self.calls = []

    def run_osv_scan(self, target, mode=None, db_path=None, **kw):
        self.calls.append({"target": target, "mode": mode, "db_path": db_path})
        # For sbom mode the caller must hand us a real, parseable SBOM file;
        # other modes point at a manifest the test does not materialize.
        if mode == "sbom":
            with open(target) as fh:
                self.last_sbom = json.load(fh)
        return {"parsed": self.parsed, "error": self.error, "raw": None}


class _FakeGuardDog:
    def __init__(self, findings=None, error=None):
        self.findings = findings or []
        self.error = error
        self.calls = []

    def scan_package(self, eco, name, version=None, **kw):
        self.calls.append((eco, name, version))
        return {"findings": self.findings, "error": self.error, "raw": None}


def _comp(name, version):
    return {"name": name, "version": version}


def _osv_finding(name, version, advisory="MAL-1", eco="npm"):
    return {"name": name, "version": version, "ecosystem": eco,
            "purl": "pkg:npm/{}@{}".format(name, version),
            "advisory_id": advisory, "summary": "s", "aliases": []}


class _JobCase(unittest.TestCase):
    """Swaps the module-level runners for the duration of a test."""

    def setUp(self):
        self._orig = (ep.retire_runner, ep.osv_runner, ep.guarddog_runner)

    def tearDown(self):
        ep.retire_runner, ep.osv_runner, ep.guarddog_runner = self._orig

    def run_job(self, job, retire=None, osv=None, guarddog=None):
        if retire is not None:
            ep.retire_runner = retire
        if osv is not None:
            ep.osv_runner = osv
        if guarddog is not None:
            ep.guarddog_runner = guarddog
        return ep.run_job(job)


# --------------------------------------------------------------------------
# js-dir mode: the retire.js path
# --------------------------------------------------------------------------

class TestJsDirMode(_JobCase):

    def test_retire_components_become_packages(self):
        retire = _FakeRetire([_comp("jquery", "3.4.1"), _comp("lodash", "4.17.20")])
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=retire, osv=_FakeOsv())
        purls = {p["purl"] for p in art["packages"]}
        self.assertEqual(purls, {"pkg:npm/jquery@3.4.1", "pkg:npm/lodash@4.17.20"})
        self.assertTrue(all(p["source"] == "retirejs" for p in art["packages"]))
        self.assertEqual(retire.scanned, ["/work/js"])

    def test_retire_packages_carry_a_version(self):
        """The whole point of retire.js: source maps give names only, so this is
        the one L2 source that can produce a verdictable coordinate."""
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("jquery", "3.4.1")]),
                           osv=_FakeOsv())
        self.assertEqual(art["packages"][0]["version"], "3.4.1")

    def test_regression_js_dir_runs_the_osv_verdict(self):
        """REGRESSION: js-dir mode harvested components and STOPPED - the
        entrypoint literally said the OSV verdict was 'wired in Phase 3'. So
        every retire.js package came back with no verdict, which reads as clean.
        """
        osv = _FakeOsv(parsed={
            "packages": [],
            "malicious": [_osv_finding("jquery", "3.4.1", "MAL-9999")],
            "vulnerable": [],
        })
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("jquery", "3.4.1")]), osv=osv)
        self.assertEqual(len(osv.calls), 1, "osv-scanner must actually run")
        self.assertEqual(osv.calls[0]["mode"], "sbom")
        self.assertEqual(len(art["malicious"]), 1)
        self.assertEqual(art["malicious"][0]["advisory_id"], "MAL-9999")

    def test_osv_receives_a_valid_cyclonedx_sbom(self):
        osv = _FakeOsv()
        self.run_job({"mode": "js-dir", "target": "/work/js"},
                     retire=_FakeRetire([_comp("jquery", "3.4.1")]), osv=osv)
        sbom = osv.last_sbom
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(len(sbom["components"]), 1)
        self.assertEqual(sbom["components"][0]["purl"], "pkg:npm/jquery@3.4.1")
        self.assertEqual(sbom["components"][0]["version"], "3.4.1")

    def test_vulnerable_verdicts_are_folded_in(self):
        osv = _FakeOsv(parsed={"packages": [], "malicious": [],
                               "vulnerable": [_osv_finding("jquery", "3.4.1", "GHSA-x")]})
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("jquery", "3.4.1")]), osv=osv)
        self.assertEqual(len(art["vulnerable"]), 1)
        self.assertEqual(len(art["malicious"]), 0)

    def test_packages_are_not_duplicated_by_the_verdict_pass(self):
        """add_osv_findings would re-add the packages under source=osv; only the
        verdicts may be folded in."""
        osv = _FakeOsv(parsed={
            "packages": [{"purl": "pkg:npm/jquery@3.4.1", "name": "jquery",
                          "version": "3.4.1", "ecosystem": "npm"}],
            "malicious": [], "vulnerable": []})
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("jquery", "3.4.1")]), osv=osv)
        self.assertEqual(len(art["packages"]), 1)
        self.assertEqual(art["packages"][0]["source"], "retirejs")

    def test_no_components_means_no_osv_call(self):
        osv = _FakeOsv()
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([]), osv=osv)
        self.assertEqual(osv.calls, [])
        self.assertEqual(art["packages"], [])

    def test_component_without_version_is_recorded_but_not_verdicted(self):
        osv = _FakeOsv()
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("mystery", None)]), osv=osv)
        self.assertEqual(len(art["packages"]), 1)
        self.assertIsNone(art["packages"][0]["purl"])
        self.assertEqual(osv.calls, [], "no purl -> nothing to verdict")

    def test_retire_error_is_surfaced(self):
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([], error="retire exploded"),
                           osv=_FakeOsv())
        self.assertTrue(any("retire" in e for e in art["errors"]))

    def test_osv_error_is_surfaced(self):
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("jquery", "3.4.1")]),
                           osv=_FakeOsv(error="offline OSV DB missing"))
        self.assertTrue(any("osv" in e for e in art["errors"]))

    def test_regression_hostile_component_name_does_not_discard_the_job(self):
        """REGRESSION: retire.js parses ATTACKER-SERVED JS, so a component name
        is untrusted. A hostile name reached validate_artifact at the end of
        run_job, which raises on the WHOLE artifact - discarding every
        legitimate package and every verdict collected in that job."""
        retire = _FakeRetire([_comp("evil;whoami", "1.0"),
                              _comp("jquery", "3.4.1")])
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=retire, osv=_FakeOsv())
        names = {p["name"] for p in art["packages"]}
        self.assertEqual(names, {"jquery"}, "hostile name dropped, good one kept")
        self.assertTrue(any("hostile component" in e for e in art["errors"]))
        validate_artifact(art)

    def test_hostile_version_is_dropped_too(self):
        retire = _FakeRetire([_comp("ok", "1.0; rm -rf /")])
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=retire, osv=_FakeOsv())
        self.assertEqual(art["packages"], [])

    def test_purl_failure_records_the_package_without_a_purl(self):
        retire = _FakeRetire([_comp("jquery", "3.4.1")], raise_on_purl=True)
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=retire, osv=_FakeOsv())
        self.assertEqual(len(art["packages"]), 1)
        self.assertIsNone(art["packages"][0]["purl"])

    def test_result_clears_the_boundary_validator(self):
        art = self.run_job({"mode": "js-dir", "target": "/work/js"},
                           retire=_FakeRetire([_comp("jquery", "3.4.1")]),
                           osv=_FakeOsv())
        validate_artifact(art)  # must not raise

    def test_sbom_tempdir_is_cleaned_up(self):
        osv = _FakeOsv()
        self.run_job({"mode": "js-dir", "target": "/work/js"},
                     retire=_FakeRetire([_comp("jquery", "3.4.1")]), osv=osv)
        self.assertFalse(os.path.exists(os.path.dirname(osv.calls[0]["target"])))


# --------------------------------------------------------------------------
# Other modes still work
# --------------------------------------------------------------------------

class TestOtherModes(_JobCase):

    def test_lockfile_mode_unchanged(self):
        osv = _FakeOsv(parsed={"packages": [], "malicious": [],
                               "vulnerable": [_osv_finding("x", "1.0", "GHSA-y")]})
        art = self.run_job({"mode": "lockfile", "target": "/work/package-lock.json"},
                           osv=osv)
        self.assertEqual(osv.calls[0]["mode"], "lockfile")
        self.assertEqual(len(art["vulnerable"]), 1)

    def test_unsupported_mode_is_an_error_not_a_crash(self):
        art = self.run_job({"mode": "nonsense", "target": "/work/x"})
        self.assertTrue(any("unsupported mode" in e for e in art["errors"]))


# --------------------------------------------------------------------------
# GuardDog leg of the same job
# --------------------------------------------------------------------------

class TestGuardDogLeg(_JobCase):

    def test_deep_analysis_off_means_no_guarddog(self):
        gd = _FakeGuardDog()
        self.run_job({"mode": "js-dir", "target": "/work/js",
                      "guarddog_packages": [{"ecosystem": "npm", "name": "x"}]},
                     retire=_FakeRetire([]), osv=_FakeOsv(), guarddog=gd)
        self.assertEqual(gd.calls, [])

    def test_deep_analysis_runs_over_the_given_packages(self):
        gd = _FakeGuardDog(findings=[{"package": "x", "version": "1.0",
                                      "rule": "capability-process-spawn",
                                      "severity": "low", "confidence": "suspicious",
                                      "message": "m", "soft_error": False}])
        art = self.run_job({"mode": "js-dir", "target": "/work/js",
                            "deep_analysis": True,
                            "guarddog_packages": [{"ecosystem": "npm", "name": "x",
                                                   "version": "1.0"}]},
                           retire=_FakeRetire([]), osv=_FakeOsv(), guarddog=gd)
        self.assertEqual(gd.calls, [("npm", "x", "1.0")])
        self.assertEqual(len(art["suspicious"]), 1)

    def test_guarddog_package_list_is_capped(self):
        gd = _FakeGuardDog()
        pkgs = [{"ecosystem": "npm", "name": "p%d" % i} for i in range(150)]
        self.run_job({"mode": "js-dir", "target": "/work/js",
                      "deep_analysis": True, "guarddog_packages": pkgs},
                     retire=_FakeRetire([]), osv=_FakeOsv(), guarddog=gd)
        self.assertEqual(len(gd.calls), 100)


# --------------------------------------------------------------------------
# analyzer_dispatch: ONE definition of the DIRTY spawn, shared by the
# orchestrator (Docker SDK) and the recon container (docker CLI via the broker)
# --------------------------------------------------------------------------

import shutil          # noqa: E402
import tempfile        # noqa: E402
from supply_chain_common import analyzer_dispatch as ad  # noqa: E402


class TestAnalyzerArgvHardening(unittest.TestCase):
    """The recon side used to hand-roll its own `docker run` for GuardDog, so a
    security boundary existed in two copies that could drift. These pin the
    flags that make the DIRTY zone safe."""

    def argv(self, **kw):
        return ad.analyzer_docker_argv("/tmp/whitehat/j", "/host/sc_common", **kw)

    def test_drops_all_capabilities(self):
        a = self.argv()
        self.assertIn("--cap-drop", a)
        self.assertEqual(a[a.index("--cap-drop") + 1], "ALL")

    def test_read_only_rootfs_with_exec_tmpfs(self):
        a = self.argv()
        self.assertIn("--read-only", a)
        self.assertTrue(any(x.startswith("/tmp:size=") and "exec" in x for x in a))

    def test_resource_caps_present(self):
        a = self.argv()
        self.assertIn("--pids-limit", a)
        self.assertIn("--memory", a)

    def test_carries_NO_secrets(self):
        """A full RCE in the analyzer must find no credential."""
        joined = " ".join(self.argv()).lower()
        for secret in ("neo4j", "password", "internal_key", "internal-key",
                       "github_token", "api_key", "scanner_api"):
            self.assertNotIn(secret, joined)

    def test_only_the_offline_db_pointer_is_injected(self):
        env = [a for i, a in enumerate(self.argv()) if self.argv()[i - 1] == "-e"]
        self.assertEqual(sorted(env), sorted([
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db",
            "PYTHONUNBUFFERED=1", "PYTHONPATH=/app"]))

    def test_osv_db_is_mounted_read_only(self):
        self.assertIn("-v", self.argv())
        self.assertTrue(any(x.endswith(":/osv-db:ro") for x in self.argv()))

    def test_sc_common_is_mounted_read_only(self):
        self.assertTrue(any(x.endswith(":/app/supply_chain_common:ro")
                            for x in self.argv()))

    def test_work_dir_is_the_only_writable_mount(self):
        rw = [x for x in self.argv() if x.endswith(":rw")]
        self.assertEqual(len(rw), 1)
        self.assertTrue(rw[0].endswith(":/work:rw"))

    def test_regression_egress_fails_closed(self):
        """GuardDog needs the registry, but without an explicitly configured
        egress network the analyzer must stay isolated rather than silently
        inheriting host networking."""
        os.environ.pop("SUPPLY_CHAIN_EGRESS_NETWORK", None)
        a = self.argv(allow_registry_egress=True)
        # Stays on the ISOLATED bridge rather than reaching a routable network.
        self.assertEqual(a[a.index("--network") + 1], ad.ANALYZER_NETWORK)
        self.assertNotIn("host", a)

    def test_regression_default_is_the_isolated_network_not_docker_bridge(self):
        """REGRESSION: omitting --network puts the analyzer on docker's default
        bridge, which has full internet egress. The OSV and retire.js paths need
        ZERO egress, so that silently handed attacker-authored code a network."""
        a = self.argv()
        self.assertIn("--network", a)
        self.assertEqual(a[a.index("--network") + 1], ad.ANALYZER_NETWORK)

    def test_egress_uses_the_configured_network_when_present(self):
        os.environ["SUPPLY_CHAIN_EGRESS_NETWORK"] = "sc-egress"
        try:
            a = self.argv(allow_registry_egress=True)
            self.assertIn("--network", a)
            self.assertEqual(a[a.index("--network") + 1], "sc-egress")
        finally:
            os.environ.pop("SUPPLY_CHAIN_EGRESS_NETWORK", None)

    def test_regression_never_falls_back_to_dockers_shared_default_bridge(self):
        """REGRESSION: with no --network, docker puts the container on its
        DEFAULT bridge - shared by every container that does not ask for one, so
        the analyzer could reach WhiteHat peers. The whole point of the dedicated
        network (README.TM.SYSTEM_OVERVIEW.md, CodeFix-sandbox pattern) is that
        NO WhiteHat service is attached to it."""
        for kw in ({}, {"allow_registry_egress": True}):
            a = self.argv(**kw)
            self.assertIn("--network", a)
            self.assertNotEqual(a[a.index("--network") + 1], "bridge")

    def test_egress_stays_on_the_peerless_network_by_default(self):
        os.environ.pop("SUPPLY_CHAIN_EGRESS_NETWORK", None)
        a = self.argv(allow_registry_egress=True)
        self.assertEqual(a[a.index("--network") + 1], ad.ANALYZER_NETWORK)

    def test_command_targets_the_job_contract(self):
        a = self.argv()
        self.assertEqual(a[-5:], ["sc-analyze", "--job", "/work/job.json",
                                  "--out", "/work/out.json"])


class TestNetworkCreationAgreesWithTheOrchestrator(unittest.TestCase):
    """Two processes create the SAME network name: this module (recon side, via
    the docker CLI) and ContainerManager._ensure_supply_chain_network (SDK).
    If they disagree on the driver, whichever runs first silently wins."""

    def _create_argv(self):
        seen = {}

        def runner(argv, timeout=None, **kw):
            if argv[:3] == ["docker", "network", "inspect"]:
                return {"stdout": "", "stderr": "", "exit_code": 1,
                        "timed_out": False, "error": None}
            seen["argv"] = argv
            return {"stdout": "", "stderr": "", "exit_code": 0,
                    "timed_out": False, "error": None}

        ad.ensure_network(runner=runner)
        return seen.get("argv", [])

    def test_regression_created_as_a_plain_bridge_not_internal(self):
        """REGRESSION: this side created the network --internal while the
        orchestrator creates it driver=bridge. Same name, two drivers - and
        --internal would also cut GuardDog off from the registry."""
        argv = self._create_argv()
        self.assertNotIn("--internal", argv)
        self.assertIn("--driver", argv)
        self.assertEqual(argv[argv.index("--driver") + 1], "bridge")

    def test_matches_the_orchestrator_driver_literally(self):
        src = open(os.path.join(_REPO, "recon_orchestrator",
                                "container_manager.py")).read()
        i = src.index("_ensure_supply_chain_network")
        block = src[i:i + 1600]
        self.assertIn('driver="bridge"', block,
                      "orchestrator changed driver; update ensure_network too")
        self.assertNotIn("internal=True", block)

    def test_network_name_matches_the_orchestrator_default(self):
        src = open(os.path.join(_REPO, "recon_orchestrator",
                                "container_manager.py")).read()
        self.assertIn('"SUPPLY_CHAIN_ANALYZER_NETWORK", "whitehat-supply-chain-net"', src)
        self.assertEqual(ad.ANALYZER_NETWORK, "whitehat-supply-chain-net")

    def test_existing_network_is_not_recreated(self):
        calls = []

        def runner(argv, timeout=None, **kw):
            calls.append(argv)
            return {"stdout": "", "stderr": "", "exit_code": 0,
                    "timed_out": False, "error": None}

        ad.ensure_network(runner=runner)
        self.assertEqual(len(calls), 1, "inspect only; must not re-create")


class TestRunAnalyzerJob(unittest.TestCase):

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="sc-dispatch-test-")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _runner(self, exit_code=0, artifact=None, stderr="", error=None):
        def run(argv, timeout=None, **kw):
            if artifact is not None:
                with open(os.path.join(self.work, "out.json"), "w") as fh:
                    json.dump(artifact, fh)
            return {"stdout": "", "stderr": stderr, "exit_code": exit_code,
                    "timed_out": False, "error": error}
        return run

    def test_happy_path_returns_a_validated_artifact(self):
        art = {"schema_version": 1, "mode": "js-dir",
               "packages": [{"purl": "pkg:npm/jquery@3.4.1", "name": "jquery",
                             "version": "3.4.1", "ecosystem": "npm",
                             "source": "retirejs"}],
               "malicious": [], "vulnerable": [], "suspicious": [], "errors": []}
        res = ad.run_analyzer_job({"mode": "js-dir", "target": "/work/js"},
                                  self.work, "/host/sc_common",
                                  runner=self._runner(artifact=art))
        self.assertIsNone(res["error"])
        self.assertEqual(len(res["artifact"]["packages"]), 1)

    def test_job_json_is_written_for_the_analyzer(self):
        ad.run_analyzer_job({"mode": "js-dir", "target": "/work/js"},
                            self.work, "/host/sc_common",
                            runner=self._runner(artifact={
                                "schema_version": 1, "mode": "js-dir",
                                "packages": [], "malicious": [], "vulnerable": [],
                                "suspicious": [], "errors": []}))
        with open(os.path.join(self.work, "job.json")) as fh:
            self.assertEqual(json.load(fh)["mode"], "js-dir")

    def test_regression_missing_output_is_an_error_not_a_clean_result(self):
        """Same false-clean class as the GuardDog dispatch: an analyzer that
        never produced out.json must NOT read as 'analysed, nothing found'."""
        res = ad.run_analyzer_job({"mode": "js-dir", "target": "/work/js"},
                                  self.work, "/host/sc_common",
                                  runner=self._runner(exit_code=0, artifact=None))
        self.assertIsNone(res["artifact"])
        self.assertIsNotNone(res["error"])

    def test_nonzero_exit_is_an_error(self):
        res = ad.run_analyzer_job({"mode": "js-dir", "target": "/work/js"},
                                  self.work, "/host/sc_common",
                                  runner=self._runner(exit_code=125,
                                                      stderr="no such image"))
        self.assertIn("125", res["error"])
        self.assertIn("no such image", res["error"])

    def test_hostile_artifact_from_a_compromised_analyzer_is_rejected(self):
        """The clean side re-validates: the analyzer processes attacker bytes,
        so its output can never be trusted on its own."""
        res = ad.run_analyzer_job(
            {"mode": "js-dir", "target": "/work/js"}, self.work, "/host/sc_common",
            runner=self._runner(artifact={
                "schema_version": 1, "mode": "js-dir",
                "packages": [{"purl": "pkg:npm/x", "name": "evil;whoami",
                              "version": "1.0", "ecosystem": "npm",
                              "source": "retirejs"}],
                "malicious": [], "vulnerable": [], "suspicious": [], "errors": []}))
        self.assertIsNone(res["artifact"])
        self.assertIsNotNone(res["error"])

    def test_unsupported_mode_is_refused_before_spawning(self):
        called = []
        with self.assertRaises(ValueError):
            ad.run_analyzer_job({"mode": "nonsense"}, self.work, "/host/sc_common",
                                runner=lambda *a, **k: called.append(1))
        self.assertEqual(called, [], "must not spawn on a bad mode")


if __name__ == "__main__":
    unittest.main()