"""Deep-review / adversarial regression suite for the supply-chain feature.

Encodes CORRECT expected behavior across every implemented module (Phases 0,
0.5, 1-graph). Written to expose real bugs (maven purl, orphan findings,
empty-string guarddog metadata, offline-flag regression) and to lock behavior
against future changes. Pure functions + fake sessions; no binaries, no DB.

Run: python -m unittest tests.test_supply_chain_review
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from supply_chain_common import osv_runner, guarddog_runner, retire_runner, osv_db_sync
from supply_chain_common._run import run_argv, strip_ansi
from supply_chain_common.purl import build_purl, normalize_name
from supply_chain_common.security import (
    sanitize_name, sanitize_version, SanitizeError,
    validate_artifact, ArtifactError, ARTIFACT_SCHEMA_VERSION,
)
from graph_db.mixins.supply_chain_mixin import SupplyChainMixin, _finding_id


# --------------------------------------------------------------------------
# purl construction
# --------------------------------------------------------------------------
class TestPurlEdgeCases(unittest.TestCase):
    def test_maven_group_artifact_becomes_namespace(self):
        # OSV maven names are "group:artifact"; the purl must split them into
        # namespace/name, NOT percent-encode the colon.
        self.assertEqual(
            build_purl("Maven", "com.google.guava:guava", "30.0-jre"),
            "pkg:maven/com.google.guava/guava@30.0-jre")

    def test_go_full_path_preserved(self):
        self.assertEqual(
            build_purl("Go", "github.com/pkg/errors", "0.9.1"),
            "pkg:golang/github.com/pkg/errors@0.9.1")

    def test_scoped_npm_without_version(self):
        self.assertEqual(build_purl("npm", "@babel/core"),
                         "pkg:npm/%40babel/core")

    def test_pypi_normalization_idempotent(self):
        once = normalize_name("PyPI", "Zope.Interface")
        twice = normalize_name("PyPI", once)
        self.assertEqual(once, "zope-interface")
        self.assertEqual(once, twice)

    def test_crates_and_rubygems_types(self):
        self.assertEqual(build_purl("crates.io", "libc", "0.2.1"),
                         "pkg:cargo/libc@0.2.1")
        self.assertEqual(build_purl("RubyGems", "rake", "13.0.0"),
                         "pkg:gem/rake@13.0.0")


# --------------------------------------------------------------------------
# sanitize
# --------------------------------------------------------------------------
class TestSanitizeDeep(unittest.TestCase):
    def test_unicode_confusable_rejected(self):
        # Greek alpha (U+03B1) looks like 'a' but is not ASCII -> rejected.
        with self.assertRaises(SanitizeError):
            sanitize_name("lodαsh")

    def test_maven_colon_allowed(self):
        self.assertEqual(sanitize_name("com.google.guava:guava"),
                         "com.google.guava:guava")

    def test_null_byte_rejected(self):
        with self.assertRaises(SanitizeError):
            sanitize_name("a\x00b")

    def test_version_with_epoch_colon(self):
        self.assertEqual(sanitize_version("1:2.3.4-1"), "1:2.3.4-1")


# --------------------------------------------------------------------------
# OSV parser
# --------------------------------------------------------------------------
class TestOsvParserDeep(unittest.TestCase):
    def test_same_package_mal_and_cve_split(self):
        raw = {"results": [{"source": {"path": "/x"}, "packages": [{
            "package": {"name": "lodash", "version": "4.0.0", "ecosystem": "npm"},
            "vulnerabilities": [
                {"id": "MAL-2020-1", "summary": "malware"},
                {"id": "CVE-2020-1", "summary": "vuln"},
                {"id": "GHSA-aaaa-bbbb-cccc", "summary": "vuln2"}],
        }]}]}
        parsed = osv_runner.parse_osv_json(raw)
        self.assertEqual(len(parsed["packages"]), 1)
        self.assertEqual(len(parsed["malicious"]), 1)
        self.assertEqual(len(parsed["vulnerable"]), 2)
        self.assertEqual(parsed["packages"][0]["source_path"], "/x")

    def test_package_without_ecosystem_skipped(self):
        raw = {"results": [{"packages": [{"package": {"name": "x"}}]}]}
        self.assertEqual(osv_runner.parse_osv_json(raw)["packages"], [])

    def test_hostile_package_name_skipped_not_raised(self):
        raw = {"results": [{"packages": [{
            "package": {"name": "$(id)", "version": "1", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "MAL-1"}]}]}]}
        parsed = osv_runner.parse_osv_json(raw)
        self.assertEqual(parsed["packages"], [])
        self.assertEqual(parsed["malicious"], [])

    def test_offline_flag_is_offline_not_offline_vulnerabilities(self):
        # Regression: --offline (loads local DB) NOT --offline-vulnerabilities.
        captured = {}
        orig = osv_runner.run_argv

        def fake(argv, **kw):
            captured["argv"] = argv
            return {"stdout": "{}", "stderr": "", "exit_code": 0,
                    "timed_out": False, "error": None}
        osv_runner.run_argv = fake
        import tempfile, os as _os
        try:
            with tempfile.TemporaryDirectory() as db:  # F5: db must exist + be non-empty
                open(_os.path.join(db, "osv-scanner"), "w").close()
                osv_runner.run_osv_scan("/tmp/package-lock.json", mode="lockfile",
                                        db_path=db)
        finally:
            osv_runner.run_argv = orig
        self.assertIn("--offline", captured["argv"])
        self.assertNotIn("--offline-vulnerabilities", captured["argv"])
        self.assertIn("--format", captured["argv"])


# --------------------------------------------------------------------------
# GuardDog parser
# --------------------------------------------------------------------------
class TestReviewRegressions2(unittest.TestCase):
    def test_F5_offline_without_db_is_hard_error_not_clean(self):
        # F5: offline scan with a missing OR EMPTY DB dir must error (an empty
        # volume created by update-but-not-yet-synced), not report clean.
        import tempfile
        res = osv_runner.run_osv_scan("/tmp/package-lock.json", mode="lockfile",
                                      db_path="/nonexistent-osv-db", offline=True)
        self.assertIsNotNone(res["error"])
        self.assertIn("missing or empty", res["error"])
        res2 = osv_runner.run_osv_scan("/tmp/x", mode="lockfile", db_path=None, offline=True)
        self.assertIsNotNone(res2["error"])
        with tempfile.TemporaryDirectory() as empty_db:  # created-but-never-synced
            res3 = osv_runner.run_osv_scan("/tmp/x", mode="lockfile",
                                           db_path=empty_db, offline=True)
            self.assertIsNotNone(res3["error"])
            self.assertIn("missing or empty", res3["error"])

    def test_missing_ecosystem_db_gives_actionable_error(self):
        # A lockfile whose ecosystem was never synced makes osv-scanner exit 127
        # with the real cause buried AFTER a filesystem-walk log. The explainer
        # must surface an instruction, not 500 chars of walk noise.
        msg = osv_runner._explain_osv_stderr(
            "Starting filesystem walk for root: /\n"
            "Scanned /tmp/requirements.txt file and found 1 package\n"
            "End status: 0 dirs visited, 1 inodes visited\n"
            "could not load db for PyPI ecosystem: unable to fetch OSV database", 127)
        self.assertIn("no 'PyPI' ecosystem", msg)
        self.assertIn("supply-chain-sync PyPI", msg)
        self.assertNotIn("filesystem walk", msg)

    def test_partially_loaded_db_is_reported_even_on_an_OK_exit(self):
        """REGRESSION: the PARTIAL-database false-clean.

        osv-scanner scans every lockfile it finds, loads the ecosystem DBs it
        has, and reports nothing at all for the ones it does not - exiting 0/1,
        which is a SUCCESS code. So an npm-only database scanning a repo that
        also has requirements.txt returns the npm findings, no error, and total
        silence about the Python packages. They read clean.

        Only reachable in volume once directory/repository scanning exists: a
        single uploaded lockfile has one ecosystem, and a total DB miss exits
        127 (already handled). Verified against osv-scanner v2.4.0 on
        2026-08-07 with an npm-only DB: exit 1, jinja2 2.4.1 and flask 0.12.2
        silently absent.
        """
        stderr = (
            "Scanning dir /work/src\n"
            "Scanned /work/src/py/requirements.txt file and found 2 packages\n"
            "Scanned /work/src/app/package-lock.json file and found 1 package\n"
            "Loaded npm local db from /osv-db/osv-scanner/npm/all.zip\n"
            "could not load db for PyPI ecosystem: unable to fetch OSV database\n")
        captured = {}

        def fake_run(argv, timeout=None, env=None):
            captured["argv"] = argv
            # Exit 1 == "vulnerabilities found", an OK code.
            return {"exit_code": 1, "stdout": '{"results": []}',
                    "stderr": stderr, "error": None}

        orig = osv_runner.run_argv
        osv_runner.run_argv = fake_run
        try:
            res = osv_runner.run_osv_scan(
                "/work/src", mode="dir", db_path=_REPO, offline=True)
        finally:
            osv_runner.run_argv = orig

        self.assertIsNotNone(
            res["error"],
            "a partially loaded DB reported no error - the unscanned "
            "ecosystem reads clean")
        self.assertIn("PyPI", res["error"])
        self.assertIn("NOT checked", res["error"])

    def test_partial_db_keeps_the_findings_it_did_resolve(self):
        """The npm results are real; only the gap is added alongside them."""
        raw = ('{"results": [{"source": {"path": "/x/package-lock.json"}, '
               '"packages": [{"package": {"name": "lodash", "version": "4.17.4", '
               '"ecosystem": "npm"}, "vulnerabilities": [{"id": "GHSA-x"}]}]}]}')

        def fake_run(argv, timeout=None, env=None):
            return {"exit_code": 1, "stdout": raw,
                    "stderr": "could not load db for Go ecosystem: nope\n",
                    "error": None}

        orig = osv_runner.run_argv
        osv_runner.run_argv = fake_run
        try:
            res = osv_runner.run_osv_scan("/x", mode="dir", db_path=_REPO)
        finally:
            osv_runner.run_argv = orig

        self.assertIn("Go", res["error"])
        names = [p["name"] for p in res["parsed"]["packages"]]
        self.assertIn("lodash", names, "resolved findings must not be discarded")

    def test_every_missing_ecosystem_is_named_not_just_the_first(self):
        """A repo spans many ecosystems; naming one sends the operator round
        the loop once per missing DB."""
        msg = osv_runner._explain_osv_stderr(
            "could not load db for PyPI ecosystem: x\n"
            "could not load db for Go ecosystem: x\n"
            "could not load db for Maven ecosystem: x\n", 127)
        for eco in ("PyPI", "Go", "Maven"):
            self.assertIn(eco, msg)

    def test_missing_ecosystems_deduplicates(self):
        self.assertEqual(
            osv_runner._missing_ecosystems(
                "could not load db for PyPI ecosystem: a\n"
                "could not load db for PyPI ecosystem: b\n"),
            ["PyPI"])

    def test_no_missing_db_lines_means_no_error(self):
        """A fully-synced scan must stay clean - this guard must not fire on
        the normal 'Loaded npm local db' line."""
        def fake_run(argv, timeout=None, env=None):
            return {"exit_code": 0, "stdout": '{"results": []}',
                    "stderr": "Loaded npm local db from /osv-db/...\n",
                    "error": None}
        orig = osv_runner.run_argv
        osv_runner.run_argv = fake_run
        try:
            res = osv_runner.run_osv_scan("/x", mode="dir", db_path=_REPO)
        finally:
            osv_runner.run_argv = orig
        self.assertIsNone(res["error"])

    def test_missing_ecosystem_message_is_not_duplicated(self):
        """REGRESSION: both the explainer and the partial-DB guard fired.

        A total DB miss exits 127 (generic explainer) AND prints "could not
        load db for X ecosystem" (partial-DB guard). Both spoke, so the
        operator saw the same instruction twice in one error:

          "...no 'PyPI' ecosystem(s); run ... to add them; ...no 'PyPI'
           ecosystem(s); those packages were NOT checked - run ..."

        Observed verbatim in a real L1 scan of requirements.txt. The
        missing-ecosystem case now owns the message outright.
        """
        def fake_run(argv, timeout=None, env=None):
            return {"exit_code": 127, "stdout": "",
                    "stderr": ("Scanned /work/requirements.txt file and found 4 packages\n"
                               "could not load db for PyPI ecosystem: unable to fetch\n"),
                    "error": None}
        orig = osv_runner.run_argv
        osv_runner.run_argv = fake_run
        try:
            res = osv_runner.run_osv_scan("/x", mode="lockfile", db_path=_REPO)
        finally:
            osv_runner.run_argv = orig
        self.assertIsNotNone(res["error"])
        self.assertEqual(res["error"].count("ecosystem(s)"), 1,
                         "the instruction is repeated: " + res["error"])
        self.assertIn("NOT checked", res["error"])

    def test_a_genuine_tool_error_still_gets_the_generic_explainer(self):
        """Suppressing the duplicate must not swallow unrelated failures."""
        def fake_run(argv, timeout=None, env=None):
            return {"exit_code": 127, "stdout": "",
                    "stderr": "Starting filesystem walk\nboom: real cause\n",
                    "error": None}
        orig = osv_runner.run_argv
        osv_runner.run_argv = fake_run
        try:
            res = osv_runner.run_osv_scan("/x", mode="lockfile", db_path=_REPO)
        finally:
            osv_runner.run_argv = orig
        self.assertIn("boom: real cause", res["error"])

    def test_generic_osv_error_keeps_the_tail_not_the_walk_log(self):
        msg = osv_runner._explain_osv_stderr(
            "Starting filesystem walk for root: /\nEnd status: 0 dirs\nboom: real cause", 127)
        self.assertIn("boom: real cause", msg)
        self.assertNotIn("Starting filesystem walk", msg)

    def test_F8_guarddog_errors_as_list_no_crash(self):
        # F8: errors emitted as a list must not raise AttributeError.
        findings = guarddog_runner.parse_guarddog(
            {"package": "x", "issues": 0, "errors": ["boom"], "results": {}})
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["soft_error"])


class TestGuarddogDeep(unittest.TestCase):
    def test_empty_string_metadata_does_not_fire(self):
        # A metadata rule that returns "" (falsy) must NOT create a finding.
        raw = {"package": "x", "issues": 0, "errors": {},
               "results": {"typosquatting": "", "empty_information": None}}
        self.assertEqual(guarddog_runner.parse_guarddog(raw), [])

    def test_verify_item_with_errors_is_soft_error(self):
        raw = [{"dependency": "d", "version": "1", "result": {
            "issues": 0, "errors": {"download-package": "404"}, "results": {}}}]
        findings = guarddog_runner.parse_guarddog(raw)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["soft_error"])

    def test_severity_unknown_rule_is_low(self):
        self.assertEqual(guarddog_runner.severity_for_rule("some-random-rule"), "low")

    def test_source_rule_multiple_entries(self):
        raw = {"package": "x", "issues": 1, "errors": {}, "results": {
            "npm-obfuscation": [
                {"message": "a"}, {"code": "b"}, {"location": "c"}]}}
        findings = guarddog_runner.parse_guarddog(raw)
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f["confidence"] == "suspicious" for f in findings))


# --------------------------------------------------------------------------
# retire parser
# --------------------------------------------------------------------------
class TestRetireDeep(unittest.TestCase):
    def test_dedup_same_component_across_files(self):
        raw = {"data": [
            {"file": "a.js", "results": [{"component": "jquery", "version": "1.0"}]},
            {"file": "b.js", "results": [{"component": "jquery", "version": "1.0"}]}]}
        parsed = retire_runner.parse_retire_json(raw)
        self.assertEqual(len(parsed["components"]), 1)

    def test_scoped_and_versionless_to_purls(self):
        comps = [{"name": "@vue/reactivity", "version": None},
                 {"name": "jquery", "version": "3.0.0"}]
        purls = set(retire_runner.to_purls(comps))
        self.assertIn("pkg:npm/%40vue/reactivity", purls)
        self.assertIn("pkg:npm/jquery@3.0.0", purls)

    def test_hostile_component_name_skipped(self):
        raw = {"data": [{"file": "x", "results": [
            {"component": "../../etc", "version": "1"}]}]}
        self.assertEqual(retire_runner.parse_retire_json(raw)["components"], [])


# --------------------------------------------------------------------------
# validate_artifact
# --------------------------------------------------------------------------
class TestValidateArtifactDeep(unittest.TestCase):
    def _base(self, **o):
        a = {"schema_version": ARTIFACT_SCHEMA_VERSION, "mode": "lockfile",
             "packages": [], "malicious": [], "vulnerable": [],
             "suspicious": [], "errors": []}
        a.update(o)
        return a

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ArtifactError):
            validate_artifact(self._base(malicious=[{"name": "x", "severity": "boom"}]))

    def test_js_dir_mode_accepted(self):
        out = validate_artifact(self._base(mode="js-dir"))
        self.assertEqual(out["mode"], "js-dir")

    def test_aliases_capped(self):
        out = validate_artifact(self._base(
            malicious=[{"name": "x", "aliases": ["a"] * 500}]))
        self.assertLessEqual(len(out["malicious"][0]["aliases"]), 100)

    def test_errors_list_capped_strings(self):
        out = validate_artifact(self._base(errors=["z" * 99999]))
        self.assertLessEqual(len(out["errors"][0]), 4096)

    def test_missing_schema_version_rejected(self):
        a = self._base()
        del a["schema_version"]
        with self.assertRaises(ArtifactError):
            validate_artifact(a)


# --------------------------------------------------------------------------
# _run helper
# --------------------------------------------------------------------------
class TestRunHelper(unittest.TestCase):
    def test_nonexistent_binary_returns_error_no_raise(self):
        res = run_argv(["___whitehat_no_such_binary___", "--x"])
        self.assertIsNone(res["exit_code"])
        self.assertIn("spawn failed", res["error"])

    def test_empty_argv_raises(self):
        with self.assertRaises(ValueError):
            run_argv([])

    def test_strip_ansi(self):
        self.assertEqual(strip_ansi("\x1b[31mred\x1b[0m"), "red")
        self.assertEqual(strip_ansi(None), "")

    def test_real_true_command(self):
        res = run_argv(["true"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIsNone(res["error"])


# --------------------------------------------------------------------------
# osv_db_sync
# --------------------------------------------------------------------------
class TestOsvDbSync(unittest.TestCase):
    def test_unknown_ecosystem_error(self):
        res = osv_db_sync.download_databases("/tmp/nope_db", ["bogus"])
        self.assertIn("bogus", res["errors"])
        self.assertEqual(res["synced"], [])

    def test_all_ecosystems_have_seed_manifests(self):
        from supply_chain_common.purl import OSV_ECOSYSTEMS
        for eco in OSV_ECOSYSTEMS:
            self.assertIn(eco, osv_db_sync.SEED_MANIFESTS,
                          "no seed manifest for {}".format(eco))

    def test_db_is_fresh_false_when_absent(self):
        self.assertFalse(osv_db_sync.db_is_fresh("/tmp/definitely_absent_db", "npm"))


# --------------------------------------------------------------------------
# graph mixin - orphan-finding regression
# --------------------------------------------------------------------------
class _FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class _FakeSession:
    def __init__(self):
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kw):
        self.queries.append((query, kw))
        if "RETURN count" in query:
            return _FakeResult({"c": 1})
        return _FakeResult()


class _FakeDriver:
    def __init__(self, s):
        self._s = s

    def session(self):
        return self._s


class _Writer(SupplyChainMixin):
    def __init__(self, s):
        self.driver = _FakeDriver(s)


class TestMixinDeep(unittest.TestCase):
    def test_finding_attaches_package_even_when_absent_from_packages(self):
        # A guarddog name-only finding whose package is NOT in `packages` must
        # still attach: the finding query MERGEs the Package (not MATCH), so no
        # orphaned MalPackageFinding is ever created.
        sess = _FakeSession()
        w = _Writer(sess)
        data = {"packages": [], "malicious": [], "vulnerable": [],
                "suspicious": [{"name": "evil", "ecosystem": "npm",
                                "rule": "typosquatting", "confidence": "suspicious"}]}
        stats = w.update_graph_from_supply_chain(
            data, "u", "p", anchor_label="BaseURL", anchor_key="url",
            anchor_value="https://t")
        self.assertEqual(stats["suspicious_merged"], 1)
        finding_qs = [q for q, _ in sess.queries if "FLAGGED_AS" in q]
        self.assertEqual(len(finding_qs), 1)
        self.assertIn("MERGE (p:Package", finding_qs[0],
                      "finding path must MERGE the package, not MATCH it")

    def test_finding_id_stable_across_calls(self):
        self.assertEqual(_finding_id("pkg:npm/x@1", "MAL-1"),
                         _finding_id("pkg:npm/x@1", "MAL-1"))


if __name__ == "__main__":
    unittest.main()
