"""TruffleHog run-keying: parallel sources, one run per source, correct keys.

C3 is the whole design: the run key IS the source id, which gives "no duplicate
sources, unlimited distinct sources" with no counter to maintain and no
trufflehog-specific cap to tune. These tests pin that, plus the two key formats
that must agree (admission and reconcile) — a mismatch there makes the 30 s
reaper free a live scan's reservation and the governor over-admit into OOM.
"""

import asyncio
import os
import sys
import tempfile
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import TrufflehogState, TrufflehogStatus  # noqa: E402


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def make_manager():
    """A ContainerManager with no Docker daemon and no real ledger."""
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = MagicMock()
    m.running_states = {}
    m.gvm_states = {}
    m.github_hunt_states = {}
    m.supply_chain_states = {}
    m.partial_recon_states = {}
    m.ai_attack_states = {}
    m.trufflehog_states = {}
    m.codefix_sandboxes = {}
    m.guarddog_jobs = set()
    m.trufflehog_image = "whitehat-trufflehog:latest"
    m.trufflehog_network = "whitehat-trufflehog-net"
    m.trufflehog_scan_roots = {}
    m.trufflehog_scope_checker = None
    m.ledger = MagicMock()
    m.ledger.envelope_for.return_value = 805306368
    # get_trufflehog_status hands Docker inspection to this pool (_run_blocking).
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    return m


def running(project_id, source):
    return TrufflehogState(
        project_id=project_id, user_id="u1", source=source, run_id=source,
        status=TrufflehogStatus.RUNNING, container_id=f"c-{source}",
    )


class TestRunKeys(unittest.TestCase):
    def test_admission_kind_is_source_qualified(self):
        m = make_manager()
        self.assertEqual(m._trufflehog_kind("docker"), "trufflehog:docker")
        self.assertEqual(m._trufflehog_kind(""), "trufflehog")

    def test_reservation_key_matches_between_admission_and_reconcile(self):
        """The reaper frees any reservation whose key is not in
        _active_scan_keys. If admission and reconcile build different keys, a
        live scan's RAM is released and the next admit over-commits."""
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": running("p1", "docker")}}

        admission_key = m._scan_key(m._trufflehog_kind("docker"), "p1", "docker")
        self.assertIn(admission_key, m._active_scan_keys())

    def test_each_parallel_source_holds_its_own_reservation(self):
        m = make_manager()
        m.trufflehog_states = {
            "p1": {"docker": running("p1", "docker"), "huggingface": running("p1", "huggingface")},
        }
        keys = m._active_scan_keys()
        self.assertIn("trufflehog:docker:p1:docker", keys)
        self.assertIn("trufflehog:huggingface:p1:huggingface", keys)

    def test_terminal_runs_release_their_reservation(self):
        m = make_manager()
        done = running("p1", "docker")
        done.status = TrufflehogStatus.COMPLETED
        m.trufflehog_states = {"p1": {"docker": done}}
        self.assertEqual(
            [k for k in m._active_scan_keys() if k.startswith("trufflehog")], [])

    def test_container_names_are_per_source(self):
        """A shared name would make starting docker force-remove a live
        huggingface container."""
        m = make_manager()
        self.assertNotEqual(
            m._get_trufflehog_container_name("p1", "docker"),
            m._get_trufflehog_container_name("p1", "huggingface"),
        )

    def test_container_name_sanitises_both_parts(self):
        m = make_manager()
        name = m._get_trufflehog_container_name("p/1", "github experimental")
        self.assertNotIn("/", name)
        self.assertNotIn(" ", name)

    def test_run_dirs_are_per_source(self):
        m = make_manager()
        self.assertNotEqual(
            m._trufflehog_run_dir("p1", "docker"),
            m._trufflehog_run_dir("p1", "huggingface"),
        )


class TestEnumerations(unittest.TestCase):
    """Six sites walk the state dict; a flat walk on a nested dict either leaks
    reservations or silently under-counts."""

    def test_active_scan_projects_sees_a_nested_run(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": running("p1", "docker")}}
        self.assertIn("p1", m.active_scan_projects())

    def test_active_scan_projects_ignores_a_project_whose_runs_all_finished(self):
        m = make_manager()
        done = running("p1", "docker")
        done.status = TrufflehogStatus.COMPLETED
        m.trufflehog_states = {"p1": {"docker": done}}
        self.assertNotIn("p1", m.active_scan_projects())

    def test_running_count_counts_runs_not_projects(self):
        """/health and the dispatcher's admission accounting read this. Counting
        projects would report three parallel sources as one."""
        m = make_manager()
        m.trufflehog_states = {
            "p1": {"docker": running("p1", "docker"), "s3": running("p1", "s3")},
            "p2": {"github": running("p2", "github")},
        }
        self.assertEqual(m.get_trufflehog_running_count(), 3)

    def test_running_count_includes_starting(self):
        m = make_manager()
        st = running("p1", "docker")
        st.status = TrufflehogStatus.STARTING
        m.trufflehog_states = {"p1": {"docker": st}}
        self.assertEqual(m.get_trufflehog_running_count(), 1)


class TestStartGates(unittest.TestCase):
    """Every gate must fail closed BEFORE a reservation or container exists."""

    def setUp(self):
        self.m = make_manager()
        self.m._admit_scan = MagicMock(side_effect=AssertionError("must not admit"))
        # No real DNS in the gate tests; the egress guard has its own suite.
        self._egress = patch.object(cm_mod, "classify_host", return_value=(True, "93.184.216.34", "ok"))
        self._egress.start()
        self.addCleanup(self._egress.stop)

    def start(self, **kw):
        params = dict(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan", source="github",
            config={"orgs": ["acme"]}, common={},
            secrets={"trufflehogGithubToken": "ghp_x"},
        )
        params.update(kw)
        return run(self.m.start_trufflehog(**params))

    def test_unknown_source_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self.start(source="slack")
        self.assertIn("unknown trufflehog source", str(ctx.exception))

    def test_invalid_config_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self.start(config={})
        self.assertIn("organization", str(ctx.exception))

    def test_missing_mandatory_credential_is_refused_server_side(self):
        # Re-checked here and not only in the UI: a queued job can reach dispatch
        # long after the operator cleared the key.
        with self.assertRaises(ValueError) as ctx:
            self.start(secrets={})
        self.assertIn("GitHub Token", str(ctx.exception))
        self.assertIn("API Keys", str(ctx.exception))

    def test_optional_credential_source_starts_without_one(self):
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
        with self.assertRaises(RuntimeError):
            self.start(source="jenkins", config={"url": "https://ci.example.com"}, secrets={})

    def test_nothing_is_registered_when_a_gate_refuses(self):
        with self.assertRaises(ValueError):
            self.start(config={})
        self.assertEqual(self.m.trufflehog_states, {})

    def test_same_source_twice_is_refused(self):
        self.m.trufflehog_states = {"p1": {"github": running("p1", "github")}}
        self.m.client.containers.get.return_value = MagicMock(status="running")
        with self.assertRaises(ValueError) as ctx:
            self.start()
        self.assertIn("already running", str(ctx.exception))

    def test_a_different_source_reaches_admission(self):
        """The whole point of C3: docker and huggingface coexist."""
        self.m.trufflehog_states = {"p1": {"github": running("p1", "github")}}
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
        with self.assertRaises(RuntimeError):
            self.start(source="docker", config={"images": ["nginx:1.25"]}, secrets={})


class TestEgressGuard(unittest.TestCase):
    """12.4: deny on the RESOLVED IP, before spawning, fail closed."""

    def setUp(self):
        self.m = make_manager()
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))

    def start(self, source, config, secrets=None):
        return run(self.m.start_trufflehog(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan", source=source,
            config=config, common={}, secrets=secrets or {},
        ))

    def test_loopback_target_is_refused(self):
        with patch.object(cm_mod, "classify_host",
                          return_value=(False, None, "internal-ip:127.0.0.1")):
            with self.assertRaises(ValueError) as ctx:
                self.start("jenkins", {"url": "http://127.0.0.1:7687"})
        self.assertIn("not allowed", str(ctx.exception))

    def test_cloud_metadata_target_is_refused(self):
        with patch.object(cm_mod, "classify_host",
                          return_value=(False, None, "internal-ip:169.254.169.254")):
            with self.assertRaises(ValueError):
                self.start("elasticsearch", {"nodes": ["169.254.169.254:9200"]})

    def test_unresolvable_target_is_refused(self):
        # Fails closed: no resolved IP means no decision, which means no scan.
        with patch.object(cm_mod, "classify_host", return_value=(False, None, "unresolvable")):
            with self.assertRaises(ValueError):
                self.start("jenkins", {"url": "https://nope.invalid"})

    def test_public_target_passes_the_guard(self):
        with patch.object(cm_mod, "classify_host", return_value=(True, "93.184.216.34", "ok")):
            with self.assertRaises(RuntimeError):  # reached admission
                self.start("jenkins", {"url": "https://ci.example.com"})

    def test_sources_with_no_host_skip_the_guard_entirely(self):
        # circleci's target is defined by its token; there is nothing to resolve.
        with patch.object(cm_mod, "classify_host",
                          side_effect=AssertionError("nothing to classify")):
            with self.assertRaises(RuntimeError):
                self.start("circleci", {}, {"trufflehogCircleciToken": "t"})

    def test_guard_can_be_disabled_only_by_an_explicit_env_opt_out(self):
        with patch.dict(os.environ, {"TRUFFLEHOG_EGRESS_GUARD": "off"}):
            with patch.object(cm_mod, "classify_host",
                              side_effect=AssertionError("guard should be skipped")):
                with self.assertRaises(RuntimeError):
                    self.start("jenkins", {"url": "http://127.0.0.1:8080"})


class TestScopeCheck(unittest.TestCase):
    """12.5: a source may not be pointed outside the project's authorised scope."""

    def setUp(self):
        self.m = make_manager()
        self.m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
        self._egress = patch.object(cm_mod, "classify_host", return_value=(True, "93.184.216.34", "ok"))
        self._egress.start()
        self.addCleanup(self._egress.stop)

    def start(self, source="docker", config=None):
        return run(self.m.start_trufflehog(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan", source=source,
            config=config or {"images": ["nginx:1.25"]}, common={}, secrets={},
        ))

    def test_out_of_scope_target_is_refused(self):
        self.m.trufflehog_scope_checker = lambda pid, src, target: (False, "not in ROE")
        with self.assertRaises(ValueError) as ctx:
            self.start()
        self.assertIn("outside the project scope", str(ctx.exception))

    def test_in_scope_target_proceeds(self):
        self.m.trufflehog_scope_checker = lambda pid, src, target: (True, "")
        with self.assertRaises(RuntimeError):
            self.start()

    def test_scope_check_receives_the_redacted_target_descriptor(self):
        seen = {}

        def checker(pid, src, target):
            seen["target"] = target
            return (True, "")

        self.m.trufflehog_scope_checker = checker
        with self.assertRaises(RuntimeError):
            self.start("git", {"uri": "https://svc:glpat_secret@git.example.com/a.git"})
        self.assertNotIn("glpat_secret", seen["target"])

    def test_no_checker_configured_is_a_no_op(self):
        self.m.trufflehog_scope_checker = None
        with self.assertRaises(RuntimeError):
            self.start()


if __name__ == "__main__":
    unittest.main()


class TestDirtyContainerShape(unittest.TestCase):
    """12.3: what the scan container may and may not reach.

    The source-text assertions are deliberate: the spawn kwargs are what a future
    reviewer is most likely to "clean up", and every one of them was chosen
    against a specific failure.
    """

    def _spawn_source(self) -> str:
        import inspect
        src = inspect.getsource(cm_mod.ContainerManager)
        start = src.index("    async def start_trufflehog(")
        return src[start:src.index("\n    def _trufflehog_credential_env(", start)]

    def test_no_host_networking(self):
        # On host networking a target of 127.0.0.1:7687 resolves straight into
        # WhiteHat's own Neo4j.
        spawn = self._spawn_source()
        self.assertNotIn('network_mode="host"', spawn)
        self.assertIn("network=self.trufflehog_network", spawn)

    def test_capabilities_dropped_and_root_filesystem_read_only(self):
        spawn = self._spawn_source()
        self.assertIn('cap_drop=["ALL"]', spawn)
        self.assertIn("read_only=True", spawn)
        self.assertIn("tmpfs=", spawn)

    def test_the_source_tree_is_mounted_read_only(self):
        # rw would let a compromised scan rewrite the scanner and persist into
        # every future run.
        spawn = self._spawn_source()
        self.assertIn('"/app/trufflehog_scan", "mode": "ro"', spawn.replace('"bind": ', ''))

    def test_no_secret_beyond_the_one_source_credential(self):
        spawn = self._spawn_source()
        for forbidden in ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD",
                          "_scanner_env(", "WEBAPP_API_URL", "INTERNAL_API_KEY"):
            self.assertNotIn(forbidden, spawn, f"{forbidden} must not reach the scan container")
        self.assertIn("_trufflehog_credential_env(src, secrets)", spawn)

    def test_cap_drop_is_safe_here_because_nothing_host_owned_is_written(self):
        """cap_drop=ALL broke recon precisely because that container writes a
        host-owned bind mount as root. This one writes ONLY its own scratch dir
        (chmod 0o777 by the orchestrator); the findings are published to the
        shared output dir by the orchestrator afterwards."""
        spawn = self._spawn_source()
        self.assertIn('"output_file": "/work/out.json"', spawn)
        # The shared output dir must NOT be mounted into the container.
        self.assertNotIn('"/out"', spawn)
        self.assertIn("os.chmod(run_dir, 0o777)", spawn)

    def test_only_this_sources_credentials_are_injected(self):
        m = make_manager()
        github = cm_mod.th_sources.get_source("github")
        env = m._trufflehog_credential_env(github, {
            "trufflehogGithubToken": "ghp_x",
            "trufflehogAwsSecretKey": "aws_should_not_travel",
        })
        self.assertEqual(env, {"GITHUB_TOKEN": "ghp_x"})

    def test_credential_env_names_are_the_ones_trufflehog_documents(self):
        # The binary reads these itself, which is how the token stays out of argv.
        m = make_manager()
        es = cm_mod.th_sources.get_source("elasticsearch")
        env = m._trufflehog_credential_env(es, {
            "trufflehogElasticApiKey": "k", "trufflehogElasticUsername": "u",
        })
        self.assertEqual(sorted(env), ["ELASTICSEARCH_API_KEY", "ELASTICSEARCH_USERNAME"])

    def test_blank_credentials_are_not_injected(self):
        m = make_manager()
        github = cm_mod.th_sources.get_source("github")
        self.assertEqual(m._trufflehog_credential_env(github, {"trufflehogGithubToken": "  "}), {})

    def test_the_scan_targets_host_path_is_server_resolved(self):
        """The mount comes from the orchestrator's OWN detected mount, never
        from anything the operator typed."""
        m = make_manager()
        m.trufflehog_scan_targets = "/host/scanners/scan_targets"
        mounts = m._trufflehog_scan_root_mounts("filesystem", {})
        self.assertEqual(
            mounts,
            {"/host/scanners/scan_targets": {"bind": "/scan-targets", "mode": "ro"}})

    def test_the_tree_is_mounted_read_only(self):
        """Writable, a compromised scan could rewrite a fixture that every later
        run then reads."""
        m = make_manager()
        m.trufflehog_scan_targets = "/host/scanners/scan_targets"
        for source in ("filesystem", "git", "docker"):
            mount = m._trufflehog_scan_root_mounts(source, {})
            self.assertEqual(list(mount.values())[0]["mode"], "ro", source)

    def test_an_unresolved_scan_targets_path_is_simply_not_mounted(self):
        """Docker turns a bind source it cannot find into an EMPTY directory, so
        a guessed path would make the scan silently find nothing."""
        m = make_manager()
        m.trufflehog_scan_targets = ""
        self.assertEqual(m._trufflehog_scan_root_mounts("filesystem", {}), {})
        self.assertEqual(m._trufflehog_scan_root_mounts("git", {"localRepo": "r"}), {})

    def test_config_cannot_influence_what_is_mounted(self):
        """The whole tree is mounted at a fixed point and the fixture is selected
        by NAME inside it, so no config value can redirect the mount."""
        m = make_manager()
        m.trufflehog_scan_targets = "/host/scanners/scan_targets"
        for cfg in ({"scanRoot": "/etc"}, {"localRepo": "../../work/job.json"},
                    {"localRepo": "/etc/shadow"}):
            mounts = m._trufflehog_scan_root_mounts("git", cfg)
            self.assertEqual(
                mounts,
                {"/host/scanners/scan_targets": {"bind": "/scan-targets", "mode": "ro"}},
                cfg)

    def test_a_missing_artifact_is_an_error_not_a_clean_scan(self):
        """Regression: F2 - exit 0 with no result file reported COMPLETED.

        The wrapper writes a result on every path it can reach, failures
        included. No file at all means it died before it could, and calling that
        a clean scan is the silent lie this whole check exists to stop: the
        operator reads "completed, 0 findings" as "no secrets here".
        """
        m = make_manager()
        with tempfile.TemporaryDirectory() as tmp:
            m._trufflehog_run_dir = lambda p, s: Path(tmp)
            self.assertTrue(m._trufflehog_artifact_error("p", "git"))

    def test_a_successful_artifact_reports_no_error(self):
        m = make_manager()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "out.json").write_text(
                json.dumps({"status": "completed", "findings": []}))
            m._trufflehog_run_dir = lambda p, s: Path(tmp)
            self.assertEqual(m._trufflehog_artifact_error("p", "git"), "")

    def test_an_errored_artifact_surfaces_its_own_reason(self):
        m = make_manager()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "out.json").write_text(
                json.dumps({"status": "error", "error": "failed to stat .git"}))
            m._trufflehog_run_dir = lambda p, s: Path(tmp)
            self.assertIn("stat .git", m._trufflehog_artifact_error("p", "git"))

    def test_an_unreadable_artifact_does_not_invent_a_failure(self):
        """Half-written is indistinguishable from clean; flipping a good scan to
        ERROR on a parse blip would be its own lie."""
        m = make_manager()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "out.json").write_text("{not json")
            m._trufflehog_run_dir = lambda p, s: Path(tmp)
            self.assertEqual(m._trufflehog_artifact_error("p", "git"), "")

    def test_the_gitconfig_is_not_inside_the_container_writable_mount(self):
        """Regression: F5 - the gitconfig sat in run_dir, which is bind-mounted
        rw at /work, so the read-only bind at /etc/gitconfig promised something
        it did not deliver."""
        m = make_manager()
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "trufflehog_p_git"
            run_dir.mkdir()
            mount = m._trufflehog_git_config_mount(
                run_dir, {"/host": {"bind": "/scan-targets", "mode": "ro"}})
            self.assertTrue(mount)
            host_path = Path(next(iter(mount)))
            self.assertNotIn(run_dir, host_path.parents,
                             "gitconfig is inside the rw-mounted run dir")
            self.assertEqual(next(iter(mount.values()))["mode"], "ro")

    def test_no_gitconfig_without_a_scan_targets_mount(self):
        """A remote-URI run has no local repo, so it gets no ownership override."""
        m = make_manager()
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(m._trufflehog_git_config_mount(Path(tmp), {}), {})

    def test_only_the_disk_reading_sources_get_the_mount(self):
        """A source that cannot read a local target has no reason to see the
        tree at all."""
        m = make_manager()
        m.trufflehog_scan_targets = "/host/scanners/scan_targets"
        for source in ("github", "gitlab", "s3", "elasticsearch", "huggingface"):
            self.assertEqual(m._trufflehog_scan_root_mounts(source, {}), {}, source)


class TestAuditability(unittest.TestCase):
    """12.9: reconstructing who scanned which target with which key — from the
    log alone, and without the log ever holding a secret."""

    def test_the_start_log_names_the_credential_field_never_its_value(self):
        import inspect
        src = inspect.getsource(cm_mod.ContainerManager.start_trufflehog)
        self.assertIn("c.settings_key", src)
        # The VALUE must never be interpolated into a log line.
        self.assertNotIn("secrets.get(c.settings_key)}", src)
        self.assertIn("target: {target}", src)
        self.assertIn("user: {user_id}", src)


class TestIngestRetry(unittest.TestCase):
    """The first ingest attempt shares a poll with the container removal, so a
    failure there must not be the only attempt."""

    def _state(self, status=TrufflehogStatus.COMPLETED, ingested=False):
        st = running("p1", "docker")
        st.status = status
        st.ingested = ingested
        return st

    def test_a_terminal_un_ingested_run_is_retried_on_the_next_poll(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._state()}}
        m.client.containers.get.side_effect = cm_mod.NotFound("gone")
        calls = []
        m._ingest_trufflehog = lambda st: calls.append(st.source)
        m._get_trufflehog_status_sync("p1", "docker")
        self.assertEqual(calls, ["docker"])

    def test_an_already_ingested_run_is_not_re_ingested(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._state(ingested=True)}}
        m.client.containers.get.side_effect = cm_mod.NotFound("gone")
        m._ingest_trufflehog = lambda st: (_ for _ in ()).throw(AssertionError("re-ingested"))
        m._get_trufflehog_status_sync("p1", "docker")

    def test_a_still_running_run_is_not_ingested(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._state(status=TrufflehogStatus.RUNNING)}}
        m.client.containers.get.return_value = MagicMock(status="running")
        m._ingest_trufflehog = lambda st: (_ for _ in ()).throw(AssertionError("ingested early"))
        m._get_trufflehog_status_sync("p1", "docker")

    def test_an_errored_run_is_still_ingested(self):
        # A scan that failed part-way still wrote whatever it found.
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._state(status=TrufflehogStatus.ERROR)}}
        m.client.containers.get.side_effect = cm_mod.NotFound("gone")
        calls = []
        m._ingest_trufflehog = lambda st: calls.append(st.source)
        m._get_trufflehog_status_sync("p1", "docker")
        self.assertEqual(calls, ["docker"])


class TestLogPhaseParsing(unittest.TestCase):
    """The phase labels drive the logs drawer's progress bar. They are matched
    against the scanner's real output, which changed with the job-file rewrite."""

    def _phase(self, line):
        m = make_manager()
        event = m._parse_trufflehog_log_line(line, None, None)
        return event.phase, event.phase_number

    def test_the_real_start_line_opens_the_first_phase(self):
        self.assertEqual(self._phase("[*] Source: Docker registry (docker)"), ("Preparing", 1))

    def test_the_real_command_line_opens_the_scanning_phase(self):
        self.assertEqual(
            self._phase("[*] Running: trufflehog docker --image=nginx:1.25 --json"),
            ("Scanning", 2),
        )

    def test_a_finding_line_keeps_the_scanning_phase(self):
        self.assertEqual(self._phase("[+] Found: AWS [validated] in /app/.env (acme/app)"),
                         ("Scanning", 2))

    def test_the_real_completion_line_closes_the_run(self):
        self.assertEqual(self._phase("[+] Results saved to /work/out.json (status=completed)"),
                         ("Complete", 3))


# ===========================================================================
# Regression tests for the bugs found in the hardening review. Named after the
# bug so a reappearance is unambiguous.
# ===========================================================================

class TestF1ConcurrentStartsOfTheSameSource(unittest.TestCase):
    """F1: the duplicate check and the state claim were separated by two awaits,
    so two concurrent starts for one source both passed and the second
    force-removed the first's container while overwriting its state — orphaning
    the first run's reservation key."""

    def _manager(self, gate):
        """A manager whose admission blocks on `gate`, so the first start is
        still IN FLIGHT when the second one runs its duplicate check. Without
        holding it there the first start would finish (or fail) first, and the
        interleaving the bug needs would never occur."""
        m = make_manager()
        self._egress = patch.object(cm_mod, "classify_host", return_value=(True, "1.2.3.4", "ok"))
        self._egress.start()
        self.addCleanup(self._egress.stop)

        async def gated_admit(*a, **kw):
            await gate.wait()
            return "key"
        m._admit_scan = gated_admit
        # Stop before the container spawn; the claim is what is under test.
        m.client.containers.get.side_effect = cm_mod.NotFound("none")
        m.client.images.get.side_effect = RuntimeError("stop here")
        return m

    def _start(self, m):
        return m.start_trufflehog(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan",
            source="docker", config={"images": ["nginx:1.25"]}, common={}, secrets={},
        )

    def _race(self, m, gate):
        """Start A, let it reach the gate, then run B to completion."""
        async def scenario():
            task_a = asyncio.create_task(self._start(m))
            for _ in range(20):          # let A reach the blocked admission
                await asyncio.sleep(0)
            try:
                await asyncio.wait_for(self._start(m), timeout=2)
                b_error = None
            except Exception as exc:
                b_error = exc
            gate.set()
            await asyncio.gather(task_a, return_exceptions=True)
            return b_error

        return asyncio.get_event_loop().run_until_complete(scenario())

    def test_f1_only_one_of_two_concurrent_starts_claims_the_source(self):
        gate = asyncio.Event()
        m = self._manager(gate)
        b_error = self._race(m, gate)
        self.assertIsInstance(b_error, ValueError, "the second concurrent start was admitted")
        self.assertIn("already running", str(b_error))

    def test_f1_the_first_runs_state_object_is_never_replaced(self):
        # The overwritten state was the real damage: _active_scan_keys rebuilds
        # the reservation key from the state object, so a clobbered one leaks.
        gate = asyncio.Event()
        m = self._manager(gate)

        async def scenario():
            task_a = asyncio.create_task(self._start(m))
            for _ in range(20):
                await asyncio.sleep(0)
            claimed = m.trufflehog_states["p1"]["docker"]
            try:
                await asyncio.wait_for(self._start(m), timeout=2)
            except (ValueError, asyncio.TimeoutError):
                pass
            still = m.trufflehog_states["p1"]["docker"]
            gate.set()
            await asyncio.gather(task_a, return_exceptions=True)
            return claimed, still

        claimed, still = asyncio.get_event_loop().run_until_complete(scenario())
        self.assertIs(claimed, still, "the second start replaced the first run's state")

    def test_f1_a_second_start_is_allowed_once_the_first_has_finished(self):
        # The guard must block CONCURRENT starts, not permanently wedge a source.
        m = make_manager()
        done = running("p1", "docker")
        done.status = TrufflehogStatus.COMPLETED
        m.trufflehog_states = {"p1": {"docker": done}}
        with patch.object(cm_mod, "classify_host", return_value=(True, "1.2.3.4", "ok")):
            m._admit_scan = MagicMock(side_effect=RuntimeError("reached admission"))
            m.client.containers.get.side_effect = cm_mod.NotFound("none")
            with self.assertRaises(RuntimeError):
                run(self._start(m))

    def test_f1_a_rejected_admission_releases_the_slot(self):
        # A phantom STARTING run would block every later start of this source.
        m = make_manager()
        with patch.object(cm_mod, "classify_host", return_value=(True, "1.2.3.4", "ok")):
            async def deny(*a, **kw):
                raise cm_mod.AdmissionError(MagicMock(limit_type="ram", detail="full"))
            m._admit_scan = deny
            with self.assertRaises(cm_mod.AdmissionError):
                run(self._start(m))
        self.assertEqual(m.trufflehog_states.get("p1", {}), {})

    def test_f1_a_stop_only_drops_its_own_claim(self):
        # The guarded drop: a stop must not remove a NEWER run that took the slot.
        m = make_manager()
        old_state = running("p1", "docker")
        newer = running("p1", "docker")
        m.trufflehog_states = {"p1": {"docker": newer}}
        m._drop_trufflehog_run("p1", "docker", old_state)
        self.assertIs(m.trufflehog_states["p1"]["docker"], newer)
        m._drop_trufflehog_run("p1", "docker", newer)
        self.assertEqual(m.trufflehog_states, {})


class TestF5IngestRefusesATenantlessRun(unittest.TestCase):
    """F5: ingesting with an empty user_id writes nodes no scoped read can see
    and no scoped clear can remove."""

    def test_f5_ingest_refuses_an_empty_user_id(self):
        m = make_manager()
        state = running("p1", "docker")
        state.user_id = ""
        state.status = TrufflehogStatus.COMPLETED
        published = []
        m._publish_trufflehog_output = lambda p, s: published.append((p, s))
        m._ingest_trufflehog(state)
        self.assertEqual(published, [], "ingest proceeded without a tenant key")
        self.assertFalse(state.ingested)


class TestF9ErrorPathRedaction(unittest.TestCase):
    """F9: state.error is returned by the status API and rendered in the UI. It
    was redacted against os.environ, which never holds the injected credential."""

    def test_f9_a_credential_echoed_in_an_exception_is_redacted(self):
        m = make_manager()
        secret = "ghp_thisisaverysecrettoken"
        with patch.object(cm_mod, "classify_host", return_value=(True, "1.2.3.4", "ok")):
            async def admit(*a, **kw):
                return "key"
            m._admit_scan = admit
            m.client.containers.get.side_effect = cm_mod.NotFound("none")
            # An SDK error whose message echoes the request env.
            m.client.images.get.side_effect = RuntimeError(
                f"invalid kwargs: environment={{'GITHUB_TOKEN': '{secret}'}}")
            state = run(m.start_trufflehog(
                project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan",
                source="github", config={"orgs": ["acme"]}, common={},
                secrets={"trufflehogGithubToken": secret},
            ))
        self.assertEqual(state.status, TrufflehogStatus.ERROR)
        self.assertNotIn(secret, state.error or "")
        self.assertIn("***", state.error or "")


# ===========================================================================
# Regression tests for the failure-mode analysis findings (F1, F2, F3).
# ===========================================================================

class TestF1StaleArtifactIsNotIngested(unittest.TestCase):
    """F1: the per-run scratch dir persists across runs. A run that never got
    far enough to write out.json would publish the PREVIOUS run's file and the
    graph would show one target's findings under a scan of another."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.m = make_manager()
        self.run_dir = Path(self._tmp.name) / "run"
        self.m._trufflehog_run_dir = lambda p, s: self.run_dir
        self.addCleanup(self._tmp.cleanup)
        self._egress = patch.object(cm_mod, "classify_host", return_value=(True, "1.2.3.4", "ok"))
        self._egress.start()
        self.addCleanup(self._egress.stop)

    def _start_failing(self):
        async def admit(*a, **kw):
            return "key"
        self.m._admit_scan = admit
        self.m.client.containers.get.side_effect = cm_mod.NotFound("none")
        # Fail at the spawn, after the run dir has been prepared.
        self.m.client.images.get.side_effect = RuntimeError("daemon unavailable")
        return run(self.m.start_trufflehog(
            project_id="p1", user_id="u1", trufflehog_path="/app/trufflehog_scan",
            source="docker", config={"images": ["nginx:1.25"]}, common={}, secrets={},
        ))

    def test_f1_a_previous_runs_artifact_is_removed_at_start(self):
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "out.json").write_text('{"source":"docker","findings":[{"x":1}]}')
        state = self._start_failing()
        self.assertEqual(state.status, TrufflehogStatus.ERROR)
        self.assertFalse((self.run_dir / "out.json").exists(),
                         "the previous run's artifact survived into this run")

    def test_f1_a_failed_run_has_nothing_to_ingest(self):
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "out.json").write_text('{"source":"docker","findings":[{"x":1}]}')
        state = self._start_failing()
        ingested = []
        self.m._trufflehog_output_path = lambda p, s: Path(self._tmp.name) / "published.json"
        with patch.object(cm_mod.ContainerManager, "_publish_trufflehog_output",
                          side_effect=lambda p, s: ingested.append((p, s))):
            self.m._ingest_trufflehog(state)
        # publish is reached (there is no artifact to find), but nothing is written.
        self.assertFalse(state.ingested)

    def test_f1_a_missing_artifact_is_not_an_error(self):
        self.run_dir.mkdir(parents=True)
        self._start_failing()  # no out.json existed to begin with
        self.assertFalse((self.run_dir / "out.json").exists())


class TestF3NoGraphClearBeforeTheSpawn(unittest.TestCase):
    """F3: clearing up front meant a spawn that failed destroyed the last good
    results and left nothing in their place."""

    def test_f3_the_start_path_does_not_clear_the_graph(self):
        import inspect
        src = inspect.getsource(cm_mod.ContainerManager.start_trufflehog)
        self.assertNotIn("clear_trufflehog_data", src)
        self.assertNotIn("_clear_trufflehog_graph", src)

    def test_f3_the_clear_still_happens_at_ingest_time(self):
        # The scoped clear must not simply have been dropped:
        # update_graph_from_trufflehog owns it now. Read as text — this suite
        # runs in the orchestrator image, which has no neo4j driver to import.
        mixin = (REPO / "graph_db" / "mixins" / "secret_mixin.py").read_text()
        body = mixin[mixin.index("def update_graph_from_trufflehog"):]
        self.assertIn("clear_trufflehog_data(user_id, project_id, source=source)", body)


class TestF2TerminalRunsDoNotAccumulate(unittest.TestCase):
    """F2: every finished run was re-inspected on every 30 s sweep, forever, and
    a permanently-failing ingest retried just as often."""

    def _terminal(self, completed_secs_ago: float, ingested: bool = True):
        st = running("p1", "docker")
        st.status = TrufflehogStatus.COMPLETED
        st.completed_at = datetime.now(timezone.utc) - timedelta(seconds=completed_secs_ago)
        st.ingested = ingested
        st.container_removed = True
        return st

    def test_f2a_a_settled_run_is_never_inspected_again(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._terminal(1)}}
        m.client.containers.get.side_effect = AssertionError("Docker was polled for a settled run")
        state = m._get_trufflehog_status_sync("p1", "docker")
        self.assertEqual(state.status, TrufflehogStatus.COMPLETED)

    def test_f2a_a_live_run_is_still_inspected(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": running("p1", "docker")}}
        m.client.containers.get.return_value = MagicMock(status="running")
        m._get_trufflehog_status_sync("p1", "docker")
        self.assertTrue(m.client.containers.get.called)

    def test_f2b_ingest_retries_are_bounded(self):
        m = make_manager()
        st = self._terminal(1, ingested=False)
        st.container_removed = True
        m.trufflehog_states = {"p1": {"docker": st}}
        attempts = []

        def fail(state):
            attempts.append(1)
            state.ingest_attempts += 1
        with patch.object(cm_mod.ContainerManager, "_ingest_trufflehog", side_effect=fail):
            for _ in range(50):
                m._get_trufflehog_status_sync("p1", "docker")
        self.assertEqual(len(attempts), cm_mod.MAX_TRUFFLEHOG_INGEST_ATTEMPTS)

    def test_f2b_the_counter_advances_even_when_ingest_returns_early(self):
        m = make_manager()
        st = self._terminal(1, ingested=False)
        st.user_id = ""      # refused by the tenant guard, which returns early
        m._ingest_trufflehog(st)
        self.assertEqual(st.ingest_attempts, 1)

    def test_f2c_a_long_finished_run_is_pruned(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._terminal(
            cm_mod.TRUFFLEHOG_TERMINAL_RETENTION_S + 60)}}
        run(m.get_all_trufflehog_statuses("p1"))
        self.assertEqual(m.trufflehog_states.get("p1", {}), {})

    def test_f2c_a_recently_finished_run_is_kept_for_the_reconcile(self):
        # Pruning inside the webapp's 90 s reconcile grace would make a completed
        # run vanish from /all before its outcome was read, and its history row
        # would be recorded as `canceled` instead of `completed`.
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": self._terminal(60)}}
        runs = run(m.get_all_trufflehog_statuses("p1"))
        self.assertEqual(len(runs), 1)
        self.assertIn("docker", m.trufflehog_states["p1"])

    def test_f2c_the_retention_window_clears_the_reconcile_grace(self):
        # 90_000 ms in webapp/src/app/api/internal/job-queue/reconcile/route.ts.
        self.assertGreater(cm_mod.TRUFFLEHOG_TERMINAL_RETENTION_S, 90)

    def test_f2c_a_live_run_is_never_pruned(self):
        m = make_manager()
        m.trufflehog_states = {"p1": {"docker": running("p1", "docker")}}
        m.client.containers.get.return_value = MagicMock(status="running")
        run(m.get_all_trufflehog_statuses("p1"))
        self.assertIn("docker", m.trufflehog_states["p1"])
