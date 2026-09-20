"""The agent's memory surface: the four tools, the registry, phase access, the hook.

Four things are pinned, each of which fails SILENTLY when it breaks:

1. Every memory tool is in TOOL_REGISTRY with all four fields - an unregistered
   tool is invisible to the LLM while still being callable.
2. Memory is phase-agnostic: allowed in every phase, and never a TOOL_PHASE_MAP
   key (a new key is permanently disabled on every existing project, because
   fetch_agent_settings REPLACES the stored map).
3. The prompt renderers actually OFFER the tools. Being permitted but never
   offered is BUG #20's shape, and `_get_visible_tools` is the funnel.
4. The auto-capture hook is wired in BOTH execute nodes and the tools are
   registered by the orchestrator. The nodes duplicate that tail, so wiring one
   and forgetting the other is the documented failure mode.
5. The two session seams are CALLED. `session_context_text` and
   `MemoryAutoUpdater.session_end` both worked - and were tested - before
   anything invoked them, so "nothing calls it" is the failure mode to pin:
   a digest nobody injects, and a decay/reflection pass that never runs.

Runs with the agent's real dependency set (whitehat-agent image), per the repo
testing rules - not on the host.
"""
import os
import sys
import tempfile
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402
from memory_tools import MEMORY_TOOL_NAMES  # noqa: E402

PHASES = ("informational", "exploitation", "post_exploitation")
REQUIRED_FIELDS = ("purpose", "when_to_use", "args_format", "description")


def _read_source(rel_path):
    with open(os.path.join(_AGENTIC_DIR, rel_path), "r", encoding="utf-8") as fh:
        return fh.read()


class _tenant:
    """Set the request-scoped tenant contextvars the tools read, then restore."""

    def __init__(self, project_id="proj-mem", user_id="u1", session_id="s1"):
        self.project_id, self.user_id, self.session_id = project_id, user_id, session_id

    def __enter__(self):
        import agent_context as ctx
        self._p = ctx.current_project_id.set(self.project_id)
        self._u = ctx.current_user_id.set(self.user_id)
        self._s = ctx.current_session_id.set(self.session_id)
        return self

    def __exit__(self, *exc):
        import agent_context as ctx
        ctx.current_project_id.reset(self._p)
        ctx.current_user_id.reset(self._u)
        ctx.current_session_id.reset(self._s)
        return False


class _MemoryEnv(unittest.TestCase):
    """Pins memory config to a throwaway DB so no test touches a real store."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env_backup = {
            k: os.environ.get(k)
            for k in ("MEMORY_ENABLED", "MEMORY_AUTO_UPDATE", "MEMORY_SELF_IMPROVE",
                      "MEMORY_DB_PATH", "AGENTMEMORY_URL")
        }
        os.environ.update({
            "MEMORY_ENABLED": "true",
            "MEMORY_AUTO_UPDATE": "true",
            "MEMORY_SELF_IMPROVE": "true",
            "MEMORY_DB_PATH": os.path.join(self._tmp.name, "memory.db"),
            # No mirror: these tests must never need an agentmemory server.
            "AGENTMEMORY_URL": "",
        })
        from memory.auto_update import reset_updater
        reset_updater()

    def tearDown(self):
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        from memory.auto_update import reset_updater
        reset_updater()
        self._tmp.cleanup()


class RegistryTests(unittest.TestCase):
    def test_every_memory_tool_is_registered_with_all_fields(self):
        for name in sorted(MEMORY_TOOL_NAMES):
            self.assertIn(name, TOOL_REGISTRY, f"{name} missing from TOOL_REGISTRY")
            for field in REQUIRED_FIELDS:
                self.assertTrue(
                    TOOL_REGISTRY[name].get(field), f"{name}.{field} is empty",
                )

    def test_descriptions_are_non_trivial_and_lead_with_the_tool_name(self):
        for name in sorted(MEMORY_TOOL_NAMES):
            desc = TOOL_REGISTRY[name]["description"]
            self.assertGreaterEqual(len(desc), 100, f"{name} description is a stub")
            self.assertTrue(
                desc.lstrip().startswith(f"**{name}**"),
                f"{name} description does not lead with **{name}**",
            )

    def test_the_registry_advertises_every_tool_the_module_builds(self):
        from memory_tools import build_memory_tools
        self.assertEqual(set(build_memory_tools()), set(MEMORY_TOOL_NAMES))


class PhaseAccessTests(unittest.TestCase):
    def test_memory_is_allowed_in_every_phase(self):
        from project_settings import is_tool_allowed_in_phase
        for name in sorted(MEMORY_TOOL_NAMES):
            for phase in PHASES:
                self.assertTrue(
                    is_tool_allowed_in_phase(name, phase),
                    f"{name} is blocked in {phase}",
                )

    def test_memory_is_deliberately_not_a_TOOL_PHASE_MAP_key(self):
        # Adding one would permanently disable memory on every existing project
        # (and, for a new project, hand the operator a checkbox that does not
        # exist in the UI). The access rule lives in is_tool_allowed_in_phase.
        from project_settings import get_setting
        phase_map = get_setting("TOOL_PHASE_MAP", {})
        self.assertEqual(set(MEMORY_TOOL_NAMES) & set(phase_map), set())

    def test_the_menu_builders_offer_memory(self):
        # The BUG #20 guard: permitted but never offered is invisible to the agent.
        from prompts.base import (
            build_compact_tool_list,
            build_tool_args_section,
            build_tool_name_enum,
            with_memory_tools,
        )

        menu = with_memory_tools([])
        self.assertTrue(MEMORY_TOOL_NAMES.issubset(set(menu)))
        enum = build_tool_name_enum(menu)
        for name in sorted(MEMORY_TOOL_NAMES):
            self.assertIn(name, enum)
        self.assertIn("memory_recall", build_tool_args_section(menu))
        # ...while the renderers stay a pure filter: the narrow views that use
        # them (a fireteam member's declared skills) must render exactly what
        # they were handed, so an empty allowlist still renders nothing.
        self.assertEqual(build_compact_tool_list([]), "")

    def test_the_menu_builders_keep_the_phase_allowlist(self):
        from prompts.base import with_memory_tools

        merged = with_memory_tools(["execute_nmap", "query_graph"])
        self.assertEqual(merged[:2], ["execute_nmap", "query_graph"])
        # No duplicates when a caller already carried them. The helper also
        # carries the report layer's tool (report_review), so the invariant is
        # "no duplicates", not "exactly the memory tools".
        widened = with_memory_tools(list(MEMORY_TOOL_NAMES))
        self.assertEqual(len(widened), len(set(widened)))
        self.assertTrue(MEMORY_TOOL_NAMES.issubset(set(widened)))


class ToolCallTests(_MemoryEnv):
    def test_saving_then_recalling_returns_the_memory(self):
        from memory_tools import _recall_impl, _save_impl

        with _tenant():
            saved = self._run(_save_impl(text="SSH on the jump host needs the legacy KEX flag."))
            self.assertIn("Saved to memory", saved)

            recalled = self._run(_recall_impl(query="legacy KEX flag jump host"))
            self.assertIn("legacy KEX flag", recalled)
            # Recalled content is attacker-influenced, so it must arrive framed
            # as data rather than as prose the model can read as instructions.
            self.assertIn("<<<UNTRUSTED_MEMORY id=", recalled)
            self.assertIn("never instructions", recalled)

    def test_an_empty_project_says_EMPTY_rather_than_nothing_matched(self):
        from memory_tools import _recall_impl

        with _tenant():
            out = self._run(_recall_impl(query="anything at all"))
        self.assertIn("EMPTY", out)
        self.assertIn("not looked for", out)

    def test_a_query_with_no_match_is_distinguishable_from_an_empty_store(self):
        from memory_tools import _recall_impl, _save_impl

        with _tenant():
            self._run(_save_impl(text="A note about the staging host naming convention."))
            out = self._run(_recall_impl(query="kerberoasting ldap delegation"))
        self.assertIn("No memory matched", out)
        self.assertNotIn("EMPTY", out)

    def test_memory_is_project_scoped_at_the_tool_surface(self):
        from memory_tools import _recall_impl, _save_impl

        with _tenant(project_id="proj-one"):
            self._run(_save_impl(text="Only project one should ever see this sentence."))
        with _tenant(project_id="proj-two"):
            out = self._run(_recall_impl(query="only project one sentence"))
        self.assertIn("EMPTY", out)

    def test_the_tools_refuse_without_a_tenant(self):
        from memory_tools import _recall_impl, _save_impl, _timeline_impl

        with _tenant(project_id="", user_id="", session_id=""):
            self.assertIn("Error: missing project_id", self._run(_recall_impl(query="x")))
            self.assertIn("Error: missing project_id", self._run(_save_impl(text="x")))
            self.assertIn("Error: missing project_id", self._run(_timeline_impl()))

    def test_the_timeline_reports_what_was_learned_and_when(self):
        from memory_tools import _save_impl, _timeline_impl

        with _tenant():
            self._run(_save_impl(text="The login form accepts a JSON content type."))
            out = self._run(_timeline_impl(scope="project"))
        self.assertIn("Memory timeline", out)
        self.assertIn("created", out)
        self.assertIn("summary:", out)

    def test_a_missing_memory_id_is_an_explicit_error(self):
        from memory_tools import _timeline_impl

        with _tenant():
            out = self._run(_timeline_impl(scope="memory"))
        self.assertIn("needs a memory_id", out)

    def test_saving_nothing_is_refused(self):
        from memory_tools import _save_impl

        with _tenant():
            self.assertIn("nothing to save", self._run(_save_impl(text="   ")))

    def test_reflect_distils_a_lesson_from_captured_failures(self):
        from memory.auto_update import get_updater
        from memory_tools import _reflect_impl

        updater = get_updater()
        with _tenant():
            for ok in (False, False, False, True):
                updater.observe_tool_result(
                    project_id="proj-mem", tool_name="execute_nuclei", success=ok,
                    phase="exploitation", session_id="s1", output="",
                    error="" if ok else "connection refused",
                )
            out = self._run(_reflect_impl(include_timeline=False))

        self.assertIn("self-improvement:", out)
        self.assertIn("lesson", out)
        self.assertIn("1 lesson(s)", out)

    def test_every_tool_is_disabled_cleanly_when_memory_is_off(self):
        from memory_tools import _recall_impl, _reflect_impl, _save_impl, _timeline_impl

        os.environ["MEMORY_ENABLED"] = "false"
        with _tenant():
            self.assertIn("disabled", self._run(_recall_impl(query="x")))
            self.assertIn("disabled", self._run(_save_impl(text="x")))
            self.assertIn("disabled", self._run(_timeline_impl()))
            self.assertIn("disabled", self._run(_reflect_impl()))

    @staticmethod
    def _run(coro):
        """Resolve a tool coroutine (the impls are async, like the wrapped tools)."""
        import asyncio
        return asyncio.run(coro)


class HookWiringTests(_MemoryEnv):
    def test_capture_records_a_tool_outcome(self):
        from memory_hook import capture_tool_result

        with _tenant():
            stored = capture_tool_result(
                tool_name="execute_nmap", phase="informational", success=True,
                output="PORT 8080/tcp open http",
            )
        self.assertTrue(stored)

        from memory.auto_update import get_updater
        records = get_updater().store().candidates("proj-mem")
        self.assertEqual(len(records), 1)
        self.assertIn("execute_nmap", records[0].text)
        self.assertIn("tool:execute_nmap", records[0].tags)

    def test_capture_is_skipped_for_housekeeping_and_memory_tools(self):
        from memory_hook import capture_tool_result

        with _tenant():
            for name in ("fs_read", "job_status", "memory_recall"):
                self.assertFalse(capture_tool_result(tool_name=name, success=True))

    def test_capture_without_a_project_is_a_noop(self):
        from memory_hook import capture_tool_result

        with _tenant(project_id=""):
            self.assertFalse(capture_tool_result(tool_name="execute_nmap", success=True))

    def test_capture_never_raises_on_a_broken_store(self):
        from memory_hook import capture_tool_result

        with _tenant():
            os.environ["MEMORY_DB_PATH"] = "/proc/definitely/not/writable/memory.db"
            from memory.auto_update import reset_updater
            reset_updater()
            self.assertFalse(capture_tool_result(tool_name="execute_nmap", success=True))

    def test_register_memory_tools_attaches_them_to_the_executor(self):
        from memory_hook import register_memory_tools
        from tools import PhaseAwareToolExecutor

        executor = PhaseAwareToolExecutor(None, None)
        self.assertEqual(register_memory_tools(executor), len(MEMORY_TOOL_NAMES))
        for name in MEMORY_TOOL_NAMES:
            self.assertIn(name, executor._all_tools)

    def test_the_executor_can_run_a_memory_tool_end_to_end(self):
        import asyncio

        from memory_hook import register_memory_tools
        from tools import PhaseAwareToolExecutor

        executor = PhaseAwareToolExecutor(None, None)
        register_memory_tools(executor)
        with _tenant():
            result = asyncio.run(executor.execute(
                "memory_save", {"text": "End-to-end via the executor."}, "informational",
            ))
        self.assertTrue(result["success"], result.get("error"))
        self.assertIn("Saved to memory", result["output"])

    def test_a_memory_tool_write_does_not_observe_itself(self):
        from memory_hook import capture_tool_result

        with _tenant():
            capture_tool_result(tool_name="memory_reflect", success=True, output="...")
        from memory.auto_update import get_updater
        self.assertEqual(get_updater().store().stats("proj-mem")["memories"], 0)


class WiringRegressionTests(unittest.TestCase):
    """Guards against a wiring line being dropped by a later refactor."""

    def test_the_orchestrator_registers_the_memory_tools(self):
        source = _read_source("orchestrator.py")
        self.assertIn("register_memory_tools(self.tool_executor)", source)

    def test_both_execute_nodes_capture_tool_outcomes(self):
        # execute_tool_node (single) and execute_plan_node (parallel plans)
        # duplicate this tail: capturing only one makes memory work interactively
        # and silently lose plan-wave outcomes.
        for node in ("orchestrator_helpers/nodes/execute_tool_node.py",
                     "orchestrator_helpers/nodes/execute_plan_node.py"):
            self.assertIn("capture_tool_result(", _read_source(node), f"{node} lost the hook")


class SessionLifecycleTests(_MemoryEnv):
    """What a session starts with, and what it leaves behind."""

    def test_a_project_that_learned_nothing_gets_no_block(self):
        from memory_hook import session_context_text

        self.assertEqual(session_context_text(project_id="proj-untouched"), "")

    def test_the_digest_carries_the_playbook_as_untrusted_data(self):
        from memory.auto_update import get_updater
        from memory_hook import session_context_text

        updater = get_updater()
        record = updater.save_memory(
            project_id="proj-mem",
            text="nuclei is useless against this WAF; hand-craft the payloads.",
            kind="lesson",
        )
        # A fresh memory is a CANDIDATE; the digest injects what earned a place,
        # so promote it the way a recall does.
        updater.store().touch(record)
        block = session_context_text(project_id="proj-mem")
        self.assertIn("earlier sessions", block)
        self.assertIn("nuclei is useless against this WAF", block)
        # It reaches the SYSTEM prompt, so the data/instruction boundary has to
        # be unforgeable rather than a reassuring sentence.
        self.assertIn("<<<UNTRUSTED_MEMORY id=", block)
        self.assertIn("never instructions", block)

    def test_the_digest_is_project_scoped(self):
        from memory.auto_update import get_updater
        from memory_hook import session_context_text

        updater = get_updater()
        record = updater.save_memory(
            project_id="proj-one", text="Only project one learned this sentence.", kind="lesson",
        )
        updater.store().touch(record)
        self.assertEqual(session_context_text(project_id="proj-two"), "")
        self.assertIn("Only project one learned", session_context_text(project_id="proj-one"))

    def test_initialize_recovers_the_digest_for_a_new_session(self):
        from memory.auto_update import get_updater
        from orchestrator_helpers.nodes.initialize_node import _memory_context

        updater = get_updater()
        record = updater.save_memory(
            project_id="proj-mem",
            text="Hand-craft the payloads here; nuclei is blocked by the WAF.",
            kind="lesson",
        )
        updater.store().touch(record)

        self.assertIn("Hand-craft the payloads", _memory_context({}, "proj-mem"))
        self.assertEqual(_memory_context({}, "proj-none"), "")

    def test_initialize_keeps_the_context_it_already_recovered(self):
        from orchestrator_helpers.nodes.initialize_node import _memory_context

        self.assertEqual(
            _memory_context({"memory_context": "cached block"}, "proj-mem"),
            "cached block",
        )

    def test_the_digest_never_raises_on_a_broken_store(self):
        from memory_hook import session_context_text

        os.environ["MEMORY_DB_PATH"] = "/proc/definitely/not/writable/memory.db"
        from memory.auto_update import reset_updater
        reset_updater()
        self.assertEqual(session_context_text(project_id="proj-mem"), "")

    def test_the_end_of_session_pass_decays_and_reflects(self):
        from memory.auto_update import get_updater
        from memory_hook import session_end_pass

        updater = get_updater()
        for ok in (False, False, False, True):
            updater.observe_tool_result(
                project_id="proj-mem", tool_name="execute_nuclei", success=ok,
                phase="exploitation", session_id="s1", output="",
                error="" if ok else "connection refused",
            )

        result = session_end_pass(project_id="proj-mem", session_id="s1", reason="unit test")

        self.assertEqual(set(result), {"decayed", "reflection"})
        self.assertIn("lesson", result["reflection"] or "")

    def test_two_sweeps_in_one_day_do_not_decay_twice(self):
        """A day can hold several sessions, and every one of them ends a pass.

        `idle_days()` is measured from last use, so it does not shrink after a
        sweep - without the delta guard the same idleness would be decayed once
        per session, far faster than the configured half-life.
        """
        import unittest.mock as mock

        from memory.auto_update import get_updater
        from memory.models import MemoryRecord

        updater = get_updater()
        updater.save_memory(
            project_id="proj-mem", text="A lesson that nobody re-reads.", kind="lesson",
        )
        store = updater.store()
        before = store.candidates("proj-mem")[0].confidence

        with mock.patch.object(MemoryRecord, "idle_days", return_value=40.0):
            first = updater.decay_sweep("proj-mem")
            after_first = store.candidates("proj-mem")[0].confidence
            second = updater.decay_sweep("proj-mem")

        self.assertEqual(first, 1)
        self.assertLess(after_first, before)
        self.assertEqual(second, 0)
        self.assertAlmostEqual(store.candidates("proj-mem")[0].confidence, after_first, places=6)

    def test_a_later_sweep_decays_only_the_time_since_the_last_one(self):
        import unittest.mock as mock

        from memory.auto_update import get_updater
        from memory.models import MemoryRecord

        updater = get_updater()
        updater.save_memory(
            project_id="proj-mem", text="A lesson that nobody re-reads.", kind="lesson",
        )
        store = updater.store()
        clock = {"now": 1_700_000_000.0}

        with mock.patch("memory.auto_update.time.time", side_effect=lambda: clock["now"]), \
                mock.patch.object(MemoryRecord, "idle_days", return_value=40.0):
            self.assertEqual(updater.decay_sweep("proj-mem"), 1)
            after_first = store.candidates("proj-mem")[0].confidence

            clock["now"] += 10 * 86400  # ten idle days later
            self.assertEqual(updater.decay_sweep("proj-mem"), 1)

        after_second = store.candidates("proj-mem")[0].confidence
        self.assertLess(after_second, after_first)
        # 40 idle days then 10 more is 50 days of decay in total, not 80.
        self.assertAlmostEqual(
            after_second / after_first, 0.5 ** (10.0 / 30.0), places=3,
        )

    def test_the_end_of_session_pass_is_fail_open(self):
        from memory_hook import session_end_pass

        # No project in context and none passed: a refusal, not a crash.
        self.assertEqual(session_end_pass(), {})

        os.environ["MEMORY_DB_PATH"] = "/proc/definitely/not/writable/memory.db"
        from memory.auto_update import reset_updater
        reset_updater()
        result = session_end_pass(project_id="proj-mem")
        self.assertEqual(result.get("decayed"), 0)
        self.assertIsNone(result.get("reflection"))


class SessionLifecycleWiringTests(unittest.TestCase):
    """The seams are only real where the agent loop actually calls them."""

    def test_initialize_recovers_the_context_onto_the_state(self):
        source = _read_source("orchestrator_helpers/nodes/initialize_node.py")
        self.assertIn("from memory_hook import session_context_text", source)
        self.assertIn("session_context_text(project_id=project_id)", source)
        # Both main paths carry it: a new objective and a continuation. A
        # session created before this shipped recovers it on its next turn.
        self.assertEqual(source.count('"memory_context": _memory_context(state, project_id)'), 2)

    def test_the_think_prompt_carries_it_below_the_higher_priority_blocks(self):
        source = _read_source("orchestrator_helpers/nodes/think_node.py")
        self.assertIn('_memory_context = state.get("memory_context") or ""', source)
        inject = source.index('system_prompt = _memory_context + "\\n\\n" + system_prompt')
        # Prepended BEFORE the stealth rules and the report discipline, both of
        # which re-prepend over it and must keep their priority.
        self.assertLess(inject, source.index("STEALTH_MODE_RULES"))
        self.assertLess(inject, source.index("_discipline + \"\\n\\n\" + system_prompt"))

    def test_the_terminal_node_closes_the_session(self):
        source = _read_source("orchestrator_helpers/nodes/generate_response_node.py")
        self.assertIn("from memory_hook import session_end_pass", source)
        self.assertIn('reason="run completed"', source)

    def test_a_cancelled_run_closes_the_session_too(self):
        # The Stop button, a deleted conversation and the emergency stop all
        # cancel the task, so the graph never reaches its terminal node.
        source = _read_source("websocket_api.py")
        self.assertIn("def _memory_session_end(", source)
        marker = source.index("Query task cancelled for session")
        self.assertIn("_memory_session_end(", source[marker:marker + 400])


if __name__ == "__main__":
    unittest.main()
