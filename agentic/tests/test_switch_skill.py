"""
Tests for the dynamic attack-skill switch feature (action="switch_skill").

The feature lets the root agent rebind `attack_path_type` mid-run — without a
phase change or a new objective — so a run that started as `recon-unclassified`
can load the specialized workflow (e.g. xss) the moment recon reveals the class.

Coverage layers:
  1. UNIT       — schema (ActionType, SkillSwitchDecision, LLMDecision.skill_switch),
                  validators, and the pure decision helper evaluate_skill_switch().
  2. INTEGRATION— parsing.try_parse_llm_decision() over real switch_skill JSON,
                  prompt wiring (build_attack_path_behavior, REACT template), and
                  get_phase_tools() proving a flipped attack_path_type swaps the
                  injected workflow WITHOUT a phase change.
  3. SMOKE      — router (_route_after_think) sends switch_skill back to `think`;
                  chain_graph_writer exposes the persistence helper.
  4. REGRESSION — pre-existing actions (use_tool / transition_phase / complete)
                  still parse; adding switch_skill didn't perturb KNOWN_ATTACK_PATHS.
  5. WIRING     — source-inspection locks that think_node applies the helper's
                  outcome (heavyweight full-node fixture avoided per project
                  convention, see test_root_think_and_guardrail_retry.py).

Run (inside agent container):
    docker run --rm -v "$PWD/agentic:/app" -v "$PWD/graph_db:/app/graph_db" \\
        -v "$PWD/knowledge_base:/app/knowledge_base" -w /app \\
        whitehat-agent python -m unittest tests.test_switch_skill -v
"""

from __future__ import annotations

import inspect
import os
import sys
import typing
import unittest
from unittest.mock import MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# --- Stub heavy deps so the module imports outside Docker too (mirrors
#     test_xss_skill.py). Inside the container real deps exist but pre-stubbing
#     is harmless because these tests never build a real LangGraph.
class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"


class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"


def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right


_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client', 'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint', 'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic', 'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]
for _mod in _stub_modules:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

# Now safe to import agentic modules under test.
from state import (  # noqa: E402
    ActionType, LLMDecision, SkillSwitchDecision, KNOWN_ATTACK_PATHS,
    is_valid_attack_path_value, evaluate_skill_switch,
)
from orchestrator_helpers.parsing import try_parse_llm_decision  # noqa: E402


def _decision_json(action, **fields):
    """Build a minimal decision JSON string with required thought/reasoning."""
    import json
    base = {"thought": "t", "reasoning": "r", "action": action}
    base.update(fields)
    return json.dumps(base)


# ===========================================================================
# 1. UNIT — schema
# ===========================================================================

class TestSchema(unittest.TestCase):
    def test_switch_skill_in_action_literal(self):
        self.assertIn("switch_skill", typing.get_args(ActionType))

    def test_existing_actions_still_present(self):
        args = set(typing.get_args(ActionType))
        for a in ("use_tool", "plan_tools", "transition_phase", "complete",
                  "ask_user", "deploy_fireteam"):
            self.assertIn(a, args)

    def test_llm_decision_has_skill_switch_field(self):
        d = LLMDecision(thought="t", reasoning="r", action="use_tool")
        self.assertIsNone(d.skill_switch)  # defaults None

    def test_skill_switch_decision_accepts_known_skill(self):
        s = SkillSwitchDecision(to_skill="xss", reason="reflected input")
        self.assertEqual(s.to_skill, "xss")
        self.assertEqual(s.reason, "reflected input")

    def test_skill_switch_decision_reason_optional(self):
        s = SkillSwitchDecision(to_skill="sql_injection")
        self.assertEqual(s.reason, "")

    def test_skill_switch_decision_accepts_user_skill(self):
        self.assertEqual(SkillSwitchDecision(to_skill="user_skill:abc123").to_skill,
                         "user_skill:abc123")

    def test_skill_switch_decision_accepts_unclassified(self):
        self.assertEqual(SkillSwitchDecision(to_skill="xxe-unclassified").to_skill,
                         "xxe-unclassified")

    def test_skill_switch_decision_rejects_bogus(self):
        with self.assertRaises(Exception):
            SkillSwitchDecision(to_skill="not_a_real_skill")

    def test_skill_switch_decision_rejects_empty(self):
        with self.assertRaises(Exception):
            SkillSwitchDecision(to_skill="")


class TestIsValidAttackPathValue(unittest.TestCase):
    def test_known(self):
        for s in ("xss", "sql_injection", "ssrf", "rce", "path_traversal", "cve_exploit"):
            self.assertTrue(is_valid_attack_path_value(s), s)

    def test_user_skill(self):
        self.assertTrue(is_valid_attack_path_value("user_skill:x"))

    def test_unclassified(self):
        self.assertTrue(is_valid_attack_path_value("recon-unclassified"))
        self.assertTrue(is_valid_attack_path_value("file_upload-unclassified"))

    def test_invalid(self):
        self.assertFalse(is_valid_attack_path_value("bogus"))
        self.assertFalse(is_valid_attack_path_value("XSS"))  # case-sensitive
        self.assertFalse(is_valid_attack_path_value(""))
        self.assertFalse(is_valid_attack_path_value("-unclassified"))  # regex needs a term


# ===========================================================================
# 2. UNIT — pure decision helper evaluate_skill_switch()
# ===========================================================================

class TestEvaluateSkillSwitch(unittest.TestCase):
    ENABLED = {"xss", "sql_injection", "ssrf", "rce", "path_traversal", "cve_exploit"}
    USERS = {"myskill"}

    def _eval(self, new, cur, enabled=None, users=None):
        return evaluate_skill_switch(
            new, cur,
            self.ENABLED if enabled is None else enabled,
            self.USERS if users is None else users,
        )

    def test_valid_switch(self):
        self.assertEqual(self._eval("xss", "recon-unclassified"), ("switched", "xss"))

    def test_noop_same_skill(self):
        self.assertEqual(self._eval("xss", "xss"), ("noop", "xss"))

    def test_reject_disabled_builtin(self):
        # brute_force is a KNOWN path but NOT in the enabled set here.
        self.assertEqual(self._eval("brute_force_credential_guess", "xss"),
                         ("rejected", None))

    def test_reject_bogus(self):
        self.assertEqual(self._eval("nonsense", "xss"), ("rejected", None))

    def test_reject_none(self):
        self.assertEqual(self._eval(None, "xss"), ("rejected", None))

    def test_reject_empty(self):
        self.assertEqual(self._eval("", "xss"), ("rejected", None))

    def test_user_skill_enabled(self):
        self.assertEqual(self._eval("user_skill:myskill", "xss"),
                         ("switched", "user_skill:myskill"))

    def test_user_skill_disabled(self):
        self.assertEqual(self._eval("user_skill:ghost", "xss"), ("rejected", None))

    def test_unclassified_always_allowed(self):
        # A *-unclassified target is always structurally valid (used to de-specialize).
        self.assertEqual(self._eval("sqli-unclassified", "xss"),
                         ("switched", "sqli-unclassified"))

    def test_empty_enabled_sets_reject_builtin(self):
        self.assertEqual(self._eval("xss", "recon-unclassified", enabled=set()),
                         ("rejected", None))

    def test_none_enabled_sets_do_not_crash(self):
        # Defensive: helper tolerates None for the enabled collections.
        self.assertEqual(evaluate_skill_switch("xss", "cur", None, None),
                         ("rejected", None))
        self.assertEqual(evaluate_skill_switch("xxe-unclassified", "cur", None, None),
                         ("switched", "xxe-unclassified"))


# ===========================================================================
# 3. INTEGRATION — parsing real switch_skill JSON
# ===========================================================================

class TestParsing(unittest.TestCase):
    def test_parse_valid_switch(self):
        d, err = try_parse_llm_decision(_decision_json(
            "switch_skill", skill_switch={"to_skill": "xss", "reason": "reflected"}))
        self.assertIsNone(err)
        self.assertEqual(d.action, "switch_skill")
        self.assertEqual(d.skill_switch.to_skill, "xss")
        self.assertEqual(d.skill_switch.reason, "reflected")

    def test_parse_empty_skill_switch_object_becomes_none(self):
        # {} would fail the sub-model (to_skill required); parser coerces to None,
        # action stays switch_skill so think_node rejects gracefully (loops to think),
        # instead of the fallback-to-complete path that ends the run.
        d, err = try_parse_llm_decision(_decision_json("switch_skill", skill_switch={}))
        self.assertIsNone(err)
        self.assertEqual(d.action, "switch_skill")
        self.assertIsNone(d.skill_switch)

    def test_parse_missing_skill_switch_stays_alive(self):
        d, err = try_parse_llm_decision(_decision_json("switch_skill"))
        self.assertIsNone(err)
        self.assertEqual(d.action, "switch_skill")
        self.assertIsNone(d.skill_switch)

    def test_parse_invalid_to_skill_is_rejected_by_validator(self):
        # A present-but-bogus to_skill must fail model_validate (validator), so the
        # parser returns an error and parse_llm_decision falls back — acceptable
        # because the LLM emitted a structurally-invalid skill id.
        d, err = try_parse_llm_decision(_decision_json(
            "switch_skill", skill_switch={"to_skill": "totally_bogus"}))
        self.assertIsNone(d)
        self.assertIsNotNone(err)

    def test_parse_does_not_break_other_actions(self):
        for action, extra in [
            ("use_tool", {"tool_name": "execute_curl", "tool_args": {"args": "-I http://x"}}),
            ("complete", {"completion_reason": "done"}),
            ("transition_phase", {"phase_transition": {"to_phase": "exploitation"}}),
        ]:
            d, err = try_parse_llm_decision(_decision_json(action, **extra))
            self.assertIsNone(err, f"{action}: {err}")
            self.assertEqual(d.action, action)


# ===========================================================================
# 4. INTEGRATION — prompt wiring
# ===========================================================================

class TestPromptWiring(unittest.TestCase):
    def test_react_template_lists_switch_skill(self):
        from prompts.base import REACT_SYSTEM_PROMPT
        self.assertIn("switch_skill", REACT_SYSTEM_PROMPT)
        # both the action enum and the worked example
        self.assertIn('"to_skill"', REACT_SYSTEM_PROMPT)

    def test_unclassified_behavior_advertises_switch(self):
        from prompts.base import build_attack_path_behavior
        beh = build_attack_path_behavior("recon-unclassified")
        self.assertIn("switch_skill", beh)
        self.assertIn("do NOT need to", beh.replace("\n", " "))

    def test_specialized_behavior_unchanged(self):
        # Switching in a concrete skill still yields its own behavior (regression:
        # the unclassified guidance must not leak into specialized paths).
        from prompts.base import build_attack_path_behavior
        beh = build_attack_path_behavior("xss")
        self.assertNotIn("switch_skill", beh)


# ===========================================================================
# 5. INTEGRATION/REGRESSION — get_phase_tools swaps workflow on a flipped path
#    WITHOUT a phase change (the whole point of the feature).
# ===========================================================================

class TestPhaseIndependentSkillInjection(unittest.TestCase):
    """Prove that flipping attack_path_type changes the injected workflow while
    the phase stays 'informational' — i.e. the skill gate is phase-independent."""

    def _get_phase_tools(self, attack_path_type, enabled_skills, phase="informational",
                         allowed_tools=None):
        if allowed_tools is None:
            # informational-legal tools: curl + kali_shell both available in info.
            allowed_tools = ['kali_shell', 'execute_curl', 'execute_code',
                             'execute_playwright', 'query_graph']
        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase', return_value=allowed_tools), \
             patch('project_settings.get_enabled_builtin_skills', return_value=enabled_skills), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value="## Tools\n"), \
             patch('prompts.get_hydra_flags_from_settings', return_value="-t 16 -f"), \
             patch('prompts.get_dos_settings_dict', return_value={}), \
             patch('prompts.get_session_config_prompt', return_value=""), \
             patch('prompts.build_informational_tool_descriptions', return_value="info tools"):

            def _side(key, default=None):
                return {
                    'STEALTH_MODE': False, 'INFORMATIONAL_SYSTEM_PROMPT': '',
                    'EXPL_SYSTEM_PROMPT': '', 'POST_EXPL_SYSTEM_PROMPT': '',
                    'XSS_DALFOX_ENABLED': True, 'XSS_BLIND_CALLBACK_ENABLED': False,
                    'XSS_CSP_BYPASS_ENABLED': True, 'ROE_ENABLED': False,
                    'SQLI_OOB_ENABLED': False, 'ACTIVATE_POST_EXPL_PHASE': True,
                }.get(key, default)
            mock_setting.side_effect = _side

            from prompts import get_phase_tools
            return get_phase_tools(
                phase=phase, activate_post_expl=True, post_expl_type="stateless",
                attack_path_type=attack_path_type, execution_trace=[],
            )

    def test_unclassified_in_informational_has_no_specialized_workflow(self):
        out = self._get_phase_tools("recon-unclassified", {"xss", "sql_injection"})
        self.assertNotIn("ATTACK SKILL: CROSS-SITE SCRIPTING", out)

    def test_switch_to_xss_injects_xss_in_informational(self):
        # THE key regression: same phase (informational), flipped path -> xss workflow.
        out = self._get_phase_tools("xss", {"xss", "sql_injection"})
        self.assertIn("ATTACK SKILL: CROSS-SITE SCRIPTING", out)

    def test_switch_to_sqli_injects_sqli_in_informational(self):
        out = self._get_phase_tools("sql_injection", {"xss", "sql_injection"})
        # SQLi workflow requires kali_shell (present in our informational tool set).
        self.assertNotIn("ATTACK SKILL: CROSS-SITE SCRIPTING", out)
        self.assertIn("SQL", out.upper())

    def test_switch_to_disabled_skill_does_not_inject(self):
        # Defence in depth: even if attack_path_type were flipped to a disabled
        # skill (shouldn't happen — think_node rejects first), the prompt gate
        # also refuses to inject it.
        out = self._get_phase_tools("xss", {"sql_injection"})  # xss NOT enabled
        self.assertNotIn("ATTACK SKILL: CROSS-SITE SCRIPTING", out)


# ===========================================================================
# 6. SMOKE — router + persistence helper
# ===========================================================================

class TestRouter(unittest.TestCase):
    """_route_after_think must send action=switch_skill back to `think`."""

    def _route(self, state):
        import orchestrator
        inst = orchestrator.AgentOrchestrator.__new__(orchestrator.AgentOrchestrator)
        return orchestrator.AgentOrchestrator._route_after_think(inst, state)

    def _base_state(self, **over):
        s = {"current_iteration": 3, "max_iterations": 300, "_decision": {}}
        s.update(over)
        return s

    def test_switch_skill_routes_to_think(self):
        st = self._base_state(_decision={"action": "switch_skill"})
        self.assertEqual(self._route(st), "think")

    def test_switch_skill_routes_to_think_even_with_tool_name(self):
        # A stray tool_name must not divert a switch_skill decision.
        st = self._base_state(_decision={"action": "switch_skill", "tool_name": "execute_curl"})
        self.assertEqual(self._route(st), "think")

    def test_max_iterations_still_short_circuits(self):
        # Regression: the iteration cap must win even for switch_skill.
        st = self._base_state(current_iteration=300,
                              _decision={"action": "switch_skill"})
        self.assertEqual(self._route(st), "generate_response")

    def test_use_tool_still_routes_to_execute_tool(self):
        st = self._base_state(_decision={"action": "use_tool", "tool_name": "execute_curl"})
        self.assertEqual(self._route(st), "execute_tool")


class TestPersistenceHelper(unittest.TestCase):
    def test_fire_update_chain_attack_path_exists(self):
        from orchestrator_helpers.chain_graph_writer import fire_update_chain_attack_path
        self.assertTrue(callable(fire_update_chain_attack_path))

    def test_fire_update_chain_attack_path_noop_without_creds(self):
        # No neo4j uri/password -> returns immediately, no exception.
        from orchestrator_helpers.chain_graph_writer import fire_update_chain_attack_path
        fire_update_chain_attack_path("", "", "", chain_id="c", attack_path_type="xss")


# ===========================================================================
# 7. REGRESSION — known-paths unchanged
# ===========================================================================

class TestKnownPathsRegression(unittest.TestCase):
    def test_all_original_paths_present(self):
        required = {
            "cve_exploit", "brute_force_credential_guess",
            "phishing_social_engineering", "denial_of_service",
            "sql_injection", "xss", "ssrf", "rce", "path_traversal",
        }
        self.assertTrue(required.issubset(KNOWN_ATTACK_PATHS),
                        f"Missing: {required - KNOWN_ATTACK_PATHS}")


# ===========================================================================
# 8. WIRING — source inspection of the think_node dispatch branch
#    (full-node fixture avoided per project convention).
# ===========================================================================

class TestThinkNodeWiring(unittest.TestCase):
    def setUp(self):
        import orchestrator_helpers.nodes.think_node  # noqa: F401
        mod = sys.modules["orchestrator_helpers.nodes.think_node"]
        self.src = inspect.getsource(mod.think_node)
        self.mod_src = inspect.getsource(mod)

    def test_imports_evaluate_skill_switch(self):
        self.assertIn("evaluate_skill_switch", self.mod_src)

    def test_dispatch_branch_present(self):
        self.assertIn('decision.action == "switch_skill"', self.src)

    def test_branch_writes_attack_path_type_on_switch(self):
        # The switched arm must set updates["attack_path_type"].
        i = self.src.find('decision.action == "switch_skill"')
        j = self.src.find('decision.action == "ask_user"', i)
        branch = self.src[i:j]
        self.assertIn('updates["attack_path_type"] = resolved', branch)

    def test_branch_persists_switch(self):
        i = self.src.find('decision.action == "switch_skill"')
        j = self.src.find('decision.action == "ask_user"', i)
        branch = self.src[i:j]
        self.assertIn("fire_update_chain_attack_path", branch)

    def test_branch_gives_feedback_on_reject(self):
        i = self.src.find('decision.action == "switch_skill"')
        j = self.src.find('decision.action == "ask_user"', i)
        branch = self.src[i:j]
        self.assertIn('outcome == "rejected"', branch)
        self.assertIn("HumanMessage", branch)

    def test_branch_does_not_write_path_on_reject_or_noop(self):
        # Guard: attack_path_type is only written in the switched arm.
        i = self.src.find('decision.action == "switch_skill"')
        j = self.src.find('decision.action == "ask_user"', i)
        branch = self.src[i:j]
        self.assertEqual(branch.count('updates["attack_path_type"]'), 1)


# ===========================================================================
# 9. INTEGRATION — real think_node invocation driving the dispatch branch.
#    Heavier than the rest, but exercises the actual node end-to-end (prompt
#    build -> parse -> dispatch) with only the LLM call and the Neo4j write
#    mocked. Proves the branch's real state/message/persistence effects.
# ===========================================================================

_SWITCH_JSON = ('{{"thought":"recon shows reflected JS in name param",'
                '"reasoning":"looks like XSS","action":"switch_skill",'
                '"skill_switch":{{"to_skill":"{to_skill}","reason":"reflected input"}},'
                '"updated_todo_list":[]}}')


class _FakeLLMResp:
    def __init__(self, content):
        self.content = content
        self.usage_metadata = {"input_tokens": 10, "output_tokens": 5}
        self.response_metadata = {}


class TestThinkNodeDispatchBehavioral(unittest.IsolatedAsyncioTestCase):
    """Drive the real think_node with a mocked LLM emitting switch_skill."""

    async def _run(self, to_skill, current="recon-unclassified",
                   enabled=None):
        if enabled is None:
            enabled = {"xss", "sql_injection", "cve_exploit"}
        from unittest.mock import AsyncMock
        import orchestrator_helpers.nodes.think_node  # noqa: F401
        tn = sys.modules["orchestrator_helpers.nodes.think_node"]

        resp = _FakeLLMResp(_SWITCH_JSON.format(to_skill=to_skill))
        ps = [
            patch.object(tn, "retry_llm_call", new=AsyncMock(return_value=resp)),
            patch.object(tn, "get_enabled_builtin_skills", return_value=enabled),
            patch.object(tn, "get_enabled_user_skills", return_value=[]),
            patch.object(tn.chain_graph, "fire_update_chain_attack_path", new=MagicMock()),
        ]
        for p in ps:
            p.start()
        try:
            state = {
                "attack_path_type": current, "current_phase": "informational",
                "current_iteration": 2, "max_iterations": 300,
                "messages": [], "todo_list": [], "execution_trace": [],
                "conversation_objectives": [{"objective": "find the flag", "status": "in_progress"}],
                "current_objective_index": 0, "objective_history": [],
            }
            config = {"configurable": {"thread_id": "u/p/s", "user_id": "u",
                                       "project_id": "p", "session_id": "s"}}
            updates = await tn.think_node(
                state, config, llm=MagicMock(), guidance_queues={},
                neo4j_creds=("", "", ""), streaming_callbacks=None,
                graph_view_cyphers=None,
            )
            return updates, tn.chain_graph.fire_update_chain_attack_path
        finally:
            for p in ps:
                try:
                    p.stop()
                except Exception:
                    pass

    async def test_valid_switch_applies_state_and_persists(self):
        updates, fire = await self._run("xss")
        # action stays switch_skill so the router loops back to think
        self.assertEqual(updates["_decision"]["action"], "switch_skill")
        self.assertEqual(updates.get("attack_path_type"), "xss")
        self.assertTrue(fire.called)
        self.assertEqual(fire.call_args.kwargs.get("attack_path_type"), "xss")
        msgs = updates.get("messages") or []
        self.assertTrue(any("switched" in getattr(m, "content", "") for m in msgs))

    async def test_reject_disabled_skill_no_state_change(self):
        # brute_force is NOT in the enabled set -> rejected.
        updates, fire = await self._run("brute_force_credential_guess")
        self.assertEqual(updates["_decision"]["action"], "switch_skill")  # still loops to think
        self.assertNotIn("attack_path_type", updates)  # path NOT written
        self.assertFalse(fire.called)
        msgs = updates.get("messages") or []
        self.assertTrue(any("[system] switch_skill rejected" in getattr(m, "content", "")
                            for m in msgs))

    async def test_noop_same_skill_no_state_change(self):
        updates, fire = await self._run("xss", current="xss")
        self.assertNotIn("attack_path_type", updates)
        self.assertFalse(fire.called)


# ===========================================================================
# 10. REGRESSION — fireteam members may NOT switch skill (defense in depth).
#     switch_skill is a global action; a member's state is discarded on collect,
#     so a member emitting it must be stripped to complete, like the other
#     forbidden member actions.
# ===========================================================================

class TestFireteamMemberForbidsSwitch(unittest.TestCase):
    def test_switch_skill_in_forbidden_map(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _FORBIDDEN_MEMBER_ACTIONS,
        )
        self.assertIn("switch_skill", _FORBIDDEN_MEMBER_ACTIONS)

    def test_member_switch_skill_stripped_to_complete(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _strip_forbidden_actions,
        )
        d = LLMDecision(
            thought="t", reasoning="r", action="switch_skill",
            skill_switch=SkillSwitchDecision(to_skill="xss"),
        )
        stripped = _strip_forbidden_actions(d, "member-1")
        self.assertEqual(stripped.action, "complete")
        self.assertEqual(stripped.completion_reason, "cannot_switch_skill_in_member")

    def test_member_use_tool_not_stripped(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _strip_forbidden_actions,
        )
        d = LLMDecision(thought="t", reasoning="r", action="use_tool",
                        tool_name="execute_curl")
        self.assertEqual(_strip_forbidden_actions(d, "m").action, "use_tool")


if __name__ == "__main__":
    unittest.main()
