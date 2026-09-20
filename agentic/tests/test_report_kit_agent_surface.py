"""The report layer's agent surface: the tool, the seams, the prompt injections.

Five things are pinned, each of which fails SILENTLY when it breaks:

1. `report_review` is in TOOL_REGISTRY with all four fields - an unregistered
   tool is invisible to the LLM while still being callable.
2. Report review is phase-agnostic: allowed in every phase, and never a
   TOOL_PHASE_MAP key (a new key is permanently disabled on every existing
   project, because fetch_agent_settings REPLACES the stored map).
3. The menu builders actually OFFER it. Permitted but never offered is BUG #20's
   shape, and `with_agent_tools` is the funnel.
4. The prompt seams are wired: the always-on discipline in the think node, and
   the report block + self-check in the response node, plus registration in the
   orchestrator.
5. The three reporting skills are discoverable through the real skill loader -
   a skill file whose frontmatter does not parse is invisible to the catalog.

Runs with the agent's real dependency set (redamon-agent image), per the repo
testing rules - not on the host.
"""
import asyncio
import os
import sys
import unittest
from unittest import mock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402
from report_tools import REPORT_TOOL_NAMES, _review_impl  # noqa: E402

PHASES = ("informational", "exploitation", "post_exploitation")
REQUIRED_FIELDS = ("purpose", "when_to_use", "args_format", "description")

CLEAN_REPORT = """# Reflected XSS in /search via q

## PoC
```
GET /search?q=<svg onload=alert(document.domain)> HTTP/1.1
Host: app.internal
```
The alert fires in the response page.

## Exploitation
1. Send the request above.
2. Observe the alert in the page origin.

## Impact
JS execution in the victim browser, demonstrated by reading document.cookie.
"""


def _read_source(rel_path):
    with open(os.path.join(_AGENTIC_DIR, rel_path), "r", encoding="utf-8") as fh:
        return fh.read()


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class RegistryTests(unittest.TestCase):
    def test_the_report_tool_is_registered_with_all_fields(self):
        for name in sorted(REPORT_TOOL_NAMES):
            self.assertIn(name, TOOL_REGISTRY, f"{name} missing from TOOL_REGISTRY")
            for field in REQUIRED_FIELDS:
                self.assertTrue(TOOL_REGISTRY[name].get(field),
                                f"{name}.{field} is empty")

    def test_the_description_leads_with_the_tool_name_and_names_the_modes(self):
        desc = TOOL_REGISTRY["report_review"]["description"]
        self.assertGreaterEqual(len(desc), 200, "description is a stub")
        self.assertTrue(desc.lstrip().startswith("**report_review**"))
        for mode in ("triage", "gotchas", "structure", "cvss"):
            self.assertIn(mode, desc)

    def test_the_registry_advertises_every_tool_the_module_builds(self):
        from report_tools import build_report_tools
        self.assertEqual(set(build_report_tools()), set(REPORT_TOOL_NAMES))


class PhaseAccessTests(unittest.TestCase):
    def test_report_review_is_allowed_in_every_phase(self):
        from project_settings import is_tool_allowed_in_phase
        for name in sorted(REPORT_TOOL_NAMES):
            for phase in PHASES:
                self.assertTrue(is_tool_allowed_in_phase(name, phase),
                                f"{name} is blocked in {phase}")

    def test_report_review_is_deliberately_not_a_TOOL_PHASE_MAP_key(self):
        from project_settings import get_setting
        phase_map = get_setting("TOOL_PHASE_MAP", {})
        self.assertEqual(set(REPORT_TOOL_NAMES) & set(phase_map), set())

    def test_the_menu_builders_offer_the_agent_native_tools(self):
        from prompts.base import (
            build_tool_args_section,
            build_tool_name_enum,
            with_agent_tools,
            with_memory_tools,
        )

        menu = with_agent_tools([])
        self.assertTrue(REPORT_TOOL_NAMES.issubset(set(menu)))
        enum = build_tool_name_enum(menu)
        for name in sorted(REPORT_TOOL_NAMES):
            self.assertIn(name, enum)
        self.assertIn("report_review", build_tool_args_section(menu))
        # The renderers stay a pure filter: an empty allowlist renders nothing.
        self.assertEqual(build_tool_args_section([]), "")
        # ...and the memory-only name still reaches the widened helper.
        self.assertTrue(REPORT_TOOL_NAMES.issubset(set(with_memory_tools([]))))

    def test_the_menu_helper_keeps_the_phase_allowlist(self):
        from prompts.base import with_agent_tools
        merged = with_agent_tools(["execute_nmap", "query_graph"])
        self.assertEqual(merged[:2], ["execute_nmap", "query_graph"])
        # Idempotent, and never duplicated - the helper now carries both the
        # memory and the report tools.
        widened = with_agent_tools(list(REPORT_TOOL_NAMES))
        self.assertEqual(len(widened), len(set(widened)))
        self.assertTrue(REPORT_TOOL_NAMES.issubset(set(widened)))


class ToolCallTests(unittest.TestCase):
    def test_triage_without_a_draft_refuses(self):
        out = _run(_review_impl(mode="triage", draft=""))
        self.assertIn("Nothing to triage", out)

    def test_triage_returns_a_verdict_block(self):
        out = _run(_review_impl(mode="triage", draft=CLEAN_REPORT))
        self.assertIn("VERDICT:", out)
        self.assertIn("What's good", out)

    def test_structure_mode_returns_the_sections(self):
        out = _run(_review_impl(mode="structure"))
        self.assertIn("Required report structure", out)
        self.assertIn("**Proof of Concept**", out)

    def test_gotchas_mode_names_the_class_and_its_proof(self):
        out = _run(_review_impl(mode="gotchas", vulnerability_class="SSRF"))
        self.assertIn("### SSRF", out)
        self.assertIn("Minimum proof", out)

    def test_gotchas_mode_without_input_lists_the_known_classes(self):
        out = _run(_review_impl(mode="gotchas"))
        self.assertIn("Known classes", out)

    def test_cvss_mode_scores_and_checks_the_vector(self):
        out = _run(_review_impl(mode="cvss",
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                auth_gate=True))
        self.assertIn("9.8", out)
        self.assertIn("PR:N", out)

    def test_unknown_mode_is_reported_not_raised(self):
        self.assertIn("Unknown mode", _run(_review_impl(mode="nonsense")))

    def test_the_executor_runs_report_review_end_to_end(self):
        from report_hook import register_report_tools
        from tools import PhaseAwareToolExecutor

        executor = PhaseAwareToolExecutor(None, None)
        self.assertEqual(register_report_tools(executor), len(REPORT_TOOL_NAMES))
        result = asyncio.run(executor.execute(
            "report_review", {"mode": "structure"}, "informational",
        ))
        self.assertTrue(result["success"], result.get("error"))
        self.assertIn("Required report structure", result["output"])


class HookTests(unittest.TestCase):
    def test_the_discipline_block_is_injected_and_switched_by_env(self):
        from report_hook import report_discipline_block
        self.assertIn("EVIDENCE DISCIPLINE", report_discipline_block())
        with mock.patch.dict(os.environ, {"REDAMON_REPORT_DISCIPLINE": "false"}):
            self.assertEqual(report_discipline_block(), "")

    def test_the_report_block_carries_the_class_gotchas(self):
        from report_hook import report_prompt_block
        self.assertIn("Minimum proof", report_prompt_block("xss"))

    def test_self_check_appends_only_when_it_found_something(self):
        from report_hook import self_check_appendix
        self.assertEqual(self_check_appendix(CLEAN_REPORT), "")
        noisy = ("## Impact\nThis could lead to full account takeover of every "
                 "tenant via the /admin endpoint.")
        appendix = self_check_appendix(noisy)
        self.assertIn("Report self-check", appendix)
        self.assertIn("VERDICT:", appendix)

    def test_self_check_is_switched_off_by_env(self):
        from report_hook import self_check_appendix
        with mock.patch.dict(os.environ,
                             {"REDAMON_REPORT_DISCIPLINE_AUTOCHECK": "false"}):
            self.assertEqual(
                self_check_appendix("This could lead to full compromise."), "")

    def test_every_seam_is_fail_open(self):
        # A broken report layer must cost the agent its review, never its turn.
        import report_hook
        with mock.patch.dict(sys.modules, {"report_kit": None}):
            self.assertEqual(report_hook.report_discipline_block(), "")
            self.assertEqual(report_hook.report_prompt_block("xss"), "")
            self.assertEqual(report_hook.self_check_appendix("could lead to x"), "")


class WiringRegressionTests(unittest.TestCase):
    """Guards against a wiring line being dropped by a later refactor."""

    def test_the_orchestrator_registers_the_report_tools(self):
        source = _read_source("orchestrator.py")
        self.assertIn("register_report_tools(self.tool_executor)", source)

    def test_the_think_node_injects_the_always_on_discipline(self):
        source = _read_source("orchestrator_helpers/nodes/think_node.py")
        self.assertIn("from report_hook import report_discipline_block", source)
        self.assertIn("_discipline = report_discipline_block()", source)
        self.assertIn("_discipline + \"\\n\\n\" + system_prompt", source)

    def test_the_response_node_adds_the_report_block_and_the_self_check(self):
        source = _read_source("orchestrator_helpers/nodes/generate_response_node.py")
        self.assertIn("report_prompt_block(", source)
        self.assertIn("self_check_appendix(", source)
        # The self-check reviews the report that was written - it must run after
        # the LLM call and only for the full-report tier.
        self.assertLess(source.index("llm.ainvoke([HumanMessage(content=report_prompt)])"),
                        source.index("self_check_appendix("))
        self.assertIn("tier == \"full_report\"", source)


class ReportingSkillTests(unittest.TestCase):
    """The three skills must be visible to the catalog, not just on disk."""

    EXPECTED = {
        "reporting/report_writing": "Report Writing",
        "reporting/report_triage": "Report Triage",
        "reporting/vuln_gotchas": "Vulnerability Class Gotchas",
    }

    def test_they_are_discovered_with_their_frontmatter_names(self):
        from orchestrator_helpers.skill_loader import list_skills
        by_id = {s["id"]: s for s in list_skills()}
        for skill_id, name in self.EXPECTED.items():
            self.assertIn(skill_id, by_id, f"{skill_id} is not discoverable")
            self.assertEqual(by_id[skill_id]["name"], name)
            self.assertEqual(by_id[skill_id]["category"], "reporting")
            self.assertTrue(by_id[skill_id]["description"], "description is empty")

    def test_they_load_and_point_at_the_real_tool(self):
        from orchestrator_helpers.skill_loader import load_skill_content
        for skill_id in self.EXPECTED:
            content = load_skill_content(skill_id)
            self.assertIsNotNone(content)
            self.assertIn("report_review", content, f"{skill_id} names no tool")


if __name__ == "__main__":
    unittest.main()
