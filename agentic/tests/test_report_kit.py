"""report_kit units: the discipline text, the class reference, CVSS, slop, triage.

The tests are written around the two properties that make this layer useful:

* it must be HARD to pass by accident - an unverified claim, a placeholder PoC
  and an out-of-scope host each have to land in the right bucket, and a clean
  draft has to come back clean;
* it must be cheap to run - deterministic, no LLM, no network, so a verdict is
  reproducible and every flag points at the phrase that produced it.

Runs with the agent's real dependency set (redamon-agent image), per the repo
testing rules - not on the host.
"""
import os
import sys
import unittest
from unittest import mock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from report_kit import (  # noqa: E402
    CLASSES,
    DISCIPLINE_RULES,
    GOTCHAS,
    base_score,
    build_gotchas_block,
    build_report_block,
    build_structure_block,
    classes_for_attack_path,
    detect_classes,
    discipline_block,
    is_base_only,
    metric_mismatch_flags,
    parse_vector,
    resolve_class,
    scan_slop,
    severity,
    triage_draft,
)
from report_kit.triage import render_triage  # noqa: E402

# A draft that holds the bar: replayable request, atomic steps, demonstrated
# impact, base-only vector, no invented facts and no boilerplate.
CLEAN_REPORT = """# Reflected XSS in /search via q

## Description
Reflected XSS in /search via the q parameter. The value is echoed into the HTML
response body without encoding.

## PoC
```
GET /search?q=<svg onload=alert(document.domain)> HTTP/1.1
Host: app.internal
Accept: text/html
```
The response body contains the payload unencoded and the alert fires in the page
origin.

## Exploitation
1. Send the request above as any authenticated user.
2. Observe alert(document.domain) firing in the response page.

## Impact
JS execution in the victim browser in the app.internal origin, demonstrated by
reading document.cookie in step 1. CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N
"""

SLOPPY_REPORT = """# Account takeover in the profile endpoint

## Introduction
Cross-Site Scripting (XSS) is a type of injection attack where an application
reflects user input.

## PoC
Send this request and you will get a session token:
curl https://shop.acme-corp.net/profile?user=<XSS>

## Impact
This could lead to full account takeover of every user. CVE-2024-99999 was used.

## Conclusion
It is important to note that this vulnerability highlights the need to always
validate all user input.

## Remediation
TBD
"""


class TestRules(unittest.TestCase):
    def test_discipline_rules_are_always_on_content(self):
        for phrase in ("Never invent facts", "Never write theoretical impact",
                       "zero prior context can replay", "Report the primitive",
                       "Stealth Mode forbid a technique"):
            self.assertIn(phrase, DISCIPLINE_RULES)

    def test_discipline_block_follows_the_env_switch(self):
        with mock.patch.dict(os.environ, {"REDAMON_REPORT_DISCIPLINE": "false"}):
            self.assertEqual(discipline_block(), "")
        with mock.patch.dict(os.environ, {"REDAMON_REPORT_DISCIPLINE": "true"}):
            self.assertEqual(discipline_block(), DISCIPLINE_RULES)

    def test_structure_lists_the_sections_in_order(self):
        block = build_structure_block()
        positions = [block.index(f"**{title}**") for title, _ in (
            ("Description", None), ("Discovery", None),
            ("Proof of Concept", None), ("Exploitation", None), ("Impact", None),
        )]
        self.assertEqual(positions, sorted(positions), "sections out of order")
        for omitted in ("Executive summary", "Conclusion", "Acknowledgements"):
            self.assertIn(omitted, block)

    def test_report_block_carries_the_class_gotchas(self):
        block = build_report_block("ssrf")
        self.assertIn("Required report structure", block)
        self.assertIn("Minimum proof", block)
        self.assertIn("inbound request", block)

    def test_report_block_is_empty_when_switched_off(self):
        with mock.patch.dict(os.environ,
                             {"REDAMON_REPORT_DISCIPLINE_REPORT_BLOCK": "false"}):
            self.assertEqual(build_report_block("ssrf"), "")

    def test_report_block_without_a_known_class_says_so(self):
        block = build_report_block("denial_of_service")
        self.assertIn("No class-specific reference applies", block)


class TestGotchas(unittest.TestCase):
    def test_every_class_has_all_three_parts(self):
        self.assertEqual(len(CLASSES), len(set(CLASSES)))
        for cls in CLASSES:
            entry = GOTCHAS[cls]
            for key in ("minimum_proof", "common_na", "overclaim_traps"):
                self.assertTrue(entry[key], f"{cls}.{key} is empty")

    def test_resolve_class_handles_names_paths_and_skill_ids(self):
        self.assertEqual(resolve_class("SSRF"), "SSRF")
        self.assertEqual(resolve_class("path_traversal"), "Path Traversal / LFI")
        self.assertEqual(resolve_class("idor_bola_exploitation"), "IDOR / BOLA")
        self.assertIsNone(resolve_class("definitely_not_a_class"))

    def test_attack_path_mapping(self):
        self.assertEqual(classes_for_attack_path("rce"), ("RCE", "SSTI"))
        self.assertEqual(classes_for_attack_path("access_control"),
                         ("IDOR / BOLA", "Auth Bypass"))
        # Techniques with no class-specific reference must not invent one.
        self.assertEqual(classes_for_attack_path("denial_of_service"), ())
        self.assertEqual(classes_for_attack_path(""), ())

    def test_community_skill_id_maps_through_the_user_skill_prefix(self):
        self.assertEqual(classes_for_attack_path("user_skill:ssti"),
                         ("SSTI",))

    def test_blocks_are_rendered_once_per_class(self):
        block = build_gotchas_block(["SSRF", "ssrf", "SQLi"])
        self.assertEqual(block.count("### SSRF"), 1)
        self.assertIn("### SQLi", block)
        self.assertEqual(build_gotchas_block(["nonsense"]), "")

    def test_detect_classes_reads_a_draft(self):
        text = "An IDOR lets account A read the invoice of account B over /api/invoices."
        self.assertIn("IDOR / BOLA", detect_classes(text))
        self.assertEqual(detect_classes(""), ())


class TestCvss(unittest.TestCase):
    def test_parses_with_and_without_the_prefix(self):
        for vector in ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
            parsed = parse_vector(vector)
            self.assertEqual(parsed["AV"], "N")
            self.assertEqual(base_score(parsed), 9.8)

    def test_known_scores(self):
        self.assertEqual(base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertEqual(base_score("AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"), 3.1)

    def test_incomplete_vector_is_unscored_rather_than_guessed(self):
        self.assertIsNone(base_score("AV:N/AC:L/PR:N/UI:N"))
        self.assertIsNone(parse_vector("no vector here"))

    def test_severity_bands(self):
        self.assertEqual(severity(9.8), "Critical")
        self.assertEqual(severity(7.0), "High")
        self.assertEqual(severity(4.0), "Medium")
        self.assertEqual(severity(0.1), "Low")
        self.assertEqual(severity(None), "unscored")

    def test_extended_metrics_are_flagged(self):
        parsed = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O")
        self.assertFalse(is_base_only(parsed))
        flags = metric_mismatch_flags(parsed)
        self.assertTrue(any(f.category == "cvss" and "E set" in f.quote for f in flags))

    def test_metric_claim_mismatches(self):
        vector = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        flags = metric_mismatch_flags(vector, auth_gate=True, victim_interaction=True,
                                      non_guessable_id=True, trust_boundary=False)
        joined = " ".join(f.quote for f in flags)
        self.assertIn("PR:N", joined)
        self.assertIn("UI:N", joined)
        self.assertIn("S:C", joined)
        self.assertIn("AC:L", joined)

    def test_a_defensible_vector_produces_no_mismatch(self):
        vector = "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
        self.assertEqual(
            metric_mismatch_flags(vector, auth_gate=True, victim_interaction=True),
            [],
        )


class TestSlop(unittest.TestCase):
    def _categories(self, text):
        return {flag.category for flag in scan_slop(text)}

    def test_theoretical_impact_is_critical(self):
        flags = scan_slop("This may lead to full compromise of the platform.")
        critical = [f for f in flags if f.severity == "critical"]
        self.assertTrue(any(f.category == "theoretical-impact" for f in critical))

    def test_negation_is_honoured(self):
        text = ("We could not achieve account takeover; that link of the chain is "
                "unverified.")
        self.assertNotIn("impact-not-demonstrated", self._categories(text))

    def test_a_claim_without_evidence_is_flagged(self):
        text = "The endpoint allows account takeover of any tenant."
        flags = [f for f in scan_slop(text) if f.category == "impact-not-demonstrated"]
        self.assertTrue(flags)
        self.assertEqual(flags[0].severity, "critical")

    def test_placeholder_payload_is_not_a_poc(self):
        self.assertIn("poc-placeholder",
                      self._categories("curl 'https://x.tld/s?q=<XSS>'"))
        self.assertIn("poc-placeholder",
                      self._categories("Send the request and you will get an admin cookie."))

    def test_boilerplate_and_structural_tics(self):
        cats = self._categories(SLOPPY_REPORT)
        self.assertIn("owasp-boilerplate", cats)
        self.assertIn("ai-structural-tics", cats)
        self.assertIn("empty-section", cats)
        self.assertIn("unverified-cve", cats)
        self.assertIn("theoretical-impact", cats)

    def test_prose_only_draft_has_no_poc(self):
        # A curl command in the draft counts as a reproduction; prose does not.
        self.assertIn("no-poc", self._categories("The endpoint is vulnerable to XSS."))
        self.assertNotIn("no-poc", self._categories(SLOPPY_REPORT))

    def test_flags_quote_a_single_line(self):
        for flag in scan_slop(SLOPPY_REPORT):
            self.assertNotIn("\n", flag.quote, f"{flag.category} quote spans lines")

    def test_clean_report_has_no_critical_flags(self):
        flags = scan_slop(CLEAN_REPORT)
        self.assertEqual([f for f in flags if f.severity == "critical"], [],
                         f"unexpected critical flags: {flags}")


class TestTriage(unittest.TestCase):
    def test_clean_draft_with_scope_is_ready(self):
        result = triage_draft(CLEAN_REPORT, scope="app.internal and *.internal "
                                                  "are in scope")
        self.assertEqual(result.critical, [])
        self.assertEqual(result.verdict, "READY TO SUBMIT", render_triage(result))
        self.assertTrue(result.whats_good)
        self.assertEqual(result.score, base_score(
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"))

    def test_missing_scope_is_a_major_not_an_assumption(self):
        result = triage_draft(CLEAN_REPORT)
        self.assertFalse(result.checked_scope)
        self.assertTrue(any(f.category == "scope-unknown" for f in result.major))
        self.assertNotIn("Critical (blocks submission)", render_triage(result))

    def test_out_of_scope_host_is_a_do_not_submit(self):
        result = triage_draft(SLOPPY_REPORT, scope="*.acme-corp.com is in scope")
        self.assertEqual(result.verdict, "DO NOT SUBMIT")
        self.assertTrue(any(f.category == "out-of-scope" for f in result.critical))

    def test_in_scope_host_passes_the_scope_pass(self):
        result = triage_draft(CLEAN_REPORT,
                              scope="https://app.internal/ is in scope")
        self.assertTrue(result.checked_scope)
        self.assertFalse(any(f.category.startswith("scope") for f in result.critical))

    def test_sloppy_draft_is_rejected_with_fixes(self):
        result = triage_draft(SLOPPY_REPORT)
        self.assertEqual(result.verdict, "DO NOT SUBMIT")
        rendered = render_triage(result)
        self.assertIn("VERDICT: DO NOT SUBMIT", rendered)
        self.assertIn("->", rendered)

    def test_render_caps_a_bucket_and_says_how_many_are_left(self):
        result = triage_draft(SLOPPY_REPORT)
        self.assertGreater(len(result.critical), 1)
        rendered = render_triage(result, max_per_bucket=1)
        self.assertIn("... and", rendered)

    def test_preconditions_without_a_vector_are_flagged(self):
        vectorless = CLEAN_REPORT.replace(
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", "")
        result = triage_draft(vectorless, scope="app.internal",
                              auth_gate=True, victim_interaction=True)
        self.assertTrue(any(f.quote == "preconditions stated without a CVSS vector"
                            for f in result.major),
                        [f.quote for f in result.major])

    def test_require_scope_false_drops_the_standing_scope_major(self):
        # The final-report self-check has no scope list to read, so it must not
        # report a scope failure on every report.
        result = triage_draft(CLEAN_REPORT, require_scope=False)
        self.assertFalse(any(f.category.startswith("scope") for f in result.major))
        self.assertIn("did not check scope compliance", " ".join(result.notes))

    def test_result_serialises(self):
        payload = triage_draft(CLEAN_REPORT).as_dict()
        self.assertIn("verdict", payload)
        self.assertIsInstance(payload["critical"], list)


if __name__ == "__main__":
    unittest.main()
