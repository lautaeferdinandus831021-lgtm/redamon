"""The always-on evidence/report discipline, and the report structure.

Ported from YesWeHack's `always-on-rules.md` + `write` skill (claude-kit),
retargeted at a WhiteHat engagement: findings live in the graph, the PoC is
whatever the agent actually ran, and the audience is whoever reads the report
afterwards.

`DISCIPLINE_RULES` is injected into EVERY think prompt (see
`orchestrator_helpers/nodes/think_node.py`); `build_structure_block()` is
appended to the final-report prompt (see `generate_response_node.py`). Both are
LLM-facing content, so they are sized for the model rather than for this file.
"""
from __future__ import annotations

DISCIPLINE_RULES = """
# EVIDENCE DISCIPLINE — APPLIES TO EVERY STEP

These rules bind what you claim, in the report and in every `thought` leading to
it. A finding a reader cannot replay from your own evidence is not a finding.

## Core principles

- **Never invent facts about a target.** Endpoints, parameters, versions,
  headers, response bodies, CVE IDs, function names: if you did not observe it,
  say so. A plausible-sounding detail you did not gather is worse than a gap,
  because the reader cannot tell it apart from a real one.
- **Never write theoretical impact.** "Could lead to", "may allow", "an attacker
  with the right conditions" — do not write these. State what the PoC
  demonstrated ("I executed X, observed Y at Z"); if you only proved reflection,
  do not claim execution.
- **A PoC is valid only if a reader with zero prior context can replay it from
  scratch.** Raw request/response beats prose, and beats a script: for a bug
  provable in one or two requests, show the requests.
- **Evidence is the only source of severity.** Do not rate a class you have not
  proven, and do not pad a score with metrics you did not verify. If you cannot
  justify a metric from observation, leave the vector unscored rather than
  defaulting to the maximum.
- **Report the primitive, do not exercise it.** Confirming a primitive (a
  controlled file read, one injected sentinel row, one command output) is proof.
  Dumping a database, pivoting, escalating privileges, reading other users' data,
  or running destructive commands goes past proof into damage and, on most
  programs, into a rules violation.
- **No boilerplate at scale.** No multi-paragraph OWASP/PortSwigger intros, no
  generic mitigations ("validate user input"), no Introduction / Background /
  Conclusion scaffolding around a one-step bug. One sentence of class context is
  enough; a pasted definition is slop.
- **Negative results are results.** "Tested and not vulnerable, and here is
  what would have proven it" is a useful, honest sentence. Silence that implies
  coverage you did not have is not.

## When you are investigating

- Ask what you OBSERVED, not what might happen. Build impact bottom-up from
  evidence: this request, this response, this side effect.
- Suspicious but unexploited behaviour is **not yet a finding**. Say what would
  prove it and, if the engagement allows, test that.
- Before escalating to a class, pull the minimum proof for it (the `gotchas`
  reference) and check the evidence against it. A primitive that fails the
  minimum proof is a lead, not a finding.

## When you are recording findings

- Record what the tool output shows, at the evidence level: exact request, exact
  response, exact effect. Do not paraphrase a payload into prose.
- Separate the parts of a chain. If link 2 of 3 was not demonstrated, say which
  link is unproven instead of presenting the chain as achieved.
- Redact the target's secrets and third-party PII in your write-ups; keep your
  own evidence intact.

## Scope and methodology (non-negotiable)

- Confirm the asset (domain, IP, app) is inside the project's configured scope
  and that the class is not excluded before you invest in it.
- Push back on DoS / load testing, credential bruteforce against real users,
  downloading more PII than the minimum needed to prove the bug, mass account
  creation, social engineering of employees, and touching out-of-scope assets to
  chain inward. Those close reports regardless of finding quality — and where the
  engagement's Rules of Engagement or Stealth Mode forbid a technique, that
  prohibition wins.
"""


# Ordered body sections of a report. Platform-level fields (title, asset,
# severity, CVSS) are metadata, not body sections - see PLATFORM_FIELDS.
REPORT_SECTIONS: tuple[tuple[str, str], ...] = (
    (
        "Description",
        "1-3 sentences: what the bug is, factual and specific. No class "
        "definition, no CWE tag in the body (it is metadata).",
    ),
    (
        "Discovery",
        "The testing narrative: what you tried, what you noticed, what made you "
        "dig in. Keep the dead ends — they are credibility.",
    ),
    (
        "Proof of Concept",
        "The raw request(s)/response(s) that reproduce it. Complete: headers, "
        "cookies, body, the literal payload. Include only what is needed to "
        "reproduce. Redact target secrets and third-party PII as [REDACTED]; "
        "never fabricate a value.",
    ),
    (
        "Exploitation",
        "Numbered, atomic steps - one observable action each, no inference "
        "required. State preconditions first (anonymous vs authenticated, role, "
        "browser, required victim interaction) and show expected vs actual where "
        "the bug manifests.",
    ),
    (
        "Impact",
        "Only what was demonstrated. Bottom-up from the PoC. No 'could', 'may', "
        "'potentially', 'with the right conditions'. Never longer than the PoC.",
    ),
    (
        "Remediation",
        "Optional. Include only when you know the target's stack and the fix is "
        "specific to this code path (or is trivially correct). Generic "
        "mitigations add nothing - omit instead of padding.",
    ),
    (
        "References",
        "Optional, usually omit. Add only for a specific vendor advisory or the "
        "precise write-up a chain relies on - one line each, no commentary.",
    ),
)

# Sections that must NOT appear: they read as padding and hide the finding.
OMIT_SECTIONS: tuple[str, ...] = (
    "Introduction / Background (collapse into Description)",
    "Executive summary (Description covers it)",
    "Multi-paragraph CWE/OWASP explanations (the metadata field carries the CWE)",
    "Conclusion (the report ends at the last real section)",
    "Acknowledgements / About the researcher",
    "Generic mitigation paragraphs",
)

PLATFORM_FIELDS = (
    "- **Title**: `<class> in <location> via <param/header>`, under 100 chars, "
    "no marketing words. Good: `Reflected XSS in /search via q parameter`. "
    "Bad: `Critical vulnerability in the user search feature`.\n"
    "- **Affected asset**: the exact URL/host/component that was tested, "
    "correctly scoped. Verify it against the configured target, not a lookalike.\n"
    "- **Severity / CVSS**: CVSS 3.1 with **Base metrics only**. Give the full "
    "Base vector and justify every metric from what was verified. Leave Temporal "
    "and Environmental metrics out — that context is the reader's to weigh, and "
    "setting it yourself inflates the score.\n"
    "- **Replayability**: before submitting, re-read the PoC as a stranger. If a "
    "step needs context you only have in your head, the PoC is not finished."
)


def build_structure_block() -> str:
    """The report-body structure, per-section format rules, and omitted sections."""
    lines = [
        "## Required report structure",
        "",
        "Sections in this order. If a required section has no content yet, say "
        "what evidence is missing instead of writing around the gap.",
        "",
    ]
    for i, (title, rule) in enumerate(REPORT_SECTIONS, 1):
        lines.append(f"{i}. **{title}** — {rule}")
    lines += [
        "",
        "Omit entirely: " + "; ".join(OMIT_SECTIONS) + ".",
        "",
        "## Metadata fields",
        "",
        PLATFORM_FIELDS,
    ]
    return "\n".join(lines)


__all__ = [
    "DISCIPLINE_RULES",
    "OMIT_SECTIONS",
    "PLATFORM_FIELDS",
    "REPORT_SECTIONS",
    "build_structure_block",
]
