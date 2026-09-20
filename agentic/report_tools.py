"""The agent's report-review tool: `report_review`.

Built like `memory_tools.py` / `supply_chain_tools.py`: a plain in-process
coroutine wrapped with the LangChain `tool()` decorator and handed to
`PhaseAwareToolExecutor` at construction. Not an MCP tool - reviewing a draft
must not ride the target-facing Kali worker, and it sends no traffic at all.

Two properties it keeps:

* **Never raise.** A review sits between the agent and finishing its report; a
  failure returns a readable error string, never an exception that aborts a turn.
* **Point, do not rewrite.** Every answer names what is wrong and what would fix
  it. The agent stays the author - the same contract the reference keeps, and the
  reason triage here cannot silently "fix" an unverified claim into a plausible
  one.
"""
from __future__ import annotations

import logging

from langchain_core.tools import tool

from report_kit import cvss as cvss_mod
from report_kit.gotchas import CLASSES, build_gotchas_block, resolve_class
from report_kit.rules import build_structure_block
from report_kit.triage import gotchas_for, render_triage, triage_draft

logger = logging.getLogger(__name__)

REPORT_TOOL_NAMES = frozenset({"report_review"})


async def _review_impl(
    mode: str = "triage",
    draft: str = "",
    vulnerability_class: str = "",
    scope: str = "",
    cvss_vector: str = "",
    auth_gate: bool = False,
    victim_interaction: bool = False,
    trust_boundary: bool = False,
    non_guessable_id: bool = False,
) -> str:
    """Review a finding or report draft against the evidence bar before it ships.

    Run `mode="triage"` on your write-up BEFORE you complete the session, and
    `mode="gotchas"` before claiming a vulnerability class. The review is
    deterministic: it reads the draft you pass in and never awards credit for
    evidence that is not there.

    Args:
        mode: "triage" (full pre-submission pass with a verdict), "gotchas"
              (minimum proof / common auto-close / overclaim traps for a class),
              "structure" (the required report sections and per-section rules),
              "cvss" (score a base vector and check the metrics against what you
              verified).
        draft: The finding or report text to review (markdown or plain text).
               Required for triage and gotchas.
        vulnerability_class: The claimed class (e.g. "SSRF", "IDOR"), or a
               technique id (e.g. "path_traversal"). Optional - the draft's own
               wording is used when omitted.
        scope: The program's scope page / rules of engagement, if you have it.
               Without it the scope pass cannot run, and triage says so instead of
               assuming the asset is in scope.
        cvss_vector: A CVSS 3.1 base vector (e.g.
               "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"). Optional - a
               vector already in the draft is used when omitted.
        auth_gate: True if reaching the vulnerable feature required privileges
               that are not self-serve (paid tier, invite, org membership).
        victim_interaction: True if the victim must click, paste, load or open
               something for the exploit to work.
        trust_boundary: True only if the exploit crosses a security authority
               boundary (container/VM escape), which is what S:C means.
        non_guessable_id: True if the resource identifier is a random UUIDv4 or
               another value an attacker cannot enumerate.

    Returns:
        The verdict with concrete fixes (triage), the class reference, the report
        structure, or the scored vector - always with what to fix, never applied
        to your draft for you.
    """
    try:
        requested = (mode or "triage").strip().lower()

        if requested == "structure":
            return build_structure_block()

        if requested == "gotchas":
            if not draft and not vulnerability_class:
                return (
                    "Give me the draft or name the class (e.g. vulnerability_class="
                    "\"SSRF\"). Known classes: " + ", ".join(CLASSES) + "."
                )
            block = gotchas_for(draft, vulnerability_class)
            if not block:
                return (
                    "No class-specific reference matches that claim, so hold it to "
                    "the general evidence bar: a replayable PoC, impact only as "
                    "demonstrated, CVSS base metrics only. Known classes: "
                    + ", ".join(CLASSES) + "."
                )
            return block

        if requested == "cvss":
            parsed = cvss_mod.parse_vector(cvss_vector) or cvss_mod.parse_vector(draft)
            if not parsed:
                return (
                    "No CVSS vector found. Pass cvss_vector=\"CVSS:3.1/AV:N/AC:L/"
                    "PR:N/UI:N/S:U/C:H/I:H/A:H\" (or a draft containing one)."
                )
            score = cvss_mod.base_score(parsed)
            lines = [
                f"Vector: {cvss_mod.format_vector(parsed)}",
                f"CVSS 3.1 base score: {score} ({cvss_mod.severity(score)})"
                if score is not None
                else "CVSS 3.1 base score: incomplete - the base metrics AV/AC/PR/"
                     "UI/S/C/I/A must all be set, and an unscored vector is honest "
                     "where a guessed one is not.",
            ]
            flags = cvss_mod.metric_mismatch_flags(
                parsed,
                auth_gate=auth_gate,
                victim_interaction=victim_interaction,
                trust_boundary=trust_boundary,
                non_guessable_id=non_guessable_id,
            )
            if flags:
                lines.append("")
                lines.append("Metric checks:")
                lines += [f"- {f.category}: {f.quote} -> {f.fix}" for f in flags]
            else:
                lines.append("")
                lines.append(
                    "No metric/precondition mismatch found for the facts given."
                )
            return "\n".join(lines)

        if requested != "triage":
            return (
                f"Unknown mode {mode!r}. Use triage, gotchas, structure or cvss."
            )

        if not draft or not draft.strip():
            return (
                "Nothing to triage: pass the report draft in `draft`. A verdict "
                "without a draft would be fiction, which is the failure this tool "
                "exists to prevent."
            )

        result = triage_draft(
            draft,
            scope=scope or None,
            vulnerability_class=vulnerability_class,
            vector=cvss_vector,
            auth_gate=auth_gate,
            victim_interaction=victim_interaction,
            trust_boundary=trust_boundary,
            non_guessable_id=non_guessable_id,
        )
        resolved = resolve_class(vulnerability_class) if vulnerability_class else None
        if resolved and build_gotchas_block([resolved]):
            block = build_gotchas_block([resolved])
            return render_triage(result) + (
                "\n\n---\n\nCheck the evidence against the minimum proof for the "
                "class you claimed:\n\n" + block
            )
        return render_triage(result)
    except Exception as e:  # noqa: BLE001 - a review must never break the turn
        logger.warning(f"report_review failed (mode={mode}): {e}")
        return f"Error: report review could not run ({e})."


# LangChain-wrapped tool the executor registers. The impl stays separate and named
# so tests can exercise the real coroutine even when a sibling test has stubbed
# langchain_core.tools.tool into a MagicMock (focused-suite isolation).
report_review = tool("report_review")(_review_impl)


def build_report_tools() -> dict:
    """The agent's report tools, keyed by name (non-MCP, registered like fs_*)."""
    return {"report_review": report_review}


__all__ = ["REPORT_TOOL_NAMES", "build_report_tools"]
