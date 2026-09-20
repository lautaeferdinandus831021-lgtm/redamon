"""Deterministic AI-slop detection for findings and reports.

Ported from claude-kit's `references/ai-slop.md`, minus the checks that need a
human's judgement. Everything here is a text rule over the draft: no LLM call,
no network, and a flag can always be traced back to the phrase that produced it,
which is what makes it safe to show the agent as *its own* output being reviewed.

Severities match the reference and map onto the triage buckets:
`critical` blocks submission, `strong` needs fixing, `minor` is cleanup.

One caveat the reference makes and this module keeps: a checker cannot tell an
honest "we did not achieve X" apart from a claim, so negation is honoured - a
claim inside a negated window is not flagged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_BUCKETS = {"critical": "Critical", "strong": "Major", "minor": "Minor"}


@dataclass(frozen=True)
class Flag:
    """One reviewable issue found in a draft."""

    severity: str  # critical | strong | minor
    category: str
    quote: str
    fix: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "quote": self.quote,
            "fix": self.fix,
        }

    def render(self) -> str:
        return f"[{self.severity.upper()}] {self.category}: {self.quote}\n  -> {self.fix}"


@dataclass
class _Rule:
    severity: str
    category: str
    pattern: re.Pattern
    fix: str
    skip_if_negated: bool = False
    quote_chars: int = field(default=120)


def _rule(severity, category, pattern, fix, *, skip_if_negated=False, flags=re.I):
    return _Rule(severity, category, re.compile(pattern, flags), fix, skip_if_negated)


# --- theoretical impact -----------------------------------------------------
_THEORETICAL = (
    r"could\s+(?:potentially\s+)?(?:lead to|result in|allow|enable|be\s+used)",
    r"may\s+(?:lead to|result in|allow|enable)",
    r"might\s+(?:lead to|result in|allow|enable)",
    r"is\s+possible\s+to",
    r"an\s+attacker\s+with\s+the\s+right\s+conditions",
    r"under\s+certain\s+conditions",
    r"potentially\s+(?:gain|access|compromise|exfiltrate)",
    r"theoretical(?:ly)?\s+(?:impact|exploit)",
)

# --- claim -> the evidence that makes the claim legitimate ------------------
_CLAIM_EVIDENCE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        r"account\s+takeover|\bato\b|take\s+over\s+(?:an?\s+)?account",
        "account takeover claimed",
        ("logged in as", "session", "cookie", "password", "email address"),
    ),
    (
        r"remote\s+code\s+execution|\brce\b|arbitrary\s+command\s+execution",
        "RCE claimed",
        ("whoami", "uid=", "id\n", "hostname", "command output", "callback",
         "oob", "shell", "executed"),
    ),
    (
        r"session\s+hijack|session\s+theft|hijack(?:ing)?\s+(?:the\s+)?session",
        "session hijack claimed",
        ("cookie", "set-cookie", "document.cookie", "bearer", "token"),
    ),
    (
        r"full\s+database|database\s+compromise|exfiltrat\w+\s+the\s+(?:entire|whole)",
        "database-wide impact claimed",
        ("sentinel", "table", "schema", "version", "rows", "dump"),
    ),
    (
        r"arbitrary\s+file\s+(?:read|disclosure)|file\s+disclosure",
        "arbitrary file read claimed",
        ("/etc/passwd", "root:x", "win.ini", "config", "content of", "returned"),
    ),
    (
        r"privilege\s+escalation|admin\s+access|become\s+an?\s+admin",
        "privilege escalation claimed",
        ("admin", "role", "permission", "token", "panel", "dashboard", "200"),
    ),
)

_NEGATION_WINDOW = re.compile(
    r"(?:not|no|never|cannot|can't|couldn't|unable|without|would\s+have|"
    r"unverified|theoretical|did\s+not|does\s+not|do\s+not|failed\s+to|"
    r"no\s+evidence|not\s+proven|unproven|rather\s+than)\b[^.]{0,60}$",
    re.I,
)

_RULES: tuple[_Rule, ...] = (
    _rule(
        "critical", "theoretical-impact",
        r"|".join(_THEORETICAL),
        "State what was demonstrated. If it was not demonstrated, delete the claim "
        "or move it to a clearly-labelled 'not yet proven' note.",
        skip_if_negated=True,
    ),
    _rule(
        "critical", "poc-placeholder",
        r"<(?:payload|script|xss|sqli|command|file|id|insert[- _]?payload)>|"
        r"\byou\s+will\s+get\b|"
        r"\bas\s+shown\s+(?:above|below)\b|"
        r"\bthe\s+attacker\s+(?:would|could|can)\b|"
        r"\betc\.\s*$|"
        r"\btrigger\s+the\s+vulnerability\b",
        "Replace the placeholder with the literal request/payload/response. A PoC a "
        "reader cannot replay is a description, not a PoC.",
    ),
    _rule(
        "critical", "empty-section",
        r"^\s*(?:[-*]\s*)?(?:tbd|todo|see\s+poc|to\s+be\s+(?:filled|written|added)|"
        r"\(?n/?a\)?)\s*$",
        "A placeholder section has no content: gather the evidence or delete the "
        "section. Empty is honest; a placeholder is not.",
        flags=re.I | re.M,
    ),
    _rule(
        "strong", "ai-structural-tics",
        r"^\s*#{1,4}\s*(?:introduction|background|executive\s+summary|conclusion|"
        r"recommendations|acknowledg\w+|about\s+the\s+researcher)\b|"
        r"\bin\s+conclusion\b|\bit\s+is\s+important\s+to\s+note\b|"
        r"\bthis\s+vulnerability\s+highlights\b|\bin\s+summary,?\s+this\s+report\b",
        "Collapse the scaffolding. A one-step bug needs Description, PoC, steps and "
        "impact - not Introduction/Background/Conclusion.",
        flags=re.I | re.M,
    ),
    _rule(
        "strong", "owasp-boilerplate",
        r"is\s+a\s+type\s+of\s+injection\s+attack|"
        r"occurs\s+when\s+an\s+application|"
        r"is\s+a\s+common\s+(?:vulnerability|security\s+issue|web\s+application)\b|"
        r"(?:always\s+)?validate\s+all\s+user\s+input|"
        r"use\s+parameteri[sz]ed\s+queries|"
        r"sanitize\s+all\s+user\s+input|"
        r"follow\s+owasp\s+guidelines|"
        r"implement\s+proper\s+input\s+validation",
        "Delete the pasted definition/mitigation, or replace it with the fix specific "
        "to this code path. One sentence of class context is the ceiling.",
        flags=re.I | re.M,
    ),
    _rule(
        "strong", "unverified-cve",
        r"\bCVE-\d{4}-\d{4,}\b",
        "Verify every CVE ID resolves and matches THIS bug. A wrong or invented CVE "
        "is the single fastest way to get a report closed.",
    ),
    _rule(
        "strong", "unfingerprinted-version",
        r"\b[a-z][\w.-]{2,}\s+\d+\.\d+(?:\.\d+)?\b",
        "If a library/version is claimed, show how it was fingerprinted (header, "
        "response, package file). Otherwise remove the version.",
        skip_if_negated=True,
    ),
    _rule(
        "minor", "unicode-in-payload",
        r"[’‘“”]|→|←",
        "Smart quotes and arrows break copy-paste: use plain ASCII inside payloads "
        "and requests.",
    ),
    _rule(
        "minor", "ai-self-reference",
        r"\bas\s+an\s+ai\s+(?:language\s+)?model\b|\bthe\s+ai\s+assistant\b|"
        r"\bas\s+a\s+language\s+model\b",
        "Remove the self-reference: the report is written by the researcher.",
    ),
)

_CODE_FENCE = re.compile(r"```.*?```", re.S)
_POC_MARKERS = re.compile(
    r"```|^\s*(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S|"
    r"\bcurl\s|http/1\.[01]\s|HTTP/2\b|\bContent-Type:",
    re.I | re.M,
)
_STEPS_MARKER = re.compile(r"^\s*\d+\.\s+\S", re.M)


def _is_negated(text: str, start: int) -> bool:
    """True when the match sits inside a negated window (an honest 'we did not')."""
    return bool(_NEGATION_WINDOW.search(text[max(0, start - 80):start]))


def _first_match(rule: _Rule, text: str) -> re.Match | None:
    for match in rule.pattern.finditer(text):
        if rule.skip_if_negated and _is_negated(text, match.start()):
            continue
        return match
    return None


def _claim_flags(text: str) -> list[Flag]:
    """Impact claims with no matching evidence anywhere in the draft."""
    lowered = text.lower()
    flags = []
    for pattern, label, markers in _CLAIM_EVIDENCE:
        match = re.search(pattern, lowered)
        if not match or _is_negated(text, match.start()):
            continue
        if any(marker in lowered for marker in markers):
            continue
        flags.append(Flag(
            "critical" if label.startswith(("RCE", "account")) else "strong",
            "impact-not-demonstrated",
            f"{label}: '{text[match.start():match.start() + 60].strip()}'",
            "The PoC does not show this: either demonstrate it and show the "
            "evidence, or state plainly that it is unverified.",
        ))
    return flags


def _poc_flags(text: str) -> list[Flag]:
    flags = []
    if not _POC_MARKERS.search(text):
        flags.append(Flag(
            "critical", "no-poc",
            "no raw request, response, curl command or fenced block found",
            "Add the replayable PoC: the literal request(s) and the response that "
            "proves the bug. Prose is not a PoC.",
        ))
    if _STEPS_MARKER.search(text) is None and "exploit" in text.lower():
        flags.append(Flag(
            "minor", "no-atomic-steps",
            "an exploitation section without numbered atomic steps",
            "Number the steps, one observable action each, with preconditions stated "
            "up front.",
        ))
    return flags


def _fenced_blocks(text: str) -> list[str]:
    return [m.group(0) for m in _CODE_FENCE.finditer(text)]


def _render_flags(text: str) -> list[Flag]:
    """Markdown that was never rendered, inside a code block."""
    flags = []
    for block in _fenced_blocks(text):
        if re.search(r"\*\*\w[^*]*\*\*", block):
            flags.append(Flag(
                "minor", "unrendered-markdown",
                block.strip().splitlines()[0][:60],
                "Literal ** in a code block is markdown that never rendered - strip it.",
            ))
            break
    return flags


def scan_slop(text: str) -> list[Flag]:
    """Every deterministic slop flag in `text`, worst-severity first.

    Ordering is stable for a given draft, so a caller can cap the list without
    the report's 'what I found' changing between runs.
    """
    if not text:
        return []
    body = str(text)
    flags: list[Flag] = []
    for rule in _RULES:
        match = _first_match(rule, body)
        if match is None:
            continue
        # Quote the line the match is on, not the next `quote_chars` of text: a
        # flag has to be readable by the person who has to fix it.
        excerpt = body[match.start():match.start() + rule.quote_chars].splitlines()[0].strip()
        flags.append(Flag(rule.severity, rule.category, excerpt, rule.fix))
    flags += _claim_flags(body)
    flags += _poc_flags(body)
    flags += _render_flags(body)

    order = {"critical": 0, "strong": 1, "minor": 2}
    flags.sort(key=lambda f: order.get(f.severity, 3))
    return flags


__all__ = ["Flag", "SEVERITY_BUCKETS", "scan_slop"]
