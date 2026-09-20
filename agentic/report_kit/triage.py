"""Pre-submission triage of a finding or report.

Ported from claude-kit's `triage` skill: scope, then slop, then PoC quality, then
the class gotchas - and a verdict of READY TO SUBMIT / NEEDS FIXES / DO NOT
SUBMIT with concrete fixes. The difference is that this is a deterministic
pass, so the agent can run it on its own draft before the user ever reads it.

It never rewrites the draft. It points at what is wrong and what would fix it;
the fixes are the writer's to make.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from report_kit import cvss as cvss_mod
from report_kit.gotchas import build_gotchas_block, detect_classes, resolve_class
from report_kit.slop import Flag, scan_slop

VERDICT_READY = "READY TO SUBMIT"
VERDICT_FIXES = "NEEDS FIXES"
VERDICT_REJECT = "DO NOT SUBMIT"

# Hosts that appear in examples/boilerplate and must not be treated as findings
# about the target's scope.
_DOC_HOSTS = frozenset({
    "example.com", "example.org", "example.net", "localhost", "test.com",
    "target.com", "owasp.org", "w3.org", "schema.org", "mitre.org",
    "github.com", "portswigger.net", "youtube.com", "google.com",
    "python.org", "mozilla.org", "wikipedia.org",
})

# A hostname-ish token whose last label is not a TLD but a JS API, file
# extension or file name (`document.domain`, `document.cookie`, `config.json`).
# The host regex cannot tell those apart from a real host, and a false
# "out of scope" on a PoC is worse than no scope check at all.
_NON_TLD_SUFFIXES = frozenset({
    "domain", "cookie", "cookies", "location", "origin", "href", "host",
    "hostname", "json", "html", "htm", "css", "js", "mjs", "ts", "tsx",
    "txt", "md", "xml", "yml", "yaml", "php", "asp", "aspx", "jsp",
    "py", "rb", "sh", "go", "java", "exe", "dll", "so", "zip", "tar",
    "gz", "png", "jpg", "jpeg", "gif", "svg", "pdf", "log", "conf",
    "config", "env", "bak", "sql", "csv",
})

_HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
_URL_RE = re.compile(r"https?://[^\s)\]\"'>]+", re.I)

_SCOPE_MAX_HOSTS = 5


@dataclass
class TriageResult:
    """One triage pass over one draft."""

    verdict: str
    critical: list[Flag] = field(default_factory=list)
    major: list[Flag] = field(default_factory=list)
    minor: list[Flag] = field(default_factory=list)
    whats_good: list[str] = field(default_factory=list)
    classes: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)
    score: float | None = None
    checked_scope: bool = False

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "critical": [f.as_dict() for f in self.critical],
            "major": [f.as_dict() for f in self.major],
            "minor": [f.as_dict() for f in self.minor],
            "whats_good": list(self.whats_good),
            "classes": list(self.classes),
            "notes": list(self.notes),
            "cvss_base_score": self.score,
            "scope_provided": self.checked_scope,
        }


def _hosts_in(text: str) -> list[str]:
    """Hostnames the draft talks about, minus docs examples and code identifiers."""
    hosts: list[str] = []
    for match in _HOST_RE.finditer(text):
        host = match.group(1).lower()
        if host in _DOC_HOSTS:
            continue
        if any(host.endswith("." + doc) for doc in _DOC_HOSTS):
            continue
        if host.rsplit(".", 1)[-1] in _NON_TLD_SUFFIXES:
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts


def _scope_flags(draft: str, scope: str | None,
                 require_scope: bool = True) -> tuple[list[Flag], list[Flag], bool]:
    """(critical, major, scope_was_checked) for the scope pass.

    `require_scope=False` is for a caller that is reviewing something whose
    scope was already enforced elsewhere (the final-report self-check: the RoE
    and scope-guardrail machinery gated the engagement itself), where a
    standing "scope unknown" flag would be noise on every single report.
    """
    if not scope or not str(scope).strip():
        missing = [Flag(
            "strong", "scope-unknown",
            "no program scope / rules of engagement supplied",
            "Confirm the asset is in the in-scope list (or matches a wildcard) "
            "and the class is not excluded before submitting. Ask for the scope "
            "rather than inferring it from the domain name.",
        )] if require_scope else []
        return [], missing, False

    scope_text = str(scope).lower()
    hosts = _hosts_in(draft)
    if not hosts:
        return [], [], True
    if len(hosts) > _SCOPE_MAX_HOSTS:
        return (
            [],
            [Flag(
                "strong", "scope-many-hosts",
                f"{len(hosts)} distinct hosts in one draft",
                "Verify EACH host against the scope list (and each wildcard) before "
                "submitting; a sister/acquired domain that merely looks related is "
                "out of scope.",
            )],
            True,
        )

    outside = [host for host in hosts if host not in scope_text]
    if not outside:
        return [], [], True
    return (
        [Flag(
            "critical", "out-of-scope",
            "host(s) not found in the supplied scope: " + ", ".join(outside),
            "Either drop these assets or get explicit pre-approval and state it in "
            "the report. Out-of-scope submission is a DO NOT SUBMIT.",
        )],
        [],
        True,
    )


def _cvss_pass(draft: str, vector: str, **claims) -> tuple[list[Flag], float | None]:
    """(metric mismatch flags, base score) for the vector in play, if any."""
    parsed = cvss_mod.parse_vector(vector) or cvss_mod.parse_vector(draft)
    if not parsed:
        return [], None
    return cvss_mod.metric_mismatch_flags(parsed, **claims), cvss_mod.base_score(parsed)


def _positives(draft: str, parsed: dict | None, flags: list[Flag]) -> list[str]:
    good: list[str] = []
    if re.search(r"```", draft) or re.search(r"^\s*(?:GET|POST|PUT|PATCH|DELETE)\s+\S", draft, re.M | re.I):
        good.append("a replayable request/PoC is present in the draft")
    if re.search(r"^\s*\d+\.\s+\S", draft, re.M):
        good.append("exploitation steps are numbered and atomic")
    if re.search(r"^\s*#+\s*impact\b", draft, re.M | re.I):
        good.append("an explicit Impact section is present")
    if parsed and cvss_mod.is_base_only(parsed):
        good.append("the CVSS vector uses base metrics only")
    if not [f for f in flags if f.category in {"theoretical-impact", "owasp-boilerplate"}]:
        good.append("no theoretical-impact or boilerplate phrasing detected")
    return good


def triage_draft(
    draft: str,
    *,
    scope: str | None = None,
    vulnerability_class: str = "",
    vector: str = "",
    auth_gate: bool = False,
    victim_interaction: bool = False,
    trust_boundary: bool = False,
    non_guessable_id: bool = False,
    max_per_bucket: int = 12,
    require_scope: bool = True,
) -> TriageResult:
    """Run the triage pass. Deterministic; never raises on odd input.

    `scope` is the program's scope page / RoE text. Without it the scope pass
    cannot run, which is reported as a Major (fixable by supplying it) rather
    than assumed to pass - the same rule as the reference: ask, do not infer.

    `require_scope=False` drops that Major for a caller that cannot have the
    scope text and is not the one deciding scope (the final-report self-check);
    the result then says the scope pass did not run instead of implying it
    passed.
    """
    body = str(draft or "")

    classes: list[str] = []
    resolved = resolve_class(vulnerability_class) if vulnerability_class else None
    if resolved:
        classes.append(resolved)
    for cls in detect_classes(body):
        if cls not in classes:
            classes.append(cls)

    critical, major, minor = [], [], []
    scope_critical, scope_major, scope_checked = _scope_flags(body, scope, require_scope)
    critical += scope_critical
    major += scope_major

    for flag in scan_slop(body):
        (critical if flag.severity == "critical"
         else major if flag.severity == "strong"
         else minor).append(flag)

    cvss_flags, score = _cvss_pass(
        body, vector,
        auth_gate=auth_gate,
        victim_interaction=victim_interaction,
        trust_boundary=trust_boundary,
        non_guessable_id=non_guessable_id,
    )
    if cvss_flags:
        major += cvss_flags
    elif score is None and (auth_gate or victim_interaction or trust_boundary or non_guessable_id):
        major.append(Flag(
            "strong", "cvss", "preconditions stated without a CVSS vector",
            "Score CVSS 3.1 with base metrics only, justifying each metric from "
            "what was verified.",
        ))

    notes = []
    if classes:
        notes.append(
            "Class gotchas checked against: " + ", ".join(classes)
            + " - read the minimum proof for each (report_review mode=\"gotchas\")."
        )
    if not scope_checked:
        notes.append(
            "Scope was not supplied, so scope compliance is UNVERIFIED. Supply the "
            "scope page to check it." if require_scope else
            "This pass did not check scope compliance (it cannot see the program's "
            "scope list); the engagement's Rules of Engagement and target guardrail "
            "are what gate that."
        )
    if not vector and score is None:
        notes.append("No CVSS vector found in the draft.")

    deduped = _dedupe(critical)
    major = [f for f in _dedupe(major) if f not in deduped]
    minor = [f for f in _dedupe(minor) if f not in deduped and f not in major]

    verdict = VERDICT_REJECT if critical else (VERDICT_FIXES if major else VERDICT_READY)
    return TriageResult(
        verdict=verdict,
        critical=critical[:max_per_bucket],
        major=major[:max_per_bucket],
        minor=minor[:max_per_bucket],
        whats_good=_positives(body, cvss_mod.parse_vector(vector) or cvss_mod.parse_vector(body), critical + major),
        classes=tuple(classes),
        notes=notes,
        score=score,
        checked_scope=scope_checked,
    )


def _dedupe(flags: list[Flag]) -> list[Flag]:
    seen, out = set(), []
    for flag in flags:
        key = (flag.severity, flag.category, flag.quote)
        if key in seen:
            continue
        seen.add(key)
        out.append(flag)
    return out


def render_triage(result: TriageResult, *, max_per_bucket: int = 8) -> str:
    """Render a triage result in the reference's output format."""
    lines = [f"VERDICT: {result.verdict}", ""]
    if result.score is not None:
        lines += [
            f"CVSS 3.1 base score: {result.score} ({cvss_mod.severity(result.score)})",
            "",
        ]

    for bucket, title in (
        (result.critical, "Critical (blocks submission)"),
        (result.major, "Major (needs fixing)"),
        (result.minor, "Minor (cleanup)"),
    ):
        if not bucket:
            continue
        lines.append(f"## {title}")
        for flag in bucket[:max_per_bucket]:
            lines.append(f"- {flag.category}: {flag.quote} -> {flag.fix}")
        if len(bucket) > max_per_bucket:
            lines.append(f"- ... and {len(bucket) - max_per_bucket} more")
        lines.append("")

    lines.append("## What's good")
    for item in result.whats_good or ["nothing to keep yet"]:
        lines.append(f"- {item}")

    if result.notes:
        lines += ["", "## Notes"]
        lines += [f"- {note}" for note in result.notes]
    return "\n".join(lines).rstrip()


def gotchas_for(draft: str, vulnerability_class: str = "") -> str:
    """The gotchas block for a class claim (or the classes the draft claims)."""
    classes = []
    resolved = resolve_class(vulnerability_class) if vulnerability_class else None
    if resolved:
        classes.append(resolved)
    classes += [c for c in detect_classes(draft or "") if c not in classes]
    return build_gotchas_block(classes)


__all__ = [
    "TriageResult",
    "VERDICT_FIXES",
    "VERDICT_READY",
    "VERDICT_REJECT",
    "gotchas_for",
    "render_triage",
    "triage_draft",
]
