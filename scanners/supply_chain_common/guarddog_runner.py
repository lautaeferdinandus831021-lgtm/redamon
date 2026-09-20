"""GuardDog runner + parser (behavioural analysis).

Verified against GuardDog v3.0.1 (2026-08-06):
  - Scan one package:   guarddog <eco> scan <name> [--version X] --output-format json
  - Scan a tarball/dir: guarddog <eco> scan <path> --output-format json
  - Verify a lockfile:  guarddog <eco> verify <path> --output-format json
  - Ecosystems: npm, pypi, go, crates, rubygems, github_action, extension.

Output shapes:
  scan   -> a single object {package, path, issues, errors, results}
  verify -> a LIST of {dependency, version, result:{issues, errors, results, path}}
  results[rule] is a STRING (or null) for metadata rules and a LIST of finding
  objects for source-code rules; both shapes are handled.

GuardDog downloads attacker-authored tarballs, so this runner is only ever
invoked INSIDE the dirty sandbox (Phase 0.5), never inline in a secret-holding
container. A GuardDog finding is ALWAYS `suspicious` confidence, never
`malicious` (only an OSV MAL- hit is malicious).
"""

import json

from ._run import run_argv
from .security import sanitize_name, sanitize_version

__all__ = ["scan_package", "verify_lockfile", "parse_guarddog",
           "severity_for_rule", "hardened_docker_argv", "GUARDDOG_ECOSYSTEMS",
           "ANALYZER_IMAGE"]

GUARDDOG_ECOSYSTEMS = {"npm", "pypi", "go", "crates", "rubygems",
                       "github_action", "extension"}

ANALYZER_IMAGE = "whitehat-supply-chain-analyzer:latest"

# GuardDog 3.x tries to build its OWN kernel-level sandbox (user namespaces +
# seccomp) around the extraction step, auto-detecting availability. Inside a
# container it cannot set that up, and the failure is SILENT in the worst way:
# the run still exits 0 with `issues: 0` and the real cause buried in
# `errors["download-package"]` - a false clean on the one tool whose job is to
# triage a suspicious package. Verified on GuardDog 3.0.1 (2026-08-07): it fails
# identically with and without --cap-drop ALL / --read-only, so it is the
# container context itself, not our hardening.
#
# We pass --no-sandbox and rely on the ANALYZER CONTAINER as the sandbox
# instead: cap_drop=ALL, read-only rootfs, non-root uid 1001, pids/memory caps,
# no secrets, restricted network. That container boundary is strictly stronger
# than GuardDog's in-process one, and it is the entire reason the dirty analyzer
# exists. NEVER run guarddog outside that image just because this flag is set.
_NO_SANDBOX = "--no-sandbox"

# Rule -> severity. GuardDog emits no severity of its own; this is our
# convention (plan section 2.2). Matched by substring so ecosystem-prefixed
# variants (npm-*, pypi-*) map without enumerating every one.
_HIGH_MARKERS = (
    "install-script", "exec-base64", "exfiltrate-sensitive-data",
    "serialize-environment", "silent-process-execution", "dll-hijacking",
    "steganography", "code-execution", "download-executable",
)
_MEDIUM_MARKERS = (
    "typosquatting", "unclaimed_maintainer_email_domain",
    "potentially_compromised_email_domain", "metadata_mismatch",
    "shady-links", "obfuscation",
)


def severity_for_rule(rule):
    r = (rule or "").lower()
    if any(m in r for m in _HIGH_MARKERS):
        return "high"
    if any(m in r for m in _MEDIUM_MARKERS):
        return "medium"
    return "low"


def hardened_docker_argv(image=None, *, memory="1500m", pids=512,
                         tmpfs_size="1g"):
    """argv prefix that runs guarddog INSIDE the dirty analyzer container.

    For callers that are NOT already inside the analyzer (the L2 recon module
    spawns it through the broker socket). The flags mirror the container the
    orchestrator would have created: no capabilities, read-only rootfs, an
    exec-able tmpfs for the extraction, and hard pid/memory ceilings.

    Registry egress is required (guarddog downloads the tarball), so this
    deliberately does NOT use --network none.
    """
    return [
        "docker", "run", "--rm",
        "--cap-drop", "ALL",
        "--read-only",
        "--tmpfs", "/tmp:size={},exec".format(tmpfs_size),
        "--pids-limit", str(pids),
        "--memory", memory,
        "--entrypoint", "guarddog",
        image or ANALYZER_IMAGE,
    ]


def scan_package(ecosystem, name, version=None, *, timeout=120,
                 binary="guarddog", argv_prefix=None):
    """Statically analyse one named package. Returns {raw, findings, error}.

    `argv_prefix` replaces the bare binary with a full launcher (see
    hardened_docker_argv) so a caller outside the analyzer image can dispatch
    into it without duplicating the sanitization/parsing done here.
    """
    if ecosystem not in GUARDDOG_ECOSYSTEMS:
        return {"raw": None, "findings": [],
                "error": "unsupported ecosystem: {}".format(ecosystem)}
    sanitize_name(name)
    sanitize_version(version)

    argv = list(argv_prefix) if argv_prefix else [binary]
    argv += [ecosystem, "scan", name]
    if version:
        argv += ["--version", version]
    # --no-sandbox: see the _NO_SANDBOX comment above. Without it every scan
    # returns a false clean.
    argv += [_NO_SANDBOX, "--output-format", "json"]

    res = run_argv(argv, timeout=timeout)
    return _finalize(res, name)


def verify_lockfile(ecosystem, path, *, timeout=600, binary="guarddog",
                    argv_prefix=None):
    """Scan every dependency in a lockfile. Returns {raw, findings, error}.

    NOTE: `verify` takes NO --no-sandbox option (verified against GuardDog
    3.0.1: `guarddog npm verify --help` lists only --exit-non-zero-on-finding,
    --output-format, -x/--exclude-rules, -r/--rules). Passing it makes click
    exit 2 with "No such option", which reads as a tool failure on every call.
    Only `scan` accepts it.
    """
    if ecosystem not in GUARDDOG_ECOSYSTEMS:
        return {"raw": None, "findings": [],
                "error": "unsupported ecosystem: {}".format(ecosystem)}
    argv = list(argv_prefix) if argv_prefix else [binary]
    argv += [ecosystem, "verify", str(path), "--output-format", "json"]
    res = run_argv(argv, timeout=timeout)
    return _finalize(res, None)


def _finalize(res, package_hint):
    """Normalize a run into {raw, findings, error}.

    CRITICAL: a run that produced NO parseable JSON is an ERROR, even when
    run_argv itself succeeded. run_argv only reports spawn failures and
    timeouts - it deliberately does not treat a non-zero exit as an error,
    because tools signal "findings present" that way. GuardDog, though, prints
    its JSON to stdout and nothing else; empty stdout means it never produced a
    verdict.

    Without this, a docker CLI that runs but fails (unreachable DOCKER_HOST,
    image missing, broker denial, click usage error -> exit 2/125/127, empty
    stdout) returned error=None and findings=[], which every caller reads as
    "analysed, nothing found" - a FALSE CLEAN on the tool whose entire job is
    triaging a suspicious package.
    """
    raw = None
    error = res["error"]
    stdout = res.get("stdout") or ""
    if stdout.strip():
        try:
            raw = json.loads(stdout)
        except (ValueError, TypeError):
            if error is None:
                error = "guarddog produced non-JSON output: {}".format(
                    stdout.strip()[:300])
    if raw is None and error is None:
        exit_code = res.get("exit_code")
        stderr = (res.get("stderr") or "").strip()
        error = "guarddog produced no output (exit {}){}".format(
            exit_code, ": " + stderr[:300] if stderr else "")
    return {"raw": raw, "findings": parse_guarddog(raw), "error": error}


def parse_guarddog(raw):
    """Normalize scan-object OR verify-list output into a flat finding list.

    Each finding: {package, version, rule, severity, confidence, message,
    soft_error}. A download failure (`errors` non-empty, issues 0) yields a
    soft_error finding, never silently a clean result.
    """
    findings = []
    if raw is None:
        return findings

    if isinstance(raw, list):
        # verify output
        for item in raw:
            if not isinstance(item, dict):
                continue
            dep = item.get("dependency")
            ver = item.get("version")
            result = item.get("result") or {}
            findings.extend(_parse_one_result(result, dep, ver))
    elif isinstance(raw, dict):
        # scan output
        pkg = raw.get("package")
        findings.extend(_parse_one_result(raw, pkg, raw.get("version")))
    return findings


def _parse_one_result(result, package, version):
    out = []
    if not isinstance(result, dict):
        return out

    errors = result.get("errors") or {}
    # F8: GuardDog normally emits errors as a dict, but tolerate a list/other
    # shape rather than raising AttributeError on .items() (which would drop the
    # whole run). Normalize non-dict errors into a single soft error.
    if errors and not isinstance(errors, dict):
        errors = {"error": str(errors)[:2000]}
    if errors:
        # A rule failed to run (e.g. download-package failure). Surface as a
        # soft error so the caller does not treat this package as clean.
        for rule, msg in errors.items():
            out.append({
                "package": package,
                "version": version,
                "rule": rule,
                "severity": "low",
                "confidence": "suspicious",
                "message": str(msg)[:2000],
                "soft_error": True,
            })

    results = result.get("results") or {}
    if not isinstance(results, dict):
        return out

    for rule, value in results.items():
        if not value:
            # Falsy = rule did not fire: None (metadata not triggered), "" (empty
            # message), or [] (no source-code hits). Skip all of them.
            continue
        severity = severity_for_rule(rule)
        if isinstance(value, str):
            # metadata rule fired -> human message string
            out.append(_finding(package, version, rule, severity, value))
        elif isinstance(value, list):
            # source-code rule fired -> list of finding objects
            if not value:
                continue
            for entry in value:
                if isinstance(entry, dict):
                    msg = entry.get("message") or entry.get("code") or ""
                else:
                    msg = str(entry)
                out.append(_finding(package, version, rule, severity, msg))
        else:
            out.append(_finding(package, version, rule, severity, str(value)))
    return out


def _finding(package, version, rule, severity, message):
    return {
        "package": package,
        "version": version,
        "rule": rule,
        "severity": severity,
        "confidence": "suspicious",
        "message": str(message)[:2000],
        "soft_error": False,
    }
