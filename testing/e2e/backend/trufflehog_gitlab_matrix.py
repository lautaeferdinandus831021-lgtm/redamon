#!/usr/bin/env python3
"""Parameter matrix for the Secret Multiscanner `gitlab` source, live stack.

Sibling of trufflehog_github_matrix.py, same contract: every case starts a REAL
scan through the orchestrator, waits for it to settle, and asserts on the
published artifact. What a flag DOES to a scan is a property of the binary and
of GitLab's API, and neither survives being mocked.

The fixtures are built by build_gitlab_fixtures.sh in this directory and hold
SYNTHETIC credentials only. One detector per LOCATION, so an assertion can name
exactly where a finding must have come from:

    alpha  .env.example          Github, SlackWebhook
    alpha  keys/deploy_key.pem   PrivateKey
    alpha  config.yml            (none - AWS's example pair, the negative control)
    beta   monitoring.env        DatadogApikey        (private)
    gamma  shipping.env          Shippo

Two things make this source differ from `github`, and both are asserted here:

* **`repos` must be a full http(s) URL.** The pinned binary answers `group/repo`
  with "Gitlab requires http/https repo urls" at INFO level and then scans
  NOTHING for it - a silent miss, not a failure. `validate_config` refuses the
  shorthand before a run can start, and case "repos shorthand" proves it.
* **`includeRepos`/`excludeRepos` carry no `requires: 'orgs'` gate.** Unlike
  github they are never disabled, and they filter a `groupIds` enumeration.
* **`includeRepos` is a CONJUNCTION of two globs.** TruffleHog applies the
  pattern to `group/project` while enumerating AND to
  `https://host/group/project.git` before scanning, keeping a project only when
  BOTH match, so it must start and end with `*`. `excludeRepos` drops on EITHER
  match, so a full-path pattern works there. The asymmetry is invisible in the
  binary's output, which is why both directions are asserted below.

Enumeration flags (group ids, globs) are asserted on the set of PROJECTS that
produced findings, not on detectors: that is what those flags actually change.

Run:  python3 testing/e2e/backend/trufflehog_gitlab_matrix.py
      python3 testing/e2e/backend/trufflehog_gitlab_matrix.py --only glob
      python3 testing/e2e/backend/trufflehog_gitlab_matrix.py --skip selfhosted
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY,
      GITLAB_FIXTURE_TOKEN (else _local/gitlab_fixture_token)
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PROJECT = os.environ.get("WHITEHAT_PROJECT", "e651f859c3114faf94196ab02")
USER = os.environ.get("WHITEHAT_USER", "cmrzlj3xk0000ob3vo67o3igg")
ORCH = os.environ.get("ORCH_URL", "http://127.0.0.1:8010")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ARTIFACT = os.path.join(
    REPO_ROOT, "scanners", "trufflehog_scan", "output",
    f"trufflehog_{PROJECT}_gitlab.json")
MANIFEST = os.path.join(REPO_ROOT, "_local", "gitlab_fixtures.json")

SETTINGS_KEY = "trufflehogGitlabToken"


def _token() -> str:
    tok = os.environ.get("GITLAB_FIXTURE_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with open(os.path.join(REPO_ROOT, "_local", "gitlab_fixture_token")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _manifest() -> dict:
    try:
        with open(MANIFEST) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


TOKEN = _token()
MF = _manifest()
# No fallback: the account and group come from the manifest the builder wrote,
# so this file carries no one's GitLab login. main() refuses to run without it.
HOST = MF.get("host", "https://gitlab.com")
GROUP = MF.get("group", "")
GROUP_ID = str(MF.get("groupId", "") or "")
VISIBLE_PROJECTS = int(MF.get("visibleProjects", 0) or 0)

ALPHA_URL = MF.get("alpha", "")
BETA_URL = MF.get("beta", "")
GAMMA_URL = MF.get("gamma", "")
ALPHA = MF.get("alphaPath", "")
BETA = MF.get("betaPath", "")
GAMMA = MF.get("gammaPath", "")

ALPHA_FILES = {"Github", "SlackWebhook", "PrivateKey"}


def orchestrator_key() -> str:
    key = os.environ.get("ORCHESTRATOR_API_KEY", "").strip()
    if key:
        return key
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "recon-orchestrator",
         "printenv", "ORCHESTRATOR_API_KEY"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    return out.stdout.strip()


KEY = orchestrator_key()
HEADERS = {"Content-Type": "application/json", "X-Orchestrator-Key": KEY}


def start(config: dict, common: dict, secrets=None) -> tuple[int, dict]:
    body = json.dumps({
        "project_id": PROJECT, "user_id": USER,
        "webapp_api_url": "http://webapp:3000",
        "source": "gitlab", "config": config, "common": common,
        "secrets": {SETTINGS_KEY: TOKEN} if secrets is None else secrets,
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(timeout: float = 600.0) -> dict:
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/gitlab/status", headers=HEADERS)
    deadline = time.time() + timeout
    state = {}
    while time.time() < deadline:
        time.sleep(3)
        try:
            state = json.loads(urllib.request.urlopen(req, timeout=20).read())
        except Exception:
            continue
        if state.get("status") not in ("running", "starting", "stopping"):
            return state
    return state


def artifact() -> dict:
    try:
        with open(ARTIFACT) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def detectors(art: dict) -> set:
    return {f.get("detector_name") for f in (art.get("findings") or [])}


def statuses(art: dict) -> set:
    return {f.get("validation_status") for f in (art.get("findings") or [])}


def _slug(asset: str) -> str:
    """`group/project` for a GitLab asset, whatever shape it arrived in.

    TruffleHog reports the clone URL (https://gitlab.com/group/project.git); the
    host is stripped so an assertion reads as the path an operator recognises,
    and a bare slug (should the binary ever emit one) passes through unchanged
    rather than losing its namespace to the host-stripping split.
    """
    a = str(asset or "").strip()
    if "://" in a:
        a = a.split("://", 1)[1]
        a = a.split("/", 1)[1] if "/" in a else ""
    if a.endswith(".git"):
        a = a[:-4]
    return a.strip("/")


def projects(art: dict) -> set:
    """The `group/project` of every project that produced a finding."""
    return {s for s in (_slug(f.get("asset")) for f in (art.get("findings") or [])) if s}


class Case:
    def __init__(self, name, config, common, check, why="", secrets=None, tags=()):
        self.name, self.config, self.common, self.check, self.why = (
            name, config, common, check, why)
        self.secrets, self.tags = secrets, tags


def run_case(c: Case) -> tuple[bool, str]:
    # A stale artifact would let a refused start "pass" on the previous run's
    # findings, so it is removed before every case.
    try:
        os.remove(ARTIFACT)
    except OSError:
        pass
    code, resp = start(c.config, c.common, c.secrets)
    if code != 200:
        return c.check({"http": code, "detail": resp.get("detail", "")}, {}, set())
    state = wait_settled()
    art = artifact()
    return c.check({"http": 200, **state}, art, detectors(art))


# --------------------------------------------------------------------------
# Expectations. Each returns (ok, detail).
# --------------------------------------------------------------------------

def _completed(state, art):
    if state["http"] != 200:
        return f"start refused: HTTP {state['http']} {state.get('detail','')}"
    if art.get("status") != "completed":
        return (f"artifact status={art.get('status')!r} "
                f"(run={state.get('status')!r} err={str(state.get('error'))[:120]})")
    return ""


def expect_detectors(want: set):
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        if found != want:
            return False, f"detectors={sorted(found)}, want {sorted(want)}"
        return True, f"{len(art.get('findings') or [])} findings {sorted(found)}"
    return check


def expect_projects(want: set):
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        got = projects(art)
        if got != want:
            return False, f"projects={sorted(got)}, want {sorted(want)}"
        return True, f"{len(art.get('findings') or [])} findings from {sorted(got)}"
    return check


def expect_detector_present(name: str, present: bool = True):
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        if (name in found) != present:
            return False, (f"{name} {'absent' if present else 'present'}; "
                           f"detectors={sorted(found)}")
        return True, f"{name} {'found' if present else 'correctly absent'} ({sorted(found)})"
    return check


def expect_no_findings():
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        n = len(art.get("findings") or [])
        if n:
            return False, f"{n} findings, expected none: {sorted(found)}"
        return True, "0 findings, as expected"
    return check


def expect_all_status(want: str):
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        got = statuses(art)
        if got != {want}:
            return False, f"validation_status={sorted(got)}, want all {want!r}"
        return True, f"{len(art['findings'])} findings, all {want}"
    return check


def expect_target(want: str):
    """`describe_target('gitlab', cfg)` is what the audit row and the graph's
    MultiscannerScan.target both carry, so it is asserted as an exact string."""
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        got = str(art.get("target") or "")
        if got != want:
            return False, f"target={got!r}, want {want!r}"
        return True, f"target={got!r}"
    return check


def expect_group_path_is_not_silent():
    """A group PATH must not be accepted and then quietly scan nothing.

    Three outcomes are acceptable, one is not:
      * refused by validate_config (best: the operator is told),
      * the run errors (acceptable: the operator sees a failure),
      * it works, i.e. GitLab resolves the path (fine).
    Completing with ZERO findings is the failure this exists to catch, because
    the fixture group demonstrably holds five.
    """
    def check(state, art, found):
        if state["http"] != 200:
            return True, f"refused up front: {state.get('detail','')[:120]}"
        if state.get("status") == "error":
            return True, f"failed loudly: {str(state.get('error'))[:120]}"
        n = len(art.get("findings") or [])
        if n == 0:
            return False, ("ACCEPTED, completed, and found NOTHING. A group path "
                           "is silently ignored where the numeric id finds 5 "
                           "findings; validate_config should refuse it")
        return True, f"the path resolved: {n} findings from {sorted(projects(art))}"
    return check


def expect_rejected(fragment: str):
    def check(state, art, found):
        if state["http"] == 200:
            return False, "start was ACCEPTED; expected a 400 from validation"
        if fragment.lower() not in state.get("detail", "").lower():
            return False, f"400 did not mention {fragment!r}: {state.get('detail','')[:200]}"
        return True, f"refused with {state['http']} ({fragment})"
    return check


def expect_accepted():
    """Only that the start passed every gate. Used for the empty-scope case,
    where the POINT is that an empty config is legal - not what it finds."""
    def check(state, art, found):
        if state["http"] != 200:
            return False, f"start refused: HTTP {state['http']} {state.get('detail','')}"
        if state.get("status") == "error":
            return False, f"accepted but errored: {str(state.get('error'))[:160]}"
        return True, (f"accepted and ran: status={state.get('status')!r}, "
                      f"{len(art.get('findings') or [])} findings from "
                      f"{sorted(projects(art))}")
    return check


def expect_scan_error(fragment: str = ""):
    def check(state, art, found):
        if state["http"] != 200:
            return False, f"start refused before running: HTTP {state['http']}"
        if state.get("status") != "error":
            return False, (f"run status={state.get('status')!r}, want 'error' "
                           f"(artifact={art.get('status')!r}, "
                           f"{len(art.get('findings') or [])} findings)")
        blob = f"{state.get('error','')} {art.get('error','')}"
        if fragment and fragment.lower() not in blob.lower():
            return False, f"error did not mention {fragment!r}: {blob[:200]}"
        return True, f"errored as expected: {str(state.get('error'))[:90]}"
    return check


def expect_no_token_leak():
    """The token must not survive into the artifact, in any field."""
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        blob = json.dumps(art) + json.dumps(state, default=str)
        if TOKEN and TOKEN in blob:
            return False, "THE TOKEN APPEARS IN THE PUBLISHED ARTIFACT"
        return True, "token absent from the artifact and the run state"
    return check


CASES = [
    # ---- targeting ---------------------------------------------------------
    Case("repos, one full https URL", {"repos": [ALPHA_URL]}, {},
         expect_detectors(ALPHA_FILES),
         "the baseline every filtering case is measured against"),
    Case("repos, two URLs, one of them PRIVATE", {"repos": [ALPHA_URL, BETA_URL]}, {},
         expect_projects({ALPHA, BETA}),
         "beta is private: reaching it at all proves the token was injected"),
    Case("repos shorthand is refused before anything runs",
         {"repos": [f"{GROUP}/alpha"]}, {},
         expect_rejected("must be a full URL"),
         "the binary answers `group/repo` with 'Gitlab requires http/https repo "
         "urls' at INFO level and then scans NOTHING - a silent miss. The "
         "validator is the only thing standing between an operator and a clean "
         "'0 findings' for a repository that was never read"),
    Case("groupIds enumerates the whole group", {"groupIds": [GROUP_ID]}, {},
         expect_projects({ALPHA, BETA, GAMMA}),
         "--group-id takes the NUMERIC id and includes subgroups"),
    Case("explicit endpoint changes nothing",
         {"repos": [ALPHA_URL], "endpoint": HOST}, {},
         expect_detectors(ALPHA_FILES), "the default, stated"),
    Case("token never reaches the artifact", {"repos": [ALPHA_URL]}, {},
         expect_no_token_leak()),

    # ---- describe_target, the string the graph and the audit row carry ------
    Case("target string, repos", {"repos": [ALPHA_URL, BETA_URL]}, {},
         expect_target(f"{ALPHA_URL}, {BETA_URL}")),
    Case("target string, group id", {"groupIds": [GROUP_ID]}, {},
         expect_target(f"group:{GROUP_ID}")),

    # ---- filtering ---------------------------------------------------------
    # Asserted on the set of PROJECTS, not on detector names: what these two
    # flags change is which projects are enumerated at all.
    Case("groupIds + includeRepos glob narrows to one project",
         {"groupIds": [GROUP_ID], "includeRepos": [f"*{GROUP}/a*"]}, {},
         expect_projects({ALPHA}),
         "no `requires: orgs` gate on this source, unlike github. The leading "
         "star is load-bearing, see the refused case below"),
    Case("includeRepos without the wrapping stars is refused",
         {"groupIds": [GROUP_ID], "includeRepos": [f"{GROUP}/a*"]}, {},
         expect_rejected("would match nothing"),
         "measured against the pinned binary: TruffleHog applies this glob "
         "TWICE, to 'group/project' while enumerating and to "
         "'https://host/group/project.git' before scanning, and keeps a project "
         "only if BOTH match. This pattern matches the path, fails the URL, and "
         "selects NOTHING with no error anywhere. It is the exact shape that "
         "works on github, so an operator will write it"),
    Case("groupIds + excludeRepos glob drops one project",
         {"groupIds": [GROUP_ID], "excludeRepos": [f"{GROUP}/b*"]}, {},
         expect_projects({ALPHA, GAMMA})),
    Case("includePaths keeps only the pem",
         {"repos": [ALPHA_URL], "includePaths": r"\.pem$"}, {},
         expect_detectors({"PrivateKey"})),
    Case("excludePaths drops .env.example",
         {"repos": [ALPHA_URL], "excludePaths": r"\.env\.example"}, {},
         expect_detectors({"PrivateKey"})),

    # ---- the group PATH trap -----------------------------------------------
    # `--group-id` takes a NUMERIC id. A path is the obvious thing to type,
    # especially since `repos` takes a URL and `includeRepos` takes a path, so
    # this asserts what actually happens rather than assuming it errors. If the
    # binary accepts a path and scans NOTHING, that is the same silent-miss
    # class as the `group/repo` shorthand and belongs in validate_config too.
    Case("groupIds given a PATH instead of the numeric id",
         {"groupIds": [GROUP]}, {},
         expect_group_path_is_not_silent(),
         "a path that is quietly ignored reports 0 findings for a group that "
         "was never opened, which reads as 'no secrets here'"),

    # ---- pathfile fields are newline-separated ------------------------------
    # `includePaths`/`excludePaths` are the `pathfile` type: the runner writes
    # the value to a temp file, ONE REGEX PER LINE, and passes the path. A
    # single-line value never exercises that split, so a bug that sends only the
    # first line (or the whole blob as one regex) would pass unnoticed.
    Case("excludePaths with TWO regexes, one per line",
         {"repos": [ALPHA_URL], "excludePaths": "\\.env\\.example\n\\.pem$"}, {},
         expect_no_findings(),
         "each line alone removes part of alpha; both together must remove all "
         "of it, which only holds if BOTH lines reached the file"),
    Case("includePaths with TWO regexes, one per line",
         {"repos": [ALPHA_URL], "includePaths": "\\.env\\.example\n\\.pem$"}, {},
         expect_detectors(ALPHA_FILES),
         "the mirror of the case above: both lines together select every "
         "secret-bearing file in alpha"),

    # ---- shared options ----------------------------------------------------
    Case("verification on -> checked and dead", {"repos": [ALPHA_URL]}, {},
         expect_all_status("unvalidated"),
         "synthetic keys are rejected by the real API: 'checked, dead'"),
    Case("verification off -> never checked", {"repos": [ALPHA_URL]},
         {"skipVerification": True}, expect_all_status("unverified"),
         "the distinction a pentest report depends on"),
    Case("results=verified with nothing live", {"repos": [ALPHA_URL]},
         {"resultTypes": ["verified"]}, expect_no_findings()),
    Case("includeDetectors=PrivateKey keeps only the pem", {"repos": [ALPHA_URL]},
         {"includeDetectors": ["PrivateKey"]}, expect_detectors({"PrivateKey"}),
         "the same narrowing as includePaths, reached through a shared option"),

    # ---- legal empty scope -------------------------------------------------
    # No repos AND no group ids is VALID for this source: it scans every project
    # the token can reach. Tagged so it self-skips when the account holds
    # anything besides the fixtures - scanning someone's unrelated projects is
    # not this suite's to do.
    Case("no repos and no groupIds is legal", {}, {}, expect_accepted(),
         "empty is not the same as unconfigured here; the UI hint says so",
         tags=("emptyscope",)),
    Case("target string, empty scope", {}, {},
         expect_target("gitlab.com (all visible)"), tags=("emptyscope",)),

    # ---- refused before anything runs --------------------------------------
    Case("a repos entry with a leading dash", {"repos": ["--tmpdir=/etc"]}, {},
         expect_rejected("must be a full URL"),
         "a value starting with `-` becomes an OPTION to TruffleHog; the "
         "http(s) rule closes that vector for this source"),
    Case("a repos entry with a shell metacharacter",
         {"repos": ["gitlab.com/a;rm -rf /"]}, {},
         expect_rejected("must be a full URL"),
         "argv is a list so there is no shell, but the value must still not be "
         "readable as an option or reach the binary as a bogus target"),
    Case("endpoint aimed at the loopback",
         {"repos": [ALPHA_URL], "endpoint": "http://127.0.0.1:8010"}, {},
         expect_rejected("not allowed"),
         "the egress guard: egress_hosts('gitlab', cfg) reads `endpoint`, so "
         "this source genuinely has an egress surface"),
    Case("endpoint aimed at the cloud metadata IP",
         {"repos": [ALPHA_URL], "endpoint": "http://169.254.169.254"}, {},
         expect_rejected("not allowed")),
    Case("no token at all", {"repos": [ALPHA_URL]}, {},
         expect_rejected("Secret Multiscanner GitLab Token"), secrets={}),
    Case("a revoked token fails LOUDLY", {"repos": [ALPHA_URL]}, {},
         expect_scan_error(),
         "exit 0 with zero findings would read as 'no secrets here', which is "
         "why --fail-on-scan-errors is passed unconditionally",
         secrets={SETTINGS_KEY: "glpat-0000000000000000000000"}),

    # ---- self-hosted -------------------------------------------------------
    # Only meaningful against an instance the operator owns. Skipped by default
    # rather than pointed at a stranger's GitLab.
    Case("self-hosted endpoint is honoured",
         {"endpoint": os.environ.get("GITLAB_SELFHOSTED", ""),
          "repos": [os.environ.get("GITLAB_SELFHOSTED_REPO", "")]}, {},
         expect_accepted(), tags=("selfhosted",)),
]


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    if not TOKEN:
        print("no GitLab token: set GITLAB_FIXTURE_TOKEN or "
              "_local/gitlab_fixture_token", file=sys.stderr)
        return 2
    if not MF or not GROUP_ID or not ALPHA_URL:
        print(f"no usable fixture manifest at {MANIFEST}; "
              f"run build_gitlab_fixtures.sh first", file=sys.stderr)
        return 2

    only = ""
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].lower()
    skip_tags = set()
    if "--skip" in sys.argv:
        skip_tags = {t.strip() for t in sys.argv[sys.argv.index("--skip") + 1].split(",")}

    reasons = {}
    # Both auto-skips are driven by the MANIFEST / the environment rather than a
    # hand-typed --skip, so a plain run is green AND says out loud what it did
    # not cover.
    # Empty scope reads EVERY project the token can reach, so it stays off by
    # default the moment the account holds anything besides the fixtures.
    # GITLAB_ALLOW_EMPTY_SCOPE is the operator saying, explicitly, that they have
    # looked at what else is reachable and it is theirs to scan.
    if VISIBLE_PROJECTS > 3 and not os.environ.get("GITLAB_ALLOW_EMPTY_SCOPE", "").strip():
        skip_tags.add("emptyscope")
        reasons["emptyscope"] = (
            f"the token can reach {VISIBLE_PROJECTS} projects, more than the 3 "
            f"fixtures; an empty-scope scan would read every one of them. Set "
            f"GITLAB_ALLOW_EMPTY_SCOPE=1 if the extras are yours to scan")
    if not os.environ.get("GITLAB_SELFHOSTED", "").strip():
        skip_tags.add("selfhosted")
        reasons["selfhosted"] = (
            "no self-hosted GitLab available; set GITLAB_SELFHOSTED and "
            "GITLAB_SELFHOSTED_REPO to cover it")

    cases = [c for c in CASES
             if (not only or only in c.name.lower())
             and not (skip_tags & set(c.tags))]
    skipped = [c for c in CASES if skip_tags & set(c.tags)]
    print(f"project={PROJECT}  orchestrator={ORCH}  group={GROUP} (id {GROUP_ID})  "
          f"cases={len(cases)}\n")

    failures = []
    for i, c in enumerate(cases, 1):
        t0 = time.time()
        try:
            ok, detail = run_case(c)
        except Exception as e:                      # noqa: BLE001 - report, continue
            ok, detail = False, f"harness error: {e}"
        mark = "PASS" if ok else "FAIL"
        print(f"[{i:2d}/{len(cases)}] {mark}  {c.name}  ({time.time()-t0:.0f}s)")
        print(f"          {detail}")
        if not ok and c.why:
            print(f"          why it matters: {c.why}")
        if not ok:
            failures.append((c.name, detail))
    print(f"\n{len(cases)-len(failures)}/{len(cases)} passed")
    for name, detail in failures:
        print(f"  FAIL {name}: {detail}")
    # Never silent. A suite that quietly drops a case reads as full coverage.
    for c in skipped:
        tag = next(iter(set(c.tags) & set(reasons)), None)
        print(f"  SKIP {c.name} ({reasons.get(tag, 'skipped by --skip')})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
