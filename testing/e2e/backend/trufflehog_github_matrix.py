#!/usr/bin/env python3
"""Parameter matrix for the Secret Multiscanner `github` source, live stack.

Sibling of trufflehog_git_matrix.py, same contract: every case starts a REAL
scan through the orchestrator, waits for it to settle, and asserts on the
published artifact. What a flag DOES to a scan is a property of the binary and
of GitHub's API, and neither survives being mocked.

The fixtures are built by build_github_fixtures.sh in this directory and hold
SYNTHETIC credentials only. One detector per LOCATION, so an assertion can name
exactly where a finding must have come from:

    alpha  .env.example    Github, SlackWebhook      alpha  wiki   (none: see delta)
    alpha  deploy_key.pem  PrivateKey                delta  wiki   NpmToken
    alpha  issue comment   SendGrid                  beta          DatadogApikey
    alpha  PR body+comment Mailgun                   gamma         Shippo
    gist   file            LinearAPI                 gist comment  SentryToken

Enumeration flags (forks, archived, globs) are asserted on the set of
REPOSITORIES that produced findings, not on detectors: that is what those flags
actually change, and it stays readable when a repo holds several detectors.

Run:  python3 testing/e2e/backend/trufflehog_github_matrix.py
      python3 testing/e2e/backend/trufflehog_github_matrix.py --only gist
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY,
      GITHUB_FIXTURE_TOKEN (else _local/gh_fixture_token)
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
    f"trufflehog_{PROJECT}_github.json")
MANIFEST = os.path.join(REPO_ROOT, "_local", "github_fixtures.json")


def _token() -> str:
    tok = os.environ.get("GITHUB_FIXTURE_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with open(os.path.join(REPO_ROOT, "_local", "gh_fixture_token")) as fh:
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
# No fallback: the account comes from the manifest the builder wrote, so this
# file carries no one's GitHub login. main() refuses to run without it.
OWNER = MF.get("owner", "")
PREFIX = MF.get("prefix", "whitehat-th")

ALPHA = f"{OWNER}/{PREFIX}-alpha"
BETA = f"{OWNER}/{PREFIX}-beta"
GAMMA = f"{OWNER}/{PREFIX}-gamma"
DELTA = f"{OWNER}/{PREFIX}-delta"
FORK = f"{OWNER}/test_keys"

# Everything under the fixture prefix, so an org-scan case never touches a real
# repository of the account. This is not a convenience: `orgs` on a personal
# account enumerates EVERY repo the token can see, including private work.
ALL_FIXTURES = f"{OWNER}/{PREFIX}-*"

# Gists are enumerated as repositories, so `includeRepos` filters them too - and
# a fixtures-only glob therefore silences the gist along with the real repos.
# Naming the gist id as a second include pattern is what keeps a gist case
# scoped: 5 units enumerated (4 fixture repos + this gist) instead of the whole
# account.
#
# `excludeRepos` is NOT an alternative here. Against a USER login it is a no-op -
# `{OWNER}/*` left 583 findings from real repositories in place - even though the
# same flag filters correctly on a real organization. The UI hint already says
# "org scans only"; this is what that costs when the target is an account.
GIST = MF.get("gist", "")
GIST_GLOB = f"*{GIST}*"
GIST_SCOPE = [ALL_FIXTURES, GIST_GLOB]

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
        "source": "github", "config": config, "common": common,
        "secrets": {"trufflehogGithubToken": TOKEN} if secrets is None else secrets,
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(timeout: float = 600.0) -> dict:
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/github/status", headers=HEADERS)
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


def repos(art: dict) -> set:
    """The `owner/name` of every repository that produced a finding.

    The asset is a clone URL (https://github.com/o/n.git); gist findings carry a
    gist URL instead, which normalises to `gist:<id>` so the two never collide.
    """
    out = set()
    for f in (art.get("findings") or []):
        asset = str(f.get("asset") or "")
        if "gist.github.com" in asset:
            out.add("gist:" + asset.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
            continue
        slug = asset.split("github.com/", 1)[-1].removesuffix(".git").strip("/")
        if slug:
            out.add(slug)
    return out


def links(art: dict) -> list:
    return [str(f.get("link") or "") for f in (art.get("findings") or [])]


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


def expect_repos(want: set):
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        got = repos(art)
        if got != want:
            return False, f"repos={sorted(got)}, want {sorted(want)}"
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


def expect_link_contains(fragment: str):
    """A finding whose link proves WHERE it came from - the only way to tell a
    comment hit from a file hit when both live in the same repository."""
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        hits = [ln for ln in links(art) if fragment in ln]
        if not hits:
            return False, f"no finding linked to {fragment!r}; links={links(art)[:4]}"
        return True, f"{len(hits)} finding(s) at {hits[0][:90]}"
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


def expect_rejected(fragment: str):
    def check(state, art, found):
        if state["http"] == 200:
            return False, "start was ACCEPTED; expected a 400 from validation"
        if fragment.lower() not in state.get("detail", "").lower():
            return False, f"400 did not mention {fragment!r}: {state.get('detail','')[:200]}"
        return True, f"refused with {state['http']} ({fragment})"
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
    Case("repos, owner/repo shorthand", {"repos": [ALPHA]}, {},
         expect_detectors(ALPHA_FILES),
         "the shorthand the field hint promises; the baseline for the rest"),
    Case("repos, full https URL", {"repos": [f"https://github.com/{ALPHA}"]}, {},
         expect_detectors(ALPHA_FILES), "must be identical to the shorthand"),
    Case("two repos, one of them PRIVATE", {"repos": [ALPHA, BETA]}, {},
         expect_repos({ALPHA, BETA}),
         "beta is private: reaching it at all proves the token was injected"),
    Case("explicit endpoint", {"repos": [ALPHA], "endpoint": "https://api.github.com"}, {},
         expect_detectors(ALPHA_FILES), "the default, stated; must change nothing"),
    Case("token never reaches the artifact", {"repos": [ALPHA]}, {},
         expect_no_token_leak()),

    # ---- org enumeration and its globs -------------------------------------
    Case("org scan, scoped to the fixtures",
         {"orgs": [OWNER], "includeRepos": [ALL_FIXTURES]}, {},
         expect_repos({ALPHA, BETA, GAMMA}),
         "delta holds no secret in code, so it contributes nothing here"),
    Case("includeRepos narrows to one repo",
         {"orgs": [OWNER], "includeRepos": [f"{OWNER}/{PREFIX}-a*"]}, {},
         expect_repos({ALPHA})),
    Case("excludeRepos drops the private one",
         {"orgs": [OWNER], "includeRepos": [ALL_FIXTURES],
          "excludeRepos": [f"{OWNER}/{PREFIX}-b*"]}, {},
         expect_repos({ALPHA, GAMMA})),
    Case("excludeArchived drops gamma",
         {"orgs": [OWNER], "includeRepos": [ALL_FIXTURES], "excludeArchived": True}, {},
         expect_repos({ALPHA, BETA})),
    Case("forks excluded by default",
         {"orgs": [OWNER], "includeRepos": [f"{OWNER}/test_keys"]}, {},
         expect_no_findings(), "the fork is enumerated but must not be scanned"),
    Case("includeForks pulls the fork in",
         {"orgs": [OWNER], "includeRepos": [f"{OWNER}/test_keys"], "includeForks": True}, {},
         expect_repos({FORK})),

    # ---- comments ----------------------------------------------------------
    Case("issue comments off by default", {"repos": [ALPHA]}, {},
         expect_detector_present("SendGrid", False)),
    Case("issueComments finds the comment",
         {"repos": [ALPHA], "issueComments": True}, {},
         expect_link_contains("/issues/"),
         "the detector alone cannot prove it: the link must point at the issue"),
    Case("pr comments off by default", {"repos": [ALPHA]}, {},
         expect_detector_present("Mailgun", False)),
    Case("prComments finds the PR body",
         {"repos": [ALPHA], "prComments": True}, {},
         expect_detector_present("Mailgun"),
         "the PR's own diff is secret-free, so a hit can only be the body/comment"),
    Case("commentsTimeframe=1 keeps a comment made today",
         {"repos": [ALPHA], "issueComments": True, "commentsTimeframe": 1}, {},
         expect_detector_present("SendGrid"),
         "the pass-through direction; excluding an OLD comment needs a >1d fixture"),

    # ---- gists (a user target only; organizations have no gists) -----------
    Case("gists are scanned in a user scan",
         {"orgs": [OWNER], "includeRepos": GIST_SCOPE}, {},
         expect_detector_present("LinearAPI"),
         "LinearAPI exists ONLY in the gist, so finding it proves the gist was read"),
    Case("ignoreGists silences them",
         {"orgs": [OWNER], "includeRepos": GIST_SCOPE, "ignoreGists": True}, {},
         expect_detector_present("LinearAPI", present=False),
         "the fixture repos are still in scope, so this asserts the gist is gone "
         "rather than that the scan found nothing"),
    Case("gistComments finds the comment",
         {"orgs": [OWNER], "includeRepos": GIST_SCOPE, "gistComments": True}, {},
         expect_detector_present("SentryToken"),
         "SentryToken lives only in the gist COMMENT, not in the gist file"),

    # ---- wiki --------------------------------------------------------------
    Case("delta has nothing in its code", {"repos": [DELTA]}, {},
         expect_no_findings(), "the zero half of the wiki contrast", tags=("wiki",)),
    Case("includeWikis finds the wiki page",
         {"repos": [DELTA], "includeWikis": True}, {},
         expect_detector_present("NpmToken"),
         "delta's code is empty of secrets, so this can only be the wiki",
         tags=("wiki",)),

    # ---- path filtering ----------------------------------------------------
    Case("includePaths keeps only the pem",
         {"repos": [ALPHA], "includePaths": r"\.pem$"}, {},
         expect_detectors({"PrivateKey"})),
    Case("excludePaths drops .env.example",
         {"repos": [ALPHA], "excludePaths": r"\.env\.example"}, {},
         expect_detectors({"PrivateKey"})),

    # ---- verification ------------------------------------------------------
    Case("verification on -> checked and dead", {"repos": [ALPHA]}, {},
         expect_all_status("unvalidated"),
         "synthetic keys are rejected by the real API: 'checked, dead'"),
    Case("verification off -> never checked", {"repos": [ALPHA]}, {"skipVerification": True},
         expect_all_status("unverified"),
         "the distinction a pentest report depends on"),
    Case("results=verified with nothing live", {"repos": [ALPHA]},
         {"resultTypes": ["verified"]}, expect_no_findings()),

    # ---- refused before anything runs --------------------------------------
    Case("no repo and no org", {}, {},
         expect_rejected("at least one repository or organization")),
    Case("includeRepos without an org", {"repos": [ALPHA], "includeRepos": [ALL_FIXTURES]}, {},
         expect_rejected("only applies to organization scans")),
    Case("includeMembers without an org", {"repos": [ALPHA], "includeMembers": True}, {},
         expect_rejected("only applies to organization scans")),
    Case("endpoint aimed at the loopback",
         {"repos": [ALPHA], "endpoint": "http://127.0.0.1:8010"}, {},
         expect_rejected("not allowed"),
         "the egress guard: a source may not be pointed at WhiteHat's own services"),
    Case("endpoint aimed at the cloud metadata IP",
         {"repos": [ALPHA], "endpoint": "http://169.254.169.254"}, {},
         expect_rejected("not allowed")),
    Case("no token at all", {"repos": [ALPHA]}, {},
         expect_rejected("GitHub Token"), secrets={}),
    Case("a revoked token fails LOUDLY", {"repos": [ALPHA]}, {},
         expect_scan_error(),
         "exit 0 with zero findings would read as 'no secrets here'",
         secrets={"trufflehogGithubToken": "ghp_000000000000000000000000000000000000"}),
]


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    if not TOKEN:
        print("no GitHub token: set GITHUB_FIXTURE_TOKEN or _local/gh_fixture_token",
              file=sys.stderr)
        return 2
    if not MF:
        print(f"no fixture manifest at {MANIFEST}; run build_github_fixtures.sh first",
              file=sys.stderr)
        return 2

    only = ""
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].lower()
    skip_tags = set()
    if "--skip" in sys.argv:
        skip_tags = {t.strip() for t in sys.argv[sys.argv.index("--skip") + 1].split(",")}

    # The wiki fixture needs a page that only a human can create: GitHub has no
    # REST endpoint for a wiki's first page, and until one exists the wiki git
    # repo does not either. Skipped from the MANIFEST rather than by a hand-typed
    # --skip, so a plain run is green and says out loud what it did not cover.
    if not MF.get("wikiReady"):
        skip_tags.add("wiki")

    cases = [c for c in CASES
             if (not only or only in c.name.lower())
             and not (skip_tags & set(c.tags))]
    skipped = [c.name for c in CASES if skip_tags & set(c.tags)]
    print(f"project={PROJECT}  orchestrator={ORCH}  owner={OWNER}  cases={len(cases)}\n")

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
    for name in skipped:
        print(f"  SKIP {name} (wiki fixture not initialised; "
              f"see build_github_fixtures.sh)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
