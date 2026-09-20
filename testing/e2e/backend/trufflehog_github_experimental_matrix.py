#!/usr/bin/env python3
"""Parameter matrix for the Secret Multiscanner `github_experimental` source.

Sibling of trufflehog_github_matrix.py, same contract: every case starts a REAL
scan through the orchestrator, waits for it to settle, and asserts on the
published artifact. What a flag DOES to a scan is a property of the binary and
of GitHub's API, and neither survives being mocked.

This source is the odd one out. `--object-discovery` hunts for objects that are
still on GitHub's servers but unreachable from any ref - force-pushed and
deleted commits - so:

  * it is FAR slower than `github`; the settle timeout defaults to 40 minutes
    and is overridable with GHX_SCAN_TIMEOUT
  * its findings have no live file path, so assertions are on the `commit` and
    on the detector, never on `location`
  * SOURCE_META_KEYS['github_experimental'] == 'github': it reports under the
    `Github` metadata key, not one of its own
  * `egress_hosts()` returns [] because the source has NO endpoint field, so
    there is no egress-guard case here. That is not an omission: with no
    operator-typed host there is nothing for the guard to resolve.

The fixtures are built by build_github_experimental_fixtures.sh and hold
SYNTHETIC credentials only:

    whitehat-thx-dangling   SentryToken, ONLY in an unreachable commit
    whitehat-thx-live       an RSA PrivateKey in the live tree; nothing dangling
    both repos             AWS's example pair as a negative control (never fires)

The detector NAMES come from the manifest rather than being written here: the
fixture repos must be public for object discovery, GitHub push-protects public
pushes, and which detectors survive that is GitHub's call, not ours (see the
builder's header).

The most valuable case in the file is the CONTRAST: the ordinary `github` source
finds nothing at all in the dangling repo. The zero half is what proves this
source reads something no other source can.

Run:  python3 testing/e2e/backend/trufflehog_github_experimental_matrix.py
      python3 testing/e2e/backend/trufflehog_github_experimental_matrix.py --only dangling
      python3 testing/e2e/backend/trufflehog_github_experimental_matrix.py --verify-last
        ^ assert the baseline cases against an artifact already on disk, instead
          of paying for the same 90-minute scan once per assertion. See
          BASELINE_REUSABLE for exactly which cases that is allowed for.
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY,
      GHX_SCAN_TIMEOUT, GITHUB_FIXTURE_TOKEN (else _local/gh_fixture_token)
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
OUTPUT_DIR = os.path.join(REPO_ROOT, "scanners", "trufflehog_scan", "output")
MANIFEST = os.path.join(REPO_ROOT, "_local", "github_experimental_fixtures.json")

SOURCE = "github_experimental"
# Object discovery walks a short-SHA space repo by repo; a run that would settle
# in 30s for `github` takes minutes here, and a timeout that fires mid-scan looks
# exactly like a scanner that found nothing.
# MEASURED: 5,666s (94 min) against the two-commit fixture on 2026-08-19. The
# cost is the 65,536-candidate short-SHA sweep, which is the floor for ANY
# repository, so a smaller fixture does not make it cheaper. Two hours leaves
# headroom for GitHub's secondary rate limiter (TruffleHog sleeps 60s and
# retries on it).
SCAN_TIMEOUT = float(os.environ.get("GHX_SCAN_TIMEOUT", "7200"))


def artifact_path(source: str) -> str:
    return os.path.join(OUTPUT_DIR, f"trufflehog_{PROJECT}_{source}.json")


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
DANGLING = MF.get("dangling", "")
LIVE = MF.get("live", "")
DANGLING_SHA = MF.get("danglingSha", "")
# Read, never hardcoded: the builder picks detectors GitHub's push protection
# lets through, and that set can change under us.
DANGLING_DETECTOR = MF.get("danglingDetector", "SentryToken")
LIVE_DETECTOR = MF.get("liveDetector", "PrivateKey")


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


def start(config: dict, common: dict, secrets=None, source=SOURCE) -> tuple[int, dict]:
    body = json.dumps({
        "project_id": PROJECT, "user_id": USER,
        "webapp_api_url": "http://webapp:3000",
        "source": source, "config": config, "common": common,
        "secrets": {"trufflehogGithubToken": TOKEN} if secrets is None else secrets,
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(source=SOURCE, timeout: float = None) -> dict:
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/{source}/status", headers=HEADERS)
    deadline = time.time() + (SCAN_TIMEOUT if timeout is None else timeout)
    state = {}
    while time.time() < deadline:
        time.sleep(5)
        try:
            state = json.loads(urllib.request.urlopen(req, timeout=20).read())
        except Exception:
            continue
        if state.get("status") not in ("running", "starting", "stopping"):
            return state
    # Distinguishable from a scan that genuinely ended: a bare timeout would
    # otherwise be reported as whatever the last poll happened to say.
    return {**state, "timed_out": True}


def artifact(source=SOURCE) -> dict:
    try:
        with open(artifact_path(source)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def detectors(art: dict) -> set:
    return {f.get("detector_name") for f in (art.get("findings") or [])}


def statuses(art: dict) -> set:
    return {f.get("validation_status") for f in (art.get("findings") or [])}


def commits(art: dict) -> set:
    return {str(f.get("commit") or "") for f in (art.get("findings") or [])}


class Case:
    def __init__(self, name, config, common, check, why="", secrets=None,
                 source=SOURCE, tags=()):
        self.name, self.config, self.common, self.check, self.why = (
            name, config, common, check, why)
        self.secrets, self.source, self.tags = secrets, source, tags


def run_case(c: Case) -> tuple[bool, str]:
    # A stale artifact would let a refused start "pass" on the previous run's
    # findings, so it is removed before every case.
    try:
        os.remove(artifact_path(c.source))
    except OSError:
        pass
    code, resp = start(c.config, c.common, c.secrets, c.source)
    if code != 200:
        return c.check({"http": code, "detail": resp.get("detail", "")}, {}, set())
    state = wait_settled(c.source)
    art = artifact(c.source)
    return c.check({"http": 200, **state}, art, detectors(art))


# --------------------------------------------------------------------------
# Expectations. Each returns (ok, detail).
# --------------------------------------------------------------------------

def _completed(state, art):
    if state["http"] != 200:
        return f"start refused: HTTP {state['http']} {state.get('detail','')}"
    if state.get("timed_out"):
        return (f"run did NOT settle within {SCAN_TIMEOUT:.0f}s "
                f"(last status={state.get('status')!r}); raise GHX_SCAN_TIMEOUT "
                "rather than trusting the partial artifact")
    if art.get("status") != "completed":
        return (f"artifact status={art.get('status')!r} "
                f"(run={state.get('status')!r} err={str(state.get('error'))[:120]})")
    return ""


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


def expect_dangling_commit():
    """The whole point of the source: the finding must come from the commit the
    builder force-pushed out of the branch, not from anything still reachable."""
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        if DANGLING_DETECTOR not in found:
            return False, f"{DANGLING_DETECTOR} absent; detectors={sorted(found)}"
        got = commits(art)
        if DANGLING_SHA not in got:
            # A short SHA is a legitimate answer here: object discovery works in
            # short-sha space, so accept a prefix match and say which it was.
            short = [c for c in got if c and DANGLING_SHA.startswith(c)]
            if not short:
                return False, (f"no finding carries the dangling commit "
                               f"{DANGLING_SHA[:12]}; commits={sorted(got)}")
            return True, f"found at short commit {short[0]} of {DANGLING_SHA[:12]}"
        return True, (f"{DANGLING_DETECTOR} found at the dangling commit "
                      f"{DANGLING_SHA[:12]}")
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


def expect_completes(note: str = ""):
    """For a flag whose effect is not observable on this fixture. Pins that the
    run still SUCCEEDS, and reports the finding set so a future change that
    silently alters it is visible in the log rather than asserted away."""
    def check(state, art, found):
        bad = _completed(state, art)
        if bad:
            return False, bad
        return True, (f"completed, {len(art.get('findings') or [])} findings "
                      f"{sorted(found)}" + (f" [{note}]" if note else ""))
    return check


def expect_rejected(fragment: str):
    def check(state, art, found):
        if state["http"] == 200:
            return False, "start was ACCEPTED; expected a 4xx from validation"
        if fragment.lower() not in state.get("detail", "").lower():
            return False, f"{state['http']} did not mention {fragment!r}: {state.get('detail','')[:200]}"
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
    # ---- the source's whole reason to exist --------------------------------
    Case("the dangling commit is found", {"repo": DANGLING}, {},
         expect_dangling_commit(),
         "the fixture's dangling detector exists ONLY in a commit no ref points at"),
    Case("the ordinary github source finds NOTHING in the same repo",
         {"repos": [DANGLING]}, {}, expect_no_findings(),
         "the contrast that proves object discovery read something no other "
         "source can reach", source="github"),
    Case("full clone URL is accepted like the shorthand",
         {"repo": f"https://github.com/{DANGLING}.git"}, {},
         expect_dangling_commit(),
         "the --repo help text shows a clone URL; the UI hint shows a slug"),

    # ---- the control repo ---------------------------------------------------
    Case("a repo with nothing dangling", {"repo": LIVE}, {},
         expect_completes("does object discovery also surface the LIVE tree?"),
         "recorded rather than asserted: what a hidden-object scan does with a "
         "repo that has no hidden objects is the binary's choice, not ours"),

    # ---- the two optional fields -------------------------------------------
    Case("collisionThreshold at its default of 1",
         {"repo": DANGLING, "collisionThreshold": 1}, {},
         expect_dangling_commit(),
         "stated explicitly; must be identical to omitting it"),
    # collisionThreshold is PROVABLY inert on this fixture, and the arithmetic
    # says so rather than the absence of an observation.
    #
    # object_discovery.go picks the short-SHA length by growing it from 4 while
    #   collisions = k(k-1) / (2 * 16^len)  >  collisionThreshold
    # where k = commits + commits*0.001*forks. The dangling fixture has 3 commits
    # and no forks, so collisions at 4 chars is 0.000046 - five orders of
    # magnitude below the DEFAULT threshold of 1. The loop never runs, the key
    # space is 16^4 for any threshold at or above 0.000046, and raising it to 8
    # cannot change a thing.
    #
    # A repo of 363+ commits is where threshold=1 first tips the length to 5. So
    # the fixture that would make this flag observable is also the fixture that
    # multiplies the candidate space by 16 (65,536 -> 1,048,576) and every run
    # with it. That trade is why this case pins "the run still completes and the
    # findings do not move" instead of asserting a difference that cannot exist.
    Case("collisionThreshold raised is inert on a small repo",
         {"repo": DANGLING, "collisionThreshold": 8}, {},
         expect_dangling_commit(),
         "same finding as the default case: the threshold cannot bite below "
         "363 commits, so a DIFFERENCE here would be the bug"),
    Case("deleteCachedData on changes nothing about the results",
         {"repo": DANGLING, "deleteCachedData": True}, {},
         expect_dangling_commit(),
         "a disk-hygiene flag; pinning that it is inert is what catches a future "
         "change that deletes the cache mid-scan"),

    # ---- verification ------------------------------------------------------
    Case("verification on -> checked and dead", {"repo": DANGLING}, {},
         expect_all_status("unvalidated"),
         "a synthetic key is rejected by the real API: 'checked, dead'"),
    Case("verification off -> never checked", {"repo": DANGLING},
         {"skipVerification": True}, expect_all_status("unverified"),
         "the distinction a pentest report depends on"),
    Case("results=verified with nothing live", {"repo": DANGLING},
         {"resultTypes": ["verified"]}, expect_no_findings()),

    # ---- the credential ----------------------------------------------------
    Case("token never reaches the artifact", {"repo": DANGLING}, {},
         expect_no_token_leak()),
    Case("no token at all", {"repo": DANGLING}, {},
         expect_rejected("GitHub Token"),
         "credential_required() is unconditionally true for this source",
         secrets={}),
    Case("a revoked token fails LOUDLY", {"repo": DANGLING}, {},
         expect_scan_error(),
         "exit 0 with zero findings would read as 'no secrets here'",
         secrets={"trufflehogGithubToken": "ghp_000000000000000000000000000000000000"}),

    # ---- refused before anything runs --------------------------------------
    Case("repo is required", {}, {},
         expect_rejected("'repo' is required"),
         "enforced generically by validate_config from Field(required=True)"),
    Case("an ORG given where a repo belongs", {"repo": OWNER}, {},
         expect_completes("what does the binary do with a non-repo --repo?"),
         "the UI hint says 'a single repo, not an org'; this records what "
         "actually happens, the way the GitLab org/repo trap was recorded"),

    # `--object-discovery` is asserted directly by
    # tests/test_trufflehog_sources.py::test_github_experimental_forces_object_discovery
    # and indirectly by every case above: the subcommand errors out without it,
    # so a completed run is itself the proof that it was emitted.
]


# Cases whose config is BYTE-IDENTICAL to the baseline run `{"repo": <dangling>}`
# with default common settings. --verify-last checks these against an artifact
# that already exists instead of paying for the same 90-minute scan again.
#
# Deliberately short, and deliberately not "close enough". `collisionThreshold=1`
# is NOT in here even though 1 is the default: stating it emits
# `--collision-threshold=1` where the baseline emits nothing, so the argv differs
# and only a real run can say the two behave the same. The published artifact
# records `target` and `verification_enabled` but NOT the config that produced
# it, so nothing downstream could catch a wrong reuse - which is exactly why the
# list is hand-written rather than matched at runtime.
BASELINE_CONFIG = {"repo": DANGLING}
BASELINE_COMMON: dict = {}
BASELINE_REUSABLE = (
    "the dangling commit is found",
    "token never reaches the artifact",
    "verification on -> checked and dead",
)


def verify_last(only: str = "") -> int:
    """Assert the baseline cases against the artifact already on disk.

    Refuses to run if the artifact was not produced by the baseline config, on
    the two fields the artifact actually carries. A reuse that silently checked
    the wrong run would be worse than no check at all.
    """
    art = artifact(SOURCE)
    if not art:
        print(f"no artifact at {artifact_path(SOURCE)}", file=sys.stderr)
        return 2
    want_target = th_describe_target(BASELINE_CONFIG)
    if str(art.get("target") or "") != want_target:
        print(f"artifact target is {art.get('target')!r}, not the baseline "
              f"{want_target!r}; refusing to reuse it", file=sys.stderr)
        return 2
    if art.get("verification_enabled") is not True:
        print("artifact was produced with verification OFF; the baseline runs it "
              "ON, so the reusable cases do not apply", file=sys.stderr)
        return 2

    state = {"http": 200, "status": art.get("status")}
    cases = [c for c in CASES if c.name in BASELINE_REUSABLE
             and (not only or only in c.name.lower())]
    print(f"verifying {len(cases)} baseline case(s) against the existing "
          f"artifact (target={want_target!r}, "
          f"{len(art.get('findings') or [])} findings)\n")
    failures = []
    for i, c in enumerate(cases, 1):
        ok, detail = c.check(state, art, detectors(art))
        print(f"[{i}/{len(cases)}] {'PASS' if ok else 'FAIL'}  {c.name}")
        print(f"          {detail}")
        if not ok:
            failures.append((c.name, detail))
    print(f"\n{len(cases)-len(failures)}/{len(cases)} passed (artifact reuse)")
    not_run = [c.name for c in CASES if c.name not in BASELINE_REUSABLE]
    for name in not_run:
        print(f"  NOT RUN {name} (needs its own scan)")
    return 1 if failures else 0


def th_describe_target(config: dict) -> str:
    """What describe_target() puts in the artifact for this source: the bare
    repo string. Reimplemented rather than imported because this harness runs on
    the host, where the scanner package is not importable."""
    return str(config.get("repo") or "")


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    if not TOKEN:
        print("no GitHub token: set GITHUB_FIXTURE_TOKEN or _local/gh_fixture_token",
              file=sys.stderr)
        return 2
    if not MF or not DANGLING_SHA:
        print(f"no fixture manifest at {MANIFEST}; run "
              "build_github_experimental_fixtures.sh first", file=sys.stderr)
        return 2

    only = ""
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].lower()
    if "--verify-last" in sys.argv:
        return verify_last(only)
    skip_tags = set()
    if "--skip" in sys.argv:
        skip_tags = {t.strip() for t in sys.argv[sys.argv.index("--skip") + 1].split(",")}

    cases = [c for c in CASES
             if (not only or only in c.name.lower())
             and not (skip_tags & set(c.tags))]
    skipped = [c.name for c in CASES if skip_tags & set(c.tags)]
    print(f"project={PROJECT}  orchestrator={ORCH}  owner={OWNER}  "
          f"cases={len(cases)}  settle_timeout={SCAN_TIMEOUT:.0f}s\n")

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
        sys.stdout.flush()
    print(f"\n{len(cases)-len(failures)}/{len(cases)} passed")
    for name, detail in failures:
        print(f"  FAIL {name}: {detail}")
    # Never silent. A suite that quietly drops a case reads as full coverage.
    for name in skipped:
        print(f"  SKIP {name}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
