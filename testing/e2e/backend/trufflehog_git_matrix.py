#!/usr/bin/env python3
"""Parameter matrix for the TruffleHog `git` source, against the live stack.

Every case starts a REAL scan through the orchestrator, waits for it to settle,
and asserts on the published artifact. That is the only place several of these
can be checked: the field-to-argv mapping is unit-tested, but "does
--exclude-globs actually remove that finding" is a property of the binary, and
"does a failed clone report as an error" is a property of the orchestrator's
status logic - neither survives being mocked.

The fixtures live in scanners/scan_targets/git/ and are built by
`build_fixtures.sh` in this directory. They hold SYNTHETIC secrets only.

Run:  python3 testing/e2e/backend/trufflehog_git_matrix.py
Env:  WHITEHAT_PROJECT, WHITEHAT_USER, ORCH_URL, ORCHESTRATOR_API_KEY
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
    f"trufflehog_{PROJECT}_git.json")

BARE = "testrepo.git"
WORK = "workrepo"

# What the fixtures contain, and therefore what a full scan must find.
ALL_DETECTORS = {"Github", "SlackWebhook", "PrivateKey"}
ENV_FILE_DETECTORS = {"Github", "SlackWebhook"}   # both live in .env.example
PEM_DETECTORS = {"PrivateKey"}                    # deploy_key.pem


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


def start(config: dict, common: dict) -> tuple[int, dict]:
    body = json.dumps({
        "project_id": PROJECT, "user_id": USER,
        "webapp_api_url": "http://webapp:3000",
        "source": "git", "config": config, "common": common, "secrets": {},
    }).encode()
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/start", data=body, headers=HEADERS)
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=90).read())
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:400]}


def wait_settled(timeout: float = 180.0) -> dict:
    """Poll until the run leaves running/starting. The status endpoint is the
    orchestrator's view; the artifact is the scan's own."""
    req = urllib.request.Request(
        f"{ORCH}/trufflehog/{PROJECT}/git/status", headers=HEADERS)
    deadline = time.time() + timeout
    state = {}
    while time.time() < deadline:
        time.sleep(2)
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


class Case:
    def __init__(self, name, config, common, check, why=""):
        self.name, self.config, self.common, self.check, self.why = (
            name, config, common, check, why)


def run_case(c: Case) -> tuple[bool, str]:
    # A stale artifact would let a refused start "pass" on the previous run's
    # findings, so it is removed before every case.
    try:
        os.remove(ARTIFACT)
    except OSError:
        pass
    code, resp = start(c.config, c.common)
    if code != 200:
        return c.check({"http": code, "detail": resp.get("detail", "")}, {}, set())
    state = wait_settled()
    art = artifact()
    return c.check({"http": 200, **state}, art, detectors(art))


# --------------------------------------------------------------------------
# Expectations. Each returns (ok, detail).
# --------------------------------------------------------------------------

def expect_findings(want: set, status: str = "completed"):
    def check(state, art, found):
        if state["http"] != 200:
            return False, f"start refused: HTTP {state['http']} {state.get('detail','')}"
        if art.get("status") != status:
            return False, f"artifact status={art.get('status')!r}, want {status!r}"
        if found != want:
            return False, f"detectors={sorted(found)}, want {sorted(want)}"
        return True, f"{len(art.get('findings') or [])} findings {sorted(found)}"
    return check


def expect_scan_error(fragment: str = ""):
    def check(state, art, found):
        if state["http"] != 200:
            return False, f"start refused before running: HTTP {state['http']}"
        if state.get("status") != "error":
            return False, (f"run status={state.get('status')!r}, want 'error' "
                           f"(artifact={art.get('status')!r})")
        blob = f"{state.get('error','')} {art.get('error','')}"
        if fragment and fragment.lower() not in blob.lower():
            return False, f"error did not mention {fragment!r}: {blob[:160]}"
        return True, f"errored as expected: {str(state.get('error'))[:90]}"
    return check


def expect_rejected(fragment: str):
    def check(state, art, found):
        if state["http"] == 200:
            return False, "start was ACCEPTED; expected a 400 from validation"
        if fragment.lower() not in state.get("detail", "").lower():
            return False, f"400 did not mention {fragment!r}: {state.get('detail','')[:160]}"
        return True, f"refused with 400 ({fragment})"
    return check


def expect_all_status(want: str):
    def check(state, art, found):
        if art.get("status") != "completed":
            return False, f"artifact status={art.get('status')!r}"
        got = statuses(art)
        if got != {want}:
            return False, f"validation_status={sorted(got)}, want all {want!r}"
        return True, f"{len(art['findings'])} findings, all {want}"
    return check


def expect_at_most(n: int):
    def check(state, art, found):
        if state["http"] != 200:
            return False, f"start refused: HTTP {state['http']}"
        if art.get("status") != "completed":
            return False, f"artifact status={art.get('status')!r}"
        count = len(art.get("findings") or [])
        if count > n:
            return False, f"{count} findings, expected at most {n}"
        return True, f"{count} findings (<= {n})"
    return check


CASES = [
    # ---- the two repo shapes ------------------------------------------------
    Case("bare repo + Bare toggle", {"localRepo": BARE, "bare": True}, {},
         expect_findings(ALL_DETECTORS),
         "the baseline every filtering case is measured against"),
    Case("working clone, no toggle", {"localRepo": WORK}, {},
         expect_findings(ALL_DETECTORS),
         "same commits reached through a working tree"),
    Case("bare repo WITHOUT the toggle", {"localRepo": BARE}, {},
         expect_scan_error("stat .git"),
         "must fail loudly, not report a clean empty scan"),

    # ---- path filtering -----------------------------------------------------
    Case("excludePaths drops .env.example", {"localRepo": WORK, "excludePaths": r"\.env\.example"}, {},
         expect_findings(PEM_DETECTORS)),
    Case("includePaths keeps only the pem", {"localRepo": WORK, "includePaths": r"\.pem$"}, {},
         expect_findings(PEM_DETECTORS)),
    Case("excludeGlobs drops the pem", {"localRepo": WORK, "excludeGlobs": "*.pem"}, {},
         expect_findings(ENV_FILE_DETECTORS)),

    # ---- history controls ---------------------------------------------------
    Case("branch=main", {"localRepo": WORK, "branch": "main"}, {},
         expect_findings(ALL_DETECTORS)),
    Case("branch that does not exist", {"localRepo": WORK, "branch": "no-such-branch"}, {},
         expect_scan_error()),
    Case("maxDepth=1 sees less history", {"localRepo": WORK, "maxDepth": 1}, {},
         expect_at_most(3), "one commit of diff cannot exceed the full history"),

    # ---- detector selection (shared options) --------------------------------
    Case("includeDetectors=PrivateKey", {"localRepo": WORK}, {"includeDetectors": "PrivateKey"},
         expect_findings(PEM_DETECTORS)),
    Case("excludeDetectors=PrivateKey", {"localRepo": WORK}, {"excludeDetectors": "PrivateKey"},
         expect_findings(ENV_FILE_DETECTORS)),
    Case("excludeDetectors wins over include", {"localRepo": WORK},
         {"includeDetectors": "PrivateKey", "excludeDetectors": "PrivateKey"},
         expect_findings(set()), "exclude takes precedence; documented in the UI"),

    # ---- verification -------------------------------------------------------
    Case("verification on -> checked and dead", {"localRepo": WORK}, {},
         expect_all_status("unvalidated"),
         "synthetic keys are rejected by the real API, which is 'checked, dead'"),
    Case("verification off -> never checked", {"localRepo": WORK}, {"skipVerification": True},
         expect_all_status("unverified"),
         "the distinction a pentest report depends on"),
    Case("results=verified with nothing live", {"localRepo": WORK}, {"resultTypes": "verified"},
         expect_findings(set()),
         "the filter applies; the old both-on trap is what the UI now prevents"),
    Case("results=verified + skipVerification", {"localRepo": WORK},
         {"resultTypes": "verified", "skipVerification": True},
         expect_findings(ALL_DETECTORS),
         "build_common_flags DROPS the filter when verification is off, so this "
         "returns everything instead of the silent zero the pairing used to give"),

    # ---- misc shared options ------------------------------------------------
    Case("concurrency=1", {"localRepo": WORK}, {"concurrency": 1},
         expect_findings(ALL_DETECTORS), "must not change what is found"),
    Case("filterEntropy=8 drops low-entropy hits", {"localRepo": WORK}, {"filterEntropy": 8},
         expect_at_most(3)),

    # ---- validation, refused before anything runs ---------------------------
    Case("traversing local name", {"localRepo": "../../work/job.json"}, {},
         expect_rejected("not a valid local repository name"),
         "the credential file is at /work/job.json inside the container"),
    Case("both URI and local repo", {"uri": "https://example.com/a/b.git", "localRepo": WORK}, {},
         expect_rejected("mutually exclusive")),
    Case("neither target", {}, {},
         expect_rejected("set a Repository URI")),
]


def main() -> int:
    if not KEY:
        print("ORCHESTRATOR_API_KEY could not be resolved", file=sys.stderr)
        return 2
    print(f"project={PROJECT}  orchestrator={ORCH}  cases={len(CASES)}\n")
    failures = []
    for i, c in enumerate(CASES, 1):
        t0 = time.time()
        try:
            ok, detail = run_case(c)
        except Exception as e:                      # noqa: BLE001 - report, continue
            ok, detail = False, f"harness error: {e}"
        mark = "PASS" if ok else "FAIL"
        print(f"[{i:2d}/{len(CASES)}] {mark}  {c.name}  ({time.time()-t0:.0f}s)")
        print(f"          {detail}")
        if not ok:
            failures.append((c.name, detail))
    print(f"\n{len(CASES)-len(failures)}/{len(CASES)} passed")
    for name, detail in failures:
        print(f"  FAIL {name}: {detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
