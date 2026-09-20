"""Scan Queue Phase 6 - supply_chain_repo per-repo override.

An org-batch item scans ONE repo, passed by the orchestrator as
SUPPLY_CHAIN_REPO_OVERRIDE_* env. project_settings.load_project_settings must apply
that override on EVERY return path (both DEFAULT fallbacks AND the successful
project fetch), forcing github input mode + the batch repo, so an item never scans
the project's default target.

Run under the root-agent section (image whitehat-agent).
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

_REPO = str(Path(__file__).resolve().parents[1])
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# Load scanners/supply_chain_scan/project_settings.py in isolation (avoid colliding with the
# other project_settings.py modules in the tree).
_spec = importlib.util.spec_from_file_location(
    "sc_project_settings", os.path.join(_REPO, "scanners", "supply_chain_scan", "project_settings.py"))
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)

_OVERRIDE_ENV = (
    "SUPPLY_CHAIN_REPO_OVERRIDE_URL", "SUPPLY_CHAIN_REPO_OVERRIDE_REF",
    "SUPPLY_CHAIN_REPO_OVERRIDE_SCOPE", "SUPPLY_CHAIN_REPO_OVERRIDE_DEEP",
    "SUPPLY_CHAIN_REPO_OVERRIDE_HOST", "USER_ID",
    "WEBAPP_API_URL",
)


class TestRepoOverride(unittest.TestCase):
    def setUp(self):
        for k in _OVERRIDE_ENV:
            os.environ.pop(k, None)
        ps._settings = None
        ps._current_project_id = None

    def tearDown(self):
        for k in _OVERRIDE_ENV:
            os.environ.pop(k, None)
        ps._settings = None
        ps._current_project_id = None

    def test_no_override_is_a_noop(self):
        base = ps.DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
        out = ps._apply_repo_override(base)
        self.assertEqual(out["SUPPLY_CHAIN_INPUT_MODE"], "upload")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_URL"], "")

    def test_override_forces_github_and_the_repo(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/a.git"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_REF"] = "main"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_SCOPE"] = "packages/x"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_DEEP"] = "1"
        out = ps._apply_repo_override(ps.DEFAULT_SUPPLY_CHAIN_SETTINGS.copy())
        self.assertEqual(out["SUPPLY_CHAIN_INPUT_MODE"], "github")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_URL"], "https://github.com/acme/a.git")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_REF"], "main")
        self.assertEqual(out["SUPPLY_CHAIN_REPO_SCOPE"], "packages/x")
        self.assertTrue(out["SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED"])

    def test_deep_flag_off_is_respected(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/a.git"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_DEEP"] = "0"
        out = ps._apply_repo_override({**ps.DEFAULT_SUPPLY_CHAIN_SETTINGS, "SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED": True})
        self.assertFalse(out["SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED"])

    def test_load_applies_override_on_the_no_webapp_fallback(self):
        # No WEBAPP_API_URL -> DEFAULT fallback path, override must still apply.
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/b.git"
        settings = ps.load_project_settings("p1")
        self.assertEqual(settings["SUPPLY_CHAIN_INPUT_MODE"], "github")
        self.assertEqual(settings["SUPPLY_CHAIN_REPO_URL"], "https://github.com/acme/b.git")


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeRequests:
    """Stands in for `requests` inside fetch_supply_chain_settings: the project
    fetch first, then the user-settings fetch."""

    def __init__(self, project, user):
        self.project = project
        self.user = user
        self.urls = []

    def get(self, url, timeout=None, headers=None):
        self.urls.append(url)
        return _FakeResp(self.user if "/api/users/" in url else self.project)


class TestEnterpriseHostAndCredential(unittest.TestCase):
    """The credential is chosen BY HOST: a GitHub Enterprise PAT must never be
    sent to github.com, nor a github.com PAT to an internal server."""

    GHE = "ghe.example.com"
    USER = {
        # Supply Chain holds its own github.com PAT, separate from the GitHub
        # Secret Hunt one, so a scope change to either cannot widen the other.
        "supplyChainGithubToken": "ghp_dotcom",
        "githubAccessToken": "ghp_secret_hunt_must_not_be_used",
        "githubEnterpriseHost": GHE,
        "githubEnterpriseToken": "ghp_ghe",
    }
    PROJECT = {"supplyChainInputMode": "github", "supplyChainRepoUrl": ""}

    def setUp(self):
        for k in _OVERRIDE_ENV:
            os.environ.pop(k, None)
        os.environ["USER_ID"] = "u1"
        ps._settings = None
        ps._current_project_id = None
        self._real_requests = sys.modules.get("requests")

    def tearDown(self):
        for k in _OVERRIDE_ENV:
            os.environ.pop(k, None)
        if self._real_requests is not None:
            sys.modules["requests"] = self._real_requests
        else:
            sys.modules.pop("requests", None)
        ps._settings = None
        ps._current_project_id = None

    def _fetch(self, project=None, user=None):
        fake = _FakeRequests(project or self.PROJECT, user if user is not None else self.USER)
        sys.modules["requests"] = fake
        return fake, ps.fetch_supply_chain_settings("p1", "http://webapp:3000")

    def test_override_host_is_applied(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://%s/acme/a.git" % self.GHE
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_HOST"] = self.GHE
        out = ps._apply_repo_override(ps.DEFAULT_SUPPLY_CHAIN_SETTINGS.copy())
        self.assertEqual(out["SUPPLY_CHAIN_GITHUB_HOST"], self.GHE)

    def test_no_override_host_means_github_com(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://github.com/acme/a.git"
        out = ps._apply_repo_override(ps.DEFAULT_SUPPLY_CHAIN_SETTINGS.copy())
        self.assertEqual(out["SUPPLY_CHAIN_GITHUB_HOST"], "github.com")

    def test_enterprise_batch_item_gets_the_enterprise_token(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://%s/acme/a.git" % self.GHE
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_HOST"] = self.GHE
        _fake, settings = self._fetch()
        self.assertEqual(settings["SUPPLY_CHAIN_GITHUB_HOST"], self.GHE)
        self.assertEqual(settings["SUPPLY_CHAIN_GHE_HOST"], self.GHE)
        self.assertEqual(settings["GITHUB_ACCESS_TOKEN"], "ghp_ghe")

    def test_github_com_scan_gets_the_github_com_token(self):
        _fake, settings = self._fetch(
            project={"supplyChainInputMode": "github",
                     "supplyChainRepoUrl": "https://github.com/acme/a"})
        self.assertEqual(settings["SUPPLY_CHAIN_GITHUB_HOST"], "github.com")
        self.assertEqual(settings["GITHUB_ACCESS_TOKEN"], "ghp_dotcom")

    def test_an_unconfigured_host_gets_no_credential_at_all(self):
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_URL"] = "https://evil.example.com/acme/a.git"
        os.environ["SUPPLY_CHAIN_REPO_OVERRIDE_HOST"] = "evil.example.com"
        _fake, settings = self._fetch()
        self.assertEqual(settings["GITHUB_ACCESS_TOKEN"], "",
                         "a host the operator did not configure must get no token")

    def test_the_host_is_derived_from_the_repo_url_when_no_override(self):
        _fake, settings = self._fetch(
            project={"supplyChainInputMode": "github",
                     "supplyChainRepoUrl": "https://%s/acme/a" % self.GHE})
        self.assertEqual(settings["SUPPLY_CHAIN_GITHUB_HOST"], self.GHE)
        self.assertEqual(settings["GITHUB_ACCESS_TOKEN"], "ghp_ghe")

    def test_upload_mode_still_fetches_no_token(self):
        fake, settings = self._fetch(
            project={"supplyChainInputMode": "upload", "supplyChainSbomFile": "sbom.json"})
        self.assertEqual(settings["GITHUB_ACCESS_TOKEN"], "")
        self.assertTrue(all("/api/users/" not in u for u in fake.urls),
                        "an SBOM-upload scan must not request a credential")


if __name__ == "__main__":
    unittest.main()
