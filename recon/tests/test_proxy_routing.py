"""
Unit tests for recon capture-proxy routing (Phase 1).

Loads the helper modules by path so the test runs on the host without triggering
recon/helpers/__init__.py (which imports heavy optional deps). Also verifies the
recon copy of whitehat_ctx is cross-compatible with the capture_proxy copy — a
token signed on the recon side must verify on the ingest side.

Run: python3 -m unittest recon.tests.test_proxy_routing
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
RECON_HELPERS = REPO / "recon" / "helpers"
CAPTURE = REPO / "scanners" / "capture_proxy"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# Temporarily register a lightweight `helpers` package so proxy_routing's
# `from helpers.whitehat_ctx import sign_tag` resolves to the recon copy without
# executing the real recon/helpers/__init__.py (which imports heavy deps absent
# on the host). CRITICAL: restore sys.modules afterward so we don't poison other
# test modules that share this process and DO need the real `helpers` package.
_saved_helpers = sys.modules.get("helpers")
_saved_ctx = sys.modules.get("helpers.whitehat_ctx")
try:
    _helpers_pkg = types.ModuleType("helpers")
    _helpers_pkg.__path__ = []
    sys.modules["helpers"] = _helpers_pkg
    recon_ctx = _load("helpers.whitehat_ctx", RECON_HELPERS / "whitehat_ctx.py")
    sys.modules["helpers.whitehat_ctx"] = recon_ctx
    # proxy_routing captures sign_tag at import, so restoring below is safe.
    pr = _load("helpers.proxy_routing", RECON_HELPERS / "proxy_routing.py")
finally:
    if _saved_helpers is not None:
        sys.modules["helpers"] = _saved_helpers
    else:
        sys.modules.pop("helpers", None)
    if _saved_ctx is not None:
        sys.modules["helpers.whitehat_ctx"] = _saved_ctx
    else:
        sys.modules.pop("helpers.whitehat_ctx", None)

# The ingest-side copy, loaded independently for the cross-compat check.
capture_ctx = _load("capture_whitehat_ctx", CAPTURE / "whitehat_ctx.py")

SCANNER = "scanner-key-xyz"


class TestCrossCompat(unittest.TestCase):
    def test_recon_signed_token_verifies_on_ingest_side(self):
        payload = {"source": "recon", "project_id": "p1", "user_id": "u1", "tool": "katana"}
        token = recon_ctx.sign_tag(payload, SCANNER)
        out = capture_ctx.verify_tag(token, {"recon": SCANNER, "agent": "other"})
        self.assertEqual(out, payload)


class TestRouting(unittest.TestCase):
    def setUp(self):
        pr._config.update(enabled=False, port=8888, reachable=False)
        pr._token_cache.clear()
        self._orig_reach = pr.is_capture_proxy_reachable

    def tearDown(self):
        pr.is_capture_proxy_reachable = self._orig_reach

    def test_disabled_yields_no_routing(self):
        pr.configure({"CAPTURE_PROXY_ENABLED": False})
        self.assertEqual(pr.get_capture_routing("katana"), (None, None))

    def test_enabled_but_unreachable_fails_open(self):
        pr.is_capture_proxy_reachable = lambda **k: False
        pr.configure({"CAPTURE_PROXY_ENABLED": True})
        # §20.1 fail-open: no routing when the proxy is down.
        self.assertEqual(pr.get_capture_routing("katana"), (None, None))

    def test_enabled_and_reachable_routes_with_signed_tag(self):
        pr.is_capture_proxy_reachable = lambda **k: True
        with mock.patch.dict(os.environ, {
            "PROJECT_ID": "p1", "USER_ID": "u1", "RECON_RUN_ID": "run-1",
            "SCANNER_API_KEY": SCANNER, "CAPTURE_PROXY_PORT": "8888",
        }, clear=False):
            pr.configure({"CAPTURE_PROXY_ENABLED": True})
            url, token = pr.get_capture_routing("katana")
        self.assertEqual(url, "http://127.0.0.1:8888")
        # The token verifies on the ingest side and carries the right attribution.
        payload = capture_ctx.verify_tag(token, {"recon": SCANNER, "agent": "x"})
        self.assertEqual(payload["source"], "recon")
        self.assertEqual(payload["tool"], "katana")
        self.assertEqual(payload["project_id"], "p1")
        self.assertEqual(payload["user_id"], "u1")
        self.assertEqual(payload["run_id"], "run-1")

    def test_no_scanner_key_no_routing(self):
        pr.is_capture_proxy_reachable = lambda **k: True
        with mock.patch.dict(os.environ, {"SCANNER_API_KEY": "", "INTERNAL_API_KEY": ""}, clear=False):
            pr.configure({"CAPTURE_PROXY_ENABLED": True})
            self.assertEqual(pr.get_capture_routing("katana"), (None, None))

    def test_no_internal_fallback_for_recon(self):
        # REGRESSION: source=recon tags verify ONLY against SCANNER_API_KEY, so a
        # missing scanner key must NOT fall back to INTERNAL (that tag never verifies).
        pr.is_capture_proxy_reachable = lambda **k: True
        with mock.patch.dict(os.environ, {"SCANNER_API_KEY": "", "INTERNAL_API_KEY": "internal"}, clear=False):
            pr.configure({"CAPTURE_PROXY_ENABLED": True})
            self.assertEqual(pr.get_capture_routing("katana"), (None, None))

    def test_reprobe_flips_to_direct_when_proxy_dies(self):
        # REGRESSION (§20.1 fail-open): a proxy that dies mid-scan must flip routing
        # back to direct on the next re-probe, not keep routing to a dead port.
        alive = {"v": True}
        pr.is_capture_proxy_reachable = lambda **k: alive["v"]
        with mock.patch.dict(os.environ, {"PROJECT_ID": "p1", "USER_ID": "u1", "SCANNER_API_KEY": SCANNER}, clear=False):
            pr.configure({"CAPTURE_PROXY_ENABLED": True})
            self.assertIsNotNone(pr.get_capture_routing("katana")[0])  # routing on
            alive["v"] = False
            pr._config["probed_at"] = 0.0  # force the TTL to expire -> re-probe
            self.assertEqual(pr.get_capture_routing("katana"), (None, None))  # fell to direct

    def test_configure_camelcase_gate(self):
        # partial recon passes a raw project dict (camelCase captureProxyEnabled).
        pr.is_capture_proxy_reachable = lambda **k: True
        with mock.patch.dict(os.environ, {"PROJECT_ID": "p1", "USER_ID": "u1", "SCANNER_API_KEY": SCANNER}, clear=False):
            pr.configure({"captureProxyEnabled": True})
            self.assertIsNotNone(pr.get_capture_routing("katana")[0])

    def test_token_cached_per_tool(self):
        pr.is_capture_proxy_reachable = lambda **k: True
        with mock.patch.dict(os.environ, {
            "PROJECT_ID": "p1", "USER_ID": "u1", "SCANNER_API_KEY": SCANNER,
        }, clear=False):
            pr.configure({"CAPTURE_PROXY_ENABLED": True})
            a = pr.get_capture_routing("katana")
            b = pr.get_capture_routing("katana")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
