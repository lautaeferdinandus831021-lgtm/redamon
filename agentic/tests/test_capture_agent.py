"""
Unit tests for agent-side capture-proxy tagging (Phase 1).

Verifies the agent's whitehat_ctx copy is cross-compatible with the ingest copy
(an agent-signed token, source=agent/INTERNAL_API_KEY, must verify on the ingest
side) and that the kali-side routing helper obeys the §20.2 no-leak rule.

Modules are loaded by path (pure stdlib) so this runs on the host.

Run: python3 -m unittest agentic.tests.test_capture_agent
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# This is a cross-layer test: it needs agentic/, capture_proxy/ and mcp/servers/
# siblings all present under one repo root. That layout exists in the repo-root
# test run (full repo mounted) but NOT in the agentic-only section image (where
# capture_proxy/ is not mounted). Locate the files defensively and self-skip
# cleanly (bucket 2) when they are absent, rather than erroring at import.
_AGENT_CTX = REPO / "agentic" / "whitehat_ctx.py"
_INGEST_CTX = REPO / "capture_proxy" / "whitehat_ctx.py"
_KALI_ROUTING = REPO / "mcp" / "servers" / "capture_routing.py"

agent_ctx = ingest_ctx = kali_routing = None
if _AGENT_CTX.exists() and _INGEST_CTX.exists() and _KALI_ROUTING.exists():
    agent_ctx = _load("agent_whitehat_ctx", _AGENT_CTX)
    ingest_ctx = _load("ingest_whitehat_ctx", _INGEST_CTX)
    kali_routing = _load("kali_capture_routing", _KALI_ROUTING)


def setUpModule():
    if agent_ctx is None:
        raise unittest.SkipTest(
            "cross-layer capture files not all present in this image "
            "(needs agentic/ + capture_proxy/ + mcp/servers/ under one root)")

INTERNAL = "internal-key-abc"
SCANNER = "scanner-key-xyz"


class TestAgentCrossCompat(unittest.TestCase):
    def test_agent_signed_token_verifies_on_ingest_side(self):
        payload = {"source": "agent", "project_id": "p1", "user_id": "u1",
                   "session_id": "s1", "tool": "execute_curl", "phase": "exploitation"}
        token = agent_ctx.sign_tag(payload, INTERNAL)
        out = ingest_ctx.verify_tag(token, {"recon": SCANNER, "agent": INTERNAL})
        self.assertEqual(out, payload)

    def test_agent_token_rejected_under_recon_key(self):
        # source=agent must verify against INTERNAL, not SCANNER.
        token = agent_ctx.sign_tag({"source": "agent", "project_id": "p", "user_id": "u"}, SCANNER)
        self.assertIsNone(ingest_ctx.verify_tag(token, {"recon": SCANNER, "agent": INTERNAL}))


class TestKaliRouting(unittest.TestCase):
    def test_no_token_no_routing(self):
        self.assertEqual(kali_routing.agent_capture_routing(""), (None, None))
        self.assertEqual(kali_routing.agent_capture_routing(None), (None, None))

    def test_token_but_unreachable_no_routing(self):
        with mock.patch.object(kali_routing, "_reachable", lambda url, timeout=1.0: False):
            self.assertEqual(kali_routing.agent_capture_routing("tok"), (None, None))

    def test_token_and_reachable_routes(self):
        with mock.patch.object(kali_routing, "_reachable", lambda url, timeout=1.0: True):
            url, tok = kali_routing.agent_capture_routing("tok")
        self.assertEqual(tok, "tok")
        self.assertTrue(url.startswith("http://"))
        self.assertIn("whitehat-capture-proxy", url)

    def test_proxy_url_env_override(self):
        with mock.patch.dict("os.environ", {"CAPTURE_PROXY_URL": "http://x:9999"}, clear=False):
            self.assertEqual(kali_routing.proxy_url(), "http://x:9999")


if __name__ == "__main__":
    unittest.main()
