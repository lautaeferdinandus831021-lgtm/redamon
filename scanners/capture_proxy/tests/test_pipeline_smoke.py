"""
Smoke / integration test: the whole capture_proxy in-process pipeline.

recon signs a tag  ->  capture_lib shapes a spool record carrying it verbatim  ->
the trusted ingest verifies the tag, stamps the tenant from the VERIFIED payload,
and builds a DB row  ->  the INSERT SQL is well-formed. This is the end-to-end
data path minus the mitmproxy hook (untestable off-container) and the live DB.

Run: python3 -m unittest capture_proxy.tests.test_pipeline_smoke
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import whitehat_ctx  # noqa: E402
from capture_lib import build_record  # noqa: E402
from ingest_worker import build_row, _insert_sql, _JSONB_COLS  # noqa: E402

_KEY = "scanner-key"


class TestFullPipelineSmoke(unittest.TestCase):
    def _signed_record(self, forged_user=None):
        payload = {
            "source": "recon", "project_id": "proj-1", "user_id": "owner-1",
            "run_id": "run-9", "tool": "nuclei", "phase": "informational",
        }
        token = whitehat_ctx.sign_tag(payload, _KEY)
        rec = build_record(
            ctx_token=token, method="GET", scheme="https", host="target.tld",
            port=443, path="/login", query="next=/admin",
            req_headers={"user-agent": "x", "cookie": "s=1"},
            resp_headers={"set-cookie": "s=2", "content-type": "text/html"},
            status_code=200, req_body_inline=None, req_body_ref=None,
            req_body_size=0, req_body_sha=None, resp_body_inline="<html>hi</html>",
            resp_body_ref=None, resp_body_size=15, resp_body_sha="abc",
            http_version="HTTP/1.1", is_tls=True, tls_version=None,
            target_ip="93.184.216.34", response_time_ms=42,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        # A target/proxy cannot change the tenant: the record's own tenant claim,
        # if any, is ignored; only the verified tag decides. Simulate a forged one.
        if forged_user:
            rec["user_id"] = forged_user
        return token, rec

    def test_happy_path_end_to_end(self):
        token, rec = self._signed_record()
        payload = whitehat_ctx.verify_tag(rec["ctx_token"], {"recon": _KEY})
        self.assertIsNotNone(payload)
        row = build_row(payload, rec, redact=True)
        # tenant + attribution come from the verified tag
        self.assertEqual(row["project_id"], "proj-1")
        self.assertEqual(row["user_id"], "owner-1")
        self.assertEqual(row["source"], "recon")
        self.assertEqual(row["run_id"], "run-9")
        # request/response come from the (untrusted) record
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["host"], "target.tld")
        self.assertEqual(row["status_code"], 200)
        # redaction masked the sensitive headers
        self.assertTrue(row["redacted"])
        self.assertIn("cookie", (row["req_headers"] or ""))
        self.assertNotIn("s=1", (row["req_headers"] or ""))

    def test_tenant_cannot_be_forged_via_record(self):
        token, rec = self._signed_record(forged_user="attacker")
        payload = whitehat_ctx.verify_tag(rec["ctx_token"], {"recon": _KEY})
        row = build_row(payload, rec, redact=False)
        self.assertEqual(row["user_id"], "owner-1")  # NOT "attacker"

    def test_wrong_key_rejects_whole_record(self):
        token, rec = self._signed_record()
        self.assertIsNone(whitehat_ctx.verify_tag(rec["ctx_token"], {"recon": "wrong"}))

    def test_insert_sql_is_wellformed(self):
        token, rec = self._signed_record()
        payload = whitehat_ctx.verify_tag(rec["ctx_token"], {"recon": _KEY})
        row = build_row(payload, rec, redact=False)
        sql, values = _insert_sql(row)
        self.assertTrue(sql.startswith("INSERT INTO captured_http_transactions"))
        # one placeholder per value
        self.assertEqual(sql.count("%s"), len(values))
        # jsonb columns get the cast, non-jsonb do not
        self.assertIn('"req_headers"', sql)
        self.assertEqual(sql.count("::jsonb"),
                         sum(1 for c in row if c in _JSONB_COLS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
