"""
Unit tests for the capture-proxy pure logic: egress guard, header normalization,
passive signals, body inline/offload, record shaping.

Run: python3 -m unittest capture_proxy.tests.test_capture_lib
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import egress  # noqa: E402
import capture_lib as cl  # noqa: E402


class TestEgress(unittest.TestCase):
    def test_internal_ips_blocked(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                   "169.254.169.254", "100.64.0.1", "::1", "0.0.0.0"):
            self.assertTrue(egress.is_internal_ip(ip), ip)

    def test_public_ips_allowed(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            self.assertFalse(egress.is_internal_ip(ip), ip)

    def test_unparseable_ip_fails_closed(self):
        self.assertTrue(egress.is_internal_ip("not-an-ip"))

    def test_extra_blocked_service_ip(self):
        self.assertTrue(egress.is_internal_ip("8.8.8.8", extra_blocked=["8.8.8.8"]))

    def test_extra_blocked_cidr(self):
        # REGRESSION: a CIDR entry must block by membership, not be ignored.
        self.assertTrue(egress.is_internal_ip("8.8.8.8", extra_blocked=["8.8.8.0/24"]))
        self.assertFalse(egress.is_internal_ip("9.9.9.9", extra_blocked=["8.8.8.0/24"]))

    def test_resolve_bad_idna_fails_closed(self):
        # REGRESSION: an oversized IDNA label raises UnicodeError in getaddrinfo;
        # resolve must fail CLOSED (empty list) so check_egress blocks it.
        self.assertEqual(egress.resolve_host("a" * 64 + ".example.com"), [])
        allowed, _, reason = egress.check_egress("a" * 64 + ".example.com")
        self.assertFalse(allowed)
        self.assertEqual(reason, "unresolvable")

    def test_check_egress_public_ip_allowed(self):
        allowed, pinned, reason = egress.check_egress("8.8.8.8")
        self.assertTrue(allowed)
        self.assertEqual(pinned, "8.8.8.8")

    def test_check_egress_internal_ip_blocked(self):
        allowed, pinned, reason = egress.check_egress("127.0.0.1")
        self.assertFalse(allowed)
        self.assertIsNone(pinned)
        self.assertTrue(reason.startswith("internal-ip"))

    def test_check_egress_hard_guardrail(self):
        allowed, _, reason = egress.check_egress(
            "agency.gov", hard_blocked=lambda h: h.endswith(".gov"))
        self.assertFalse(allowed)
        self.assertEqual(reason, "hard-guardrail")

    def test_check_egress_empty_host(self):
        self.assertFalse(egress.check_egress("")[0])

    def test_hard_blocked_exception_fails_closed(self):
        def boom(_):
            raise RuntimeError("x")
        allowed, _, reason = egress.check_egress("1.1.1.1", hard_blocked=boom)
        self.assertFalse(allowed)

    # --- EgressPolicy toggles ---------------------------------------------
    def test_default_policy_matches_always_on(self):
        # Passing DEFAULT_POLICY explicitly == the old always-on behavior.
        self.assertTrue(egress.is_internal_ip("172.24.0.8"))
        self.assertTrue(egress.is_internal_ip("172.24.0.8", policy=egress.DEFAULT_POLICY))

    def test_relax_private_allows_rfc1918_only(self):
        p = egress.EgressPolicy(block_private=False)
        # RFC1918 now allowed...
        self.assertFalse(egress.is_internal_ip("172.24.0.8", policy=p))
        allowed, pinned, _ = egress.check_egress("172.24.0.8", policy=p)
        self.assertTrue(allowed)
        self.assertEqual(pinned, "172.24.0.8")
        # ...but loopback / link-local stay blocked by their own checks.
        self.assertTrue(egress.is_internal_ip("127.0.0.1", policy=p))
        self.assertTrue(egress.is_internal_ip("169.254.169.254", policy=p))

    def test_extra_blocked_enforced_even_when_private_relaxed(self):
        # The explicit denylist (WhiteHat service IPs) is never policy-gated.
        p = egress.EgressPolicy(block_private=False)
        self.assertTrue(egress.is_internal_ip("172.24.0.9", extra_blocked=["172.24.0.9"], policy=p))

    def test_policy_from_env_defaults_block(self):
        self.assertEqual(egress.policy_from_env({}), egress.DEFAULT_POLICY)
        p = egress.policy_from_env({"CAPTURE_EGRESS_BLOCK_PRIVATE": "false"})
        self.assertFalse(p.block_private)
        self.assertTrue(p.block_loopback)  # unrelated checks stay on
        # Only explicit false-like values relax a check; a typo keeps it blocking.
        self.assertTrue(egress.policy_from_env({"CAPTURE_EGRESS_BLOCK_PRIVATE": "flase"}).block_private)


class TestHeaders(unittest.TestCase):
    def test_normalize_lowercases_and_collapses_duplicates(self):
        h = cl.normalize_headers([("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("Server", "nginx")])
        self.assertEqual(h["set-cookie"], ["a=1", "b=2"])
        self.assertEqual(h["server"], "nginx")

    def test_cookie_flag_issues(self):
        issues = cl.cookie_flag_issues(["sid=1", "j=2; HttpOnly; Secure; SameSite=Lax"])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["cookie"], "sid")


class TestPassiveSignals(unittest.TestCase):
    def test_signals(self):
        sig = cl.passive_signals(
            req_headers={"authorization": "Bearer x"},
            resp_headers={"set-cookie": "sid=1"},
            query="?q=INJECTME", req_body=None, resp_body="<p>INJECTME echoed</p>")
        self.assertTrue(sig["hasSetCookie"])
        self.assertTrue(sig["hadAuth"])
        self.assertTrue(sig["reflectedParams"])
        self.assertIn("content-security-policy", sig["securityHeadersMissing"])

    def test_no_reflection_short_values(self):
        sig = cl.passive_signals({}, {}, "?a=1", None, "1 appears everywhere")
        self.assertFalse(sig["reflectedParams"])  # len < 4


def _decide(raw, *, family="text", rules=None, cap=1024, max_store=0, store=True):
    """decide_body with test defaults (Recommended rules unless overridden)."""
    return cl.decide_body(
        raw, family=family, rules=rules if rules is not None else cl.DEFAULT_BODY_RULES,
        inline_cap_bytes=cap, max_store_bytes=max_store, store=store)


class TestDecideBody(unittest.TestCase):
    def test_small_text_inline(self):
        inline, ref, size, sha = _decide(b"hello", family="text")
        self.assertEqual(inline, "hello")
        self.assertIsNone(ref)
        self.assertEqual(size, 5)
        self.assertIsNotNone(sha)

    def test_large_text_offloaded(self):
        inline, ref, size, sha = _decide(b"x" * 5000, family="text", cap=1024)
        self.assertIsNone(inline)
        self.assertEqual(ref, sha)
        self.assertEqual(size, 5000)

    def test_binary_family_auto_offloaded(self):
        # A binary family under 'auto' never inlines, even when small.
        inline, ref, size, sha = _decide(b"\x00\x01\x02", family="binary",
                                         rules={"binary": "auto"})
        self.assertIsNone(inline)
        self.assertEqual(ref, sha)

    def test_store_master_off(self):
        inline, ref, size, sha = _decide(b"hello", family="text", store=False)
        self.assertIsNone(inline)
        self.assertIsNone(ref)
        self.assertEqual(size, 5)      # size + sha still recorded
        self.assertIsNotNone(sha)

    def test_none_body(self):
        self.assertEqual(_decide(None), (None, None, 0, None))

    # ── policy matrix ──────────────────────────────────────────────────────
    def test_policy_meta_drops_bytes(self):
        # Recommended default: image -> meta. Small or large, bytes are dropped.
        inline, ref, size, sha = _decide(b"\x89PNG" + b"x" * 50, family="image")
        self.assertIsNone(inline)
        self.assertIsNone(ref)          # not offloaded either
        self.assertEqual(size, 54)
        self.assertIsNotNone(sha)       # metadata still kept

    def test_policy_disk_forces_offload_small_binary(self):
        # Recommended default: document -> disk, even a tiny one.
        inline, ref, size, sha = _decide(b"%PDF-1.4", family="document")
        self.assertIsNone(inline)
        self.assertEqual(ref, sha)

    def test_policy_inline_forces_db_over_size_but_falls_back(self):
        small = _decide(b"x" * 10, family="image", rules={"image": "inline"}, cap=1024)
        self.assertEqual(small[0], "x" * 10)       # forced inline
        big = _decide(b"x" * 2000, family="image", rules={"image": "inline"}, cap=1024)
        self.assertIsNone(big[0])                  # too big to inline -> disk
        self.assertEqual(big[1], big[3])

    def test_max_store_ceiling_drops_to_meta(self):
        # document -> disk, but a hard 1 KB ceiling forces metadata-only.
        inline, ref, size, sha = _decide(b"x" * 2000, family="document", max_store=1024)
        self.assertIsNone(inline)
        self.assertIsNone(ref)          # ceiling wins over 'disk'
        self.assertEqual(size, 2000)
        self.assertIsNotNone(sha)

    def test_max_store_ceiling_zero_means_unlimited(self):
        inline, ref, size, sha = _decide(b"x" * 10_000, family="document", max_store=0)
        self.assertEqual(ref, sha)      # offloaded, no ceiling

    def test_json_auto_inline(self):
        inline, ref, _, _ = _decide(b'{"a":1}', family="json")
        self.assertEqual(inline, '{"a":1}')

    def test_ceiling_below_inline_cap_drops_small_text(self):
        # A ceiling smaller than the body forces meta even for small inline text.
        inline, ref, size, sha = _decide(b"x" * 100, family="text", cap=1024, max_store=50)
        self.assertIsNone(inline)
        self.assertIsNone(ref)
        self.assertEqual(size, 100)
        self.assertIsNotNone(sha)

    def test_negative_ceiling_means_unlimited(self):
        # Defensive: a negative max_store is treated as no ceiling (like 0).
        inline, ref, size, sha = _decide(b"x" * 5000, family="document", max_store=-1)
        self.assertEqual(ref, sha)     # offloaded, not dropped

    def test_meta_policy_ignores_ceiling_and_cap(self):
        # meta drops regardless of size or ceiling; sha/size still recorded.
        inline, ref, size, sha = _decide(b"x" * 3, family="image", max_store=999999)
        self.assertIsNone(inline)
        self.assertIsNone(ref)
        self.assertEqual(size, 3)
        self.assertIsNotNone(sha)


class TestClassifyFamily(unittest.TestCase):
    def test_by_content_type(self):
        cases = {
            "text/html; charset=utf-8": "text",
            "application/json": "json",
            "text/css": "text",
            "application/javascript": "script",
            "image/png": "image",
            "font/woff2": "font",
            "video/mp4": "video",
            "audio/mpeg": "audio",
            "application/pdf": "document",
            "application/zip": "archive",
            "application/octet-stream": "binary",
            "application/wasm": "binary",
        }
        for ct, fam in cases.items():
            self.assertEqual(cl.classify_family(ct), fam, ct)

    def test_octet_stream_reclassified_by_extension(self):
        # The real-world woff2-as-octet-stream case that started all this.
        self.assertEqual(
            cl.classify_family("application/octet-stream", "/static/f/Game.woff2"), "font")
        self.assertEqual(
            cl.classify_family("application/octet-stream", "/dl/report.pdf"), "document")
        # A genuine octet-stream download with no telling extension stays binary.
        self.assertEqual(cl.classify_family("application/octet-stream", "/dl/blob"), "binary")

    def test_extension_fallback_when_no_content_type(self):
        self.assertEqual(cl.classify_family(None, "/a/b/logo.PNG"), "image")
        self.assertEqual(cl.classify_family("", "/x.woff2?v=3"), "font")

    def test_unknown_is_other(self):
        self.assertEqual(cl.classify_family("application/x-weird-thing", "/x"), "other")
        self.assertEqual(cl.classify_family(None, None), "other")

    def test_ambiguous_content_types_resolve_by_precedence(self):
        # document is checked before text, so text/rtf is a document not text.
        self.assertEqual(cl.classify_family("text/rtf", "/x"), "document")
        # script is checked before text, so text/javascript is a script.
        self.assertEqual(cl.classify_family("text/javascript", "/a.js"), "script")
        # image is checked before text, so image/svg+xml is an image (not xml/text).
        self.assertEqual(cl.classify_family("image/svg+xml", "/logo.svg"), "image")
        # +json suffix types are json.
        self.assertEqual(cl.classify_family("application/ld+json", "/x"), "json")
        self.assertEqual(cl.classify_family("application/manifest+json", "/x"), "json")
        # application/xml is text-family.
        self.assertEqual(cl.classify_family("application/xml", "/x"), "text")
        # explicit font content-type.
        self.assertEqual(cl.classify_family("application/font-woff", "/x"), "font")

    def test_dot_in_directory_not_treated_as_extension(self):
        # "/a.b/c" has a dot in the DIRECTORY, not the filename -> no ext family.
        self.assertEqual(cl.classify_family("", "/a.b/c"), "other")
        # trailing-slash path, no filename.
        self.assertEqual(cl.classify_family(None, "/dir/"), "other")

    def test_explicit_content_type_wins_over_mismatched_extension(self):
        # A real image content-type is trusted over a misleading .pdf path.
        self.assertEqual(cl.classify_family("image/png", "/x.pdf"), "image")
        # Only the generic octet-stream defers to the extension.
        self.assertEqual(cl.classify_family("application/octet-stream", "/x.pdf"), "document")

    def test_every_classified_family_has_a_default_rule(self):
        # Guard against drift: any family classify_family can emit must be a key in
        # DEFAULT_BODY_RULES, else decide_body silently falls back to 'auto'.
        emit = set(fam for fam, _ in cl._CT_FAMILY) | set(cl._EXT_FAMILY.values()) | {"other"}
        for fam in emit:
            self.assertIn(fam, cl.DEFAULT_BODY_RULES, fam)


class TestParseBodyRules(unittest.TestCase):
    def test_empty_returns_recommended_defaults(self):
        self.assertEqual(cl.parse_body_rules(""), cl.DEFAULT_BODY_RULES)
        self.assertEqual(cl.parse_body_rules(None), cl.DEFAULT_BODY_RULES)

    def test_override_merges_over_defaults(self):
        rules = cl.parse_body_rules('{"image": "disk", "document": "meta"}')
        self.assertEqual(rules["image"], "disk")     # overridden
        self.assertEqual(rules["document"], "meta")  # overridden
        self.assertEqual(rules["json"], "auto")      # default preserved

    def test_invalid_family_or_policy_ignored(self):
        rules = cl.parse_body_rules('{"image": "banana", "bogusfam": "disk"}')
        self.assertEqual(rules["image"], "meta")     # bad policy ignored -> default
        self.assertNotIn("bogusfam", rules)          # unknown family dropped

    def test_malformed_json_falls_back_to_defaults(self):
        self.assertEqual(cl.parse_body_rules("{not json"), cl.DEFAULT_BODY_RULES)

    def test_accepts_dict_directly(self):
        rules = cl.parse_body_rules({"font": "disk"})
        self.assertEqual(rules["font"], "disk")


class TestBuildRecord(unittest.TestCase):
    def test_ctx_token_carried_verbatim(self):
        rec = cl.build_record(
            ctx_token="TOKEN.SIG", method="GET", scheme="https", host="x.example",
            port=443, path="/", query="", req_headers={}, resp_headers={"set-cookie": "s=1"},
            status_code=200, req_body_inline=None, req_body_ref=None, req_body_size=0,
            req_body_sha=None, resp_body_inline="hi", resp_body_ref=None, resp_body_size=2,
            resp_body_sha="abc", http_version="HTTP/2", is_tls=True, tls_version="TLSv1.3",
            target_ip="93.184.216.34", response_time_ms=12, started_at="2026-07-19T00:00:00Z")
        self.assertEqual(rec["ctx_token"], "TOKEN.SIG")
        self.assertTrue(rec["hasSetCookie"])
        self.assertTrue(rec["isTls"])
        self.assertEqual(rec["targetIp"], "93.184.216.34")


class TestEnsureDirWritable(unittest.TestCase):
    """Issue #159: a root-initialised spool volume must fail with an actionable
    message, not a bare EACCES traceback repeated forever by restart=unless-stopped."""

    def test_creates_nested_dir_and_returns_it(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "spool", ".tmp")
            self.assertEqual(cl.ensure_dir_writable(target), target)
            self.assertTrue(os.path.isdir(target))

    def test_existing_dir_is_a_noop(self):
        with tempfile.TemporaryDirectory() as d:
            cl.ensure_dir_writable(d)  # exist_ok, must not raise

    @unittest.skipIf(os.getuid() == 0, "root ignores directory permissions")
    def test_unwritable_parent_raises_actionable_error(self):
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "spool")
            os.makedirs(parent)
            os.chmod(parent, 0o555)  # r-xr-xr-x, like a root:root 0755 volume
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    cl.ensure_dir_writable(os.path.join(parent, ".tmp"))
            finally:
                os.chmod(parent, 0o755)  # so TemporaryDirectory can clean up
            msg = str(ctx.exception)
            self.assertIn(parent, msg)
            self.assertIn(f"uid={os.getuid()}", msg)
            self.assertIn("chmod 0777", msg)          # the repair command
            self.assertIn("whitehat_capture_spool", msg)  # names the volume

    def test_non_permission_oserror_is_not_swallowed(self):
        # ENOTDIR (a file where a dir should be) is a different bug; let it surface
        # as-is rather than mislabelling it a volume-ownership problem.
        with tempfile.TemporaryDirectory() as d:
            blocker = os.path.join(d, "spool")
            with open(blocker, "w") as fh:
                fh.write("x")
            with self.assertRaises(OSError) as ctx:
                cl.ensure_dir_writable(os.path.join(blocker, ".tmp"))
            self.assertNotIsInstance(ctx.exception, RuntimeError)


if __name__ == "__main__":
    unittest.main()
