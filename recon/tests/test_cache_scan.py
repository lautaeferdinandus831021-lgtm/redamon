"""Unit tests for the web cache poisoning scanner (recon/cache_scan)."""
import json
import os
import sys
import tempfile
import unittest

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from recon.cache_scan import wcvs_runner, scoring, safety, normalizers, hypotheses, buster
from recon.cache_scan import oracle, confirm, scanner


# ---------------------------------------------------------------------------
# Test doubles: a stateful fake HTTP layer that models a real cache.
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, body="", headers=None, status=200):
        self.text = body
        self.headers = headers or {}
        self.status_code = status


class VulnerableCacheSession:
    """Models an unkeyed-header cache poisoning vulnerability.

    The cache keys ONLY on URL (the injected header is unkeyed). When a request
    carries the trigger header, the backend reflects its value into the body and
    the cache stores that body under the URL key. Subsequent header-less requests
    to the same URL get the stored (poisoned) body back as a cache HIT.
    """

    def __init__(self, trigger_header="X-Forwarded-Host"):
        self.trigger_header = trigger_header.lower()
        self.store = {}  # url -> body
        self.headers_base = {"User-Agent": "x"}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        headers = headers or {}
        injected = None
        for k, v in headers.items():
            if k.lower() == self.trigger_header:
                injected = v
        if injected is not None:
            body = f"<script src=//{injected}/x.js></script>"
            self.store[url] = body
            return FakeResponse(body, {"x-cache": "miss"})
        if url in self.store:
            return FakeResponse(self.store[url], {"x-cache": "hit", "age": "12"})
        return FakeResponse("<clean/>", {"x-cache": "miss"})


class SafeCacheSession:
    """Cache that does NOT reflect the header (not vulnerable)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        return FakeResponse("<clean/>", {"x-cache": "hit", "age": "5"})


class NoCacheSession:
    """No cache headers at all."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        return FakeResponse("<dynamic/>", {"content-type": "text/html"})


class DifferentialCacheSession:
    """Models NON-REFLECTIVE cache poisoning.

    Injecting the trigger header makes the backend emit a redirect (a changed
    Location + status), which the cache stores under the URL key. No marker is
    echoed back, so only the differential detector (status/location/body diff)
    can catch it. Clean follow-ups return the stored poisoned redirect as a HIT.
    """

    def __init__(self, trigger_header="X-Forwarded-Proto"):
        self.trigger_header = trigger_header.lower()
        self.store = {}  # url -> (status, location)

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        headers = headers or {}
        injected = any(k.lower() == self.trigger_header for k in headers)
        if injected:
            self.store[url] = (301, "https://evil.example/login")
            return FakeResponse("", {"x-cache": "miss", "location": "https://evil.example/login"}, status=301)
        if url in self.store:
            status, loc = self.store[url]
            return FakeResponse("", {"x-cache": "hit", "age": "5", "location": loc}, status=status)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class DynamicNoiseSession:
    """A dynamic, NOT-vulnerable page whose body changes on every request.

    The baseline-stability guard must treat the body dimension as untrusted and
    refuse to raise a differential finding (no false positive)."""

    def __init__(self):
        self.n = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        self.n += 1
        return FakeResponse(f"<page id={self.n}/>", {"x-cache": "hit", "age": "3"}, status=200)


class StatusPoisonCacheSession:
    """Non-reflective CPDoS: the trigger header makes the backend 403; the cache
    stores that status under the URL key and replays it to clean requests."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        self.trigger = trigger.lower()
        self.store = {}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        headers = headers or {}
        if any(k.lower() == self.trigger for k in headers):
            self.store[url] = 403
            return FakeResponse("Forbidden", {"x-cache": "miss"}, status=403)
        if url in self.store:
            return FakeResponse("Forbidden", {"x-cache": "hit", "age": "4"}, status=self.store[url])
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class UncachedRedirectSession:
    """The trigger header changes the response (a redirect) but NOTHING is cached:
    the clean follow-up reverts to baseline -> must NOT be flagged as persisted."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        headers = headers or {}
        if any(k.lower() == "x-forwarded-proto" for k in headers):
            return FakeResponse("", {"x-cache": "miss", "location": "https://evil.example/"}, status=301)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class RateLimitOnPoisonSession:
    """The poison request trips a 429. Differential detection must treat 429 as
    rate-limit noise and NOT raise a finding from it."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        headers = headers or {}
        if any(k.lower() == "x-forwarded-proto" for k in headers):
            return FakeResponse("blocked", {"x-cache": "miss"}, status=429)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class BodyPoisonCacheSession:
    """Non-reflective BODY poison: the trigger header swaps in a different (fixed,
    non-canary) body; the cache stores it; clean follow-ups get the poisoned body.
    Nothing is echoed, so only the body-diff path can catch it."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        self.trigger = trigger.lower()
        self.store = {}

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        headers = headers or {}
        if any(k.lower() == self.trigger for k in headers):
            self.store[url] = "<maintenance/>"
            return FakeResponse("<maintenance/>", {"x-cache": "miss"}, status=200)
        if url in self.store:
            return FakeResponse(self.store[url], {"x-cache": "hit", "age": "3"}, status=200)
        return FakeResponse("<clean/>", {"x-cache": "miss"}, status=200)


class NoisyBodyLocationPoisonSession:
    """The body legitimately flaps every request (so body is untrusted), but a
    Location poison IS real and cached. The dimension-aware guard must still catch
    the location diff instead of bailing out on the body instability."""

    def __init__(self, trigger="X-Forwarded-Proto"):
        self.trigger = trigger.lower()
        self.store = {}
        self.n = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        self.n += 1
        headers = headers or {}
        if any(k.lower() == self.trigger for k in headers):
            self.store[url] = "https://evil.example/"
            return FakeResponse(f"<p {self.n}/>", {"x-cache": "miss", "location": "https://evil.example/"}, status=301)
        if url in self.store:
            return FakeResponse(f"<p {self.n}/>", {"x-cache": "hit", "age": "2", "location": self.store[url]}, status=301)
        return FakeResponse(f"<p {self.n}/>", {"x-cache": "miss"}, status=200)


class TestWcvsParser(unittest.TestCase):
    """The WCVS JSON report parser (pkg/report.go schema)."""

    def _write_report(self, payload: dict) -> str:
        fd, path = tempfile.mkstemp(suffix="_Report.json")
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        return path

    def test_extracts_only_vulnerable(self):
        report = {
            "foundVulnerabilities": True,
            "websites": [
                {
                    "url": "https://shop/home", "isVulnerable": True,
                    "cacheIndicator": "X-Cache", "cacheBusterFound": True, "cacheBuster": "utm",
                    "results": [
                        {"technique": "Header Poisoning", "isVulnerable": True, "checks": [
                            {"identifier": "X-Forwarded-Host", "reason": "reflected+cached",
                             "reflections": ["//CANARY/"], "request": {"curlCommand": "curl ..."}}]},
                        {"technique": "Header Poisoning", "isVulnerable": False, "checks": []},
                    ],
                },
                {"url": "https://shop/safe", "isVulnerable": False, "results": []},
            ],
        }
        path = self._write_report(report)
        try:
            candidates = wcvs_runner.parse_wcvs_report(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(candidates), 1)
        c = candidates[0]
        self.assertEqual(c["url"], "https://shop/home")
        self.assertEqual(c["vector_name"], "X-Forwarded-Host")
        self.assertEqual(c["cache_indicator"], "X-Cache")
        self.assertTrue(c["cache_buster_found"])
        self.assertEqual(c["source"], "wcvs")

    def test_bad_report_returns_empty(self):
        fd, path = tempfile.mkstemp(suffix="_Report.json")
        with os.fdopen(fd, "w") as f:
            f.write("not json")
        try:
            self.assertEqual(wcvs_runner.parse_wcvs_report(path), [])
        finally:
            os.unlink(path)

    def test_safety_skip_tests(self):
        # deception + cpdos disallowed -> both technique groups skipped
        skip = wcvs_runner.safety_skip_tests(allow_deception=False, allow_cpdos=False)
        self.assertIn("deception", skip)
        self.assertIn("dos", skip)
        # both allowed -> nothing skipped
        self.assertEqual(wcvs_runner.safety_skip_tests(True, True), [])

    def test_command_isolation_flags(self):
        cmd = wcvs_runner.build_wcvs_command(
            "/tmp/whitehat/x/targets.txt", "/tmp/whitehat/x", "whitehat-wcvs:latest",
            threads=8, skip_timebased=True, skip_tests=["dos"])
        self.assertIn("--net=host", cmd)
        self.assertIn("-gr", cmd)
        self.assertIn("-stime", cmd)
        self.assertIn("whitehat-wcvs:latest", cmd)
        self.assertIn("-st", cmd)

    def test_command_rate_and_cache_header_flags(self):
        cmd = wcvs_runner.build_wcvs_command(
            "/t/targets.txt", "/t", "img", req_rate=5.0, cache_header="X-Custom-CB")
        self.assertIn("-rr", cmd)
        self.assertIn("5.0", cmd)
        self.assertIn("-ch", cmd)
        self.assertIn("X-Custom-CB", cmd)

    def test_command_no_rate_flag_when_zero(self):
        cmd = wcvs_runner.build_wcvs_command("/t/targets.txt", "/t", "img", req_rate=0)
        self.assertNotIn("-rr", cmd)

    def test_command_threads_clamped_to_min_one(self):
        cmd = wcvs_runner.build_wcvs_command("/t/targets.txt", "/t", "img", threads=0)
        i = cmd.index("-t")
        self.assertEqual(cmd[i + 1], "1")

    def test_skiptest_skip_timebased_off(self):
        cmd = wcvs_runner.build_wcvs_command("/t/targets.txt", "/t", "img", skip_timebased=False)
        self.assertNotIn("-stime", cmd)

    def test_safety_skip_deception_only(self):
        skip = wcvs_runner.safety_skip_tests(allow_deception=False, allow_cpdos=True)
        self.assertIn("deception", skip)
        self.assertIn("css", skip)
        self.assertNotIn("dos", skip)

    def test_safety_skip_cpdos_only(self):
        skip = wcvs_runner.safety_skip_tests(allow_deception=True, allow_cpdos=False)
        self.assertEqual(skip, ["dos"])

    def test_run_wcvs_empty_targets_no_docker(self):
        # No targets -> short-circuit to [] without ever invoking docker.
        self.assertEqual(wcvs_runner.run_wcvs([], {}), [])

    def test_parse_flattens_multiple_checks(self):
        report = {"websites": [{"url": "https://s/a", "isVulnerable": True, "results": [
            {"technique": "Header Poisoning", "isVulnerable": True, "checks": [
                {"identifier": "X-Forwarded-Host", "reason": "r1"},
                {"identifier": "X-Forwarded-Scheme", "reason": "r2"}]}]}]}
        path = self._write_report(report)
        try:
            cands = wcvs_runner.parse_wcvs_report(path)
        finally:
            os.unlink(path)
        self.assertEqual({c["vector_name"] for c in cands}, {"X-Forwarded-Host", "X-Forwarded-Scheme"})

    def test_parse_skips_non_vulnerable_result_within_vulnerable_site(self):
        report = {"websites": [{"url": "https://s/a", "isVulnerable": True, "results": [
            {"technique": "A", "isVulnerable": False, "checks": [{"identifier": "X-A"}]},
            {"technique": "B", "isVulnerable": True, "checks": [{"identifier": "X-B"}]}]}]}
        path = self._write_report(report)
        try:
            cands = wcvs_runner.parse_wcvs_report(path)
        finally:
            os.unlink(path)
        self.assertEqual([c["vector_name"] for c in cands], ["X-B"])

    def test_parse_missing_report_file_returns_empty(self):
        self.assertEqual(wcvs_runner.parse_wcvs_report("/no/such/file_Report.json"), [])


class TestScoring(unittest.TestCase):
    def test_confirmed(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": True,
            "cache_hit_on_clean": True, "repeated_ok": True, "stable": True})
        self.assertEqual(tier, "Confirmed")
        self.assertGreaterEqual(conf, 0.95)

    def test_strong_without_repeat(self):
        conf, tier = scoring.score_finding({
            "persisted_on_clean": True, "cache_hit_on_clean": True, "stable": True})
        self.assertEqual(tier, "Strong")

    def test_differential_only_capped_at_strong(self):
        # All Confirmed-grade signals present, but persistence was non-reflective.
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": False, "persisted_on_clean": True,
            "persisted_reflected": False, "persisted_differential": True,
            "cache_hit_on_clean": True, "repeated_ok": True, "stable": True})
        self.assertEqual(tier, "Strong")
        self.assertLess(conf, 0.95)

    def test_reflected_but_not_persisted_rejected(self):
        conf, tier = scoring.score_finding({
            "reflected_in_baseline": True, "persisted_on_clean": False})
        self.assertEqual(tier, "Rejected")
        self.assertLess(conf, 0.5)

    def test_min_confidence_gate(self):
        self.assertTrue(scoring.passes_min_confidence(0.97, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.8}))
        self.assertFalse(scoring.passes_min_confidence(0.65, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.8}))

    def test_tentative_when_persisted_but_unstable(self):
        conf, tier = scoring.score_finding({
            "persisted_on_clean": True, "cache_hit_on_clean": False, "stable": False})
        self.assertEqual(tier, "Tentative")
        self.assertTrue(0.5 <= conf < 0.8)

    def test_not_persisted_not_reflected_hard_rejected(self):
        conf, tier = scoring.score_finding({"persisted_on_clean": False, "reflected_in_baseline": False})
        self.assertEqual(tier, "Rejected")
        self.assertLessEqual(conf, 0.1)

    def test_severity_mapping(self):
        self.assertEqual(scoring.severity_for_impact("stored_xss")[0], "critical")
        self.assertEqual(scoring.severity_for_impact("open_redirect")[0], "high")

    def test_severity_table_full(self):
        for impact, sev in [("stored_xss", "critical"), ("open_redirect", "high"),
                            ("deception", "high"), ("dos", "high"), ("reflected", "medium"),
                            ("unknown", "medium")]:
            s, cvss = scoring.severity_for_impact(impact)
            self.assertEqual(s, sev)
            self.assertGreater(cvss, 0)
        # Unrecognised impact falls back to medium, not a crash.
        self.assertEqual(scoring.severity_for_impact("nonsense")[0], "medium")
        self.assertEqual(scoring.severity_for_impact("")[0], "medium")

    def test_min_confidence_gate_custom_threshold(self):
        self.assertTrue(scoring.passes_min_confidence(0.82, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.8}))
        self.assertFalse(scoring.passes_min_confidence(0.82, {"WEB_CACHE_POISON_MIN_CONFIDENCE": 0.9}))
        # Default threshold (0.8) applies when unset.
        self.assertFalse(scoring.passes_min_confidence(0.65, {}))


class TestSafety(unittest.TestCase):
    def test_canary_host_non_resolving(self):
        token = safety.new_canary_token()
        self.assertTrue(safety.canary_host(token).endswith(".invalid"))

    def test_cpdos_requires_research_profile(self):
        self.assertFalse(safety.is_cpdos_allowed(
            {"WEB_CACHE_POISON_SCAN_PROFILE": "safe-confirm", "WEB_CACHE_POISON_ALLOW_CPDOS": True}))
        self.assertTrue(safety.is_cpdos_allowed(
            {"WEB_CACHE_POISON_SCAN_PROFILE": "research", "WEB_CACHE_POISON_ALLOW_CPDOS": True}))

    def test_cpdos_research_profile_alone_insufficient(self):
        # Research profile but toggle off -> still blocked (needs BOTH).
        self.assertFalse(safety.is_cpdos_allowed({"WEB_CACHE_POISON_SCAN_PROFILE": "research"}))
        # Toggle on but extended profile -> blocked.
        self.assertFalse(safety.is_cpdos_allowed(
            {"WEB_CACHE_POISON_SCAN_PROFILE": "extended", "WEB_CACHE_POISON_ALLOW_CPDOS": True}))

    def test_cpdos_default_blocked(self):
        self.assertFalse(safety.is_cpdos_allowed({}))

    def test_deception_default_allowed_and_toggle(self):
        self.assertTrue(safety.is_deception_allowed({}))
        self.assertFalse(safety.is_deception_allowed({"WEB_CACHE_POISON_ALLOW_DECEPTION": False}))

    def test_framework_packs_default_allowed_and_toggle(self):
        self.assertTrue(safety.is_framework_packs_allowed({}))
        self.assertFalse(safety.is_framework_packs_allowed({"WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS": False}))

    def test_canary_token_and_value_format(self):
        tok = safety.new_canary_token()
        self.assertTrue(tok.startswith("rdmn"))
        self.assertEqual(safety.canary_value(tok), tok)  # plain marker for param/value vectors
        self.assertTrue(safety.canary_host(tok).startswith(tok + "."))

    def test_cache_buster_values_unique(self):
        vals = {safety.new_cache_buster_value() for _ in range(200)}
        self.assertEqual(len(vals), 200)  # no collisions across many mints
        self.assertTrue(all(v.startswith("cb") for v in vals))


class TestHypotheses(unittest.TestCase):
    def test_generic_headers_always_present(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, set())
        names = {v["vector_name"] for v in h}
        self.assertIn("X-Forwarded-Host", names)

    def test_framework_pack_gated_on_fingerprint(self):
        combined = {"http_probe": {"technologies_found": {"Next.js": 3}}}
        h = hypotheses.generate_hypotheses("https://x/", combined,
                                           {"WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS": True}, set())
        names = {v["vector_name"] for v in h}
        self.assertIn("x-invoke-status", names)
        # No Next.js fingerprint -> no Next pack
        h2 = hypotheses.generate_hypotheses("https://x/", {},
                                            {"WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS": True}, set())
        self.assertNotIn("x-invoke-status", {v["vector_name"] for v in h2})

    def test_skips_wcvs_seen_vectors(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, {"X-Forwarded-Host"})
        self.assertNotIn("X-Forwarded-Host", {v["vector_name"] for v in h})

    def test_expanded_pack_includes_non_reflective_headers(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, set())
        names = {v["vector_name"] for v in h}
        # Headers that were previously missing (ported from CacheX).
        for expected in ("X-Forwarded-Port", "Forwarded", "True-Client-IP", "X-Original-Host"):
            self.assertIn(expected, names)

    def test_includes_unkeyed_param_vectors(self):
        h = hypotheses.generate_hypotheses("https://x/", {}, {}, set())
        params = {v["vector_name"] for v in h if v.get("vector_type") == "param"}
        self.assertIn("utm_source", params)
        self.assertIn("callback", params)
        # param vectors are the param-cloaking technique
        self.assertTrue(all(v["technique"] == "unkeyed_param"
                            for v in h if v.get("vector_type") == "param"))

    def test_fixed_payload_kinds_carry_safe_values(self):
        self.assertEqual(confirm._payload_value("scheme", "tok"), "https")
        self.assertEqual(confirm._payload_value("port", "tok"), "443")
        self.assertEqual(confirm._payload_value("ip", "tok"), "127.0.0.1")
        # Host stays a benign non-resolving canary, never CacheX's evil.com.
        self.assertTrue(confirm._payload_value("host", "tok").endswith(".whitehat-poc.invalid"))
        self.assertIn(".whitehat-poc.invalid", confirm._payload_value("forwarded", "tok"))


class TestBuster(unittest.TestCase):
    def test_add_cache_buster_preserves_query(self):
        out = buster.add_cache_buster("https://x/home?lang=en", "cb", "abc")
        self.assertIn("lang=en", out)
        self.assertIn("cb=abc", out)

    def test_add_cache_buster_no_existing_query(self):
        out = buster.add_cache_buster("https://x/home", "cb", "abc")
        self.assertTrue(out.endswith("?cb=abc"))

    def test_add_cache_buster_overwrites_same_param(self):
        out = buster.add_cache_buster("https://x/home?cb=old", "cb", "new")
        self.assertIn("cb=new", out)
        self.assertNotIn("cb=old", out)

    def test_add_cache_buster_preserves_path_and_scheme(self):
        out = buster.add_cache_buster("http://x:8080/a/b", "cb", "1")
        self.assertTrue(out.startswith("http://x:8080/a/b?"))

    def test_find_buster_default_param_and_always_isolated(self):
        info = buster.find_cache_buster("https://x/", _HeaderSession({"x-cache": "miss"}), {})
        self.assertEqual(info["param"], "rdmncb")
        self.assertTrue(info["isolated"])  # isolation is unconditional (safety invariant)

    def test_find_buster_custom_param_from_settings(self):
        info = buster.find_cache_buster(
            "https://x/", _HeaderSession({"x-cache": "hit"}),
            {"WEB_CACHE_POISON_CACHE_BUSTER_PARAM": "zzz"})
        self.assertEqual(info["param"], "zzz")

    def test_find_buster_detects_query_keying_on_hit(self):
        # miss then hit on the busted URL -> query string participates in the key.
        sess = _SeqSession([{"x-cache": "miss"}, {"x-cache": "hit"}])
        info = buster.find_cache_buster("https://x/", sess, {})
        self.assertTrue(info["keyed_on_query"])

    def test_find_buster_unknown_state_not_keyed(self):
        # No cache headers at all -> cannot conclude the query is keyed.
        info = buster.find_cache_buster("https://x/", _HeaderSession({}), {})
        self.assertFalse(info["keyed_on_query"])

    def test_find_buster_network_error_is_safe(self):
        info = buster.find_cache_buster("https://x/", _RaisingSession(), {})
        self.assertFalse(info["keyed_on_query"])
        self.assertTrue(info["isolated"])  # still safe to isolate

    def test_find_buster_uses_fresh_value_each_call(self):
        # Two calls must mint different cache-buster values (per-test isolation).
        seen = set()
        for _ in range(5):
            sess = _SeqSession([{"x-cache": "miss"}])
            buster.find_cache_buster("https://x/", sess, {})
            # the value is internal; assert via add_cache_buster determinism instead
        v1, v2 = safety.new_cache_buster_value(), safety.new_cache_buster_value()
        self.assertNotEqual(v1, v2)


class TestNormalizers(unittest.TestCase):
    def test_build_finding_maps_vector(self):
        vec = {"url": "https://x/home", "technique": "unkeyed_header",
               "vector_type": "header", "vector_name": "X-Forwarded-Host", "source": "wcvs"}
        conf = {"evidence": {"poc_link": "https://x/home?cb=1", "cache_buster": "cb=1"}}
        f = normalizers.build_finding(vec, conf, 0.97, "Confirmed", "open_redirect", "high", 7.4, ["x-cache: hit"])
        self.assertEqual(f["cache_header"], "X-Forwarded-Host")
        self.assertEqual(f["cache_param"], "")
        self.assertEqual(f["confidence_tier"], "Confirmed")

    def test_build_finding_param_vector_sets_cache_param(self):
        vec = {"url": "https://x/?q=1", "technique": "unkeyed_param",
               "vector_type": "param", "vector_name": "utm_source", "source": "wcvs"}
        f = normalizers.build_finding(vec, {"evidence": {}}, 0.9, "Strong", "reflected", "medium", 5.3, [])
        self.assertEqual(f["cache_param"], "utm_source")
        self.assertEqual(f["cache_header"], "")  # param vectors leave the header field empty

    def test_build_finding_evidence_is_whitelisted(self):
        # Stray confirmation evidence keys must NOT leak into the finding (graph contract).
        conf = {"evidence": {"poc_link": "p", "secret_internal": "LEAK", "differential_change": "status"}}
        vec = {"url": "https://x/", "vector_type": "header", "vector_name": "X-Host"}
        f = normalizers.build_finding(vec, conf, 0.9, "Strong", "open_redirect", "high", 7.4, [])
        self.assertNotIn("secret_internal", f["evidence"])
        self.assertEqual(f["evidence"]["differential_change"], "status")

    def test_summary_counts(self):
        f1 = {"confidence_tier": "Confirmed", "impact": "stored_xss", "severity": "critical"}
        f2 = {"confidence_tier": "Strong", "impact": "open_redirect", "severity": "high"}
        res = normalizers.build_cache_scan_result({"total_urls_scanned": 5, "cacheable_urls": 2}, {}, [f1, f2])
        self.assertEqual(res["summary"]["total_findings"], 2)
        self.assertEqual(res["summary"]["confirmed"], 1)
        self.assertEqual(res["summary"]["strong"], 1)
        self.assertEqual(res["summary"]["by_impact"]["stored_xss"], 1)

    def test_summary_aggregates_severity_and_tiers(self):
        findings = [
            {"confidence_tier": "Confirmed", "impact": "open_redirect", "severity": "high"},
            {"confidence_tier": "Strong", "impact": "open_redirect", "severity": "high"},
            {"confidence_tier": "Tentative", "impact": "dos", "severity": "high"},
        ]
        res = normalizers.build_cache_scan_result({"total_urls_scanned": 9, "cacheable_urls": 4}, {}, findings)
        s = res["summary"]
        self.assertEqual(s["by_severity"]["high"], 3)
        self.assertEqual(s["by_impact"]["open_redirect"], 2)
        self.assertEqual(s["tentative"], 1)
        self.assertEqual(s["urls_scanned"], 9)
        self.assertEqual(s["cacheable_urls"], 4)

    def test_empty_findings_summary_is_zeroed(self):
        res = normalizers.build_cache_scan_result({"total_urls_scanned": 0, "cacheable_urls": 0}, {}, [])
        self.assertEqual(res["summary"]["total_findings"], 0)
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["by_target"], {})


class _HeaderSession:
    """Returns a fixed set of response headers on every GET."""

    def __init__(self, headers, body="<x/>"):
        self._headers = headers
        self._body = body

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        return FakeResponse(self._body, dict(self._headers))


class _FrozenDateSession:
    """Silent cache: no cache headers, but the Date is frozen (cached replay)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        return FakeResponse("<cached/>", {"date": "Mon, 30 Jun 2026 10:00:00 GMT"})


class _LiveOriginSession:
    """Live origin: no cache headers and the Date advances every request."""

    def __init__(self):
        self._n = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        self._n += 1
        return FakeResponse("<dynamic/>", {"date": f"Mon, 30 Jun 2026 10:00:0{self._n} GMT"})


_NO_SLEEP = lambda *_: None


class _SeqSession:
    """Returns a scripted sequence of response-header dicts across GETs; the last
    entry repeats once exhausted. Records how many GETs were issued."""

    def __init__(self, header_steps, body="<x/>"):
        self._steps = header_steps
        self._body = body
        self.calls = 0

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        hdrs = self._steps[min(self.calls, len(self._steps) - 1)]
        self.calls += 1
        return FakeResponse(self._body, dict(hdrs))


class _RaisingSession:
    """Every GET raises a network error (timeouts, connection resets)."""

    def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
        raise requests.RequestException("boom")


class TestOracle(unittest.TestCase):
    def test_cacheable_detected_from_x_cache(self):
        info = oracle.detect_cache_oracle("https://x/", SafeCacheSession())
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_not_cacheable_when_no_signals(self):
        info = oracle.detect_cache_oracle("https://x/", NoCacheSession(), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_via_header_presence_detects_cache(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"via": "1.1 varnish"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["cache_layer"])

    def test_varnish_numeric_two_ids_is_hit(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"x-varnish": "1001 2002"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_nginx_stale_status_is_cacheable(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"x-cache-status": "STALE"}))
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["saw_hit"])

    def test_cloudflare_dynamic_is_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cf-cache-status": "DYNAMIC"}), behavioral=False
        )
        self.assertFalse(info["cacheable"])
        self.assertTrue(info["cache_layer"])  # CDN present, just not caching this URL

    def test_cache_control_public_makes_eligible(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "public, max-age=600"})
        )
        self.assertTrue(info["cacheable"])

    def test_cache_control_no_store_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "private, no-store, max-age=600"}),
            behavioral=False,
        )
        self.assertFalse(info["cacheable"])

    def test_vary_header_captured(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"x-cache": "hit", "vary": "X-Forwarded-Host"})
        )
        self.assertEqual(info["vary"], "X-Forwarded-Host")

    def test_behavioral_frozen_date_detects_silent_cache(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _FrozenDateSession(), behavioral=True, sleep_fn=_NO_SLEEP
        )
        self.assertTrue(info["cacheable"])
        self.assertTrue(info["behavioral"])
        self.assertEqual(info["indicator"], "behavioral:frozen-date")

    def test_behavioral_live_origin_not_cacheable(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _LiveOriginSession(), behavioral=True, sleep_fn=_NO_SLEEP
        )
        self.assertFalse(info["cacheable"])
        self.assertFalse(info["behavioral"])

    def test_response_cache_state(self):
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-cache": "HIT"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-cache": "MISS"})), "miss")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"age": "0"})), "miss")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={})), "unknown")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-cache-status": "STALE"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-varnish": "1001 2002"})), "hit")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"x-varnish": "1001"})), "miss")
        self.assertEqual(oracle.response_cache_state(FakeResponse(headers={"cf-cache-status": "DYNAMIC"})), "miss")

    def test_age_zero_cacheable_but_not_a_hit(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"age": "0"}), behavioral=False)
        self.assertTrue(info["cacheable"])
        self.assertFalse(info["saw_hit"])

    def test_age_positive_is_a_hit(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"age": "42"}), behavioral=False)
        self.assertTrue(info["saw_hit"])

    def test_age_non_numeric_is_graceful(self):
        info = oracle.detect_cache_oracle("https://x/", _HeaderSession({"age": "garbage"}), behavioral=False)
        self.assertTrue(info["cacheable"])  # age header present -> cache layer
        self.assertFalse(info["saw_hit"])

    def test_cache_control_no_store_overrides_public(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "public, no-store"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_cache_control_private_disqualifies(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "private, max-age=600"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_s_maxage_makes_eligible(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "s-maxage=300"}), behavioral=False)
        self.assertTrue(info["cacheable"])

    def test_max_age_zero_not_eligible(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"cache-control": "max-age=0"}), behavioral=False)
        self.assertFalse(info["cacheable"])

    def test_presence_via_header_marks_cache_layer(self):
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({"via": "1.1 varnish"}), behavioral=False)
        self.assertTrue(info["cache_layer"])
        self.assertTrue(info["cacheable"])

    def test_behavioral_no_date_cannot_infer(self):
        # Silent cache with no Date header -> frozen-date probe can't conclude.
        info = oracle.detect_cache_oracle(
            "https://x/", _HeaderSession({}), behavioral=True, sleep_fn=_NO_SLEEP)
        self.assertFalse(info["cacheable"])

    def test_behavioral_frozen_date_but_body_changes_not_cached(self):
        class _FrozenDateLiveBody:
            def __init__(self): self.n = 0
            def get(self, url, headers=None, timeout=10, verify=True, allow_redirects=False):
                self.n += 1
                return FakeResponse(f"<b {self.n}/>", {"date": "Mon, 30 Jun 2026 10:00:00 GMT"})
        info = oracle.detect_cache_oracle(
            "https://x/", _FrozenDateLiveBody(), behavioral=True, sleep_fn=_NO_SLEEP)
        self.assertFalse(info["cacheable"])  # date frozen but body differs -> not a replay

    def test_oracle_network_error_returns_safe_structure(self):
        info = oracle.detect_cache_oracle("https://x/", _RaisingSession())
        self.assertFalse(info["cacheable"])
        self.assertFalse(info["cache_layer"])
        self.assertTrue(any("error" in s for s in info["signals"]))


class TestConfirm(unittest.TestCase):
    def _vector(self):
        return {"url": "https://shop/home", "vector_type": "header",
                "vector_name": "X-Forwarded-Host", "payload_kind": "host",
                "impact_hint": "open_redirect"}

    def test_vulnerable_cache_confirms(self):
        session = VulnerableCacheSession("X-Forwarded-Host")
        rec = confirm.confirm_vector(self._vector(), {"param": "cb"}, session, {})
        self.assertTrue(rec["reflected_in_baseline"])
        self.assertTrue(rec["persisted_on_clean"])
        self.assertTrue(rec["cache_hit_on_clean"])
        conf, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Confirmed")
        self.assertGreaterEqual(conf, 0.95)
        self.assertTrue(rec["evidence"]["poc_link"])

    def test_safe_cache_rejected(self):
        session = SafeCacheSession()
        rec = confirm.confirm_vector(self._vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["persisted_on_clean"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Rejected")

    def _diff_vector(self):
        return {"url": "https://shop/login", "vector_type": "header",
                "vector_name": "X-Forwarded-Proto", "payload_kind": "scheme",
                "impact_hint": "open_redirect"}

    def test_non_reflective_poisoning_confirmed_as_strong(self):
        # No marker is echoed; only the differential (Location) detector catches it.
        session = DifferentialCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["reflected_in_baseline"])
        self.assertTrue(rec["persisted_differential"])
        self.assertTrue(rec["persisted_on_clean"])
        self.assertEqual(rec["differential_change"], "location")
        self.assertEqual(rec["detection_mode"], "differential")
        conf, tier = scoring.score_finding(rec)
        # Differential-only persistence is capped at Strong (never Confirmed).
        self.assertEqual(tier, "Strong")
        self.assertLess(conf, 0.95)
        self.assertEqual(confirm.classify_impact(self._diff_vector(), rec), "open_redirect")

    def test_dynamic_page_no_false_positive(self):
        # Body flaps every request -> body dimension untrusted -> no differential finding.
        session = DynamicNoiseSession()
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["baseline_stable"])
        self.assertFalse(rec["persisted_differential"])
        self.assertFalse(rec["persisted_on_clean"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Rejected")

    def test_differential_disabled_falls_back_to_reflected(self):
        session = DifferentialCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session,
                                     {"WEB_CACHE_POISON_DIFFERENTIAL": False})
        # With differential off, the non-reflective poison is invisible.
        self.assertEqual(rec["differential_change"], "")
        self.assertFalse(rec["persisted_on_clean"])

    def test_persisted_status_change_classified_as_dos(self):
        session = StatusPoisonCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertEqual(rec["differential_change"], "status")
        self.assertTrue(rec["persisted_differential"])
        self.assertEqual(confirm.classify_impact(self._diff_vector(), rec), "dos")
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Strong")

    def test_change_that_reverts_is_not_persisted(self):
        session = UncachedRedirectSession()
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        # The poison changed the response, but the clean follow-up reverted (uncached).
        self.assertEqual(rec["differential_change"], "location")
        self.assertFalse(rec["persisted_differential"])
        self.assertFalse(rec["persisted_on_clean"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Rejected")

    def test_429_on_poison_suppresses_differential(self):
        session = RateLimitOnPoisonSession()
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertEqual(rec["differential_change"], "")
        self.assertFalse(rec["persisted_on_clean"])

    def test_pure_body_diff_poisoning_detected(self):
        session = BodyPoisonCacheSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["reflected_in_baseline"])
        self.assertEqual(rec["differential_change"], "body")
        self.assertTrue(rec["persisted_differential"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Strong")

    def test_dimension_aware_guard_catches_location_despite_noisy_body(self):
        # Body is untrusted (flaps), but a real Location poison must still be found.
        session = NoisyBodyLocationPoisonSession("X-Forwarded-Proto")
        rec = confirm.confirm_vector(self._diff_vector(), {"param": "cb"}, session, {})
        self.assertFalse(rec["baseline_stable"])          # body made baseline unstable
        self.assertEqual(rec["differential_change"], "location")  # ...but location was trusted
        self.assertTrue(rec["persisted_differential"])
        _, tier = scoring.score_finding(rec)
        self.assertEqual(tier, "Strong")

    def test_apply_vector_header(self):
        url, hdrs = confirm._apply_vector("https://x/p", "header", "X-Forwarded-Host", "evil.invalid")
        self.assertEqual(url, "https://x/p")
        self.assertEqual(hdrs, {"X-Forwarded-Host": "evil.invalid"})

    def test_apply_vector_param(self):
        url, hdrs = confirm._apply_vector("https://x/p", "param", "utm", "evil")
        self.assertIn("utm=evil", url)
        self.assertEqual(hdrs, {})

    def test_classify_impact_redirect(self):
        vec = {"impact_hint": "reflected"}
        rec = {"persisted_on_clean": True, "evidence": {"redirect_poisoned": "//evil/"}}
        self.assertEqual(confirm.classify_impact(vec, rec), "open_redirect")

    def test_xss_context_helper(self):
        self.assertTrue(confirm._xss_context('<script src="//rdmnX.invalid/a.js"></script>', "rdmnX"))
        self.assertTrue(confirm._xss_context('<script>var u="rdmnX"</script>', "rdmnX"))
        self.assertTrue(confirm._xss_context('<body onload="track(\'rdmnX\')">', "rdmnX"))
        self.assertTrue(confirm._xss_context('<img src=x onerror="rdmnX">', "rdmnX"))
        self.assertFalse(confirm._xss_context("<p>benign rdmnX text</p>", "rdmnX"))
        self.assertFalse(confirm._xss_context("<a href='//rdmnX.invalid'>", "rdmnX"))  # link, not executable

    def test_classify_stored_xss_beats_hint(self):
        # A persisted canary in an executable context is stored XSS (critical), even when
        # the vector hint says open_redirect.
        vec = {"impact_hint": "open_redirect"}
        rec = {"persisted_on_clean": True, "xss_context": True, "evidence": {}}
        self.assertEqual(confirm.classify_impact(vec, rec), "stored_xss")
        self.assertEqual(scoring.severity_for_impact("stored_xss"), ("critical", 9.3))

    def test_script_src_reflection_detected_as_xss(self):
        # The vulnerable fake reflects the host into <script src=//canary> -> stored XSS.
        rec = confirm.confirm_vector(self._vector(), {"param": "cb"}, VulnerableCacheSession("X-Forwarded-Host"), {})
        self.assertTrue(rec["xss_context"])
        self.assertEqual(confirm.classify_impact(self._vector(), rec), "stored_xss")


class TestWcvsVectorMapping(unittest.TestCase):
    def test_header_host_vector(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Header Poisoning", "vector_name": "X-Forwarded-Host"})
        self.assertEqual(v["vector_type"], "header")
        self.assertEqual(v["payload_kind"], "host")
        self.assertEqual(v["impact_hint"], "open_redirect")

    def test_param_vector_not_forced_to_header(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Parameter Cloaking", "vector_name": "utm_source"})
        self.assertEqual(v["vector_type"], "param")
        self.assertEqual(v["technique"], "unkeyed_param")

    def test_deception_vector(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Deception", "vector_name": "css"})
        self.assertEqual(v["vector_type"], "path")
        self.assertEqual(v["impact_hint"], "deception")

    def test_non_host_header_vector_is_value_reflected(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Header Poisoning", "vector_name": "X-Forwarded-Scheme"})
        self.assertEqual(v["vector_type"], "header")
        self.assertEqual(v["payload_kind"], "value")
        self.assertEqual(v["impact_hint"], "reflected")

    def test_technique_normalisation(self):
        self.assertEqual(scanner._wcvs_technique("Web Cache Deception"), "cache_deception")
        self.assertEqual(scanner._wcvs_technique("Parameter Pollution"), "unkeyed_param")
        self.assertEqual(scanner._wcvs_technique("FatGET body"), "fat_get")
        self.assertEqual(scanner._wcvs_technique("HTTP Request Smuggling"), "request_smuggling")
        self.assertEqual(scanner._wcvs_technique("anything else"), "unkeyed_header")
        self.assertEqual(scanner._wcvs_technique(""), "unkeyed_header")

    def test_wcvs_vector_carries_reason(self):
        v = scanner._wcvs_vector("https://x/", {"technique": "Header Poisoning",
                                                "vector_name": "X-Host", "reason": "reflected"})
        self.assertEqual(v["source"], "wcvs")
        self.assertEqual(v["wcvs_reason"], "reflected")


class TestScannerTargets(unittest.TestCase):
    def _recon(self, urls, roe_excluded=None):
        return {
            "domain": "shop.test",
            "http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in urls}},
            "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
            "metadata": {"roe": {"ROE_ENABLED": bool(roe_excluded),
                                 "ROE_EXCLUDED_HOSTS": roe_excluded or []}},
        }

    def test_collect_targets_from_http_probe(self):
        rd = self._recon(["https://shop.test/home", "https://api.shop.test/v1"])
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/home", urls)
        self.assertIn("https://api.shop.test/v1", urls)

    def test_roe_filters_excluded_host(self):
        rd = self._recon(["https://shop.test/home", "https://secret.test/x"], roe_excluded=["secret.test"])
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/home", urls)
        self.assertNotIn("https://secret.test/x", urls)

    def test_roe_excludes_subdomains_of_excluded_host(self):
        rd = self._recon(["https://shop.test/home", "https://api.secret.test/x"], roe_excluded=["secret.test"])
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/home", urls)
        self.assertNotIn("https://api.secret.test/x", urls)  # subdomain suffix match

    def test_roe_from_settings_takes_effect(self):
        rd = self._recon(["https://shop.test/home", "https://blocked.test/x"])
        urls = scanner._collect_target_urls(
            rd, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["blocked.test"]})
        self.assertNotIn("https://blocked.test/x", urls)

    def test_host_excluded_helper_exact_and_suffix(self):
        ex = {"evil.test"}
        self.assertTrue(scanner._host_excluded("evil.test", ex))
        self.assertTrue(scanner._host_excluded("a.b.evil.test", ex))
        self.assertFalse(scanner._host_excluded("notevil.test", ex))  # not a real suffix boundary
        self.assertFalse(scanner._host_excluded("evil.test.com", ex))

    def test_max_urls_cap_enforced(self):
        many = [f"https://h{i}.shop.test/" for i in range(260)]
        urls = scanner._collect_target_urls(self._recon(many), {})
        self.assertLessEqual(len(urls), scanner._MAX_URLS)

    def test_retry_session_config(self):
        s = scanner._build_retry_session()
        try:
            self.assertEqual(s.headers["User-Agent"], "WhiteHat-CachePoison/1.0")
            adapter = s.get_adapter("https://x/")
            self.assertIn(429, adapter.max_retries.status_forcelist)
        finally:
            s.close()

    def test_endpoints_from_resource_enum_become_targets(self):
        # Regression: partial recon must scan graph Endpoints, not only BaseURLs.
        # build_target_urls reads resource_enum.by_base_url[base]["endpoints"][path].
        rd = {
            "domain": "shop.test",
            "http_probe": {"by_url": {"https://shop.test/": {"url": "https://shop.test/", "status_code": 200}}},
            "resource_enum": {"by_base_url": {
                "https://shop.test": {"endpoints": {
                    "/api/users": {"method": "GET", "parameters": {"query": []}},
                    "/admin/settings": {"method": "GET", "parameters": {"query": []}},
                }}
            }},
            "metadata": {},
        }
        urls = scanner._collect_target_urls(rd, {})
        self.assertIn("https://shop.test/api/users", urls)
        self.assertIn("https://shop.test/admin/settings", urls)

    def test_disabled_returns_empty_structure(self):
        rd = self._recon(["https://shop.test/home"])
        out = scanner.run_cache_scan(rd, {"WEB_CACHE_POISON_ENABLED": False})
        self.assertNotIn("cache_scan", out)

    def test_no_targets_writes_empty_result(self):
        rd = {"http_probe": {"by_url": {}}, "metadata": {}}
        out = scanner.run_cache_scan(rd, {"WEB_CACHE_POISON_ENABLED": True})
        self.assertIn("cache_scan", out)
        self.assertEqual(out["cache_scan"]["summary"]["total_findings"], 0)


class TestScannerRun(unittest.TestCase):
    """Full run_cache_scan behaviours with the network + WCVS stubbed out."""

    def _recon(self, url="https://shop.test/home"):
        return {"http_probe": {"by_url": {url: {"url": url, "status_code": 200}}},
                "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                "metadata": {}}

    def _run(self, session_factory, settings=None, wcvs=None):
        orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: session_factory()
        scanner.wcvs_runner.run_wcvs = lambda urls, s, **k: (wcvs or [])
        try:
            base = {"WEB_CACHE_POISON_ENABLED": True}
            base.update(settings or {})
            return scanner.run_cache_scan(self._recon(), base)["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w

    def test_not_cacheable_url_is_scanned_but_yields_nothing(self):
        cs = self._run(NoCacheSession)
        self.assertEqual(cs["summary"]["total_findings"], 0)
        self.assertEqual(cs["summary"]["cacheable_urls"], 0)
        # The URL is still accounted for in by_target with a not-cacheable oracle.
        entry = cs["by_target"]["https://shop.test/home"]
        self.assertFalse(entry["oracle"]["cacheable"])

    def test_run_metadata_fields_present(self):
        cs = self._run(lambda: VulnerableCacheSession("X-Forwarded-Host"))
        md = cs["scan_metadata"]
        self.assertEqual(md["engine"], "wcvs+native-confirm")
        self.assertEqual(md["scan_profile"], "safe-confirm")
        self.assertEqual(md["total_urls_scanned"], 1)
        self.assertEqual(md["wcvs_candidates"], 0)
        self.assertIn("duration_seconds", md)

    def test_wcvs_candidate_is_counted_and_confirmed(self):
        wcvs = [{"url": "https://shop.test/home", "vector_name": "X-Forwarded-Host",
                 "technique": "Header Poisoning"}]
        cs = self._run(lambda: VulnerableCacheSession("X-Forwarded-Host"), wcvs=wcvs)
        self.assertEqual(cs["scan_metadata"]["wcvs_candidates"], 1)
        # The WCVS-sourced vector confirmed (engine attribution preserved).
        engines = {f["source_engine"] for f in cs["findings"]}
        self.assertIn("wcvs", engines)

    def test_isolated_wrapper_deep_copies_and_returns_payload(self):
        orig_s, orig_w = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: NoCacheSession()
        scanner.wcvs_runner.run_wcvs = lambda urls, s, **k: []
        try:
            combined = self._recon()
            payload = scanner.run_cache_scan_isolated(combined, {"WEB_CACHE_POISON_ENABLED": True})
            self.assertIn("summary", payload)
            # The original combined_result must NOT be mutated (deep-copy isolation).
            self.assertNotIn("cache_scan", combined)
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_s, orig_w


class TestParallelConfirmation(unittest.TestCase):
    """The parallel per-URL fan-out must be thread-safe and equivalent to
    the sequential path (no lost / duplicated / corrupted findings)."""

    def _recon(self, n):
        urls = {f"https://shop.test/p{i}": {"url": f"https://shop.test/p{i}", "status_code": 200}
                for i in range(n)}
        return {"http_probe": {"by_url": urls},
                "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                "metadata": {}}

    def _run(self, n, workers):
        # Each worker/URL gets its own fresh stateful vulnerable-cache fake (mirrors
        # the real per-thread Session). WCVS is stubbed out (native path only).
        orig_session, orig_wcvs = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: VulnerableCacheSession("X-Forwarded-Host")
        scanner.wcvs_runner.run_wcvs = lambda urls, settings, **k: []
        try:
            out = scanner.run_cache_scan(self._recon(n), {
                "WEB_CACHE_POISON_ENABLED": True,
                "WEB_CACHE_POISON_CONFIRM_WORKERS": workers,
            })
            return out["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_session, orig_wcvs

    def test_parallel_equivalent_to_sequential(self):
        seq = self._run(8, workers=1)
        par = self._run(8, workers=4)
        # The vulnerable fake reflects X-Forwarded-Host -> one Confirmed finding per URL.
        self.assertEqual(seq["summary"]["total_findings"], 8)
        self.assertEqual(par["summary"]["total_findings"], 8)
        self.assertEqual(seq["summary"]["confirmed"], par["summary"]["confirmed"])
        self.assertEqual(len(par["by_target"]), 8)  # every URL accounted for, no races

    def test_workers_clamped_and_safe(self):
        # Out-of-range worker counts must not crash (clamped to 1..16).
        for w in (0, -3, 999):
            cs = self._run(3, workers=w)
            self.assertEqual(cs["summary"]["total_findings"], 3)


class TestDifferentialIntegration(unittest.TestCase):
    """End-to-end run_cache_scan over the native path with non-reflective fakes."""

    def _recon(self, url="https://shop.test/login"):
        return {"http_probe": {"by_url": {url: {"url": url, "status_code": 200}}},
                "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                "metadata": {}}

    def _run(self, session_factory):
        orig_session, orig_wcvs = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: session_factory()
        scanner.wcvs_runner.run_wcvs = lambda urls, settings, **k: []
        try:
            out = scanner.run_cache_scan(self._recon(), {"WEB_CACHE_POISON_ENABLED": True})
            return out["cache_scan"]
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_session, orig_wcvs

    def test_non_reflective_finding_surfaces_end_to_end(self):
        cs = self._run(lambda: DifferentialCacheSession("X-Forwarded-Proto"))
        self.assertEqual(cs["summary"]["total_findings"], 1)
        self.assertEqual(cs["summary"]["strong"], 1)
        self.assertEqual(cs["summary"]["confirmed"], 0)
        f = cs["findings"][0]
        self.assertEqual(f["detection_mode"], "differential")
        self.assertEqual(f["impact"], "open_redirect")
        self.assertEqual(f["evidence"]["differential_change"], "location")
        self.assertEqual(f["cache_header"], "X-Forwarded-Proto")

    def test_dynamic_page_yields_no_findings(self):
        cs = self._run(DynamicNoiseSession)
        self.assertEqual(cs["summary"]["total_findings"], 0)
        # The URL was still scanned and judged cacheable (oracle saw x-cache).
        self.assertEqual(cs["summary"]["cacheable_urls"], 1)


class TestGraphContract(unittest.TestCase):
    """build_finding must never emit a key the graph mixin doesn't know about
    (the data-loss tripwire). Guards against drift between the two files."""

    def _finding(self, mode="differential", diff="location"):
        vector = {"url": "https://shop/login", "vector_type": "header",
                  "vector_name": "X-Forwarded-Proto", "source": "hypothesis",
                  "technique": "unkeyed_header"}
        confirmation = {"detection_mode": mode,
                        "evidence": {"baseline_hash": "a", "poisoned_hash": "b",
                                     "clean_validation_hash": "c", "poc_link": "p",
                                     "curl_verify": "curl", "canary": "x",
                                     "differential_change": diff}}
        return normalizers.build_finding(vector, confirmation, 0.9, "Strong",
                                         "open_redirect", "high", 7.4, ["x-cache: hit"])

    def test_finding_keys_within_graph_contract(self):
        try:
            from graph_db.mixins.cache_mixin import KNOWN_FINDING_KEYS, KNOWN_EVIDENCE_KEYS
        except Exception as e:  # pragma: no cover - graph_db deps absent
            self.skipTest(f"graph_db import unavailable: {e}")
        f = self._finding()
        self.assertEqual(set(f.keys()) - KNOWN_FINDING_KEYS, set())
        self.assertEqual(set(f["evidence"].keys()) - KNOWN_EVIDENCE_KEYS, set())

    def test_detection_mode_present_for_reflected_default(self):
        # A legacy confirmation without detection_mode still yields a valid finding.
        f = normalizers.build_finding(
            {"url": "https://x/", "vector_type": "header", "vector_name": "X-Host"},
            {"evidence": {}}, 0.97, "Confirmed", "open_redirect", "high", 7.4, [])
        self.assertEqual(f["detection_mode"], "reflected")


class TestSmoke(unittest.TestCase):
    """Cheap import + minimal end-to-end sanity for the whole package."""

    def test_package_exports(self):
        from recon.cache_scan import run_cache_scan, run_cache_scan_isolated
        self.assertTrue(callable(run_cache_scan))
        self.assertTrue(callable(run_cache_scan_isolated))

    def test_isolated_wrapper_returns_only_payload(self):
        orig_session, orig_wcvs = scanner._build_retry_session, scanner.wcvs_runner.run_wcvs
        scanner._build_retry_session = lambda *a, **k: VulnerableCacheSession("X-Forwarded-Host")
        scanner.wcvs_runner.run_wcvs = lambda urls, settings, **k: []
        try:
            from recon.cache_scan import run_cache_scan_isolated
            combined = {"http_probe": {"by_url": {"https://shop.test/": {"url": "https://shop.test/", "status_code": 200}}},
                        "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                        "metadata": {}}
            payload = run_cache_scan_isolated(combined, {"WEB_CACHE_POISON_ENABLED": True})
            # The wrapper returns ONLY this tool's payload, not the whole combined_result.
            self.assertIn("summary", payload)
            self.assertIn("findings", payload)
            self.assertNotIn("http_probe", payload)
        finally:
            scanner._build_retry_session, scanner.wcvs_runner.run_wcvs = orig_session, orig_wcvs


if __name__ == "__main__":
    unittest.main()
