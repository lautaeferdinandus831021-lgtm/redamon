"""Unit tests for the supply-chain incident-intel sync (Step 0 writer).

Section: root-agent. Runs inside the whitehat-agent image, where
/repo/scanners is on PYTHONPATH.

No network: every test drives `sync_intel` through an injected fetcher.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from supply_chain_common import intel_seed, intel_sync
from supply_chain_common.security import SanitizeError, sanitize_hostname


def _feed(incidents, revised="2026-08-11", count=None):
    return {
        "revised": revised,
        "count": len(incidents) if count is None else count,
        "incidents": incidents,
    }


def _incident(iid="SCA-0001", **kw):
    base = {
        "id": iid,
        "url": "https://supplychainattack.org/incident/{}".format(iid),
        "title": "Malicious package {}".format(iid),
        "status": "confirmed",
        "severity": "high",
        "summary": "A malicious package was published.",
        "blastRadius": "3,000 downloads",
        "remediation": ["Remove the package", "Rotate credentials"],
        "attackVectors": ["malicious-package"],
        "lastUpdated": "2026-08-01",
        "iocs": {},
    }
    base.update(kw)
    return base


class TestSanitizeHostname(unittest.TestCase):
    """The charset gate that drops the feed's dirty 'domains' entries."""

    def test_accepts_plain_host(self):
        self.assertEqual(sanitize_hostname("Evil.Example.COM"), "evil.example.com")

    def test_accepts_leading_wildcard(self):
        self.assertEqual(sanitize_hostname("*.cf99-9b3.workers.dev"),
                         "*.cf99-9b3.workers.dev")

    def test_rejects_prose_sentence(self):
        # 13 of the feed's 216 "domains" are prose. They must not load.
        with self.assertRaises(SanitizeError):
            sanitize_hostname("attacker used a compromised CDN")

    def test_rejects_slash_joined_entry(self):
        # The documented malformed entry: '/' is not LDH.
        with self.assertRaises(SanitizeError):
            sanitize_hostname("cf103-070/cf102-baf/cf99-9b3.workers.dev")

    def test_rejects_ip_literal(self):
        # Must be routed to the IP validator instead, so the private-range drop
        # applies to it.
        with self.assertRaises(SanitizeError):
            sanitize_hostname("192.0.2.1")

    def test_rejects_non_leading_wildcard(self):
        with self.assertRaises(SanitizeError):
            sanitize_hostname("evil.*.com")

    def test_rejects_single_label(self):
        with self.assertRaises(SanitizeError):
            sanitize_hostname("localhost")

    def test_rejects_double_dot(self):
        with self.assertRaises(SanitizeError):
            sanitize_hostname("evil..com")


class TestNormalize(unittest.TestCase):

    def test_prose_domains_dropped_and_counted(self):
        inc = _incident(iocs={"domains": [
            "evil.example.com",
            "attacker used a compromised CDN",
            "cf103-070/cf102-baf/cf99-9b3.workers.dev",
        ]})
        norm = intel_sync.normalize([inc])
        self.assertIn("evil.example.com", norm["network_iocs"]["domains"])
        # Dropped, and visible as a count rather than silence.
        self.assertEqual(norm["stats"]["domains_dropped"], 2)
        self.assertEqual(norm["stats"]["domains"], 1)

    def test_bare_public_apex_wildcard_dropped(self):
        inc = _incident(iocs={"domains": [
            "*.workers.dev",
            "ai-script.test0ing7.workers.dev",
            "*.cf99-9b3.workers.dev",
        ]})
        norm = intel_sync.normalize([inc])
        suffixes = [w[0] for w in norm["network_iocs"]["wildcards"]]

        # '*.workers.dev' is all of Cloudflare Workers: dropped, counted.
        self.assertNotIn(".workers.dev", suffixes)
        self.assertEqual(norm["stats"]["wildcards_dropped_public_apex"], 1)
        # A specific attacker deployment survives as an exact host.
        self.assertIn("ai-script.test0ing7.workers.dev",
                      norm["network_iocs"]["domains"])
        # A deeper wildcard scopes to one attacker subdomain: kept.
        self.assertIn(".cf99-9b3.workers.dev", suffixes)

    def test_non_global_ips_dropped(self):
        inc = _incident(iocs={"ips": [
            "1.2.3.4",        # globally routable, kept
            "127.0.0.1",      # loopback
            "10.1.2.3",       # private
            "169.254.1.1",    # link-local
            "100.64.0.1",     # CGNAT: NOT covered by is_private
            "224.0.0.1",      # multicast
            "0.0.0.0",        # unspecified
            "203.0.113.10",   # TEST-NET-3 documentation range
            "not-an-ip",
        ]})
        norm = intel_sync.normalize([inc])
        self.assertEqual(list(norm["network_iocs"]["ips"]), ["1.2.3.4"])
        self.assertEqual(norm["stats"]["ips"], 1)
        self.assertEqual(norm["stats"]["ips_dropped"], 8)

    def test_cgnat_is_dropped(self):
        """Regression: is_private does NOT cover 100.64.0.0/10.

        Shared carrier-grade NAT space reaching the IOC set would let a poisoned
        feed flag traffic on any CGNAT-addressed network.
        """
        inc = _incident(iocs={"ips": ["100.64.0.1", "100.127.255.254"]})
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["network_iocs"]["ips"], {})
        self.assertEqual(norm["stats"]["ips_dropped"], 2)

    def test_raw_ip_in_domains_array_routed_to_ip_validator(self):
        inc = _incident(iocs={"domains": ["1.2.3.4", "10.0.0.5"]})
        norm = intel_sync.normalize([inc])
        self.assertIn("1.2.3.4", norm["network_iocs"]["ips"])
        self.assertNotIn("10.0.0.5", norm["network_iocs"]["ips"])
        self.assertEqual(norm["stats"]["ips_dropped"], 1)

    def test_strings_are_capped(self):
        inc = _incident(summary="A" * 99999)
        norm = intel_sync.normalize([inc])
        inc2 = _incident("SCA-0002", iocs={"packages": [{"name": "evil-pkg"}]})
        norm2 = intel_sync.normalize([inc, inc2])
        rec = norm2["packages"]["npm/evil-pkg"]
        self.assertLessEqual(len(rec["summary"]), 4096)
        self.assertTrue(norm["stats"]["incidents"], 1)

    def test_package_key_is_ecosystem_and_name(self):
        inc = _incident(iocs={"packages": [
            {"name": "evil-pkg", "ecosystem": "npm"},
            {"name": "bad-lib", "ecosystem": "PyPI"},
            "bare-string-pkg",
        ]})
        norm = intel_sync.normalize([inc])
        self.assertIn("npm/evil-pkg", norm["packages"])
        self.assertIn("pypi/bad-lib", norm["packages"])
        self.assertIn("npm/bare-string-pkg", norm["packages"])

    def test_hostile_package_name_dropped(self):
        inc = _incident(iocs={"packages": [{"name": "evil;rm -rf /"}]})
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["packages"], {})
        self.assertEqual(norm["stats"]["packages_dropped"], 1)

    def test_typosquat_pairs_extracted(self):
        inc = _incident(
            attackVectors=["typosquatting"],
            affectedEntities=[{"name": "lodahs", "note": "typosquat of lodash"}],
        )
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["typosquats"]["lodahs"]["original"], "lodash")

    def test_typosquat_pairs_ignored_without_the_vector(self):
        inc = _incident(
            attackVectors=["malicious-package"],
            affectedEntities=[{"name": "lodahs", "note": "typosquat of lodash"}],
        )
        norm = intel_sync.normalize([inc])
        self.assertEqual(norm["typosquats"], {})

    def test_incident_without_id_dropped(self):
        norm = intel_sync.normalize([_incident(id=None), "not-a-dict"])
        self.assertEqual(norm["stats"]["incidents"], 0)
        self.assertEqual(norm["stats"]["incidents_dropped"], 2)


class TestEnvelope(unittest.TestCase):

    def test_rejects_non_object(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope([])

    def test_rejects_missing_incidents(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": 3})

    def test_rejects_non_integer_count(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": "3", "incidents": [{}]})

    def test_rejects_bool_count(self):
        # bool is an int subclass; it must not pass as a count.
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": True, "incidents": [{}]})

    def test_rejects_empty_incidents(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.validate_envelope({"count": 0, "incidents": []})


class TestSyncIntel(unittest.TestCase):

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="sca-intel-test-")
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)
        # These tests pin the feed-failure contract when NO bundled seed is
        # usable; with one, a cold volume is seeded instead of failing. The seed
        # path is covered in test_sca_intel_seed.py.
        patcher = mock.patch.object(intel_seed, "SEED_FILE",
                                    os.path.join(self.out, "absent-seed.json.gz"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _sync(self, payload, **kw):
        def fetcher(url, timeout=None):
            if isinstance(payload, Exception):
                raise payload
            return payload
        return intel_sync.sync_intel(self.out, fetcher=fetcher, **kw)

    def test_writes_all_files_and_manifest(self):
        res = self._sync(_feed([_incident(iocs={"domains": ["evil.example.com"]})]))
        self.assertEqual(res["status"], "synced")
        for name in ("network_iocs.json", "packages.json", "typosquats.json",
                     "manifest.json"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)

        with open(os.path.join(self.out, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["revised"], "2026-08-11")
        self.assertEqual(manifest["count_ingested"], 1)
        self.assertIn("stats", manifest)

    def test_envelope_rejection_preserves_previous_files(self):
        first = self._sync(_feed([_incident(iocs={"domains": ["evil.example.com"]})]))
        self.assertEqual(first["status"], "synced")
        with open(os.path.join(self.out, "network_iocs.json")) as fh:
            before = fh.read()

        # A malformed feed must never truncate good data to empty.
        res = self._sync({"garbage": True}, force=True)
        self.assertEqual(res["status"], "failed")
        with open(os.path.join(self.out, "network_iocs.json")) as fh:
            self.assertEqual(fh.read(), before)

    def test_fetch_failure_never_raises(self):
        res = self._sync(intel_sync.FeedError("feed unreachable"), force=True)
        self.assertEqual(res["status"], "failed")
        self.assertIn("unreachable", res["detail"])

    def test_unexpected_exception_never_raises(self):
        res = self._sync(RuntimeError("boom"), force=True)
        self.assertEqual(res["status"], "failed")

    def test_ttl_marker_honoured(self):
        self._sync(_feed([_incident()]))
        # Second call within the TTL is a no-op.
        res = self._sync(_feed([_incident()]))
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["detail"], "within TTL")

    def test_ttl_expiry_refetches(self):
        self._sync(_feed([_incident()]))
        old = time.time() - (48 * 3600)
        for name in (intel_sync.MANIFEST_NAME, intel_sync.ATTEMPT_MARKER):
            os.utime(os.path.join(self.out, name), (old, old))
        res = self._sync(_feed([_incident()]))
        self.assertEqual(res["status"], "synced")

    def test_retry_floor_blocks_a_hammering_retry(self):
        """A broken feed must not be re-fetched on every scan spawn.

        The envelope contract leaves the previous files in place on rejection, so
        manifest.json never advances and a naive TTL check would refetch forever.
        """
        res = self._sync({"garbage": True}, force=True)
        self.assertEqual(res["status"], "failed")
        # manifest.json does not exist, so the TTL check alone would refetch.
        self.assertFalse(os.path.exists(os.path.join(self.out,
                                                     intel_sync.MANIFEST_NAME)))
        res2 = self._sync({"garbage": True})
        self.assertEqual(res2["status"], "skipped")
        self.assertEqual(res2["detail"], "within retry floor")

    def test_attempt_marker_written_before_the_fetch(self):
        self._sync(intel_sync.FeedError("down"), force=True)
        self.assertTrue(os.path.exists(
            os.path.join(self.out, intel_sync.ATTEMPT_MARKER)))

    def test_output_is_world_readable(self):
        # Scan containers run non-root + read-only; a 0640 file is an empty DB.
        self._sync(_feed([_incident()]))
        mode = os.stat(os.path.join(self.out, "manifest.json")).st_mode
        self.assertTrue(mode & 0o004, "manifest.json is not world-readable")


class TestFetchGuards(unittest.TestCase):

    def test_refuses_off_allowlist_host(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.fetch_feed("https://evil.example.com/incidents.json")

    def test_refuses_non_http_scheme(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.fetch_feed("file:///etc/passwd")

    def test_redirect_to_off_allowlist_host_is_refused(self):
        import urllib.error

        class _Resp:
            headers = {"Location": "https://evil.example.com/x.json"}

        def opener(req, timeout):
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", _Resp.headers, None)

        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        self.assertIn("off-allowlist", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


class TestPublicSuffixWildcardRegression(unittest.TestCase):
    """BUG: a bare wildcard on a MULTI-LABEL public suffix matched everything.

    `*.workers.dev` was dropped by an explicit apex list, but `*.co.uk` was not:
    its body has two labels, so it passed the hostname gate and was stored as the
    suffix `.co.uk`. Matching is `host.endswith(suffix)`, so every single .co.uk
    asset in the graph - and every captured request to one - would be reported as
    contacting a host named in a published incident.

    The feed is attacker-influenceable (anyone can get an advisory published), so
    one crafted IOC was enough to flood a whole engagement with false positives.

    The distinguisher is not label count: `*.evil-attacker.com` also has a
    two-label body and IS a legitimate, valuable IOC.
    """

    def _wildcards(self, domains):
        norm = intel_sync.normalize([_incident(iocs={"domains": domains})])
        return [w[0] for w in norm["network_iocs"]["wildcards"]], norm["stats"]

    def test_multi_label_public_suffix_wildcard_is_dropped(self):
        for suffix in ("*.co.uk", "*.com.br", "*.co.jp", "*.com.au", "*.org.uk"):
            wildcards, stats = self._wildcards([suffix])
            self.assertEqual(
                wildcards, [],
                "{} would match every host under that public suffix".format(suffix))
            self.assertEqual(stats["wildcards_dropped_public_apex"], 1, suffix)

    def test_an_attackers_own_domain_wildcard_is_still_kept(self):
        """The fix must not throw away the IOCs that make this feature useful."""
        wildcards, _ = self._wildcards(["*.evil-attacker.com"])
        self.assertEqual(wildcards, [".evil-attacker.com"])

    def test_hosting_apex_wildcard_is_still_dropped(self):
        wildcards, stats = self._wildcards(["*.workers.dev"])
        self.assertEqual(wildcards, [])
        self.assertEqual(stats["wildcards_dropped_public_apex"], 1)

    def test_deeper_wildcard_under_a_public_suffix_is_kept(self):
        """`*.attacker.co.uk` scopes to one registrable domain, not the suffix."""
        wildcards, _ = self._wildcards(["*.attacker.co.uk"])
        self.assertEqual(wildcards, [".attacker.co.uk"])


class TestJavascriptUriXssRegression(unittest.TestCase):
    """SECURITY: the incident URL reaches three <a href> sinks.

    It was length-capped but never scheme-checked, and React renders a
    `javascript:` href without complaint. Anyone can get an advisory published in
    this catalog, so a single crafted entry would have executed script in the
    operator's authenticated session the moment they clicked the incident link.

    Gated at sync time so a poisoned URL never reaches the volume, the graph or
    a browser; the three render sites re-check independently.
    """

    def _url_for(self, raw):
        norm = intel_sync.normalize([_incident(
            url=raw, iocs={"packages": [{"name": "evil-pkg"}]})])
        return norm["packages"]["npm/evil-pkg"]["url"]

    def test_javascript_uri_is_dropped(self):
        self.assertEqual(self._url_for("javascript:alert(document.cookie)"), "")

    def test_javascript_uri_is_dropped_case_insensitively(self):
        self.assertEqual(self._url_for("JaVaScRiPt:alert(1)"), "")

    def test_data_uri_is_dropped(self):
        self.assertEqual(
            self._url_for("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
            "")

    def test_vbscript_and_file_uris_are_dropped(self):
        for raw in ("vbscript:msgbox(1)", "file:///etc/passwd"):
            self.assertEqual(self._url_for(raw), "", raw)

    def test_control_characters_cannot_smuggle_a_scheme(self):
        """"java\\tscript:" defeats a naive prefix check in some parsers."""
        self.assertEqual(self._url_for("java\tscript:alert(1)"), "")
        self.assertEqual(self._url_for("http://ok.example/\n<script>"), "")

    def test_a_real_incident_url_survives(self):
        url = "https://supplychainattack.org/incident/SCA-0001"
        self.assertEqual(self._url_for(url), url)

    def test_plain_http_survives(self):
        self.assertEqual(self._url_for("http://example.test/x"), "http://example.test/x")

    def test_missing_url_becomes_empty_not_none(self):
        self.assertEqual(self._url_for(None), "")


class TestFetchLimits(unittest.TestCase):
    """The byte and redirect caps on the remote fetch.

    Not covered before: the tests exercised the host allowlist but never the
    limits that stop a hostile or runaway response.
    """

    class _Resp:
        def __init__(self, body=b"{}", headers=None):
            self._body = body
            self.headers = headers or {}
            self.closed = False

        def read(self, n=-1):
            return self._body[:n] if n and n > 0 else self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.closed = True
            return False

    def test_content_length_over_the_cap_is_refused_before_reading(self):
        resp = self._Resp(headers={"Content-Length": str(intel_sync.MAX_FEED_BYTES + 1)})
        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL,
                                  opener=lambda req, timeout: resp)
        self.assertIn("too large", str(ctx.exception))

    def test_a_body_over_the_cap_is_refused_even_without_content_length(self):
        """A lying or absent Content-Length must not get past the cap."""
        big = b"x" * (intel_sync.MAX_FEED_BYTES + 10)
        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL,
                                  opener=lambda req, timeout: self._Resp(big))
        self.assertIn("exceeded", str(ctx.exception))

    def test_a_garbage_content_length_does_not_crash_the_fetch(self):
        body = b'{"count": 1, "incidents": [{"id": "X"}]}'
        resp = self._Resp(body, headers={"Content-Length": "not-a-number"})
        payload = intel_sync.fetch_feed(intel_sync.FEED_URL,
                                        opener=lambda req, timeout: resp)
        self.assertEqual(payload["count"], 1)

    def test_non_json_body_is_a_feed_error_not_a_traceback(self):
        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL,
                                  opener=lambda req, timeout: self._Resp(b"<html>"))
        self.assertIn("not valid JSON", str(ctx.exception))

    def test_undecodable_body_is_a_feed_error(self):
        with self.assertRaises(intel_sync.FeedError):
            intel_sync.fetch_feed(intel_sync.FEED_URL,
                                  opener=lambda req, timeout: self._Resp(b"\xff\xfe\x00"))

    def test_a_redirect_chain_is_bounded(self):
        """An on-allowlist redirect loop must terminate, not spin."""
        import urllib.error

        calls = {"n": 0}

        def opener(req, timeout):
            calls["n"] += 1
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found",
                {"Location": intel_sync.FEED_URL}, None)

        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        self.assertIn("too many redirects", str(ctx.exception))
        self.assertLessEqual(calls["n"], intel_sync.MAX_REDIRECTS + 1)

    def test_a_redirect_without_a_location_is_refused(self):
        import urllib.error

        def opener(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 302, "Found", {}, None)

        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        self.assertIn("Location", str(ctx.exception))

    def test_an_http_error_status_is_a_feed_error(self):
        import urllib.error

        def opener(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 503, "Unavailable", {}, None)

        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        self.assertIn("503", str(ctx.exception))

    def test_a_transport_failure_is_a_feed_error(self):
        import urllib.error

        def opener(req, timeout):
            raise urllib.error.URLError("name or service not known")

        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        self.assertIn("unreachable", str(ctx.exception))


class TestConcurrentWriterCorruptionRegression(unittest.TestCase):
    """F1: two writers shared one temp path and could splice a table.

    `whitehat.sh sca-intel-sync --force` skips the TTL AND the retry floor, and
    the orchestrator's serialising lock is per-process, so an operator sync can
    land on top of a scan-triggered refresh. With a fixed `<name>.tmp` both
    opened the same path, truncated it and interleaved writes. The surviving
    file could be spliced from two streams - and a corrupt table reads back as
    available=True with ZERO entries, because the loader treats a parse failure
    as an empty table. That is a silent false clean.

    A pid suffix would not fix it: each container has its own PID namespace, so
    two sidecars are both pid 1.
    """

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="sca-concurrent-")
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def test_temp_path_is_unique_per_writer(self):
        seen = set()
        real_replace = os.replace

        def capture(tmp, final):
            seen.add(os.path.basename(tmp))
            return real_replace(tmp, final)

        os.replace = capture
        try:
            for _ in range(3):
                intel_sync._write_json(self.out, "network_iocs.json", {"a": 1})
        finally:
            os.replace = real_replace
        self.assertEqual(len(seen), 3,
                         "each write must use its own temp file, got {}".format(seen))
        self.assertNotIn("network_iocs.json.tmp", seen)

    def test_interleaved_writers_never_produce_an_unparseable_file(self):
        """Simulates the real interleaving: A opens, B opens+writes+renames,
        then A writes+renames. Both files must be individually valid JSON."""
        import threading

        errors = []
        barrier = threading.Barrier(2)

        def writer(payload):
            try:
                barrier.wait(timeout=5)
                for _ in range(20):
                    intel_sync._write_json(self.out, "packages.json", payload)
            except Exception as exc:            # pragma: no cover - reported below
                errors.append(exc)

        a = threading.Thread(target=writer, args=({"npm/a": {"incident_id": "A"}},))
        b = threading.Thread(target=writer, args=({"npm/b": {"incident_id": "B"}},))
        a.start(); b.start(); a.join(); b.join()
        self.assertEqual(errors, [])

        with open(os.path.join(self.out, "packages.json")) as fh:
            blob = json.load(fh)     # must not raise: a spliced file would
        self.assertIn(list(blob)[0], ("npm/a", "npm/b"))
        self.assertEqual(len(blob), 1, "the file must be one writer's payload, not a mix")

    def test_no_temp_files_are_left_behind(self):
        intel_sync._write_json(self.out, "packages.json", {"npm/a": {}})
        leftovers = [f for f in os.listdir(self.out) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_a_failed_write_cleans_up_its_temp_file(self):
        class Unserializable:
            pass

        with self.assertRaises(TypeError):
            intel_sync._write_json(self.out, "packages.json", {"k": Unserializable()})
        leftovers = [f for f in os.listdir(self.out) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [], "a failed write must not leak a temp file")


class TestEmptyFeedOverwriteRegression(unittest.TestCase):
    """F2: a well-formed feed carrying NO indicators wiped the good tables.

    The envelope check only proves there are incidents. A publisher-side schema
    change or a partial regeneration can ship thousands of incidents with empty
    `iocs`: that normalizes to empty tables, overwrites the good ones, and
    reports status=synced. Readers then load available=True and match nothing,
    so C7 records nothing either.
    """

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="sca-empty-")
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def _sync(self, payload, **kw):
        return intel_sync.sync_intel(
            self.out, fetcher=lambda url, timeout=None: payload, **kw)

    def _good_feed(self):
        return _feed([_incident(iocs={"domains": ["evil.example.com"],
                                      "packages": [{"name": "evil-pkg"}]})])

    def _iocless_feed(self):
        return _feed([_incident("SCA-{}".format(i), iocs={}) for i in range(50)])

    def test_an_iocless_feed_does_not_wipe_stored_indicators(self):
        self.assertEqual(self._sync(self._good_feed(), force=True)["status"], "synced")
        with open(os.path.join(self.out, "network_iocs.json")) as fh:
            before = fh.read()

        # ttl/retry 0 so the sync actually runs rather than being skipped as
        # fresh - the guard under test lives after the fetch.
        res = self._sync(self._iocless_feed(), ttl_seconds=0, retry_seconds=0)
        self.assertEqual(res["status"], "failed")
        self.assertIn("no indicators", res["detail"])

        with open(os.path.join(self.out, "network_iocs.json")) as fh:
            self.assertEqual(fh.read(), before, "good data was overwritten")

    def test_the_refusal_is_visible_not_silent(self):
        self._sync(self._good_feed(), force=True)
        res = self._sync(self._iocless_feed(), ttl_seconds=0, retry_seconds=0)
        # Names both sides of the comparison so the operator can act on it.
        self.assertIn("refusing to overwrite", res["detail"])
        self.assertIn("--force", res["detail"])

    def test_force_still_allows_a_deliberate_wipe(self):
        self._sync(self._good_feed(), force=True)
        res = self._sync(self._iocless_feed(), force=True)
        self.assertEqual(res["status"], "synced")

    def test_a_first_sync_onto_a_cold_volume_is_never_blocked(self):
        """Nothing stored yet means there is no good data to protect."""
        res = self._sync(self._iocless_feed(), force=True)
        self.assertEqual(res["status"], "synced")

    def test_a_shrinking_but_non_empty_feed_is_still_accepted(self):
        """Feeds legitimately drop indicators between revisions; only a TOTAL
        wipe is refused."""
        self._sync(self._good_feed(), force=True)
        smaller = _feed([_incident(iocs={"domains": ["one.example.com"]})])
        self.assertEqual(self._sync(smaller, force=True)["status"], "synced")
