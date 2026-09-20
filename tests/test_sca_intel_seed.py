"""Unit tests for the bundled offline incident-intel seed.

Section: root-agent. Runs inside the whitehat-agent image, where
/repo/scanners is on PYTHONPATH.

No network. Crafted entries use RFC 2606/6761 names and documentation IPs;
tests against the committed seed pick their probe values from the seed itself.
"""

import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from supply_chain_common import intel, intel_seed, intel_sync

PROSE_KEYS = ("title", "summary", "blast_radius", "remediation")


def _rec(iid="inc-0001", **kw):
    base = {
        "incident_id": iid,
        "url": "https://supplychainattack.org/incident/{}".format(iid),
        "title": "Upstream headline",
        "status": "active",
        "severity": "critical",
        "summary": "Upstream prose summary.",
        "blast_radius": "Upstream prose.",
        "remediation": ["Upstream step one"],
        "attack_vectors": ["compromised-package"],
        "last_updated": "2026-08-01",
    }
    base.update(kw)
    return base


def _write_volume(path, *, network=None, packages=None, typosquats=None,
                  manifest=None):
    """A synced-volume layout, as intel_sync._write_all leaves it."""
    os.makedirs(path, exist_ok=True)
    tables = {
        "network_iocs.json": network if network is not None else {
            "domains": {"evil.example.com": _rec("inc-0001")},
            "wildcards": [[".cdn.evil.example", _rec("inc-0002")]],
            "ips": {"198.51.100.7": _rec("inc-0003")}},
        "packages.json": packages if packages is not None else {
            "npm/evil-pkg": _rec("inc-0004"), "npm/@evil/scoped": _rec("inc-0005")},
        "typosquats.json": typosquats if typosquats is not None else {
            "lodahs": {"original": "lodash", "incident_id": "inc-0006"}},
        "manifest.json": manifest if manifest is not None else {
            "feed_url": intel_sync.FEED_URL, "revised": "2026-08-18",
            "fetched_at": 1787059006, "count_reported": 6, "count_ingested": 6,
            "stats": {}},
    }
    for name, payload in tables.items():
        with open(os.path.join(path, name), "w") as fh:
            json.dump(payload, fh)


class _TmpDirTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sca-seed-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        intel.reset_cache()
        self.addCleanup(intel.reset_cache)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


# ---------------------------------------------------------------------------
# The committed seed
# ---------------------------------------------------------------------------

class TestCommittedSeed(unittest.TestCase):
    """The file that ships in the repo must load, clean, and carry no prose."""

    @classmethod
    def setUpClass(cls):
        cls.seed = intel_seed.load_seed(intel_seed.SEED_FILE, intel_seed.SEED_SHA256)

    def _all_records(self):
        t = self.seed["tables"]
        net = t["network_iocs"]
        return (list(net["domains"].values()) + list(net["ips"].values())
                + [rec for _, rec in net["wildcards"]] + list(t["packages"].values()))

    def test_pinned_sha_matches_the_committed_file(self):
        with open(intel_seed.SEED_FILE, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(),
                             intel_seed.SEED_SHA256)

    def test_every_table_is_populated(self):
        t = self.seed["tables"]
        self.assertGreater(len(t["network_iocs"]["domains"]), 0)
        self.assertGreater(len(t["network_iocs"]["wildcards"]), 0)
        self.assertGreater(len(t["network_iocs"]["ips"]), 0)
        self.assertGreater(len(t["packages"]), 0)
        self.assertGreater(len(t["typosquats"]), 0)

    def test_revalidation_drops_nothing(self):
        # A committed seed that needs entries dropped on load should be rebuilt.
        dropped = {k: v for k, v in self.seed["stats"].items() if k.endswith("_dropped")}
        self.assertEqual(set(dropped.values()), {0}, dropped)

    def test_carries_no_upstream_prose(self):
        for rec in self._all_records():
            for key in PROSE_KEYS:
                self.assertFalse(rec[key], "{} leaked into {}".format(key, rec["incident_id"]))

    def test_raw_file_carries_no_prose_either(self):
        """Not just after clean_record: the bytes in the repo must be prose-free."""
        with gzip.open(intel_seed.SEED_FILE) as fh:
            blob = json.load(fh)
        for table in (blob["packages"], blob["network_iocs"]["domains"],
                      blob["network_iocs"]["ips"]):
            for rec in table.values():
                for key in PROSE_KEYS:
                    self.assertFalse(rec.get(key))

    def test_meta_names_a_real_snapshot(self):
        meta = self.seed["meta"]
        self.assertRegex(meta["revised"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertGreater(meta["fetched_at"], 0)

    def test_records_keep_the_consumer_key_set(self):
        """Seeded records must read exactly like live ones to every consumer."""
        live = intel_sync._incident_record({"_id": "x", "url": "", "_remediation": [],
                                            "_attack_vectors": []})
        for rec in self._all_records()[:50]:
            self.assertEqual(set(rec), set(live))

    def test_links_are_http_only(self):
        for rec in self._all_records():
            self.assertTrue(rec["url"] == "" or rec["url"].startswith("https://"))


# ---------------------------------------------------------------------------
# Record + table cleaning
# ---------------------------------------------------------------------------

class TestCleanRecord(unittest.TestCase):

    def test_prose_is_stripped_and_facts_kept(self):
        rec = intel_seed.clean_record(_rec())
        self.assertEqual(rec["incident_id"], "inc-0001")
        self.assertEqual(rec["status"], "active")
        self.assertEqual(rec["severity"], "critical")
        self.assertEqual(rec["attack_vectors"], ["compromised-package"])
        self.assertEqual(rec["last_updated"], "2026-08-01")
        for key in PROSE_KEYS:
            self.assertFalse(rec[key])

    def test_missing_or_hostile_id_drops_the_record(self):
        self.assertIsNone(intel_seed.clean_record(_rec(incident_id="")))
        self.assertIsNone(intel_seed.clean_record(_rec(incident_id="a b")))
        self.assertIsNone(intel_seed.clean_record(_rec(incident_id="<script>")))
        self.assertIsNone(intel_seed.clean_record(_rec(incident_id=7)))
        self.assertIsNone(intel_seed.clean_record("not a dict"))

    def test_javascript_link_is_blanked(self):
        self.assertEqual(intel_seed.clean_record(_rec(url="javascript:alert(1)"))["url"], "")

    def test_prose_smuggled_into_a_label_field_is_blanked(self):
        rec = intel_seed.clean_record(_rec(
            status="Attackers took over the maintainer account",
            severity="x" * 65,
            attack_vectors=["typosquatting", "Long prose sentence here", 5]))
        self.assertEqual(rec["status"], "")
        self.assertEqual(rec["severity"], "")
        self.assertEqual(rec["attack_vectors"], ["typosquatting"])

    def test_non_date_last_updated_is_blanked(self):
        self.assertEqual(intel_seed.clean_record(_rec(last_updated="yesterday"))["last_updated"], "")


class TestCleanTables(unittest.TestCase):

    def test_bad_entries_are_dropped_and_counted(self):
        network = {
            "domains": {"evil.example.com": _rec(), "EVIL.example.com": _rec(),
                        "192.0.2.1": _rec(), "*.evil.example": _rec(),
                        "prose sentence": _rec()},
            "wildcards": [[".cdn.evil.example", _rec()], [".workers.dev", _rec()],
                          [".co.uk", _rec()], ["no-dot.example", _rec()], "junk"],
            "ips": {"198.51.100.7": _rec(), "10.0.0.1": _rec(), "127.0.0.1": _rec(),
                    "100.64.0.1": _rec(), "not-an-ip": _rec()},
        }
        packages = {"npm/evil-pkg": _rec(), "npm/@evil/scoped": _rec(),
                    "NPM/evil": _rec(), "npm/../etc": _rec(), "noslash": _rec(),
                    "npm/-flag": _rec(), "npm/bad-rec": {"no": "id"}}
        squats = {"lodahs": {"original": "lodash", "incident_id": "inc-1"},
                  "same": {"original": "same", "incident_id": "inc-2"},
                  "noid": {"original": "x"}, "../x": {"original": "x", "incident_id": "i"}}
        tables, stats = intel_seed.clean_tables(network, packages, squats)

        net = tables["network_iocs"]
        # 198.51.100.7 is TEST-NET-2 and therefore not global: dropped too.
        self.assertEqual(list(net["domains"]), ["evil.example.com"])
        self.assertEqual([w[0] for w in net["wildcards"]], [".cdn.evil.example"])
        self.assertEqual(net["ips"], {})
        self.assertEqual(sorted(tables["packages"]), ["npm/@evil/scoped", "npm/evil-pkg"])
        self.assertEqual(list(tables["typosquats"]), ["lodahs"])
        self.assertEqual(stats["domains_dropped"], 4)
        self.assertEqual(stats["wildcards_dropped"], 4)
        self.assertEqual(stats["ips_dropped"], 5)
        self.assertEqual(stats["packages_dropped"], 5)
        self.assertEqual(stats["typosquats_dropped"], 3)

    def test_a_globally_routable_ip_is_kept(self):
        tables, _ = intel_seed.clean_tables({"ips": {"8.8.8.8": _rec()}}, {}, {})
        self.assertIn("8.8.8.8", tables["network_iocs"]["ips"])

    def test_non_canonical_ip_spelling_is_dropped(self):
        tables, stats = intel_seed.clean_tables(
            {"ips": {"2001:4860:4860:0:0:0:0:8888": _rec()}}, {}, {})
        self.assertEqual(tables["network_iocs"]["ips"], {})
        self.assertEqual(stats["ips_dropped"], 1)

    def test_garbage_shapes_do_not_raise(self):
        tables, _ = intel_seed.clean_tables("x", ["y"], None)
        self.assertEqual(tables["packages"], {})
        self.assertEqual(tables["network_iocs"]["domains"], {})


# ---------------------------------------------------------------------------
# Build + load
# ---------------------------------------------------------------------------

class TestBuildAndLoad(_TmpDirTest):

    def test_round_trip_strips_prose_and_is_reproducible(self):
        _write_volume(self.path("src"))
        sha1 = intel_seed.build_seed(self.path("src"), self.path("a.gz"))
        sha2 = intel_seed.build_seed(self.path("src"), self.path("b.gz"))
        self.assertEqual(sha1, sha2)

        seed = intel_seed.load_seed(self.path("a.gz"), sha1)
        self.assertEqual(seed["meta"]["revised"], "2026-08-18")
        self.assertEqual(seed["meta"]["fetched_at"], 1787059006)
        pkg = seed["tables"]["packages"]["npm/evil-pkg"]
        self.assertEqual(pkg["incident_id"], "inc-0004")
        self.assertEqual(pkg["summary"], "")
        with gzip.open(self.path("a.gz")) as fh:
            self.assertNotIn(b"Upstream prose", fh.read())

    def test_refuses_to_build_from_a_seeded_volume(self):
        _write_volume(self.path("src"), manifest={
            "revised": "2026-08-18-bundled", "fetched_at": 1, "source": intel_seed.SEED_SOURCE})
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.build_seed(self.path("src"), self.path("a.gz"))

    def test_refuses_to_build_an_empty_seed(self):
        _write_volume(self.path("src"), network={"domains": {}, "wildcards": [], "ips": {}},
                      packages={}, typosquats={})
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.build_seed(self.path("src"), self.path("a.gz"))

    def test_sha_mismatch_is_refused_before_decompressing(self):
        _write_volume(self.path("src"))
        intel_seed.build_seed(self.path("src"), self.path("a.gz"))
        with mock.patch.object(intel_seed.gzip, "GzipFile") as gz:
            with self.assertRaises(intel_seed.SeedError) as ctx:
                intel_seed.load_seed(self.path("a.gz"), "0" * 64)
        self.assertIn("sha256 mismatch", str(ctx.exception))
        gz.assert_not_called()

    def test_a_tampered_byte_is_refused(self):
        _write_volume(self.path("src"))
        sha = intel_seed.build_seed(self.path("src"), self.path("a.gz"))
        with open(self.path("a.gz"), "r+b") as fh:
            fh.seek(20)
            byte = fh.read(1)
            fh.seek(20)
            fh.write(bytes([byte[0] ^ 0xFF]))
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.load_seed(self.path("a.gz"), sha)

    def _pinned(self, data):
        with open(self.path("s.gz"), "wb") as fh:
            fh.write(data)
        return self.path("s.gz"), hashlib.sha256(data).hexdigest()

    def test_missing_file_is_a_seed_error(self):
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.load_seed(self.path("absent.gz"), "0" * 64)

    def test_non_gzip_is_a_seed_error(self):
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.load_seed(*self._pinned(b"plain bytes"))

    def test_non_json_is_a_seed_error(self):
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.load_seed(*self._pinned(gzip.compress(b"<html>")))

    def test_unknown_format_is_a_seed_error(self):
        blob = json.dumps({"format": 99}).encode()
        with self.assertRaises(intel_seed.SeedError):
            intel_seed.load_seed(*self._pinned(gzip.compress(blob)))

    def test_decompression_is_capped(self):
        with mock.patch.object(intel_seed, "MAX_SEED_BYTES", 100):
            blob = json.dumps({"format": 1, "pad": "x" * 500}).encode()
            with self.assertRaises(intel_seed.SeedError) as ctx:
                intel_seed.load_seed(*self._pinned(gzip.compress(blob)))
        self.assertIn("exceeds", str(ctx.exception))


# ---------------------------------------------------------------------------
# sync_intel with the seed
# ---------------------------------------------------------------------------

class TestSyncSeedsAColdVolume(_TmpDirTest):
    """Feed down + nothing usable on the volume -> the bundled copy is installed."""

    def setUp(self):
        super().setUp()
        _write_volume(self.path("src"))
        sha = intel_seed.build_seed(self.path("src"), self.path("seed.gz"))
        for name, value in (("SEED_FILE", self.path("seed.gz")), ("SEED_SHA256", sha)):
            patcher = mock.patch.object(intel_seed, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.out = self.path("vol")

    def _sync(self, outcome, **kw):
        def fetcher(url, timeout=None):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return intel_sync.sync_intel(self.out, fetcher=fetcher, **kw)

    def _manifest(self):
        with open(os.path.join(self.out, "manifest.json")) as fh:
            return json.load(fh)

    def test_feed_down_on_a_cold_volume_installs_the_seed(self):
        res = self._sync(intel_sync.FeedError("feed returned HTTP 402"))
        self.assertEqual(res["status"], "seeded")
        self.assertIn("HTTP 402", res["detail"])
        self.assertIn("2026-08-18-bundled", res["detail"])
        manifest = self._manifest()
        self.assertEqual(manifest["source"], intel_seed.SEED_SOURCE)
        self.assertEqual(manifest["revised"], "2026-08-18-bundled")
        self.assertEqual(manifest["seed_revised"], "2026-08-18")

    def test_seeded_volume_loads_and_matches_through_the_reader(self):
        self._sync(intel_sync.FeedError("down"))
        loaded = intel.load_intel(self.out, force_reload=True)
        self.assertTrue(loaded.available)
        self.assertEqual(loaded.revised, "2026-08-18-bundled")
        self.assertEqual(intel.match_host("evil.example.com", loaded)["incident_id"], "inc-0001")
        self.assertEqual(intel.match_host("a.cdn.evil.example", loaded)["incident_id"], "inc-0002")

        artifact = {"malicious": [{"name": "evil-pkg", "ecosystem": "npm"}]}
        intel.enrich_findings(artifact, loaded)
        finding = artifact["malicious"][0]
        self.assertEqual(finding["incident_id"], "inc-0004")
        self.assertEqual(finding["incident_summary"], "")
        self.assertEqual(finding["incident_remediation"], [])
        self.assertEqual(finding["incident_feed_revised"], "2026-08-18-bundled")
        self.assertNotIn("errors", artifact)

    def test_seed_does_not_read_as_fresh_so_the_feed_is_retried(self):
        self._sync(intel_sync.FeedError("down"))
        self.assertFalse(intel_sync.intel_is_fresh(self.out))
        self.assertEqual(os.path.getmtime(os.path.join(self.out, "manifest.json")),
                         1787059006)
        # Within the retry floor: skipped, not hammering the feed.
        self.assertEqual(self._sync(intel_sync.FeedError("down"))["detail"],
                         "within retry floor")
        # Past it: the live feed is tried again and replaces the seed.
        old = time.time() - 2 * intel_sync.DEFAULT_RETRY_SECONDS
        os.utime(os.path.join(self.out, intel_sync.ATTEMPT_MARKER), (old, old))
        live = {"revised": "2026-09-20", "count": 1, "incidents": [{
            "id": "live-1", "iocs": {"domains": ["live.evil.example"]}}]}
        res = self._sync(live)
        self.assertEqual(res["status"], "synced")
        manifest = self._manifest()
        self.assertNotIn("source", manifest)
        self.assertEqual(manifest["revised"], "2026-09-20")
        self.assertTrue(intel_sync.intel_is_fresh(self.out))

    def test_live_data_is_never_replaced_by_the_seed(self):
        _write_volume(self.out, manifest={"revised": "2026-07-01", "fetched_at": 1,
                                          "stats": {}})
        with open(os.path.join(self.out, "packages.json")) as fh:
            before = fh.read()
        res = self._sync(intel_sync.FeedError("feed returned HTTP 402"), force=True)
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["kept"], "2026-07-01")
        self.assertIn("existing catalog kept (feed revision 2026-07-01)", res["detail"])
        with open(os.path.join(self.out, "packages.json")) as fh:
            self.assertEqual(fh.read(), before)

    def test_an_older_seed_is_upgraded(self):
        _write_volume(self.out, manifest={
            "revised": "2026-01-01-bundled", "seed_revised": "2026-01-01",
            "source": intel_seed.SEED_SOURCE, "fetched_at": 1, "stats": {}})
        res = self._sync(intel_sync.FeedError("down"), force=True)
        self.assertEqual(res["status"], "seeded")
        self.assertEqual(self._manifest()["seed_revised"], "2026-08-18")

    def test_the_same_seed_is_not_reinstalled(self):
        self._sync(intel_sync.FeedError("down"))
        res = self._sync(intel_sync.FeedError("down"), force=True)
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["kept"], "2026-08-18-bundled")

    def test_an_unusable_seed_fails_loudly_on_a_cold_volume(self):
        with mock.patch.object(intel_seed, "SEED_SHA256", "f" * 64):
            res = self._sync(intel_sync.FeedError("down"))
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["kept"], "")
        self.assertIn("bundled offline copy unusable", res["detail"])
        self.assertFalse(os.path.exists(os.path.join(self.out, "manifest.json")))

    def test_an_unexpected_fetch_error_also_seeds(self):
        res = self._sync(RuntimeError("boom"))
        self.assertEqual(res["status"], "seeded")

    def test_an_indicator_free_feed_on_a_cold_volume_seeds(self):
        """A 'successful' empty catalog would load as available and match nothing."""
        empty = {"revised": "2026-09-20", "count": 1, "incidents": [{"id": "x"}]}
        res = self._sync(empty)
        self.assertEqual(res["status"], "seeded")
        self.assertIn("no indicators", res["detail"])

    def test_seeded_output_is_world_readable(self):
        self._sync(intel_sync.FeedError("down"))
        for name in ("manifest.json", "packages.json", "network_iocs.json"):
            self.assertTrue(os.stat(os.path.join(self.out, name)).st_mode & 0o004, name)

    def _no_fetch(self, url, timeout=None):
        raise AssertionError("the feed must not be contacted")

    def _touch_attempt(self):
        os.makedirs(self.out, exist_ok=True)
        marker = os.path.join(self.out, intel_sync.ATTEMPT_MARKER)
        with open(marker, "w") as fh:
            fh.write("0")
        return os.path.getmtime(marker)

    def test_retry_floor_still_seeds_an_empty_volume_without_fetching(self):
        """A recent failed attempt must not keep an empty volume empty for an hour."""
        before = self._touch_attempt()
        res = intel_sync.sync_intel(self.out, fetcher=self._no_fetch)
        self.assertEqual(res["status"], "seeded")
        self.assertIn("within retry floor", res["detail"])
        self.assertEqual(self._manifest()["source"], intel_seed.SEED_SOURCE)
        # No feed attempt happened, so the retry clock is not reset.
        self.assertEqual(os.path.getmtime(os.path.join(self.out, intel_sync.ATTEMPT_MARKER)),
                         before)

    def test_retry_floor_leaves_a_live_catalog_alone(self):
        _write_volume(self.out)
        # Past the TTL, so the retry floor (not freshness) is what skips.
        old = time.time() - 2 * intel_sync.DEFAULT_TTL_SECONDS
        os.utime(os.path.join(self.out, "manifest.json"), (old, old))
        with open(os.path.join(self.out, "packages.json")) as fh:
            before = fh.read()
        self._touch_attempt()
        res = intel_sync.sync_intel(self.out, fetcher=self._no_fetch)
        self.assertEqual(res, {"status": "skipped", "detail": "within retry floor", "stats": {}})
        with open(os.path.join(self.out, "packages.json")) as fh:
            self.assertEqual(fh.read(), before)

    def test_retry_floor_does_not_reseed_the_same_seed(self):
        self._sync(intel_sync.FeedError("down"))
        res = intel_sync.sync_intel(self.out, fetcher=self._no_fetch)
        self.assertEqual(res["status"], "skipped")

    def test_a_fresh_but_empty_catalog_is_seeded(self):
        """An earlier 'successful' empty sync inside the TTL loads as available
        and matches nothing; the TTL skip must not preserve that."""
        _write_volume(self.out, network={"domains": {}, "wildcards": [], "ips": {}},
                      packages={}, typosquats={})
        self.assertTrue(intel_sync.intel_is_fresh(self.out))
        res = intel_sync.sync_intel(self.out, fetcher=self._no_fetch)
        self.assertEqual(res["status"], "seeded")
        self.assertIn("within TTL", res["detail"])

    def test_skip_with_an_unusable_seed_is_still_a_plain_skip(self):
        self._touch_attempt()
        with mock.patch.object(intel_seed, "SEED_SHA256", "f" * 64):
            res = intel_sync.sync_intel(self.out, fetcher=self._no_fetch)
        self.assertEqual(res, {"status": "skipped", "detail": "within retry floor", "stats": {}})

    def test_seed_install_never_raises(self):
        with mock.patch.object(intel_sync, "_write_all", side_effect=OSError("disk full")):
            res = self._sync(intel_sync.FeedError("down"))
        self.assertEqual(res["status"], "failed")


class TestSeedOnly(_TmpDirTest):
    """Air-gapped mode: install the copy if needed, never fetch."""

    def setUp(self):
        super().setUp()
        _write_volume(self.path("src"))
        sha = intel_seed.build_seed(self.path("src"), self.path("seed.gz"))
        for name, value in (("SEED_FILE", self.path("seed.gz")), ("SEED_SHA256", sha)):
            patcher = mock.patch.object(intel_seed, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        fetch = mock.patch.object(intel_sync, "fetch_feed",
                                  side_effect=AssertionError("feed contacted"))
        self.fetch = fetch.start()
        self.addCleanup(fetch.stop)
        self.out = self.path("vol")

    def test_empty_volume_is_seeded(self):
        res = intel_sync.seed_if_empty(self.out)
        self.assertEqual(res["status"], "seeded")
        self.assertTrue(res["seed_only"])
        self.assertTrue(intel.load_intel(self.out, force_reload=True).available)
        self.fetch.assert_not_called()

    def test_no_attempt_marker_is_written(self):
        intel_sync.seed_if_empty(self.out)
        self.assertFalse(os.path.exists(os.path.join(self.out, intel_sync.ATTEMPT_MARKER)))

    def test_live_catalog_is_left_alone(self):
        _write_volume(self.out, manifest={"revised": "2026-07-01", "fetched_at": 1, "stats": {}})
        res = intel_sync.seed_if_empty(self.out)
        self.assertEqual(res["status"], "skipped")
        self.assertIn("2026-07-01", res["detail"])

    def test_second_run_is_a_no_op(self):
        intel_sync.seed_if_empty(self.out)
        res = intel_sync.seed_if_empty(self.out)
        self.assertEqual(res["status"], "skipped")
        self.assertIn("2026-08-18-bundled", res["detail"])

    def test_an_older_seed_is_upgraded(self):
        _write_volume(self.out, manifest={
            "revised": "2026-01-01-bundled", "seed_revised": "2026-01-01",
            "source": intel_seed.SEED_SOURCE, "fetched_at": 1, "stats": {}})
        self.assertEqual(intel_sync.seed_if_empty(self.out)["status"], "seeded")

    def test_unusable_seed_on_an_empty_volume_fails(self):
        with mock.patch.object(intel_seed, "SEED_SHA256", "f" * 64):
            res = intel_sync.seed_if_empty(self.out)
        self.assertEqual(res["status"], "failed")
        self.assertIn("bundled offline copy unusable", res["detail"])


# ---------------------------------------------------------------------------
# Operator-facing messages
# ---------------------------------------------------------------------------

class TestHttpFailureText(unittest.TestCase):

    def _error(self, code, headers=None):
        def opener(req, timeout):
            raise urllib.error.HTTPError(req.full_url, code, "x", headers or {}, None)
        with self.assertRaises(intel_sync.FeedError) as ctx:
            intel_sync.fetch_feed(intel_sync.FEED_URL, opener=opener)
        return str(ctx.exception)

    def test_402_names_the_paused_upstream_and_the_vercel_reason(self):
        text = self._error(402, {"x-vercel-error": "DEPLOYMENT_DISABLED"})
        self.assertIn("HTTP 402", text)
        self.assertIn("paused or disabled upstream", text)
        self.assertIn("[DEPLOYMENT_DISABLED]", text)

    def test_hostile_vercel_header_is_not_echoed(self):
        for value in ("deployment_disabled", "A" * 65, "BAD\nINJECT", "<b>X</b>"):
            self.assertNotIn(value, self._error(402, {"x-vercel-error": value}))

    def test_server_errors_say_so(self):
        self.assertIn("server error", self._error(503))

    def test_unmapped_status_is_just_the_code(self):
        self.assertEqual(self._error(418), "feed returned HTTP 418")


class TestDescribeAndCli(_TmpDirTest):

    def test_describe_each_outcome(self):
        d = intel_sync.describe_result
        self.assertIn("synced", d({"status": "synced", "detail": "revised=x"}))
        self.assertIn("nothing to do", d({"status": "skipped", "detail": "within TTL"}))
        self.assertIn("retried automatically",
                      d({"status": "seeded", "detail": "x"}))
        kept = d({"status": "failed", "detail": "HTTP 402", "kept": "2026-08-18"})
        self.assertIn("upstream problem, not a WhiteHat one", kept)
        self.assertIn("No incident catalog is available",
                      d({"status": "failed", "detail": "x", "kept": ""}))

    def _run_main(self, result):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(intel_sync, "sync_intel", return_value=result), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = intel_sync._main(["--out", self.tmp])
        return code, out.getvalue(), err.getvalue()

    def test_seeded_exits_zero_and_reports_a_change(self):
        code, out, err = self._run_main({"status": "seeded", "detail": "d", "stats": {}})
        self.assertEqual(code, 0)
        self.assertEqual(out.strip().splitlines()[-1], "__DID_SYNC__")
        self.assertIn("retried automatically", out)
        self.assertEqual(err, "")

    def test_failed_exits_one_without_the_sentinel(self):
        code, out, err = self._run_main(
            {"status": "failed", "detail": "d", "stats": {}, "kept": "2026-08-18"})
        self.assertEqual(code, 1)
        self.assertNotIn("__DID_SYNC__", out)
        self.assertIn("upstream problem", out)

    def test_sentinel_survives_the_orchestrator_log_tail(self):
        """container_manager greps only the last 500 chars for the sentinel."""
        long_detail = "x" * 2000
        _, out, _ = self._run_main({"status": "seeded", "detail": long_detail,
                                    "stats": {"k": 1}})
        self.assertIn("__DID_SYNC__", out.strip()[-500:])

    def test_seed_only_message_does_not_promise_a_retry(self):
        text = intel_sync.describe_result(
            {"status": "seeded", "detail": "x", "seed_only": True})
        self.assertIn("Auto-refresh is off", text)
        self.assertNotIn("retried automatically", text)

    def test_cli_seed_only_calls_seed_if_empty_not_sync(self):
        result = {"status": "seeded", "detail": "d", "stats": {}, "seed_only": True}
        out = io.StringIO()
        with mock.patch.object(intel_sync, "seed_if_empty", return_value=result) as seed, \
                mock.patch.object(intel_sync, "sync_intel") as sync, \
                contextlib.redirect_stdout(out):
            code = intel_sync._main(["--out", self.tmp, "--seed-only"])
        self.assertEqual(code, 0)
        seed.assert_called_once_with(self.tmp)
        sync.assert_not_called()
        self.assertEqual(out.getvalue().strip().splitlines()[-1], "__DID_SYNC__")

    def test_cli_rejects_seed_only_with_force(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            intel_sync._main(["--out", self.tmp, "--seed-only", "--force"])
        self.assertEqual(ctx.exception.code, 2)

    def test_skipped_exits_zero_without_the_sentinel(self):
        code, out, _ = self._run_main({"status": "skipped", "detail": "within TTL", "stats": {}})
        self.assertEqual(code, 0)
        self.assertNotIn("__DID_SYNC__", out)


if __name__ == "__main__":
    unittest.main()
