"""
T15 — KB feed & model integrity pinning.

Runs as stdlib unittest inside the agent image (httpx + knowledge_base present):

    docker run --rm --entrypoint sh -v "$PWD/knowledge_base:/app/knowledge_base:ro" \
      -w /app whitehat-agent -c \
      "python -m unittest knowledge_base.tests.test_t15_pins -v"

Covers: pin manifest shape, sha256 verification (no-op / match / mismatch),
the per-feed abort on mismatch (regression: test_t15_pin_mismatch_aborts),
model-revision resolution, NVD envelope schema validation, and that clients
now build immutable-commit URLs (no more refs/heads/<branch>).
"""

import hashlib
import unittest
from unittest import mock

from knowledge_base.curation import pins
from knowledge_base.curation.pins import (
    FEED_PINS,
    MODEL_PINS,
    PinMismatchError,
    get_feed_ref,
    get_feed_sha256,
    model_revision,
    verify_sha256,
)
from knowledge_base.curation.safe_http import SafeResponse

FEEDS = ["gtfobins", "lolbas", "owasp", "nuclei", "exploitdb"]
_HEX40 = set("0123456789abcdef")


def _fake_resp(body: bytes) -> SafeResponse:
    return SafeResponse(status_code=200, content=body, headers={}, url="https://x/y")


class TestFeedPinManifest(unittest.TestCase):
    def test_every_feed_pinned_to_40hex_commit(self):
        for feed in FEEDS:
            ref = get_feed_ref(feed)
            self.assertEqual(len(ref), 40, f"{feed} ref not a full commit sha")
            self.assertTrue(set(ref.lower()) <= _HEX40, f"{feed} ref not hex")

    def test_unknown_feed_raises(self):
        # A new feed MUST be pinned before it can be fetched — loud failure.
        with self.assertRaises(KeyError):
            get_feed_ref("no-such-feed")

    def test_no_client_uses_mutable_branch_ref(self):
        # The whole point of T15: no feed URL may point at refs/heads/<branch>.
        import knowledge_base.curation.gtfobins_client as g
        import knowledge_base.curation.lolbas_client as l
        import knowledge_base.curation.owasp_client as o
        import knowledge_base.curation.nuclei_client as n
        import knowledge_base.curation.exploitdb_client as e

        templates = [
            g.GTFOBINS_TARBALL_URL_TEMPLATE,
            l.LOLBAS_TARBALL_URL_TEMPLATE,
            o.WSTG_TARBALL_URL_TEMPLATE,
            n.NUCLEI_TEMPLATES_TARBALL_URL_TEMPLATE,
            e.EXPLOITDB_CSV_URL_TEMPLATE,
        ]
        for t in templates:
            self.assertNotIn("refs/heads", t, f"{t} still uses a branch ref")
            self.assertIn("{ref}", t, f"{t} has no pin slot")

        # And the formatted URL embeds the immutable commit.
        url = n.NUCLEI_TEMPLATES_TARBALL_URL_TEMPLATE.format(ref=get_feed_ref("nuclei"))
        self.assertIn(get_feed_ref("nuclei"), url)
        self.assertTrue(url.endswith(".tar.gz"))


class TestVerifySha256(unittest.TestCase):
    def test_noop_when_pin_sha_is_none(self):
        # Default manifest leaves sha256 None -> verify is a no-op, never raises.
        self.assertIsNone(get_feed_sha256("nuclei"))
        verify_sha256("nuclei", b"anything at all")  # must not raise

    def test_passes_on_matching_sha(self):
        body = b"trusted feed bytes"
        good = hashlib.sha256(body).hexdigest()
        with mock.patch.dict(FEED_PINS, {"gtfobins": {"ref": "x" * 40, "sha256": good}}):
            verify_sha256("gtfobins", body)  # must not raise

    def test_t15_pin_mismatch_aborts(self):
        """REGRESSION: a poisoned artifact (wrong sha256) aborts the feed."""
        body = b"POISONED feed bytes"
        wrong = hashlib.sha256(b"the trusted bytes").hexdigest()
        with mock.patch.dict(FEED_PINS, {"gtfobins": {"ref": "x" * 40, "sha256": wrong}}):
            with self.assertRaises(PinMismatchError):
                verify_sha256("gtfobins", body)


class TestClientAbortsOnMismatch(unittest.TestCase):
    """Exploit-repro at the client layer: a tampered download raises out of
    fetch() (per-feed fail-closed) instead of being ingested."""

    def test_gtfobins_fetch_aborts_on_mismatch(self):
        import knowledge_base.curation.gtfobins_client as g

        poisoned = b"<<< malicious tarball contents >>>"
        wrong = hashlib.sha256(b"legit").hexdigest()
        with mock.patch.dict(
            FEED_PINS, {"gtfobins": {"ref": get_feed_ref("gtfobins"), "sha256": wrong}}
        ), mock.patch.object(g, "safe_get", return_value=_fake_resp(poisoned)):
            client = g.GTFOBinsClient(cache_dir="/tmp/whitehat-t15-test-cache")
            with self.assertRaises(PinMismatchError):
                client.fetch()


class TestModelRevision(unittest.TestCase):
    def test_known_models_pinned(self):
        self.assertEqual(
            model_revision("intfloat/e5-large-v2"), MODEL_PINS["intfloat/e5-large-v2"]
        )
        self.assertEqual(
            model_revision("BAAI/bge-reranker-base"),
            MODEL_PINS["BAAI/bge-reranker-base"],
        )

    def test_unknown_model_returns_none(self):
        # Falls back to library default (branch head) rather than blocking a
        # custom operator-configured model.
        self.assertIsNone(model_revision("some/custom-model"))


class TestNVDEnvelopeValidation(unittest.TestCase):
    def setUp(self):
        from knowledge_base.curation.nvd_client import (
            NVDSchemaError,
            _validate_nvd_envelope,
        )

        self.validate = _validate_nvd_envelope
        self.err = NVDSchemaError

    def test_valid_envelope_ok(self):
        self.validate({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": []})

    def test_format_absent_but_vulns_present_ok(self):
        self.validate({"vulnerabilities": [{"cve": {"id": "CVE-1"}}]})

    def test_html_body_rejected(self):
        # resp.json() on real HTML raises first, but if a proxy returns a JSON
        # string, this catches it: not a dict.
        with self.assertRaises(self.err):
            self.validate("<html>not nvd</html>")

    def test_missing_vulnerabilities_rejected(self):
        with self.assertRaises(self.err):
            self.validate({"format": "NVD_CVE"})

    def test_wrong_format_rejected(self):
        with self.assertRaises(self.err):
            self.validate({"format": "EVIL", "vulnerabilities": []})


if __name__ == "__main__":
    unittest.main()
