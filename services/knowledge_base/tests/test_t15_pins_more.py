"""
T15 — sibling coverage for the KB integrity pins, complementing test_t15_pins.py.

test_t15_pins.py exercises the gtfobins tarball client's abort-on-mismatch. But
FIVE clients share that exact root-cause pattern (safe_get -> verify_sha256 ->
parse). This adds:

  * a behavioural abort test for EACH tarball client (lolbas/owasp/nuclei), not
    just gtfobins — a regression that drops verify_sha256 from any one of them
    would otherwise pass CI,
  * the exploitdb (CSV) client, whose fetch() has a cache-FALLBACK branch: a
    poisoned download must still raise (fail-closed) and must NOT be silently
    served from an existing cache file — the `except PinMismatchError: raise`
    must sit before the general cache-fallback except,
  * a structural guard that every client both imports and calls verify_sha256,
  * model pins are full 40-hex commits (mirrors the feed-manifest test).

Run:  docker run ... python -m unittest knowledge_base.tests.test_t15_pins_more -v
"""

import hashlib
import inspect
import unittest
from unittest import mock

from knowledge_base.curation.pins import (
    FEED_PINS,
    MODEL_PINS,
    PinMismatchError,
    get_feed_ref,
    get_feed_sha256,
)
from knowledge_base.curation.safe_http import SafeResponse

import knowledge_base.curation.gtfobins_client as gtfobins_client
import knowledge_base.curation.lolbas_client as lolbas_client
import knowledge_base.curation.owasp_client as owasp_client
import knowledge_base.curation.nuclei_client as nuclei_client
import knowledge_base.curation.exploitdb_client as exploitdb_client

_HEX40 = set("0123456789abcdef")

# (module, client class) for the four archive/tarball clients.
TARBALL_CLIENTS = [
    (gtfobins_client, "GTFOBinsClient"),
    (lolbas_client, "LOLBASClient"),
    (owasp_client, "OWASPClient"),
    (nuclei_client, "NucleiClient"),
]
ALL_CLIENTS = TARBALL_CLIENTS + [(exploitdb_client, "ExploitDBClient")]


def _fake_resp(body: bytes) -> SafeResponse:
    return SafeResponse(status_code=200, content=body, headers={}, url="https://x/y")


class TestEveryTarballClientAbortsOnMismatch(unittest.TestCase):
    """The gtfobins abort test, generalised to every tarball client."""

    def test_all_tarball_clients_fail_closed(self):
        poisoned = b"<<< malicious archive contents >>>"
        wrong = hashlib.sha256(b"legit-bytes").hexdigest()
        for module, cls_name in TARBALL_CLIENTS:
            client_cls = getattr(module, cls_name)
            source = client_cls.SOURCE
            with self.subTest(client=cls_name):  # noqa: SIM117
                with mock.patch.dict(
                    FEED_PINS, {source: {"ref": get_feed_ref(source), "sha256": wrong}}
                ), mock.patch.object(module, "safe_get", return_value=_fake_resp(poisoned)):
                    client = client_cls(cache_dir=f"/tmp/whitehat-t15-{source}-cache")
                    with self.assertRaises(PinMismatchError):
                        client.fetch()


class TestExploitDBFailsClosedEvenWithCache(unittest.TestCase):
    """The CSV client has a cache-fallback branch. A poisoned download must
    raise, NOT be swallowed into a cache read (except PinMismatchError first)."""

    def test_poison_raises_and_does_not_serve_cache(self):
        import os
        import tempfile

        source = "exploitdb"
        poisoned = b"id,description\n1,evil"
        wrong = hashlib.sha256(b"legit").hexdigest()
        cache_dir = tempfile.mkdtemp(prefix="whitehat-t15-edb-")
        # Seed a pre-existing cache file — the fail-closed contract says it must
        # NOT be served when the fresh download fails integrity.
        with open(os.path.join(cache_dir, "files_exploits.csv"), "w") as f:
            f.write("id,description\n99,cached-benign")

        with mock.patch.dict(
            FEED_PINS, {source: {"ref": get_feed_ref(source), "sha256": wrong}}
        ), mock.patch.object(exploitdb_client, "safe_get", return_value=_fake_resp(poisoned)):
            client = exploitdb_client.ExploitDBClient(cache_dir=cache_dir)
            with self.assertRaises(PinMismatchError):
                client.fetch()


class TestStructuralWiring(unittest.TestCase):
    """Cheap guard: every client imports AND calls verify_sha256 in fetch."""

    def test_every_client_calls_verify_sha256(self):
        for module, cls_name in ALL_CLIENTS:
            with self.subTest(client=cls_name):
                self.assertTrue(hasattr(module, "verify_sha256"),
                                f"{cls_name} module missing verify_sha256 import")
                fetch_src = inspect.getsource(getattr(module, cls_name).fetch)
                self.assertIn("verify_sha256(", fetch_src,
                              f"{cls_name}.fetch no longer calls verify_sha256")


class TestModelPinsAreCommits(unittest.TestCase):
    def test_all_model_pins_are_40hex(self):
        self.assertTrue(MODEL_PINS, "MODEL_PINS must not be empty")
        for name, rev in MODEL_PINS.items():
            self.assertEqual(len(rev), 40, f"{name} pin is not a full commit sha")
            self.assertTrue(set(rev.lower()) <= _HEX40, f"{name} pin is not hex (branch ref?)")


class TestUnknownFeedSha(unittest.TestCase):
    def test_unknown_feed_sha_is_none(self):
        # get_feed_sha256 tolerates an unknown source (no KeyError) -> None.
        self.assertIsNone(get_feed_sha256("no-such-feed"))


if __name__ == "__main__":
    unittest.main()
