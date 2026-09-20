"""Unit tests for container_manager.sibling_host_path (graph_db mount fix).

Proves the sibling-host-path derivation used for the graph_db bind mount of every
spawned scan container (recon / partial-recon / gvm / github-hunt / trufflehog) is
correct on POSIX *and* Windows-style Docker `Source` strings.

Regression guarded: the old `Path(recon_path).parent / "graph_db"` collapsed a
Windows source (`C:\\...\\recon`) to the RELATIVE string `graph_db` because the
orchestrator runs Linux (PurePosixPath treats '\\' as an ordinary char). Docker
Desktop then materialized an EMPTY `/app/graph_db`, so `import graph_db` failed
with `cannot import name 'Neo4jClient' from 'graph_db' (unknown location)` and no
recon graph writes landed. This test locks the fix in and forbids the regression.

Run: python3 -m unittest tests.test_sibling_host_path
"""
import os
import sys
import types
import unittest
from pathlib import PurePosixPath

# --- Import the REAL shipped function without its runtime-only deps -----------
# container_manager imports `docker`, `models` (pydantic), etc. at module load.
# None are used by sibling_host_path, so we stub them to import the actual source
# file (NOT a copy) and exercise the shipped implementation.
_ORCH = os.path.join(os.path.dirname(__file__), '..', 'recon_orchestrator')
sys.path.insert(0, _ORCH)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'graph_db'))


def _install_stubs():
    docker = types.ModuleType("docker")
    docker.from_env = lambda *a, **k: None
    errors = types.ModuleType("docker.errors")
    errors.NotFound = type("NotFound", (Exception,), {})
    errors.APIError = type("APIError", (Exception,), {})
    models_mod = types.ModuleType("docker.models")
    containers = types.ModuleType("docker.models.containers")
    containers.Container = type("Container", (), {})
    docker.errors = errors
    docker.models = models_mod
    models_mod.containers = containers
    sys.modules.setdefault("docker", docker)
    sys.modules.setdefault("docker.errors", errors)
    sys.modules.setdefault("docker.models", models_mod)
    sys.modules.setdefault("docker.models.containers", containers)

    # `from models import (...)` -> a module whose every attribute resolves.
    models = types.ModuleType("models")
    models.__getattr__ = lambda name: type(name, (), {})
    sys.modules.setdefault("models", models)


_install_stubs()
import container_manager  # noqa: E402  (after stubs)

sibling_host_path = container_manager.sibling_host_path


class SiblingHostPathTest(unittest.TestCase):
    # (input recon Source, expected graph_db host path)
    CASES = [
        ("Linux native",       "/home/u/whitehat/recon",
                               "/home/u/whitehat/graph_db"),
        ("macOS Desktop",      "/Users/foo/whitehat/recon",
                               "/Users/foo/whitehat/graph_db"),
        ("Win WSL2 Linux FS",  "/run/desktop/mnt/host/c/Users/foo/whitehat/recon",
                               "/run/desktop/mnt/host/c/Users/foo/whitehat/graph_db"),
        ("Win backslash",      r"C:\Users\foo\whitehat\recon",
                               r"C:\Users\foo\whitehat\graph_db"),
        ("Win forward-slash",  "C:/Users/foo/whitehat/recon",
                               "C:/Users/foo/whitehat/graph_db"),
        ("POSIX trailing /",   "/home/u/whitehat/recon/",
                               "/home/u/whitehat/graph_db"),
        ("Win trailing \\",    "C:\\Users\\foo\\whitehat\\recon\\",
                               "C:\\Users\\foo\\whitehat\\graph_db"),
    ]

    def test_all_platforms(self):
        for label, src, expected in self.CASES:
            with self.subTest(platform=label):
                self.assertEqual(sibling_host_path(src, "graph_db"), expected)

    def test_no_regression_on_posix(self):
        """POSIX sources must yield EXACTLY what the old Path().parent produced,
        so Linux/macOS behavior is provably unchanged."""
        for label, src, _ in self.CASES:
            if "\\" in src:
                continue
            with self.subTest(platform=label):
                old = str(PurePosixPath(src.rstrip("/")).parent / "graph_db")
                self.assertEqual(sibling_host_path(src, "graph_db"), old)

    def test_windows_bug_is_actually_fixed(self):
        """Lock in the fix: demonstrate the OLD derivation was broken on a
        Windows source, and the NEW one is not."""
        win = r"C:\Users\foo\whitehat\recon"
        # The old code path: PurePosixPath.parent collapses to '.', giving a
        # RELATIVE, useless mount source -> Docker Desktop empty-mount bug.
        old = str(PurePosixPath(win).parent / "graph_db")
        self.assertEqual(old, "graph_db", "sanity: this is the bug we are fixing")
        # The new code yields a real absolute host path.
        new = sibling_host_path(win, "graph_db")
        self.assertEqual(new, r"C:\Users\foo\whitehat\graph_db")
        self.assertNotEqual(new, "graph_db")

    def test_result_is_never_bare_relative(self):
        """The core invariant: an absolute input never degrades to a bare
        relative 'graph_db' (which is what silently empty-mounted)."""
        for label, src, _ in self.CASES:
            with self.subTest(platform=label):
                out = sibling_host_path(src, "graph_db")
                self.assertNotEqual(out, "graph_db")
                self.assertTrue(("/" in out) or ("\\" in out))

    def test_works_for_other_scan_dirs(self):
        """Same helper serves github_hunt / trufflehog spawns."""
        self.assertEqual(
            sibling_host_path(r"C:\Users\foo\whitehat\github_secret_hunt", "graph_db"),
            r"C:\Users\foo\whitehat\graph_db")
        self.assertEqual(
            sibling_host_path("/srv/whitehat/trufflehog_scan", "graph_db"),
            "/srv/whitehat/graph_db")


if __name__ == "__main__":
    unittest.main()
