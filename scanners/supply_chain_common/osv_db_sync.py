"""Lazy, per-ecosystem population of the offline OSV database volume.

The OSV DB is fetched ONCE (per ecosystem, per TTL window) via osv-scanner's own
`--download-offline-databases` step, NOT on every scan and NOT at install time
(S9: it is itself an untrusted supply-chain input, so it is pinned to osv-scanner's
official Google GCS source and mounted read-only everywhere except here).

We trigger a per-ecosystem download by handing osv-scanner a MINIMAL SEED
MANIFEST for that ecosystem and letting the tool detect the ecosystem and
download exactly its DB into the cache directory. This is layout-independent:
we never assume the tool's on-disk cache format, we let the tool own it.

Ecosystem sizes (verified 2026): npm ~208 MB, PyPI ~32 MB, Go/Packagist/Maven
~10 MB, RubyGems/crates ~3-4 MB. Default is per-ecosystem on demand, npm first.

NOTE (Phase 0 verification, open decisions #1/#4): the exact download flag set
must be reconfirmed against the pinned osv-scanner v2.4.0 binary. This uses the
documented `--offline --download-offline-databases` pair; adjust here if the
live binary differs.

stdlib only, so it runs inside the tiny analyzer image with no new deps.
"""

import os
import tempfile
import time

from ._run import run_argv
from .purl import OSV_ECOSYSTEMS

__all__ = ["download_databases", "db_is_fresh", "DEFAULT_TTL_SECONDS",
           "DEFAULT_ECOSYSTEMS", "SEED_MANIFESTS"]

DEFAULT_TTL_SECONDS = 24 * 3600
DEFAULT_ECOSYSTEMS = ["npm"]

# Minimal, valid manifest per OSV ecosystem. Pins a single benign, long-lived
# package purely so osv-scanner recognizes the ecosystem and downloads its DB.
SEED_MANIFESTS = {
    "npm": ("package-lock.json",
            '{"name":"seed","version":"1.0.0","lockfileVersion":3,'
            '"requires":true,"packages":{"":{"dependencies":{"left-pad":"1.3.0"}},'
            '"node_modules/left-pad":{"version":"1.3.0"}}}'),
    "PyPI": ("requirements.txt", "pip==24.0\n"),
    "Go": ("go.mod", "module seed\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n"),
    "crates.io": ("Cargo.lock",
                  '[[package]]\nname = "libc"\nversion = "0.2.150"\n'),
    "Maven": ("pom.xml",
              '<project><modelVersion>4.0.0</modelVersion>'
              '<groupId>seed</groupId><artifactId>seed</artifactId>'
              '<version>1.0.0</version><dependencies><dependency>'
              '<groupId>com.google.guava</groupId><artifactId>guava</artifactId>'
              '<version>30.0-jre</version></dependency></dependencies></project>'),
    "Packagist": ("composer.lock",
                  '{"packages":[{"name":"monolog/monolog","version":"2.0.0"}]}'),
    "RubyGems": ("Gemfile.lock",
                 "GEM\n  specs:\n    rake (13.0.0)\n\nPLATFORMS\n  ruby\n"),
    "NuGet": ("packages.lock.json",
              '{"version":1,"dependencies":{".NETCoreApp,Version=v6.0":'
              '{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )",'
              '"resolved":"13.0.1"}}}}'),
}


def _ecosystem_marker(db_path, ecosystem):
    safe = ecosystem.replace("/", "_").replace(".", "_")
    return os.path.join(db_path, ".whitehat_synced_{}".format(safe))


def db_is_fresh(db_path, ecosystem, ttl_seconds=DEFAULT_TTL_SECONDS):
    """True if `ecosystem` was synced into `db_path` within the TTL window."""
    marker = _ecosystem_marker(db_path, ecosystem)
    try:
        age = time.time() - os.path.getmtime(marker)
    except OSError:
        return False
    return age < ttl_seconds


def download_databases(db_path, ecosystems=None, *, force=False,
                       ttl_seconds=DEFAULT_TTL_SECONDS, timeout=600,
                       binary="osv-scanner"):
    """Download/refresh the offline DBs for the given ecosystems into db_path.

    Returns {synced: [...], skipped: [...], errors: {eco: msg}}. Idempotent:
    ecosystems within the TTL window are skipped unless force=True.
    """
    if ecosystems is None:
        ecosystems = list(DEFAULT_ECOSYSTEMS)
    os.makedirs(db_path, exist_ok=True)

    result = {"synced": [], "skipped": [], "errors": {}}
    env = dict(os.environ)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(db_path)

    for eco in ecosystems:
        if eco not in OSV_ECOSYSTEMS:
            result["errors"][eco] = "unknown ecosystem"
            continue
        if eco not in SEED_MANIFESTS:
            result["errors"][eco] = "no seed manifest for ecosystem"
            continue
        if not force and db_is_fresh(db_path, eco, ttl_seconds):
            result["skipped"].append(eco)
            continue

        err = _download_one(eco, db_path, env, timeout, binary)
        if err:
            result["errors"][eco] = err
            continue
        try:
            with open(_ecosystem_marker(db_path, eco), "w") as fh:
                fh.write(str(int(time.time())))
        except OSError as exc:
            result["errors"][eco] = "marker write failed: {}".format(exc)
            continue
        result["synced"].append(eco)

    # osv-scanner writes the DB tree 0750 (dirs) as root. The scan containers run
    # NON-root and mount this volume read-only; without world-traverse they can't
    # reach all.zip and osv-scanner then silently returns empty results (no error).
    # Make the whole tree world-readable/traversable so a hardened, non-root,
    # read-only scanner can load it.
    if result["synced"]:
        _make_world_readable(db_path)

    return result


def _make_world_readable(db_path):
    """Add o+rX across the DB tree so non-root read-only scanners can load it."""
    import stat as _stat
    for root, dirs, files in os.walk(db_path):
        for d in [root] + [os.path.join(root, x) for x in dirs]:
            try:
                os.chmod(d, os.stat(d).st_mode | _stat.S_IROTH | _stat.S_IXOTH
                         | _stat.S_IRGRP | _stat.S_IXGRP)
            except OSError:
                pass
        for f in files:
            fp = os.path.join(root, f)
            try:
                os.chmod(fp, os.stat(fp).st_mode | _stat.S_IROTH | _stat.S_IRGRP)
            except OSError:
                pass


def _download_one(ecosystem, db_path, env, timeout, binary):
    """Trigger osv-scanner's DB download for one ecosystem. Returns an error
    string on failure, else None."""
    filename, content = SEED_MANIFESTS[ecosystem]
    with tempfile.TemporaryDirectory(prefix="osv-seed-") as seed_dir:
        seed_path = os.path.join(seed_dir, filename)
        with open(seed_path, "w") as fh:
            fh.write(content)
        argv = [binary, "scan", "source",
                "--offline", "--download-offline-databases",
                "-L", seed_path, "--format", "json"]
        res = run_argv(argv, timeout=timeout, env=env)
        # The scan itself may exit 0/1 (findings) which is fine; only a spawn or
        # timeout failure (exit_code is None) means the download did not run.
        if res["exit_code"] is None:
            return res["error"] or "download failed"
    return None


def _main(argv=None):
    """CLI used by `whitehat.sh supply-chain-sync` inside the analyzer image."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Sync the offline OSV DB.")
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--ecosystems", default="npm",
                        help="space- or comma-separated OSV ecosystem names")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    ecos = [e for e in args.ecosystems.replace(",", " ").split() if e]
    result = download_databases(args.db_path, ecos or None, force=args.force)
    print(json.dumps(result))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(_main())
