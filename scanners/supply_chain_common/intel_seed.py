"""Bundled offline copy of the supply-chain incident intel.

`intel_sync` installs it when the live feed is unreachable AND the volume holds
nothing usable, so a fresh install during a feed outage still gets network IOCs,
package IOCs and typosquat labels instead of an empty catalog. The live feed is
retried on the normal retry floor and replaces the copy as soon as it answers.

INDICATORS ONLY. The upstream catalog publishes no licence, so the copy carries
facts (hosts, IPs, package names, typosquat pairs, incident id, status,
severity, attack-vector labels, date, link) and none of the upstream prose
(title, summary, remediation, blast radius). `clean_record` enforces that on
build AND on load, so a seed that did carry prose would still install without it.

TRUST: the file is part of the source tree, and its sha256 is pinned below, so a
swapped or corrupted file is refused before it is decompressed. Every entry is
then re-validated with the same gates the live sync applies, because the pin
only proves the file is the one that was committed, not that it is well-formed.

Rebuild from a volume that holds a good live sync (then update SEED_SHA256):

    docker run --rm --user root -v whitehat-sca-intel:/src:ro \\
        -v "$PWD/scanners/supply_chain_common:/app/supply_chain_common" \\
        -e PYTHONPATH=/app --entrypoint python3 \\
        whitehat-supply-chain-analyzer:latest \\
        -m supply_chain_common.intel_seed --from /src \\
        --out /app/supply_chain_common/sca_intel_seed.json.gz

stdlib only, like intel_sync: it runs in the analyzer image with no new deps.
"""

import gzip
import hashlib
import io
import ipaddress
import json
import os
import re

from .security import (SanitizeError, sanitize_advisory, sanitize_ecosystem,
                       sanitize_hostname, sanitize_name)

__all__ = ["SEED_FILE", "SEED_SHA256", "SEED_SOURCE", "SeedError",
           "build_seed", "load_seed", "clean_record", "clean_tables"]

SEED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "sca_intel_seed.json.gz")
SEED_SHA256 = "8d2a6165f281b4b32bdc5064ed83e7f0ceb33db61e6f683d143637cf2ae5e581"

SEED_FORMAT = 1
# Written into the installed manifest so a later sync can tell a seeded volume
# from a live one: only a seed may be replaced by a newer seed.
SEED_SOURCE = "bundled-seed"

# Decompressed-size cap. The pin already rules out a swapped file, so this only
# bounds an honest mistake (a seed rebuilt from a runaway volume).
MAX_SEED_BYTES = 32 * 1024 * 1024
MAX_TABLE_ENTRIES = 50000

# Status, severity and attack-vector values are short lowercase labels in the
# live feed ('contained', 'critical', 'compromised-package'). Anything longer or
# richer is prose and does not belong in an indicators-only copy.
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\Z")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
MAX_ATTACK_VECTORS = 20


class SeedError(RuntimeError):
    """The bundled seed is missing, altered, malformed or empty."""


def _label(value):
    return value if isinstance(value, str) and _LABEL_RE.match(value) else ""


def clean_record(rec):
    """The indicators-only incident record, or None if it has no valid id.

    Returns the same key set as `intel_sync._incident_record` so every consumer
    reads a seeded record exactly like a live one; the prose keys are present
    and empty, which the graph writer and the webapp already render as absent.
    """
    from .intel_sync import _safe_link

    if not isinstance(rec, dict):
        return None
    try:
        incident_id = sanitize_advisory(rec.get("incident_id") or None)
    except SanitizeError:
        return None
    if not incident_id:
        return None
    vectors = rec.get("attack_vectors")
    if not isinstance(vectors, list):
        vectors = []
    last_updated = rec.get("last_updated")
    return {
        "incident_id": incident_id,
        "url": _safe_link(rec.get("url")),
        "title": "",
        "status": _label(rec.get("status")),
        "severity": _label(rec.get("severity")),
        "summary": "",
        "blast_radius": "",
        "remediation": [],
        "attack_vectors": [v for v in (_label(x) for x in vectors[:MAX_ATTACK_VECTORS]) if v],
        "last_updated": last_updated if isinstance(last_updated, str)
        and _DATE_RE.match(last_updated) else "",
    }


def _clean_domain(host):
    """A lowercase, non-wildcard, non-IP hostname, or None."""
    try:
        clean = sanitize_hostname(host, allow_wildcard=False)
    except SanitizeError:
        return None
    return clean if clean == host else None


def _clean_wildcard(suffix):
    """A '.suffix' scoped to one registrable domain, or None."""
    from .intel_sync import _is_bare_public_apex_wildcard

    if not isinstance(suffix, str) or not suffix.startswith("."):
        return None
    try:
        host = sanitize_hostname("*" + suffix)
    except SanitizeError:
        return None
    if host != "*" + suffix or _is_bare_public_apex_wildcard(host):
        return None
    return suffix


def _clean_ip(value):
    from .intel_sync import _ip_is_usable

    try:
        addr = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None
    if not _ip_is_usable(addr) or str(addr) != value:
        return None
    return value


def _clean_package_key(key):
    """'<ecosystem>/<name>' exactly as intel_sync._package_key builds it."""
    if not isinstance(key, str) or "/" not in key:
        return None
    ecosystem, name = key.split("/", 1)
    try:
        if not sanitize_ecosystem(ecosystem) or ecosystem != ecosystem.lower():
            return None
        sanitize_name(name)
    except SanitizeError:
        return None
    return key


def _clean_typosquat(fake, value):
    if not isinstance(value, dict):
        return None
    try:
        fake = sanitize_name(fake)
        original = sanitize_name(value.get("original"))
        incident_id = sanitize_advisory(value.get("incident_id") or None)
    except SanitizeError:
        return None
    if not incident_id or fake == original:
        return None
    return {"original": original, "incident_id": incident_id}


def _keyed(table, clean_key, stats, name):
    out = {}
    if not isinstance(table, dict):
        return out
    for key, rec in list(table.items())[:MAX_TABLE_ENTRIES]:
        key = clean_key(key)
        record = clean_record(rec) if key is not None else None
        if record is None:
            stats[name + "_dropped"] += 1
            continue
        out[key] = record
    return out


def clean_tables(network, packages, typosquats):
    """Re-validate the three lookup tables; return (tables, stats).

    A bad entry is dropped and counted, never repaired: a seed that needed
    repair is a seed that should be rebuilt.
    """
    stats = {"domains_dropped": 0, "wildcards_dropped": 0, "ips_dropped": 0,
             "packages_dropped": 0, "typosquats_dropped": 0}
    network = network if isinstance(network, dict) else {}

    domains = _keyed(network.get("domains"), _clean_domain, stats, "domains")
    ips = _keyed(network.get("ips"), _clean_ip, stats, "ips")
    pkgs = _keyed(packages, _clean_package_key, stats, "packages")

    wildcards = []
    raw_wildcards = network.get("wildcards")
    for item in (raw_wildcards if isinstance(raw_wildcards, list) else [])[:MAX_TABLE_ENTRIES]:
        suffix = rec = None
        if isinstance(item, (list, tuple)) and len(item) == 2:
            suffix, rec = _clean_wildcard(item[0]), clean_record(item[1])
        if suffix is None or rec is None:
            stats["wildcards_dropped"] += 1
            continue
        wildcards.append([suffix, rec])

    squats = {}
    for fake, value in list((typosquats if isinstance(typosquats, dict) else {})
                            .items())[:MAX_TABLE_ENTRIES]:
        entry = _clean_typosquat(fake, value)
        if entry is None:
            stats["typosquats_dropped"] += 1
            continue
        squats[fake] = entry

    stats.update({"domains_unique": len(domains), "wildcards_unique": len(wildcards),
                  "ips_unique": len(ips), "packages_unique": len(pkgs),
                  "typosquats_unique": len(squats)})
    tables = {"network_iocs": {"domains": domains, "wildcards": wildcards, "ips": ips},
              "packages": pkgs, "typosquats": squats}
    return tables, stats


def _indicator_count(tables):
    net = tables["network_iocs"]
    return (len(net["domains"]) + len(net["wildcards"]) + len(net["ips"])
            + len(tables["packages"]) + len(tables["typosquats"]))


def _snapshot_meta(manifest):
    """The upstream facts the installed manifest reports (revision, counts)."""
    manifest = manifest if isinstance(manifest, dict) else {}
    revised = manifest.get("revised")
    fetched_at = manifest.get("fetched_at")
    counts = {k: manifest.get(k) for k in ("count_reported", "count_ingested")}
    return {
        "revised": revised if isinstance(revised, str) and _DATE_RE.match(revised) else "",
        "fetched_at": fetched_at if isinstance(fetched_at, int)
        and not isinstance(fetched_at, bool) and fetched_at > 0 else 0,
        **{k: v if isinstance(v, int) and not isinstance(v, bool) else None
           for k, v in counts.items()},
    }


def build_seed(src_dir, out_file):
    """Write an indicators-only seed from a synced volume; return its sha256.

    Byte-reproducible (sorted keys, gzip mtime 0), so rebuilding from the same
    volume yields the same pin.
    """
    def read(name):
        with open(os.path.join(src_dir, name)) as fh:
            return json.load(fh)

    manifest = read("manifest.json")
    if manifest.get("source") == SEED_SOURCE:
        raise SeedError("refusing to build a seed from a seeded volume")
    meta = _snapshot_meta(manifest)
    if not meta["revised"] or not meta["fetched_at"]:
        raise SeedError("source manifest has no usable revision/fetched_at")

    tables, stats = clean_tables(read("network_iocs.json"), read("packages.json"),
                                 read("typosquats.json"))
    if _indicator_count(tables) == 0:
        raise SeedError("source volume carries no indicators")

    blob = dict(tables, format=SEED_FORMAT, meta=meta, build_stats=stats)
    raw = json.dumps(blob, separators=(",", ":"), sort_keys=True).encode("utf-8")
    data = gzip.compress(raw, compresslevel=9, mtime=0)
    with open(out_file, "wb") as fh:
        fh.write(data)
    return hashlib.sha256(data).hexdigest()


def load_seed(path=SEED_FILE, expected_sha256=SEED_SHA256):
    """Verify, decompress and re-validate the seed. Raises SeedError."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_SEED_BYTES + 1)
    except OSError as exc:
        raise SeedError("bundled seed unreadable: {}".format(exc))
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise SeedError("bundled seed sha256 mismatch (got {}, pinned {})".format(
            digest, expected_sha256))
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            raw = gz.read(MAX_SEED_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise SeedError("bundled seed is not valid gzip: {}".format(exc))
    if len(raw) > MAX_SEED_BYTES:
        raise SeedError("bundled seed exceeds {} bytes decompressed".format(MAX_SEED_BYTES))
    try:
        blob = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SeedError("bundled seed is not valid JSON: {}".format(exc))
    if not isinstance(blob, dict) or blob.get("format") != SEED_FORMAT:
        raise SeedError("bundled seed has an unknown format")

    meta = _snapshot_meta(blob.get("meta"))
    if not meta["revised"] or not meta["fetched_at"]:
        raise SeedError("bundled seed has no usable revision/fetched_at")
    tables, stats = clean_tables(blob.get("network_iocs"), blob.get("packages"),
                                 blob.get("typosquats"))
    if _indicator_count(tables) == 0:
        raise SeedError("bundled seed carries no indicators")
    return {"tables": tables, "meta": meta, "stats": stats}


def _main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Build the bundled indicators-only incident-intel seed.")
    parser.add_argument("--from", dest="src", required=True,
                        help="directory holding a good live sync")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    digest = build_seed(args.src, args.out)
    tables = load_seed(args.out, digest)
    print(json.dumps({"sha256": digest, "meta": tables["meta"],
                      "stats": tables["stats"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_main())
