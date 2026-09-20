"""Read side of the supply-chain incident intel volume.

Loaded by every layer that consumes the intel: the L1 scan writer, the L2 recon
module, and the traffic-capture ingest worker. Written only by `intel_sync.py`.

CONTRACT: nothing here ever raises. A missing volume, an unreadable file, a
truncated JSON blob and a never-synced deploy all degrade to `available=False`
with empty maps. The callers treat that as "no enrichment" and, per C7, record
that the pass did not run rather than reporting a clean result.
"""

import json
import os
import threading
import time

__all__ = ["load_intel", "reset_cache", "Intel", "match_host",
           "enrich_findings", "DEFAULT_INTEL_PATH", "MAX_ENTRIES",
           "DEFAULT_IGNORE_SUFFIXES"]

DEFAULT_INTEL_PATH = "/sca-intel"

# Hard cap on loaded entries (~3 MB resident at the default). The feed is ~3,900
# entries across all three tables today; this bounds a hostile feed rather than
# the real one. Registered in the memory-governor table.
MAX_ENTRIES = int(os.environ.get("SCA_INTEL_MAX_ENTRIES", "10000") or 10000)

# OAST / interaction-server providers. These ARE real IOCs in the feed (30 of the
# 216 domains), so the sync keeps them; they are suppressed at MATCH time instead,
# because an operator running Burp Collaborator would otherwise flag their own
# callbacks on every engagement.
DEFAULT_IGNORE_SUFFIXES = (
    "oastify.com", "oast.fun", "mburpcollab.com", "canarytokens.com",
    "pipedream.net",
)

# How often a long-lived process re-checks whether the volume was re-synced.
# The webapp and traffic-ingest run for days, and the refresh sidecar rewrites
# this volume underneath them: without a re-check they would answer from the
# copy they loaded at boot forever, so a freshly synced IOC would never apply to
# newly captured traffic. Bounded to one stat() per window rather than one per
# captured request, because this sits on the ingest path.
RELOAD_CHECK_SECONDS = int(os.environ.get("SCA_INTEL_RELOAD_CHECK_SECONDS", "60") or 60)

_CACHE = None
_CACHE_MTIME = None
_CACHE_CHECKED_AT = 0.0
_CACHE_LOCK = threading.Lock()


class Intel(object):
    """Immutable view of the intel tables. Always safe to use."""

    __slots__ = ("domains", "wildcards", "ips", "packages", "typosquats",
                 "revised", "available", "path", "error")

    def __init__(self, domains=None, wildcards=None, ips=None, packages=None,
                 typosquats=None, revised="", available=False, path="",
                 error=""):
        self.domains = domains or {}
        # list of (".suffix", record) pairs
        self.wildcards = wildcards or []
        self.ips = ips or {}
        self.packages = packages or {}
        self.typosquats = typosquats or {}
        self.revised = revised or ""
        self.available = bool(available)
        self.path = path or ""
        self.error = error or ""

    def __repr__(self):
        return ("Intel(available={}, domains={}, wildcards={}, ips={}, "
                "packages={}, typosquats={}, revised={!r})").format(
            self.available, len(self.domains), len(self.wildcards),
            len(self.ips), len(self.packages), len(self.typosquats),
            self.revised)


def _read_json(path, name):
    try:
        with open(os.path.join(path, name)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _truncate_map(mapping, budget):
    """Apply the entry cap deterministically (sorted), returning (map, budget)."""
    if budget <= 0 or not isinstance(mapping, dict):
        return {}, budget
    if len(mapping) <= budget:
        return mapping, budget - len(mapping)
    keys = sorted(mapping)[:budget]
    return {k: mapping[k] for k in keys}, 0


def _manifest_mtime(path):
    try:
        return os.path.getmtime(os.path.join(path, "manifest.json"))
    except OSError:
        return None


def load_intel(path=None, *, force_reload=False):
    """Load the intel tables, re-reading them after a re-sync. Never raises."""
    global _CACHE, _CACHE_MTIME, _CACHE_CHECKED_AT
    resolved = path or os.environ.get("SCA_INTEL_PATH") or DEFAULT_INTEL_PATH

    with _CACHE_LOCK:
        if _CACHE is not None and not force_reload and _CACHE.path == resolved:
            now = time.time()
            if now - _CACHE_CHECKED_AT < RELOAD_CHECK_SECONDS:
                return _CACHE
            _CACHE_CHECKED_AT = now
            # manifest.json is written last and only on a successful sync, so
            # its mtime is exactly "the data changed".
            if _manifest_mtime(resolved) == _CACHE_MTIME:
                return _CACHE
        _CACHE = _load_uncached(resolved)
        _CACHE_MTIME = _manifest_mtime(resolved)
        _CACHE_CHECKED_AT = time.time()
        return _CACHE


def reset_cache():
    """Drop the module-level cache. For tests, and for a deliberate reload."""
    global _CACHE, _CACHE_MTIME, _CACHE_CHECKED_AT
    with _CACHE_LOCK:
        _CACHE = None
        _CACHE_MTIME = None
        _CACHE_CHECKED_AT = 0.0


def _load_uncached(path):
    try:
        manifest = _read_json(path, "manifest.json")
        if not isinstance(manifest, dict):
            return Intel(path=path, error="no manifest at {}".format(path))

        network = _read_json(path, "network_iocs.json") or {}
        packages = _read_json(path, "packages.json") or {}
        typosquats = _read_json(path, "typosquats.json") or {}
        if not isinstance(network, dict):
            network = {}
        if not isinstance(packages, dict):
            packages = {}
        if not isinstance(typosquats, dict):
            typosquats = {}

        budget = MAX_ENTRIES
        domains, budget = _truncate_map(network.get("domains"), budget)
        ips, budget = _truncate_map(network.get("ips"), budget)
        packages, budget = _truncate_map(packages, budget)
        typosquats, budget = _truncate_map(typosquats, budget)

        wildcards = []
        raw_wildcards = network.get("wildcards")
        if isinstance(raw_wildcards, list) and budget > 0:
            for item in raw_wildcards[:budget]:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    suffix, rec = item
                    if isinstance(suffix, str) and suffix:
                        wildcards.append((suffix.lower(), rec))

        return Intel(domains=domains, wildcards=wildcards, ips=ips,
                     packages=packages, typosquats=typosquats,
                     revised=str(manifest.get("revised") or ""),
                     available=True, path=path)
    except Exception as exc:  # the whole point of this module
        return Intel(path=path, error="load failed: {}".format(exc))


# ---------------------------------------------------------------------------
# Matching (A1 + A2)
# ---------------------------------------------------------------------------

def _normalize_suffixes(ignore_suffixes):
    if ignore_suffixes is None:
        ignore_suffixes = DEFAULT_IGNORE_SUFFIXES
    if isinstance(ignore_suffixes, str):
        ignore_suffixes = [s.strip() for s in ignore_suffixes.replace(",", " ").split()]
    return tuple(s.lower().lstrip(".") for s in ignore_suffixes if s)


def match_host(host, intel=None, *, ip=None, ignore_suffixes=None):
    """Return the incident record for `host` (or `ip`), else None.

    Exact hostname, then wildcard suffix, then the resolved IP. Suppressed for
    anything under the operator's ignore list, which exists so a pentester's own
    OAST callbacks are not reported as the target contacting attacker infra.
    """
    intel = intel if intel is not None else load_intel()
    if not intel.available:
        return None

    ignored = _normalize_suffixes(ignore_suffixes)
    if host:
        candidate = str(host).strip().lower().rstrip(".")
        # Strip a port if one rode along on the Host header.
        if ":" in candidate and not candidate.startswith("["):
            candidate = candidate.split(":", 1)[0]
        if candidate:
            for suffix in ignored:
                if candidate == suffix or candidate.endswith("." + suffix):
                    return None
            rec = intel.domains.get(candidate)
            if rec is not None:
                return rec
            # An IP-literal Host header belongs in the ips table, not domains -
            # the sync routes IP literals out of the feed's `domains` array the
            # same way. Without this a target addressed by IP only matches when
            # the caller also supplies a resolved ip, and the capture proxy sets
            # that on the response hook only.
            rec = intel.ips.get(candidate)
            if rec is not None:
                return rec
            for suffix, wrec in intel.wildcards:
                if candidate.endswith(suffix):
                    return wrec

    if ip:
        return intel.ips.get(str(ip).strip())
    return None


# ---------------------------------------------------------------------------
# Finding enrichment (B)
# ---------------------------------------------------------------------------

# The seven properties B attaches. Deliberately NOT added to the artifact
# allowlist in security.py: enrichment happens AFTER the last validate_artifact,
# so a re-validated enriched artifact must fail. That ordering is what keeps the
# DIRTY->CLEAN boundary closed (C1).
INCIDENT_FIELDS = ("incident_id", "incident_url", "incident_summary",
                   "incident_blast_radius", "incident_remediation",
                   "incident_status", "incident_feed_revised")


def _finding_key(finding):
    """(ecosystem, name), never the purl string.

    Only 136 of 3,541 package IOCs carry a version, so matching on a full purl
    would miss almost the whole catalog.
    """
    name = finding.get("name")
    if not name:
        return None
    ecosystem = (finding.get("ecosystem") or "npm").lower()
    return "{}/{}".format(ecosystem, name)


def enrich_findings(artifact, intel=None):
    """Attach incident context to findings that already exist. Mutates in place.

    Adds NO findings and changes NO verdict: only an OSV `MAL-` id makes a
    package malicious, and this match is name-only, which is weaker evidence.
    """
    intel = intel if intel is not None else load_intel()
    if not isinstance(artifact, dict):
        return artifact

    if not intel.available:
        # C7: a missing data source must never read as a clean result.
        errors = artifact.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(
                "sca-intel: incident catalog unavailable, findings were NOT "
                "annotated with incident context - run './whitehat.sh sca-intel-sync'")
        return artifact

    for bucket in ("malicious", "vulnerable", "suspicious"):
        entries = artifact.get(bucket)
        if not isinstance(entries, list):
            continue
        for finding in entries:
            if not isinstance(finding, dict):
                continue
            key = _finding_key(finding)
            if key is None:
                continue
            rec = intel.packages.get(key)
            if not rec:
                continue
            finding["incident_id"] = rec.get("incident_id", "")
            finding["incident_url"] = rec.get("url", "")
            finding["incident_summary"] = rec.get("summary", "")
            finding["incident_blast_radius"] = rec.get("blast_radius", "")
            finding["incident_remediation"] = list(rec.get("remediation") or [])[:20]
            finding["incident_status"] = rec.get("status", "")
            finding["incident_feed_revised"] = intel.revised
    return artifact
