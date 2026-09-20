"""Population of the supply-chain incident-intel volume (`whitehat-sca-intel`).

Fetches the supplychainattack.org incident catalog and normalizes it into three
small lookup files plus a manifest. Mirrors `osv_db_sync.py`: the remote feed is
itself an untrusted supply-chain input, so it is host-pinned, envelope-validated,
byte-capped, every value charset-gated, and the result is mounted read-only
everywhere except here.

Run two ways:
  - the operator command `./whitehat.sh sca-intel-sync`
  - the orchestrator's TTL-guarded refresh on the scan-spawn path

stdlib only, so it runs inside the tiny analyzer image with no new deps. In
particular this does NOT import services/knowledge_base/curation/safe_http.py:
that module is absent from the analyzer image and importing it fails at runtime,
not at build time. Its logic (scheme check, host allowlist re-checked on every
redirect hop, hop cap, byte cap) is mirrored below instead.

Output layout under --out:

    network_iocs.json   {"domains": {host: rec}, "wildcards": [[suffix, rec]],
                         "ips": {addr: rec}}
    packages.json       {"<ecosystem>/<name>": rec}
    typosquats.json     {"<fake>": {"original": ..., "incident_id": ...}}
    manifest.json       feed revision, fetch time, accept/drop counts
    .whitehat_sca_intel_attempt   touched on EVERY attempt (retry floor)
"""

import ipaddress
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .security import (MAX_STRING_LEN, SanitizeError, sanitize_advisory,
                       sanitize_ecosystem, sanitize_hostname, sanitize_name)

__all__ = ["sync_intel", "intel_is_fresh", "attempt_is_recent",
           "FEED_URL", "ALLOWED_HOSTS", "MAX_FEED_BYTES",
           "DEFAULT_TTL_SECONDS", "DEFAULT_RETRY_SECONDS", "describe_result",
           "seed_if_empty",
           "MANIFEST_NAME", "ATTEMPT_MARKER"]

FEED_URL = "https://supplychainattack.org/incidents.json"
ALLOWED_HOSTS = ("supplychainattack.org",)

# The feed is ~5.3 MB. 32 MB leaves a wide margin for growth while still
# bounding a hostile or runaway response.
MAX_FEED_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 60

DEFAULT_TTL_SECONDS = 24 * 3600
# Retry floor after a FAILED or REJECTED fetch. Without this a feed that is down
# (or serving a bad envelope, which by contract leaves the previous files in
# place and so never advances the manifest) would be re-fetched on every single
# scan spawn for as long as it stays broken.
DEFAULT_RETRY_SECONDS = 3600

MANIFEST_NAME = "manifest.json"
ATTEMPT_MARKER = ".whitehat_sca_intel_attempt"

# Entry caps. The feed is 3,595 incidents today; these bound a hostile feed.
MAX_INCIDENTS = 50000
MAX_PACKAGES_PER_INCIDENT = 50
MAX_REMEDIATION_STEPS = 20

# Registry/ccTLD suffixes under which ANYONE can register. A bare wildcard on one
# of these is not an IOC, it is "every website in a country": '*.co.uk' stored as
# the suffix '.co.uk' matches every .co.uk asset in the graph and every captured
# request to one. The feed is attacker-influenceable, so one crafted entry would
# otherwise flood an engagement with false positives.
#
# Label count cannot be the test: '*.evil-attacker.com' also has a two-label body
# and IS a legitimate, valuable IOC. Only suffix identity distinguishes them, and
# a full public-suffix list is not available here (this module is stdlib-only by
# contract), so this is the pragmatic subset: the multi-label public suffixes an
# engagement realistically meets. A deeper wildcard under one
# ('*.attacker.co.uk') scopes to a single registrable domain and is KEPT.
PUBLIC_REGISTRY_SUFFIXES = frozenset({
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
    "com.ph", "com.vn", "com.pl", "com.ua", "com.ru", "com.es", "com.pt",
    "co.kr", "or.kr", "ne.kr", "go.kr",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "co.id", "or.id", "web.id", "go.id",
    "com.co", "com.pe", "com.ve", "com.ec", "com.uy", "com.py",
    "co.th", "in.th", "ac.th", "go.th",
    "gov.uk", "nhs.uk", "police.uk",
    "eu.org", "us.com", "uk.com", "eu.com", "cn.com", "de.com", "jp.net",
})

# Public hosting apexes where a BARE wildcard covers every tenant of a shared
# platform. '*.workers.dev' is all of Cloudflare Workers: shipping it would flag
# every legitimate target that uses a Worker. A specific host under one of these
# ('ai-script.test0ing7.workers.dev') and a deeper wildcard ('*.cf99.workers.dev')
# both still name one attacker deployment and are kept.
PUBLIC_HOSTING_APEXES = frozenset({
    "workers.dev", "vercel.app", "netlify.app", "pages.dev", "web.app",
    "firebaseapp.com", "herokuapp.com", "github.io", "glitch.me",
    "repl.co", "replit.dev", "ngrok.io", "ngrok-free.app", "onrender.com",
    "fly.dev", "surge.sh", "azurewebsites.net", "cloudfront.net",
    "amplifyapp.com", "r2.dev", "trycloudflare.com",
    # Wildcard-DNS services: every name under them resolves to the IP embedded
    # in the name, so a bare wildcard is "the entire internet by another route".
    # The live feed does use specific hosts under these (e.g. an sslip.io host
    # naming one attacker IP), which is why only the BARE wildcard is dropped.
    "sslip.io", "nip.io", "xip.io", "traefik.me", "localtest.me",
    "requestbin.net", "webhook.site", "interact.sh", "burpcollaborator.net",
})


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

class FeedError(RuntimeError):
    """The feed could not be fetched or did not look like the expected feed."""


def _assert_allowed(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FeedError("refusing non-http(s) URL (scheme={!r})".format(parsed.scheme))
    host = (parsed.hostname or "").lower()
    if not any(host == allowed.lower() for allowed in ALLOWED_HOSTS):
        raise FeedError("refusing request to off-allowlist host {!r}".format(host))


def fetch_feed(url=FEED_URL, *, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_FEED_BYTES,
               opener=None):
    """Host-allowlisted, size-capped GET returning the decoded JSON body.

    Redirects are followed MANUALLY so every hop's host is re-checked before a
    request is sent; an off-allowlist redirect target is refused. Never logs the
    URL with query parameters and never echoes the body on error.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _assert_allowed(current)
        req = urllib.request.Request(
            current,
            headers={"User-Agent": "WhiteHat-sca-intel-sync",
                     "Accept": "application/json"},
        )
        try:
            # No redirect handler: a 3xx is returned rather than followed, so the
            # next hop goes back through _assert_allowed above.
            open_fn = opener if opener is not None else _open_no_redirect
            resp = open_fn(req, timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location") if exc.headers else None
                if not location:
                    raise FeedError("redirect with no Location header")
                current = location
                continue
            raise FeedError(_describe_http_failure(exc))
        except urllib.error.URLError as exc:
            raise FeedError("feed unreachable: {}".format(exc.reason))
        except OSError as exc:
            raise FeedError("feed unreachable: {}".format(exc))

        with resp:
            length = resp.headers.get("Content-Length") if resp.headers else None
            if length:
                try:
                    if int(length) > max_bytes:
                        raise FeedError("feed too large (Content-Length {})".format(length))
                except ValueError:
                    pass
            body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise FeedError("feed exceeded {} bytes".format(max_bytes))
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FeedError("feed is not valid JSON: {}".format(exc))

    raise FeedError("too many redirects")


# A bare "HTTP 402" reads as a WhiteHat bug; these say whose outage it is.
_HTTP_STATUS_REASONS = {
    402: "the feed's hosting is paused or disabled upstream",
    403: "the feed host refused the request",
    404: "the feed is no longer published at this URL",
    410: "the feed is no longer published at this URL",
    429: "the feed host is rate-limiting requests",
}

# Vercel names the exact reason in a header (DEPLOYMENT_DISABLED, ...). It is
# attacker-influenceable text going to a log, so only a short token is echoed.
_VERCEL_ERROR_MAX = 64


def _describe_http_failure(exc):
    """One line naming the status and whose side the failure is on."""
    code = exc.code
    reason = _HTTP_STATUS_REASONS.get(code)
    if reason is None and 500 <= code < 600:
        reason = "the feed host is having a server error"
    text = "feed returned HTTP {}".format(code)
    if reason:
        text += " ({})".format(reason)
    vercel = exc.headers.get("x-vercel-error") if exc.headers else None
    if (isinstance(vercel, str) and 0 < len(vercel) <= _VERCEL_ERROR_MAX
            and all(ch.isupper() or ch == "_" for ch in vercel)):
        text += " [{}]".format(vercel)
    return text


def _open_no_redirect(req, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    return opener.open(req, timeout=timeout)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an HTTPError so the caller re-validates the host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------------------
# Envelope + normalization
# ---------------------------------------------------------------------------

def validate_envelope(payload):
    """Reject anything that is not the expected feed shape, BEFORE ingesting.

    On rejection the caller leaves the previous derived files untouched; the one
    thing that must never happen is truncating good data to empty because the
    feed had a bad day.
    """
    if not isinstance(payload, dict):
        raise FeedError("feed must be a JSON object")
    incidents = payload.get("incidents")
    if not isinstance(incidents, list):
        raise FeedError("feed has no 'incidents' list")
    count = payload.get("count")
    if not isinstance(count, int) or isinstance(count, bool):
        raise FeedError("feed has no integer 'count'")
    if count <= 0:
        raise FeedError("feed reports count={}".format(count))
    if not incidents:
        raise FeedError("feed 'incidents' is empty")
    if len(incidents) > MAX_INCIDENTS:
        raise FeedError("feed has {} incidents (cap {})".format(
            len(incidents), MAX_INCIDENTS))
    return incidents


def _cap(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value[:MAX_STRING_LEN]


def _safe_link(value):
    """An http(s) URL, or "" for anything else.

    The feed's `url` reaches an <a href> in three tables. React escapes text but
    does NOT block a `javascript:` href, so an incident published with
    `javascript:...` would execute in the operator's authenticated session the
    moment they clicked through. Anyone can get an advisory published, which is
    exactly why every other field here is charset-gated; this one was only
    length-capped.

    Gated at sync time so a poisoned URL never reaches the volume, the graph or
    the browser. The render sites re-check for rows an earlier sync stored.
    """
    url = _cap(value).strip()
    if not url:
        return ""
    lowered = url.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        return ""
    # Control characters can split the attribute or smuggle a second scheme past
    # a naive prefix check ("java\tscript:"); no legitimate URL carries them.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return ""
    return url


def _incident_record(inc):
    """The compact record shared by every lookup file."""
    return {
        "incident_id": inc["_id"],
        "url": _safe_link(inc.get("url")),
        "title": _cap(inc.get("title")),
        "status": _cap(inc.get("status")),
        "severity": _cap(inc.get("severity")),
        "summary": _cap(inc.get("summary")),
        "blast_radius": _cap(inc.get("blastRadius")),
        "remediation": inc.get("_remediation", []),
        "attack_vectors": inc.get("_attack_vectors", []),
        "last_updated": _cap(inc.get("lastUpdated")),
    }


def _norm_remediation(raw):
    """Remediation is free text or a list of steps; normalize to a capped list."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out = []
    for step in raw[:MAX_REMEDIATION_STEPS]:
        if isinstance(step, dict):
            step = step.get("step") or step.get("text") or step.get("description")
        if step is None:
            continue
        text = _cap(step)
        if text:
            out.append(text)
    return out


def _norm_str_list(raw, cap=20):
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [_cap(x) for x in raw[:cap] if x]


def _ip_is_usable(addr):
    """Keep only globally routable addresses.

    A poisoned feed entry naming 127.0.0.1 or 10.0.0.0/8 would otherwise turn
    every internal target into a 'contacts malicious host' finding.

    `is_global` is the primary gate because it is the only one that covers the
    whole IANA special-purpose registry in one check. In particular CGNAT
    (100.64.0.0/10) is NOT in `is_private` on any Python we run, so a
    private-only check silently lets shared-carrier space through. The explicit
    checks below stay as belt-and-braces in case a future Python reclassifies
    one of them.
    """
    if not getattr(addr, "is_global", False):
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified
                or getattr(addr, "is_site_local", False))


def _is_bare_public_apex_wildcard(host):
    """True for a wildcard whose body is a shared namespace anyone can register
    or deploy under: '*.workers.dev', '*.co.uk' (drop).

    False for a wildcard scoped to one registrable domain, which is what a real
    IOC looks like: '*.evil-attacker.com', '*.cf99.workers.dev',
    '*.attacker.co.uk' (keep).
    """
    if not host.startswith("*."):
        return False
    body = host[2:]
    return body in PUBLIC_HOSTING_APEXES or body in PUBLIC_REGISTRY_SUFFIXES


def normalize(incidents):
    """Turn the raw incident list into the three lookup tables + drop counts.

    Every value passes a charset gate; a rejected value is DROPPED AND COUNTED,
    never silently vanished, so the sync report can be read as coverage.
    """
    domains, wildcards, ips, packages, typosquats = {}, [], {}, {}, {}
    stats = {
        "incidents": 0, "incidents_dropped": 0,
        "domains": 0, "domains_dropped": 0,
        "wildcards": 0, "wildcards_dropped_public_apex": 0,
        "ips": 0, "ips_dropped": 0,
        "packages": 0, "packages_dropped": 0,
        "typosquats": 0,
    }

    for inc in incidents:
        if not isinstance(inc, dict):
            stats["incidents_dropped"] += 1
            continue
        try:
            incident_id = sanitize_advisory(_cap(inc.get("id")) or None)
        except SanitizeError:
            incident_id = None
        if not incident_id:
            stats["incidents_dropped"] += 1
            continue

        inc = dict(inc)
        inc["_id"] = incident_id
        inc["_remediation"] = _norm_remediation(inc.get("remediation"))
        inc["_attack_vectors"] = _norm_str_list(inc.get("attackVectors"))
        rec = _incident_record(inc)
        stats["incidents"] += 1

        iocs = inc.get("iocs") or {}
        if not isinstance(iocs, dict):
            iocs = {}

        # ---- network IOCs -------------------------------------------------
        for raw in _norm_str_list(iocs.get("domains"), cap=200):
            # Raw IPs land in the domains array; route them to the IP validator
            # so the private-range drop applies to them too.
            try:
                addr = ipaddress.ip_address(raw.strip())
            except ValueError:
                addr = None
            if addr is not None:
                if _ip_is_usable(addr):
                    ips[str(addr)] = rec
                    stats["ips"] += 1
                else:
                    stats["ips_dropped"] += 1
                continue
            try:
                host = sanitize_hostname(raw)
            except SanitizeError:
                # Prose sentences and slash-joined garbage land here.
                stats["domains_dropped"] += 1
                continue
            if _is_bare_public_apex_wildcard(host):
                stats["wildcards_dropped_public_apex"] += 1
                continue
            if host.startswith("*."):
                wildcards.append([host[1:], rec])  # store as '.suffix'
                stats["wildcards"] += 1
            else:
                domains[host] = rec
                stats["domains"] += 1

        for raw in _norm_str_list(iocs.get("ips"), cap=200):
            try:
                addr = ipaddress.ip_address(raw.strip())
            except ValueError:
                stats["ips_dropped"] += 1
                continue
            if not _ip_is_usable(addr):
                stats["ips_dropped"] += 1
                continue
            ips[str(addr)] = rec
            stats["ips"] += 1

        # ---- package IOCs -------------------------------------------------
        for entry in (iocs.get("packages") or [])[:MAX_PACKAGES_PER_INCIDENT]:
            key = _package_key(entry)
            if key is None:
                stats["packages_dropped"] += 1
                continue
            packages[key] = rec
            stats["packages"] += 1

        # ---- typosquat labels ---------------------------------------------
        for fake, original in _typosquat_pairs(inc):
            typosquats[fake] = {"original": original, "incident_id": incident_id}
            stats["typosquats"] += 1

    # The counters above count OCCURRENCES processed; the tables are keyed by
    # host/package, so several incidents naming the same indicator collapse to
    # one entry (last writer wins - one record per indicator is the data shape).
    # Reporting only the occurrence count overstated real coverage 5x on the
    # live feed (1,159 "domains" -> 221 usable), and the sync report is meant to
    # be read as coverage. Both numbers ship, so a large gap between them is
    # visible rather than silently flattering.
    stats["domains_unique"] = len(domains)
    stats["ips_unique"] = len(ips)
    stats["packages_unique"] = len(packages)
    stats["typosquats_unique"] = len(typosquats)
    stats["wildcards_unique"] = len(wildcards)
    stats["indicator_collisions"] = (
        (stats["domains"] - len(domains))
        + (stats["ips"] - len(ips))
        + (stats["packages"] - len(packages))
    )

    return {
        "network_iocs": {"domains": domains, "wildcards": wildcards, "ips": ips},
        "packages": packages,
        "typosquats": typosquats,
        "stats": stats,
    }


def _package_key(entry):
    """'<ecosystem>/<name>' for a package IOC, or None if unusable.

    Matching is name-only by design: only 136 of 3,541 package IOCs are
    version-pinned, so a version match would drop most of the catalog. That is
    also why a hit here is weaker evidence than an OSV verdict and never sets a
    verdict of its own.
    """
    if isinstance(entry, str):
        name, ecosystem = entry, "npm"
    elif isinstance(entry, dict):
        name = entry.get("name") or entry.get("package")
        ecosystem = entry.get("ecosystem") or entry.get("registry") or "npm"
    else:
        return None
    if not name:
        return None
    try:
        name = sanitize_name(_cap(name))
        ecosystem = sanitize_ecosystem(_cap(ecosystem)) or "npm"
    except SanitizeError:
        return None
    return "{}/{}".format(ecosystem.lower(), name)


def _typosquat_pairs(inc):
    """Extract (fake, original) pairs the feed labels in affectedEntities notes.

    The catalog names the impersonated package in `affectedEntities[].note`
    (125 pairs). These are the ground truth for D's edit-distance threshold.
    """
    out = []
    entities = inc.get("affectedEntities")
    if not isinstance(entities, list):
        return out
    vectors = [v.lower() for v in inc.get("_attack_vectors", [])]
    if not any("typosquat" in v for v in vectors):
        return out
    for ent in entities[:MAX_PACKAGES_PER_INCIDENT]:
        if not isinstance(ent, dict):
            continue
        fake_raw = ent.get("name")
        note = ent.get("note") or ""
        if not fake_raw or not isinstance(note, str):
            continue
        original_raw = _original_from_note(note)
        if not original_raw:
            continue
        try:
            fake = sanitize_name(_cap(fake_raw))
            original = sanitize_name(_cap(original_raw))
        except SanitizeError:
            continue
        if fake == original:
            continue
        out.append((fake, original))
    return out


def _original_from_note(note):
    """Pull the impersonated package name out of a free-text note.

    The notes read like "typosquat of lodash" / "impersonates python-dateutil".
    Deliberately conservative: no match means no pair, because a wrong pair
    poisons D's ground-truth test set.
    """
    lowered = note.lower()
    for marker in ("typosquat of ", "typosquats ", "impersonates ",
                   "impersonating ", "mimics ", "squat of "):
        idx = lowered.find(marker)
        if idx == -1:
            continue
        tail = note[idx + len(marker):].strip()
        token = tail.split()[0] if tail.split() else ""
        return token.strip(".,;:'\"()[]")
    return None


# ---------------------------------------------------------------------------
# Freshness markers
# ---------------------------------------------------------------------------

def intel_is_fresh(out_path, ttl_seconds=DEFAULT_TTL_SECONDS):
    """True if a SUCCESSFUL sync landed within the TTL window.

    Keyed on manifest.json's mtime, which is written on success only, so there is
    no second source of truth to drift from.
    """
    try:
        age = time.time() - os.path.getmtime(os.path.join(out_path, MANIFEST_NAME))
    except OSError:
        return False
    return age < ttl_seconds


def attempt_is_recent(out_path, retry_seconds=DEFAULT_RETRY_SECONDS):
    """True if ANY attempt (success or failure) landed within the retry floor."""
    try:
        age = time.time() - os.path.getmtime(os.path.join(out_path, ATTEMPT_MARKER))
    except OSError:
        return False
    return age < retry_seconds


def _touch_attempt(out_path):
    try:
        os.makedirs(out_path, exist_ok=True)
        with open(os.path.join(out_path, ATTEMPT_MARKER), "w") as fh:
            fh.write(str(int(time.time())))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def sync_intel(out_path, *, url=FEED_URL, force=False,
               ttl_seconds=DEFAULT_TTL_SECONDS,
               retry_seconds=DEFAULT_RETRY_SECONDS,
               timeout=DEFAULT_TIMEOUT, fetcher=None):
    """Fetch, validate, normalize and write the intel files.

    Returns {"status": synced|skipped|seeded|failed, "detail": ..., "stats": {...}}
    ("seeded": the feed failed and the bundled offline copy filled a cold
    volume; a "failed" result carries "kept", the revision still on the volume).
    Never raises: a failure here must never block the scan that triggered it.
    """
    if not force:
        if intel_is_fresh(out_path, ttl_seconds):
            return _skip_or_seed(out_path, "within TTL")
        if attempt_is_recent(out_path, retry_seconds):
            return _skip_or_seed(out_path, "within retry floor")

    # Touched BEFORE the fetch: a hang that gets killed by the sidecar timeout
    # must still count as an attempt, or a wedged feed is retried every scan.
    _touch_attempt(out_path)

    try:
        payload = (fetcher or fetch_feed)(url, timeout=timeout)
        incidents = validate_envelope(payload)
    except FeedError as exc:
        # Previous derived files are left exactly as they were.
        return _feed_unavailable(out_path, str(exc))
    except Exception as exc:  # never raise into a scan spawn
        return _feed_unavailable(out_path, "unexpected: {}".format(exc))

    try:
        norm = normalize(incidents)

        # A well-formed feed that carries NO indicators is not a clean result,
        # it is a broken publisher. The envelope check upstream only proves
        # there are incidents; a schema change or a partial regeneration can
        # ship thousands of incidents with empty `iocs`, which normalizes to
        # empty tables, overwrites the good ones, and reports success. Readers
        # then load available=True and match nothing, so C7 records nothing
        # either - the same silent false clean the envelope rule exists to stop,
        # one level further down.
        #
        # Deliberately narrow: ONLY a total wipe is refused, never a shrink. A
        # feed legitimately drops indicators between revisions, and a
        # percentage heuristic here would reject good syncs.
        if not force and _indicator_total(norm) == 0:
            previous = _previous_indicator_total(out_path)
            if previous == 0:
                # Cold volume: an empty "success" would load as available=True
                # and match nothing, so the bundled copy wins when it is usable.
                # Without it, the first sync still goes through as before.
                seeded = _try_install_seed(out_path)
                if "revised" in seeded:
                    return _seeded_result("feed carried no indicators at all", seeded)
            if previous > 0:
                return {"status": "failed",
                        "detail": ("feed carried no indicators at all while {} "
                                   "are already stored; refusing to overwrite "
                                   "good data with an empty set (use --force to "
                                   "override)".format(previous)),
                        "stats": norm["stats"]}

        revised = _cap(payload.get("revised")) or ""
        manifest = {
            "feed_url": url,
            "revised": revised,
            "fetched_at": int(time.time()),
            "count_reported": payload.get("count"),
            "count_ingested": norm["stats"]["incidents"],
            "stats": norm["stats"],
        }
        _write_all(out_path, norm, manifest)
    except OSError as exc:
        return {"status": "failed", "detail": "write failed: {}".format(exc),
                "stats": {}}
    except Exception as exc:
        return {"status": "failed", "detail": "normalize failed: {}".format(exc),
                "stats": {}}

    return {"status": "synced", "detail": "revised={}".format(revised),
            "stats": norm["stats"]}


def _feed_unavailable(out_path, reason):
    """The live feed failed: keep what is on the volume, or seed a cold one.

    Never raises (sync_intel's contract). The seed is installed ONLY when the
    volume has no usable indicators, or holds an older seed; live data, however
    old, is never replaced by the bundled copy because the copy drops the prose.
    """
    seeded = _try_install_seed(out_path)
    if "revised" in seeded:
        return _seeded_result(reason, seeded)
    detail, kept = reason, ""
    catalog = _current_catalog(out_path)
    if catalog:
        kept = catalog["revised"]
        detail += "; existing catalog kept (feed revision {})".format(kept)
    elif "error" in seeded:
        detail += "; bundled offline copy unusable: {}".format(seeded["error"])
    return {"status": "failed", "detail": detail, "stats": {}, "kept": kept}


def _skip_or_seed(out_path, why):
    """A skipped fetch still seeds an empty volume, from disk, with no network.

    The TTL and the retry floor exist to spare the FEED. Without this, a volume
    left empty by a recent failed attempt stayed empty until the floor expired,
    even though the bundled copy needs no fetch at all. Deliberately does not
    touch the attempt marker: no feed attempt happened.
    """
    if _current_catalog(out_path) is None:
        seeded = _try_install_seed(out_path)
        if "revised" in seeded:
            return _seeded_result("live feed not retried ({})".format(why), seeded)
    return {"status": "skipped", "detail": why, "stats": {}}


def seed_if_empty(out_path):
    """Install the bundled copy if the volume needs it; never fetches.

    For air-gapped deploys (SCA_INTEL_AUTO_REFRESH=false), which never run a
    sync and would otherwise keep an empty catalog forever. Same rules as the
    fallback inside sync_intel: an empty volume or an older bundled copy is
    seeded, a live catalog is never touched. Never raises.
    """
    seeded = _try_install_seed(out_path)
    if "revised" in seeded:
        return dict(_seeded_result("seed-only mode, no feed contacted", seeded),
                    seed_only=True)
    catalog = _current_catalog(out_path)
    if catalog is not None:
        return {"status": "skipped",
                "detail": "catalog already present (feed revision {})".format(
                    catalog["revised"]),
                "stats": {}}
    return {"status": "failed",
            "detail": "bundled offline copy unusable: {}".format(
                seeded.get("error", "unknown")),
            "stats": {}, "kept": ""}


def _seeded_result(reason, seeded):
    return {"status": "seeded",
            "detail": "{}; installed the bundled offline copy (feed revision "
                      "{}, indicators only)".format(reason, seeded["revised"]),
            "stats": seeded["stats"]}


def _try_install_seed(out_path):
    """_install_seed_if_needed that never raises; {} when nothing was needed."""
    try:
        return _install_seed_if_needed(out_path) or {}
    except Exception as exc:
        return {"error": "unexpected: {}".format(exc)}


def _current_catalog(out_path):
    """{'revised', 'source', 'seed_revised'} of the catalog on the volume, or None."""
    if _previous_indicator_total(out_path) <= 0:
        return None
    try:
        with open(os.path.join(out_path, MANIFEST_NAME)) as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(manifest, dict):
        return None
    return {"revised": _cap(manifest.get("revised")) or "unknown",
            "source": _cap(manifest.get("source")),
            "seed_revised": _cap(manifest.get("seed_revised"))}


def _install_seed_if_needed(out_path):
    """Install the bundled seed if the volume needs it.

    Returns None when nothing was needed, {"revised", "stats"} on install, or
    {"error"} when the seed itself was refused.
    """
    from . import intel_seed

    catalog = _current_catalog(out_path)
    if catalog is not None and catalog["source"] != intel_seed.SEED_SOURCE:
        return None
    try:
        # Read at call time (not load_seed's bound defaults) so tests can point
        # the sync at a missing or altered seed.
        seed = intel_seed.load_seed(intel_seed.SEED_FILE, intel_seed.SEED_SHA256)
    except intel_seed.SeedError as exc:
        return {"error": str(exc)}
    meta = seed["meta"]
    # A seeded volume is only upgraded by a strictly newer seed (ISO dates sort).
    if catalog is not None and catalog["seed_revised"] >= meta["revised"]:
        return None

    manifest = {
        "feed_url": FEED_URL,
        # Suffixed so every surface that shows the revision (finding property,
        # graph, webapp) makes clear this is the bundled copy, not a live sync.
        "revised": "{}-bundled".format(meta["revised"]),
        "seed_revised": meta["revised"],
        "source": intel_seed.SEED_SOURCE,
        "fetched_at": meta["fetched_at"],
        "count_reported": meta["count_reported"],
        "count_ingested": meta["count_ingested"],
        "stats": seed["stats"],
    }
    _write_all(out_path, seed["tables"], manifest)
    # Back-date the manifest to when the snapshot was really fetched. Its mtime
    # is the TTL marker, and a just-installed seed must not read as a fresh sync:
    # that would suppress retries of the live feed for a whole TTL.
    manifest_path = os.path.join(out_path, MANIFEST_NAME)
    os.utime(manifest_path, (meta["fetched_at"], meta["fetched_at"]))
    return {"revised": manifest["revised"], "stats": seed["stats"]}


def describe_result(result):
    """One operator-facing line for a sync_intel result."""
    status, detail = result.get("status"), result.get("detail", "")
    if status == "synced":
        return "sca-intel: incident catalog synced ({}).".format(detail)
    if status == "skipped":
        return "sca-intel: nothing to do ({}).".format(detail)
    if status == "seeded" and result.get("seed_only"):
        return ("sca-intel: {}. Auto-refresh is off, so it stays until "
                "'./whitehat.sh sca-intel-sync' can reach the feed.".format(detail))
    if status == "seeded":
        return ("sca-intel: {}. The live feed is retried automatically and "
                "replaces it once it answers.".format(detail))
    if result.get("kept"):
        return ("sca-intel: the live incident feed could not be used: {}. This is "
                "an upstream problem, not a WhiteHat one; supply-chain findings keep "
                "using the stored catalog.".format(detail))
    return ("sca-intel: sync failed: {}. No incident catalog is available, so "
            "supply-chain findings carry no incident context.".format(detail))


def _indicator_total(norm):
    """Every usable lookup entry in a normalized result."""
    net = norm.get("network_iocs") or {}
    return (len(net.get("domains") or {})
            + len(net.get("wildcards") or [])
            + len(net.get("ips") or {})
            + len(norm.get("packages") or {})
            + len(norm.get("typosquats") or {}))


def _previous_indicator_total(out_path):
    """What is already on the volume, for the empty-overwrite guard.

    Read defensively: an unreadable or absent previous set counts as 0, so a
    first sync onto a cold volume is never blocked by this.
    """
    total = 0
    for name, key in (("network_iocs.json", None), ("packages.json", None),
                      ("typosquats.json", None)):
        try:
            with open(os.path.join(out_path, name)) as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            continue
        if name == "network_iocs.json" and isinstance(blob, dict):
            total += (len(blob.get("domains") or {})
                      + len(blob.get("wildcards") or [])
                      + len(blob.get("ips") or {}))
        elif isinstance(blob, dict):
            total += len(blob)
    return total


def _write_all(out_path, norm, manifest):
    """Write every file atomically, manifest LAST.

    manifest.json is the freshness marker, so it must not exist newer than the
    data it describes; writing it last means a crash mid-write leaves a stale
    manifest and the next run retries rather than trusting half a dataset.
    """
    os.makedirs(out_path, exist_ok=True)
    _write_json(out_path, "network_iocs.json", norm["network_iocs"])
    _write_json(out_path, "packages.json", norm["packages"])
    _write_json(out_path, "typosquats.json", norm["typosquats"])
    _write_json(out_path, MANIFEST_NAME, manifest)
    _make_world_readable(out_path)


def _write_json(out_path, name, payload):
    """Write one table, atomically, through a temp file UNIQUE to this writer.

    A fixed `<name>.tmp` was not safe: two writers can be in here at once (the
    operator's `whitehat.sh sca-intel-sync --force` skips both the TTL and the
    retry floor, so it can land on top of a scan-triggered refresh), and the
    orchestrator's lock is per-process. Both would open the SAME path, truncate
    it, and interleave their writes; the surviving file could be spliced from
    two streams. A corrupt table then reads back as `available=True` with ZERO
    entries, because the loader treats a parse failure as an empty table - a
    silent false clean, which is the one outcome this whole feature exists to
    prevent.

    A pid suffix would NOT be enough: each container has its own PID namespace,
    so two sidecars are both pid 1. mkstemp is unique on the shared filesystem
    itself, which is the only scope that matters here.
    """
    final = os.path.join(out_path, name)
    fd, tmp = tempfile.mkstemp(dir=out_path, prefix=name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, separators=(",", ":"), sort_keys=True)
        # Atomic: the reader sees either the old file or the new one, never a
        # half-written one. Concurrent writers now race only on WHICH complete
        # file wins, which is survivable; they no longer corrupt one.
        os.replace(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _make_world_readable(out_path):
    """Add o+rX across the tree.

    Same reason as the OSV DB: this volume is consumed by NON-root, read-only
    scan containers. Written 0750 by root they would see an empty directory and
    silently produce no enrichment at all.
    """
    import stat as _stat
    for root, dirs, files in os.walk(out_path):
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


def _main(argv=None):
    """CLI used by `whitehat.sh sca-intel-sync` and the orchestrator sidecar."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sync the supply-chain incident intel volume.")
    parser.add_argument("--out", required=True)
    parser.add_argument("--url", default=FEED_URL)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--force", action="store_true")
    mode.add_argument("--seed-only", action="store_true",
                      help="install the bundled offline copy if the volume is "
                           "empty; never contact the feed (air-gapped deploys)")
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    parser.add_argument("--retry-seconds", type=int, default=DEFAULT_RETRY_SECONDS)
    args = parser.parse_args(argv)

    if args.seed_only:
        result = seed_if_empty(args.out)
    else:
        result = sync_intel(args.out, url=args.url, force=args.force,
                            ttl_seconds=args.ttl_seconds,
                            retry_seconds=args.retry_seconds)
    # One stream, human line first: the orchestrator keeps only the log TAIL and
    # greps it for the sentinel, so the sentinel must be the very last line. A
    # second stream (stderr) interleaves nondeterministically in `docker logs`.
    print(describe_result(result))
    # The drop report must be visible: counts, never silence.
    print(json.dumps(result, sort_keys=True))
    if result["status"] in ("synced", "seeded"):
        # Sentinel the orchestrator greps for, so a TTL no-op is never logged as
        # a change to the volume. A seed install IS a change.
        print("__DID_SYNC__")
    return 0 if result["status"] in ("synced", "skipped", "seeded") else 1


if __name__ == "__main__":
    import sys

    sys.exit(_main())
