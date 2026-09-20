"""A2: correlate discovered hosts against the supply-chain incident catalog.

Runs INSIDE run_supply_chain_recon rather than as its own recon group, because
partial recon calls run_supply_chain_recon directly - so this gives partial-recon
parity for free.

Inputs are nodes and files the pipeline ALREADY has: the target's BaseURLs and
the hosts of the JavaScript files js_recon already downloaded. Nothing here
fetches anything, so it adds no target traffic and no SSRF surface.

Scope, worth being precise about in any report: of the 364 incidents carrying
attacker domains, roughly 74 are browser-side (compromised script, CDN hijack,
skimmer) and ~89 are install-time (a postinstall calling home during
`npm install`). WhiteHat observes browser traffic and the JS recon downloads, so
it catches the browser-side class. This is NOT "detecting supply-chain attacks"
in general.
"""

import os

__all__ = ["correlate_hosts", "collect_candidate_hosts"]


def _js_hosts(combined_result):
    """Hosts serving JS that js_recon downloaded, with the URL that named them.

    js_recon already separates third-party hosts into `external_domains`; those
    are exactly the candidates here, since a host inside the target's own scope
    is not "a third party the target contacts".
    """
    out = {}
    js = (combined_result or {}).get("js_recon") or {}
    for entry in (js.get("external_domains") or []):
        if not isinstance(entry, dict):
            continue
        host = (entry.get("domain") or "").strip().lower()
        if not host:
            continue
        urls = entry.get("urls") or []
        out[host] = urls[0] if urls else None
    return out


def collect_candidate_hosts(combined_result, base_urls):
    """{host: source_url} for every host this scan legitimately observed."""
    from urllib.parse import urlparse

    candidates = {}
    for url in base_urls or []:
        try:
            host = (urlparse(url).hostname or "").strip().lower()
        except Exception:
            continue
        if host:
            candidates.setdefault(host, url)
    for host, url in _js_hosts(combined_result).items():
        candidates.setdefault(host, url)
    return candidates


def correlate_hosts(combined_result, base_urls, *, intel=None,
                    ignore_suffixes=None):
    """Match observed hosts against the incident catalog.

    Returns {"correlations": [...], "checked": N, "available": bool}. Never
    raises: a missing catalog degrades to zero correlations plus available=False,
    which the caller records as "the pass did not run" rather than as a clean
    result.
    """
    result = {"correlations": [], "checked": 0, "available": False}
    try:
        from supply_chain_common.intel import load_intel, match_host
    except Exception as exc:
        result["error"] = "intel module unavailable: {}".format(exc)
        return result

    try:
        intel = intel if intel is not None else load_intel()
    except Exception as exc:  # load_intel is contractually non-raising, belt+braces
        result["error"] = "intel load failed: {}".format(exc)
        return result

    result["available"] = bool(intel.available)
    if not intel.available:
        return result

    if ignore_suffixes is None:
        # Passed at spawn as env because the recon container has no route to the
        # per-user setting; the orchestrator forwards it the way it forwards the
        # capture egress policy.
        ignore_suffixes = os.environ.get("CAPTURE_IOC_IGNORE_SUFFIXES") or None

    candidates = collect_candidate_hosts(combined_result, base_urls)
    result["checked"] = len(candidates)

    # One anchor BaseURL per correlation. The attacker host is NOT the target,
    # so it must never become a node of its own: it lives on the relationship.
    anchor = (base_urls or [None])[0]
    for host, source_url in sorted(candidates.items()):
        try:
            rec = match_host(host, intel, ignore_suffixes=ignore_suffixes)
        except Exception:
            continue
        if not rec:
            continue
        result["correlations"].append({
            "base_url": _anchor_for(host, base_urls, anchor),
            "matched_host": host,
            "source_url": source_url,
            "evidence": "graph-host-match",
            "incident": rec,
        })
    return result


def _anchor_for(host, base_urls, default):
    """Prefer the BaseURL whose own host matched; else the first BaseURL.

    A JS host is a third party contacted BY the target, so it anchors to the
    target's BaseURL rather than to itself.
    """
    from urllib.parse import urlparse

    for url in base_urls or []:
        try:
            if (urlparse(url).hostname or "").lower() == host:
                return url
        except Exception:
            continue
    return default
