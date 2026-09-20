"""
Cache Poisoning Scanner — Behavioural confirmation (Phase 4 of the native engine).

This is where WhiteHat becomes more than a WCVS wrapper. A vector is only
"confirmed" after a POISON-FIRST behavioural sequence:

  1. baseline      : fetch the URL clean on TWO separate cache-busters (a clean
                     reference + a non-determinism check). Two distinct slots are
                     used on purpose — re-reading ONE slot only returns the cache's
                     frozen copy and can't reveal a flapping page.
  2. poison        : fetch a THIRD, fresh cache-buster WITH the payload. Because it
                     is the first request to that key it is a cache MISS that reaches
                     the origin, lands the poison, and the cache stores the poisoned
                     response.
  3. clean follow  : fetch that SAME poison slot again WITHOUT the payload (victim
                     view) -> a cache HIT that serves the poisoned copy.
  4. persistence   : did the poison come back on the clean request?
  5. cache-hit     : was that clean response served from cache?
  (optional) repeat the clean read to confirm stability.

Poison-first is essential against a REAL cache: baselining the poison slot first
would warm it with a clean response, and the later poison (unkeyed header -> same
key) would just HIT the clean copy and never reach the origin (a false negative).

Two detection modes run side by side:
  * REFLECTED   - the benign canary marker is echoed in the body/redirect. Strong,
                  unambiguous proof (we injected that exact token).
  * DIFFERENTIAL- the poison changes the response *behaviour* (status code, Location
                  redirect, or body) WITHOUT echoing a marker. This catches the
                  non-reflective class (ported from CacheX's detector: ayuxdev/cachex,
                  MIT). To keep the low-false-positive bar, differential signals are
                  only trusted on dimensions that were STABLE across the two clean
                  baseline busters, and the cache-buster value is normalised out of
                  the comparison so distinct busters never look like a real change.

The canary is a non-resolving marker (.invalid), so a Confirmed finding never
points a victim at live attacker infrastructure.
"""

import hashlib
import re

import requests

from recon.cache_scan.buster import add_cache_buster
from recon.cache_scan.oracle import response_cache_state
from recon.cache_scan.safety import (
    new_canary_token, canary_host, canary_value, new_cache_buster_value,
)

# Fixed, benign payloads for non-reflective vectors. These poison via behaviour
# change, not by echoing a marker, so they carry a meaningful (but safe) value
# rather than a random canary token.
_FIXED_PAYLOADS = {"scheme": "https", "port": "443", "ip": "127.0.0.1"}


def _hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


def _payload_value(payload_kind: str, token: str) -> str:
    """Build the benign payload for a vector based on its kind."""
    if payload_kind == "host":
        return canary_host(token)
    if payload_kind == "path":
        return f"/{canary_value(token)}"
    if payload_kind == "forwarded":
        # RFC 7239 composite. Host carries the benign .invalid canary.
        return f"host={canary_host(token)};proto=https"
    if payload_kind in _FIXED_PAYLOADS:
        return _FIXED_PAYLOADS[payload_kind]
    return canary_value(token)


def _strip_buster(text: str, cb_param: str) -> str:
    """Remove the cache-buster query param from text so two responses fetched on
    different busters don't look different just because of the buster value."""
    if not text or not cb_param:
        return text or ""
    return re.sub(rf'[?&]{re.escape(cb_param)}=[^&\s"\'<>]+', '', text)


def _dim_value(resp, dim: str, cb_param: str = ""):
    """Extract one comparable response dimension (cache-buster normalised out)."""
    if dim == "status":
        return resp.status_code
    if dim == "location":
        return _strip_buster(resp.headers.get("location", "") or "", cb_param)
    return _strip_buster(resp.text or "", cb_param)  # body


def _changed_dims(a, b, cb_param: str = "") -> set:
    """Dimensions (status/location/body) that differ between two responses."""
    dims = set()
    for dim in ("status", "location", "body"):
        if _dim_value(a, dim, cb_param) != _dim_value(b, dim, cb_param):
            dims.add(dim)
    return dims


_XSS_PATTERNS = (
    r'<script[^>]*\bsrc\s*=\s*["\']?[^"\'>]*{n}',          # <script src=//canary> remote JS load
    r'<script[^>]*>[^<]*{n}',                               # inline <script> ... canary
    r'javascript:[^"\'<>]*{n}',                             # javascript: URI
    r'\son\w+\s*=\s*["\'][^>]*{n}',                         # event handler onerror= / onload= ...
    r'<(?:svg|img|iframe|object|embed)[^>]*\b(?:src|on\w+)[^>]*{n}',  # dangerous tag attribute
)


def _xss_context(body: str, needle: str) -> bool:
    """True if `needle` is reflected inside an executable (script / JS-URI / event-handler)
    context — i.e. the poisoning yields stored XSS, not just a benign reflection."""
    if not body or not needle:
        return False
    n = re.escape(needle)
    return any(re.search(p.format(n=n), body, re.IGNORECASE) for p in _XSS_PATTERNS)


def _pick_diff(base, mod, trusted: set, cb_param: str = "") -> str:
    """First trusted dimension that the poison changed (priority loc > status > body).

    429s are treated as rate-limit noise, never a change (mirrors CacheX).
    """
    if base.status_code == 429 or mod.status_code == 429:
        return ""
    changed = _changed_dims(base, mod, cb_param)
    for dim in ("location", "status", "body"):
        if dim in trusted and dim in changed:
            return dim
    return ""


def _apply_vector(url: str, vector_type: str, vector_name: str, payload: str):
    """Return (request_url, extra_headers) with the payload applied."""
    if vector_type == "header":
        return url, {vector_name: payload}
    if vector_type == "param":
        return add_cache_buster(url, vector_name, payload), {}
    if vector_type == "path":
        # Append the payload as a path segment (deception / path-confusion style).
        sep = "" if url.endswith("/") else "/"
        return f"{url}{sep}{payload.lstrip('/')}", {}
    return url, {}


def confirm_vector(vector: dict, buster: dict, session: requests.Session,
                   settings: dict, timeout: int = 10, verify_ssl: bool = True) -> dict:
    """Run the behavioural confirmation sequence for one vector.

    `vector` keys: url, vector_type, vector_name, payload_kind, impact_hint.
    Returns a confirmation record consumed by scoring.score_finding(), plus
    evidence fields for the graph.
    """
    url = vector["url"]
    vector_type = vector.get("vector_type", "header")
    vector_name = vector["vector_name"]
    payload_kind = vector.get("payload_kind", "value")

    cb_param = buster.get("param", "rdmncb")
    # The poison slot: a FRESH buster so the poison request below is the first request
    # to this cache key (a MISS that reaches the origin and lands the poison).
    cb_value = new_cache_buster_value()
    poison_url = add_cache_buster(url, cb_param, cb_value)

    token = new_canary_token()
    payload = _payload_value(payload_kind, token)
    differential_enabled = bool(settings.get("WEB_CACHE_POISON_DIFFERENTIAL", True))

    record = {
        "reflected_in_baseline": False,
        "persisted_on_clean": False,
        "persisted_reflected": False,
        "persisted_differential": False,
        "cache_hit_on_clean": False,
        "repeated_ok": False,
        "stable": True,
        "baseline_stable": True,
        "differential_change": "",
        "detection_mode": "none",
        "xss_context": False,
        "evidence": {},
        "cross_vantage": False,
    }

    def _get(req_url, extra_headers=None):
        return session.get(req_url, headers=extra_headers or None,
                           timeout=timeout, verify=verify_ssl, allow_redirects=False)

    try:
        # 1. baseline (clean), for differential only. TWO SEPARATE busters: comparing
        #    two clean slots reveals which dimensions are non-deterministic (a page
        #    that flaps per request) and must not be trusted. Re-reading ONE slot would
        #    just return the cache's frozen copy and hide the flapping.
        base_ref = None
        trusted: set = set()
        if differential_enabled:
            base_ref = _get(add_cache_buster(url, cb_param, new_cache_buster_value()))
            base2 = _get(add_cache_buster(url, cb_param, new_cache_buster_value()))
            unstable = _changed_dims(base_ref, base2, cb_param)
            trusted = {"status", "location", "body"} - unstable
            record["baseline_stable"] = not unstable

        # 2. POISON FIRST on the fresh poison slot -> MISS -> origin -> poison cached.
        req_url, extra_headers = _apply_vector(poison_url, vector_type, vector_name, payload)
        poisoned = _get(req_url, extra_headers)
        poisoned_body = poisoned.text or ""
        poisoned_loc = poisoned.headers.get("location", "") or ""
        reflected = (token in poisoned_body) or (token in poisoned_loc)
        record["reflected_in_baseline"] = reflected
        diff_type = (_pick_diff(base_ref, poisoned, trusted, cb_param)
                     if (differential_enabled and base_ref is not None) else "")
        record["differential_change"] = diff_type

        # 3. clean follow-up on the SAME poison slot (victim view) -> HIT -> poisoned.
        clean = _get(poison_url)
        clean_body = clean.text or ""
        clean_loc = clean.headers.get("location", "") or ""
        persisted_reflected = (token in clean_body) or (token in clean_loc)
        # Differential persistence: the poisoned value still shows on the clean request
        # AND it differs from the clean baseline (the poison stuck, didn't revert).
        persisted_differential = bool(diff_type) and (
            _dim_value(clean, diff_type, cb_param) == _dim_value(poisoned, diff_type, cb_param)
            and (base_ref is None
                 or _dim_value(clean, diff_type, cb_param) != _dim_value(base_ref, diff_type, cb_param))
        )
        persisted = persisted_reflected or persisted_differential
        record["persisted_reflected"] = persisted_reflected
        record["persisted_differential"] = persisted_differential
        record["persisted_on_clean"] = persisted
        record["cache_hit_on_clean"] = response_cache_state(clean) == "hit"
        record["detection_mode"] = (
            "both" if persisted_reflected and persisted_differential
            else "reflected" if persisted_reflected
            else "differential" if persisted_differential
            else "none"
        )
        # Stored XSS: the persisted canary lands in an executable context (the victim
        # gets attacker-controlled script from cache).
        record["xss_context"] = persisted_reflected and _xss_context(clean_body, token)

        # 4. repeat the clean read for stability (only if it persisted).
        if persisted:
            clean2 = _get(poison_url)
            clean2_body = clean2.text or ""
            if persisted_reflected:
                repeated = (token in clean2_body) or (token in (clean2.headers.get("location", "") or ""))
            else:
                repeated = _dim_value(clean2, diff_type, cb_param) == _dim_value(poisoned, diff_type, cb_param)
            record["repeated_ok"] = repeated
            record["stable"] = abs(len(clean_body) - len(clean2_body)) < max(64, len(clean_body) * 0.05)

        record["evidence"] = {
            "baseline_hash": _hash(base_ref.text if base_ref is not None else ""),
            "poisoned_hash": _hash(poisoned_body),
            "clean_validation_hash": _hash(clean_body),
            "poc_link": poison_url if persisted else "",
            "curl_verify": _build_curl(req_url, extra_headers),
            "canary": payload,
            "cache_buster": f"{cb_param}={cb_value}",
            "redirect_baseline": (base_ref.headers.get("location", "") or "") if base_ref is not None else "",
            "redirect_poisoned": poisoned_loc,
            "differential_change": diff_type,
            "poisoned_status": poisoned.status_code,
            "baseline_status": base_ref.status_code if base_ref is not None else None,
        }
    except requests.RequestException as e:
        record["stable"] = False
        record["evidence"] = {"error": str(e)}

    return record


def classify_impact(vector: dict, record: dict) -> str:
    """Resolve the concrete impact class from the vector hint + observed evidence."""
    hint = vector.get("impact_hint") or "reflected"
    ev = record.get("evidence", {}) or {}
    if not record.get("persisted_on_clean"):
        return hint
    # Most severe first: a persisted canary in an executable context is stored XSS.
    if record.get("xss_context"):
        return "stored_xss"
    # A persisted payload that lands in a redirect Location -> open redirect.
    if ev.get("redirect_poisoned"):
        return "open_redirect"
    # Non-reflective signals: classify by which dimension the poison persisted on.
    diff = record.get("differential_change") or ev.get("differential_change")
    if diff == "location":
        return "open_redirect"
    if diff == "status":
        # A persisted error/blank status served to clean users is a cache-poisoned DoS.
        status = ev.get("poisoned_status") or 0
        if isinstance(status, int) and (status >= 400 or status == 0):
            return "dos"
    return hint


def _build_curl(url: str, headers: dict) -> str:
    parts = ["curl", "-sk"]
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    parts.append(f"'{url}'")
    return " ".join(parts)
