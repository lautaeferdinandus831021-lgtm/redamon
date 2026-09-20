"""
Cache Poisoning Scanner — main orchestrator.

Runs the WCVS breadth engine + the WhiteHat-native 5-phase confirmation engine and
writes combined_result["cache_scan"]. Registered in GROUP 6 Phase A of the recon
pipeline (recon/main.py) via run_cache_scan_isolated, alongside Nuclei and GraphQL.

Engine flow per the design doc:
  Phase 1  cache oracle + WCVS breadth sweep
  Phase 2  cache-buster placement (safe isolation)
  Phase 3  hypothesis generation (generic + framework packs)
  Phase 4  behavioural confirmation (baseline -> poison -> clean -> persistence)
  Phase 5  confidence scoring (only >= min_confidence becomes a finding)
"""

import copy
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from recon.cache_scan import wcvs_runner, oracle, buster, hypotheses, confirm, scoring, normalizers

# Hard caps so a huge recon surface can't turn into a runaway active scan.
_MAX_URLS = 200
_MAX_VECTORS_PER_URL = 55


def _build_retry_session(retry_count: int = 1, backoff: float = 0.5) -> requests.Session:
    """requests.Session with retry/backoff on 429/5xx (Cloudflare-friendly)."""
    retry = Retry(
        total=max(0, min(5, int(retry_count))),
        backoff_factor=max(0.0, min(5.0, float(backoff))),
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "WhiteHat-CachePoison/1.0"})
    return session


def _roe_excluded_hosts(combined_result: dict, settings: dict) -> set[str]:
    """Hosts excluded by Rules of Engagement (from settings or recon metadata)."""
    if not settings.get("ROE_ENABLED", False):
        meta_roe = (combined_result.get("metadata") or {}).get("roe") or {}
        if not meta_roe.get("ROE_ENABLED", False):
            return set()
        return {h.strip() for h in (meta_roe.get("ROE_EXCLUDED_HOSTS") or []) if h.strip()}
    return {h.strip() for h in (settings.get("ROE_EXCLUDED_HOSTS") or []) if h.strip()}


def _host_excluded(host: str, excluded: set[str]) -> bool:
    for entry in excluded:
        if host == entry or host.endswith("." + entry):
            return True
    return False


def _collect_target_urls(combined_result: dict, settings: dict) -> list[str]:
    """Reuse the shared Nuclei target-builder, then apply RoE host filtering."""
    from recon.helpers.target_helpers import extract_targets_from_recon, build_target_urls

    hostnames, ips, _ = extract_targets_from_recon(combined_result)
    urls = build_target_urls(hostnames, ips, combined_result, scan_all_ips=False)

    excluded = _roe_excluded_hosts(combined_result, settings)
    if excluded:
        kept = [u for u in urls if not _host_excluded(urlparse(u).hostname or "", excluded)]
        removed = len(urls) - len(kept)
        if removed:
            print(f"[*][CachePoison] RoE excluded {removed} target URL(s)")
        urls = kept
    return urls[:_MAX_URLS]


def run_cache_scan(combined_result: dict, settings: dict) -> dict:
    """Main entry point. Mutates combined_result in place, returns it.

    Adds combined_result["cache_scan"].
    """
    if not settings.get("WEB_CACHE_POISON_ENABLED", False):
        print("[-][CachePoison] Web cache poisoning scanning disabled")
        return combined_result

    print("\n[*][CachePoison] Starting web cache poisoning scan")
    print("=" * 50)
    start = time.time()

    timeout = int(settings.get("WEB_CACHE_POISON_TIMEOUT_PER_REQ", 10))
    verify_ssl = bool(settings.get("WEB_CACHE_POISON_VERIFY_SSL", True))
    min_conf = float(settings.get("WEB_CACHE_POISON_MIN_CONFIDENCE", 0.8))
    cross_vantage = bool(settings.get("WEB_CACHE_POISON_CROSS_VANTAGE", False))

    target_urls = _collect_target_urls(combined_result, settings)
    if not target_urls:
        print("[!][CachePoison] No live URLs to scan")
        combined_result["cache_scan"] = normalizers.build_cache_scan_result(
            {"total_urls_scanned": 0, "cacheable_urls": 0}, {}, [])
        return combined_result

    # ---- Phase 1: WCVS breadth sweep -------------------------------------
    wcvs_candidates = wcvs_runner.run_wcvs(target_urls, settings)
    # index WCVS candidates by URL
    wcvs_by_url: dict[str, list[dict]] = {}
    for c in wcvs_candidates:
        wcvs_by_url.setdefault(c["url"], []).append(c)

    # ---- Phases 1b-5: confirm each URL, parallelized ACROSS URLs ----------
    # Every URL is independent (each vector gets its own isolated cache-buster
    # slot), so we fan out across a bounded worker pool. The 4-request sequence
    # inside one vector stays ordered (atomic, owned by a single worker).
    # WEB_CACHE_POISON_CONFIRM_WORKERS bounds concurrent in-flight requests —
    # both a speedup and a stealth/rate control. Each worker uses its OWN
    # requests.Session (Sessions are not safe to share across threads).
    workers = int(settings.get("WEB_CACHE_POISON_CONFIRM_WORKERS", 6) or 6)
    workers = max(1, min(16, workers))

    args = (wcvs_by_url, combined_result, settings, min_conf, cross_vantage, timeout, verify_ssl)
    if workers == 1 or len(target_urls) == 1:
        results = [_scan_one_url(u, *args) for u in target_urls]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_scan_one_url, u, *args): u for u in target_urls}
            for fut in as_completed(futures):
                u = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as e:
                    print(f"[!][CachePoison] {u} confirmation failed: {e}")
                    results.append((u, {"oracle": {"cacheable": False, "indicator": "",
                                                    "signals": [f"error: {e}"], "saw_hit": False},
                                        "findings": []}, 0))

    # Merge worker results in the main thread (no shared-state mutation).
    by_target: dict[str, dict] = {}
    all_findings: list[dict] = []
    cacheable_count = 0
    for url, entry, cc in results:
        by_target[url] = entry
        all_findings.extend(entry["findings"])
        cacheable_count += cc

    duration = round(time.time() - start, 1)
    scan_metadata = {
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_seconds": duration,
        "engine": "wcvs+native-confirm",
        "docker_image": settings.get("WEB_CACHE_POISON_DOCKER_IMAGE", "whitehat-wcvs:latest"),
        "scan_profile": settings.get("WEB_CACHE_POISON_SCAN_PROFILE", "safe-confirm"),
        "min_confidence": min_conf,
        "total_urls_scanned": len(target_urls),
        "cacheable_urls": cacheable_count,
        "wcvs_candidates": len(wcvs_candidates),
    }
    combined_result["cache_scan"] = normalizers.build_cache_scan_result(
        scan_metadata, by_target, all_findings)

    summary = combined_result["cache_scan"]["summary"]
    print(f"[+][CachePoison] Done in {duration}s — {summary['total_findings']} finding(s) "
          f"(confirmed={summary['confirmed']}, strong={summary['strong']}) "
          f"across {cacheable_count}/{len(target_urls)} cacheable URL(s)")
    return combined_result


def _scan_one_url(url, wcvs_by_url, combined_result, settings, min_conf,
                  cross_vantage, timeout, verify_ssl):
    """Confirm every vector for ONE URL (Phases 1b-5). Thread worker.

    Returns (url, target_entry, cacheable_int). Builds its own requests.Session
    because Sessions are not safe to share across threads. Reads combined_result
    and wcvs_by_url only (no mutation), so workers never race.
    """
    session = _build_retry_session()
    try:
        # Phase 1b: cache oracle (header detection + silent-cache frozen-Date fallback)
        behavioral = bool(settings.get("WEB_CACHE_POISON_BEHAVIORAL_ORACLE", True))
        behavioral_delay = float(settings.get("WEB_CACHE_POISON_BEHAVIORAL_DELAY", 1.1))
        oracle_info = oracle.detect_cache_oracle(
            url, session, timeout, verify_ssl,
            behavioral=behavioral, behavioral_delay=behavioral_delay,
        )
        target_entry = {"oracle": oracle_info, "findings": []}
        if not oracle_info["cacheable"]:
            return url, target_entry, 0  # no cache -> nothing to poison

        # Phase 2: cache-buster placement
        buster_info = buster.find_cache_buster(url, session, settings, timeout, verify_ssl)

        # Phase 3: build vectors (WCVS candidates + native hypotheses)
        wcvs_here = wcvs_by_url.get(url, [])
        wcvs_vectors_seen = {c["vector_name"] for c in wcvs_here if c.get("vector_name")}
        vectors: list[dict] = []
        for c in wcvs_here:
            if not c.get("vector_name"):
                continue
            vectors.append(_wcvs_vector(url, c))
        vectors.extend(
            hypotheses.generate_hypotheses(url, combined_result, settings, wcvs_vectors_seen)
        )
        vectors = vectors[:_MAX_VECTORS_PER_URL]

        # Phase 4 + 5: confirm + score (per-vector sequence stays ordered)
        for vector in vectors:
            record = confirm.confirm_vector(vector, buster_info, session, settings, timeout, verify_ssl)
            confidence, tier = scoring.score_finding(record)
            if confidence < min_conf:
                continue
            impact = confirm.classify_impact(vector, record)
            severity, cvss = scoring.severity_for_impact(impact)
            finding = normalizers.build_finding(
                vector, record, confidence, tier, impact, severity, cvss,
                cache_signals=oracle_info["signals"],
            )
            finding["cross_vantage"] = cross_vantage
            target_entry["findings"].append(finding)
        return url, target_entry, 1
    finally:
        try:
            session.close()
        except Exception:
            pass


def _wcvs_technique(raw: str) -> str:
    """Normalise a WCVS technique label into a stable token."""
    low = (raw or "").lower()
    if "decept" in low:
        return "cache_deception"
    if "param" in low or "cloak" in low or "pollution" in low:
        return "unkeyed_param"
    if "fatget" in low:
        return "fat_get"
    if "smuggl" in low:
        return "request_smuggling"
    return "unkeyed_header"


def _wcvs_vector(url: str, candidate: dict) -> dict:
    """Build a native confirmation vector from a WCVS candidate, choosing the
    right vector_type/payload_kind/impact from the WCVS technique so the native
    re-test matches what WCVS actually exercised."""
    technique = _wcvs_technique(candidate.get("technique", ""))
    name = candidate.get("vector_name", "")
    if technique == "cache_deception":
        vector_type, payload_kind, impact = "path", "path", "deception"
    elif technique == "unkeyed_param":
        vector_type, payload_kind, impact = "param", "value", "reflected"
    else:
        # Header vector: host-style headers carry a hostname payload (open
        # redirect / host-header abuse); other headers carry a plain value.
        vector_type = "header"
        if "host" in name.lower():
            payload_kind, impact = "host", "open_redirect"
        else:
            payload_kind, impact = "value", "reflected"
    return {
        "url": url,
        "technique": technique,
        "vector_type": vector_type,
        "vector_name": name,
        "payload_kind": payload_kind,
        "impact_hint": impact,
        "source": "wcvs",
        "wcvs_reason": candidate.get("reason", ""),
    }


def run_cache_scan_isolated(combined_result: dict, settings: dict) -> dict:
    """Thread-safe wrapper for GROUP 6 Phase A fan-out.

    Deep-copies combined_result and returns ONLY the cache_scan payload so the
    parallel ThreadPoolExecutor in recon/main.py has no shared-dict race.
    """
    snapshot = copy.deepcopy(combined_result)
    run_cache_scan(snapshot, settings)
    return snapshot.get("cache_scan", {})
