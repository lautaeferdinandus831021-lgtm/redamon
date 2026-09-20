"""
Web Cache Poisoning Scanner package for WhiteHat.

Active GROUP 6 vulnerability scanner that detects web cache poisoning and web
cache deception. Two stacked engines:

  Phase 1 (breadth)   WCVS (Hackmanit Web Cache Vulnerability Scanner), run
                      docker-in-docker, for wide technique coverage.
  Phase 2 (depth)     WhiteHat-native 5-phase confirmation engine:
                        1. cache oracle      (is there a cache? hit/miss signal)
                        2. cache-buster      (safe isolated test placement)
                        3. hypotheses        (generic + framework packs)
                        4. confirmation      (baseline -> poison -> clean -> persist)
                        5. confidence score  (Confirmed/Strong/Tentative/Rejected)

Only findings >= WEB_CACHE_POISON_MIN_CONFIDENCE reach the graph as
Vulnerability(source="cache_poisoning") nodes attached to Endpoint/BaseURL.
"""

from .scanner import run_cache_scan, run_cache_scan_isolated

__all__ = ["run_cache_scan", "run_cache_scan_isolated"]
