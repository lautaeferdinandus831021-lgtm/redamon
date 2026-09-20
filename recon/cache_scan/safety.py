"""
Cache Poisoning Scanner — Safety controls.

Web cache poisoning is an ACTIVE test: a careless probe can poison a production
cache for real users. This module centralises every safety control so the rest
of the engine can stay focused on detection logic.

Three scan profiles (WEB_CACHE_POISON_SCAN_PROFILE):
  - "safe-confirm"   : production recon. Benign canaries only, isolated cache
                       buckets always, no CPDoS, no destructive payloads.
  - "extended"       : owned test targets. Adds a few extra technique classes.
  - "research"       : explicit lab only. Allows CPDoS-style tests if AllowCpdos.

Golden rules enforced here:
  * Every poison test carries a unique cache-buster so it lands in its OWN cache
    slot, never the one real visitors hit.
  * Canaries are benign, non-resolving markers (never live XSS / real domains).
  * CPDoS (cache-poisoned denial of service) is OFF unless explicitly enabled.
"""

import secrets

# Benign marker host: RFC 2606 reserved TLD, guaranteed not to resolve to a real
# host. Reflecting this proves the vector without pointing victims anywhere live.
_CANARY_SUFFIX = "whitehat-poc.invalid"


def new_canary_token() -> str:
    """Return a short unique token used to recognise our own payload later."""
    return "rdmn" + secrets.token_hex(5)


def canary_host(token: str) -> str:
    """Benign hostname canary for header vectors (X-Forwarded-Host etc.).

    Non-resolving by construction (.invalid TLD), so a Confirmed finding is
    proven without ever directing a victim to attacker-controlled infrastructure.
    """
    return f"{token}.{_CANARY_SUFFIX}"


def canary_value(token: str) -> str:
    """Benign canary for parameter / generic reflection vectors."""
    return token


def new_cache_buster_value() -> str:
    """Unique value for the cache-buster so each test isolates into its own slot."""
    return "cb" + secrets.token_hex(6)


def is_cpdos_allowed(settings: dict) -> bool:
    """CPDoS tests (oversized headers, meta-char keys) are destructive-ish and
    OFF by default. Require both research profile and the explicit toggle.
    """
    profile = (settings.get("WEB_CACHE_POISON_SCAN_PROFILE") or "safe-confirm").lower()
    return profile == "research" and bool(settings.get("WEB_CACHE_POISON_ALLOW_CPDOS", False))


def is_deception_allowed(settings: dict) -> bool:
    """Web-cache-deception probing (path-confusion .css tricks)."""
    return bool(settings.get("WEB_CACHE_POISON_ALLOW_DECEPTION", True))


def is_framework_packs_allowed(settings: dict) -> bool:
    """Framework-specific hypothesis packs (Next.js / Nuxt / Remix)."""
    return bool(settings.get("WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS", True))
