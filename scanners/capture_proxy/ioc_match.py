"""A1: match a captured request's host/IP against the incident catalog.

Loaded by the ingest worker, which runs OFF the scan's critical path (it tails
the spool into Postgres). A lookup here can never slow the scan it observes.

Deliberately a thin wrapper rather than a second matcher: the tables, the
wildcard rule and the ignore-list semantics all live in
`supply_chain_common.intel`, and A1/A2 MUST agree on what counts as a match. A
parallel implementation here is how the two would drift.

The ingest worker holds only an INSERT-scoped Postgres role and no other
credential; this adds no network call, no new credential, and no new egress.
"""

import os

__all__ = ["match_transaction", "ignore_suffixes_from_env", "ENABLED_ENV"]

# Kill switch, deliberately not in the UI.
ENABLED_ENV = "SCA_INTEL_MATCH_ENABLED"

_INTEL_UNAVAILABLE_LOGGED = False


def _enabled():
    return os.environ.get(ENABLED_ENV, "true").lower() not in ("0", "false", "no")


def ignore_suffixes_from_env():
    """The operator's OAST providers, forwarded at spawn as env.

    The worker cannot SELECT the per-user setting (its role is INSERT-only on one
    table), so the orchestrator passes it the way it already passes the egress
    policy. Absent means "use the shipped default list".
    """
    raw = os.environ.get("CAPTURE_IOC_IGNORE_SUFFIXES")
    return raw or None


def match_transaction(host, target_ip=None, *, intel=None, ignore_suffixes=None):
    """Return (incident_id, incident_url) for a captured request, or (None, None).

    Never raises: this sits in the ingest hot path, and a capture row must land
    in Postgres whether or not the intel volume exists.
    """
    if not _enabled():
        return None, None
    try:
        from supply_chain_common.intel import load_intel, match_host

        intel = intel if intel is not None else load_intel()
        if not intel.available:
            _log_unavailable_once()
            return None, None
        if ignore_suffixes is None:
            ignore_suffixes = ignore_suffixes_from_env()
        rec = match_host(host, intel, ip=target_ip, ignore_suffixes=ignore_suffixes)
        if not rec:
            return None, None
        return rec.get("incident_id") or None, rec.get("url") or None
    except Exception:
        return None, None


def _log_unavailable_once():
    """Say it once, not once per captured request.

    C7 wants a missing data source recorded rather than silent, but this runs per
    transaction: an unconditional log would bury the ingest output.
    """
    global _INTEL_UNAVAILABLE_LOGGED
    if _INTEL_UNAVAILABLE_LOGGED:
        return
    _INTEL_UNAVAILABLE_LOGGED = True
    print("[ingest] supply-chain incident catalog unavailable; captured requests "
          "will NOT be checked against it (run './whitehat.sh sca-intel-sync')",
          flush=True)
