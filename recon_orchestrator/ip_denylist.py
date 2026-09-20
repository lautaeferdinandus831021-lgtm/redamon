"""Resolved-IP denylist — the shared core of every WhiteHat egress guard.

SHARED, NOT DUPLICATED. This file is the only copy. The capture-proxy image
bundles it at build time (``COPY recon_orchestrator/ip_denylist.py /app/``, the
same treatment ``hard_guardrail.py`` gets) so the proxy's ``egress.py`` and the
orchestrator's TruffleHog start guard classify addresses with identical code. A
second hand-written denylist would be the failure mode worth avoiding: the two
would eventually disagree about, say, IPv4-mapped IPv6, and only one of the two
guards would actually hold.

Why the RESOLVED IP and not the hostname: an in-scope-looking name can point at
``169.254.169.254`` (cloud metadata), ``127.0.0.1:7687`` (Neo4j) or an RFC1918
host. Name-based checks miss all three, and DNS rebinding defeats them by
construction. Callers must connect to the pinned IP this module returns rather
than re-resolving, or a rebind can still slip between check and connect.

Pure stdlib, no I/O beyond one getaddrinfo. Fails closed everywhere: an
unparseable address, an unresolvable name and an IDNA error are all refusals.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

#: Carrier-grade NAT. Not covered by `is_private`, and routable to a provider's
#: internal estate, so it gets its own check.
CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class IpPolicy:
    """Which address classes are refused. Every field defaults to True (block),
    so a default-constructed policy is the strictest one and a field a caller
    forgets to set can never silently open a hole.

    Each class is an INDEPENDENT check: relaxing ``block_private`` to reach a lab
    target on an internal network does not un-block ``127.0.0.1``, which is still
    caught by ``block_loopback`` even though it is also technically private.
    """

    block_private: bool = True       # RFC1918 10/8, 172.16/12, 192.168/16 + IPv6 ULA
    block_loopback: bool = True      # 127.0.0.0/8, ::1
    block_link_local: bool = True    # 169.254.0.0/16 (incl. cloud metadata), fe80::/10
    block_cgnat: bool = True         # 100.64.0.0/10
    block_reserved: bool = True      # IANA-reserved
    block_multicast: bool = True     # 224.0.0.0/4, ff00::/8
    block_unspecified: bool = True   # 0.0.0.0, ::


DEFAULT_IP_POLICY = IpPolicy()


def is_internal_ip(
    ip_str: str,
    extra_blocked: Optional[List[str]] = None,
    policy=DEFAULT_IP_POLICY,
) -> bool:
    """True if `ip_str` must not be reached under `policy`.

    `policy` is duck-typed on the ``block_*`` attributes so a richer policy
    object (the capture proxy's ``EgressPolicy``, which also carries non-IP
    toggles) can be passed straight through.

    The explicit `extra_blocked` denylist — WhiteHat's own service IPs — is ALWAYS
    enforced and never policy-gated, so relaxing a category can never turn a
    guard into a pivot into WhiteHat itself.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> fail closed (a resolved IP should always parse)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if getattr(policy, "block_private", True) and addr.is_private:
        return True
    if getattr(policy, "block_loopback", True) and addr.is_loopback:
        return True
    if getattr(policy, "block_link_local", True) and addr.is_link_local:
        return True
    if getattr(policy, "block_reserved", True) and addr.is_reserved:
        return True
    if getattr(policy, "block_multicast", True) and addr.is_multicast:
        return True
    if getattr(policy, "block_unspecified", True) and addr.is_unspecified:
        return True
    if getattr(policy, "block_cgnat", True) and addr in CGNAT:
        return True
    if extra_blocked:
        for entry in extra_blocked:
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
    return False


def resolve_host(host: str) -> List[str]:
    """Resolve a hostname to every A/AAAA address. Bare IPs pass through.

    Returns [] on any failure — OSError (unresolvable) and UnicodeError (a bad
    IDNA label) alike — so callers refuse rather than proceed with no address.
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    out: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def classify_host(
    host: str,
    extra_blocked: Optional[List[str]] = None,
    policy=DEFAULT_IP_POLICY,
) -> Tuple[bool, Optional[str], str]:
    """Resolve `host` and decide whether it may be reached.

    Returns ``(allowed, pinned_ip, reason)``. ``allowed`` is True only with a
    concrete pinned IP, so an empty or unresolvable host can never be approved
    regardless of the policy toggles.

    EVERY resolved address must clear the policy: a name that returns one public
    and one internal address is hostile, and picking the first would let it
    through half the time.
    """
    host = (host or "").strip().strip(".").lower()
    if not host:
        return (False, None, "empty host")

    resolved = resolve_host(host)
    if not resolved:
        return (False, None, "unresolvable")

    for ip in resolved:
        if is_internal_ip(ip, extra_blocked, policy):
            return (False, None, f"internal-ip:{ip}")

    return (True, resolved[0], "ok")
