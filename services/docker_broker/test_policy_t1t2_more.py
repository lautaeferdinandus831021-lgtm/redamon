#!/usr/bin/env python3
"""T1/T2 — additional broker mount-MODE coverage, complementing test_policy.py.

Focuses on paths test_policy.py doesn't reach:
  * compound docker mode fields ('ro,z', 'rw,z', 'Z') parsed correctly,
  * the ALLOWED_RW_VOLUMES gate for named volumes (rw volume denial),
  * the _bind_is_readonly / _rw_host_path_allowed helpers directly, incl. that
    a traversal source is NOT silently treated as rw-allowed.

Run:  cd docker_broker && python3 test_policy_t1t2_more.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker  # noqa: E402

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {desc}")
    else:
        FAIL += 1
        print(f"  FAIL {desc}")


def allow(desc, body):
    ok, reason = broker.validate_create(body)
    check(f"ALLOW {desc}", ok is True)


def deny(desc, body, must_mention=None):
    ok, reason = broker.validate_create(body)
    cond = ok is False and (must_mention is None or must_mention in reason)
    check(f"DENY  {desc} (reason={reason!r})", cond)


NAABU = "projectdiscovery/naabu:latest"

print("=== T1/T2: compound mode fields (SELinux :z/:Z relabel suffixes) ===")
broker.ALLOWED_BIND_PREFIXES = ["/tmp/whitehat", "/repo"]
broker.ALLOWED_RW_PREFIXES = ["/tmp/whitehat"]
# ':ro,z' must still read as read-only -> source-tree bind allowed
allow("source tree ro,z (relabel + ro)",
      {"Image": NAABU, "HostConfig": {"Binds": ["/repo/recon:/app:ro,z"]}})
allow("source tree z,ro (order-independent)",
      {"Image": NAABU, "HostConfig": {"Binds": ["/repo/recon:/app:z,ro"]}})
# ':rw,z' is still read-write -> source-tree bind denied
deny("source tree rw,z (relabel + rw)",
     {"Image": NAABU, "HostConfig": {"Binds": ["/repo/recon:/app:rw,z"]}}, "read-write")
# ':Z' alone is a relabel with NO ro token -> read-write -> denied for source tree
deny("source tree Z-only (relabel, implicit rw)",
     {"Image": NAABU, "HostConfig": {"Binds": ["/repo/recon:/app:Z"]}}, "read-write")
# scratch prefix rw,z stays allowed
allow("scratch rw,z", {"Image": NAABU, "HostConfig": {"Binds": ["/tmp/whitehat/o:/o:rw,z"]}})

print("=== T1/T2: ALLOWED_RW_VOLUMES gate for named volumes ===")
broker.ALLOWED_VOLUMES = {"nuclei-templates", "writable-vol"}
broker.ALLOWED_RW_VOLUMES = {"writable-vol"}
# read-only mount of a normal named volume: allowed
allow("ro named volume (not on rw allowlist)",
      {"Image": NAABU, "HostConfig": {"Mounts": [
          {"Type": "volume", "Source": "nuclei-templates", "Target": "/t", "ReadOnly": True}]}})
# rw (ReadOnly absent) of a volume NOT on the rw allowlist: denied
deny("rw named volume not on rw allowlist",
     {"Image": NAABU, "HostConfig": {"Mounts": [
         {"Type": "volume", "Source": "nuclei-templates", "Target": "/t"}]}}, "read-write volume")
# rw of a volume that IS on the rw allowlist: allowed
allow("rw named volume on rw allowlist",
      {"Image": NAABU, "HostConfig": {"Mounts": [
          {"Type": "volume", "Source": "writable-vol", "Target": "/w"}]}})
# restore
broker.ALLOWED_VOLUMES = {"nuclei-templates"}
broker.ALLOWED_RW_VOLUMES = set()

print("=== T1/T2: helper units ===")
broker.ALLOWED_RW_PREFIXES = ["/tmp/whitehat"]
check("_bind_is_readonly('ro') True", broker._bind_is_readonly("ro") is True)
check("_bind_is_readonly('rw') False", broker._bind_is_readonly("rw") is False)
check("_bind_is_readonly('') False (default rw)", broker._bind_is_readonly("") is False)
check("_bind_is_readonly('ro,z') True", broker._bind_is_readonly("ro,z") is True)
check("_bind_is_readonly('z,ro') True", broker._bind_is_readonly("z,ro") is True)
check("_bind_is_readonly('Z') False", broker._bind_is_readonly("Z") is False)
check("_rw_host_path_allowed('/tmp/whitehat/x') True", broker._rw_host_path_allowed("/tmp/whitehat/x") is True)
check("_rw_host_path_allowed('/tmp/whitehat') True (exact)", broker._rw_host_path_allowed("/tmp/whitehat") is True)
check("_rw_host_path_allowed('/repo/recon') False", broker._rw_host_path_allowed("/repo/recon") is False)
# a traversal that normalizes out of the rw prefix must NOT be treated as rw-allowed
check("_rw_host_path_allowed traversal escapes -> False",
      broker._rw_host_path_allowed("/tmp/whitehat/../etc") is False)
# a sibling that merely shares the prefix string must not match (/tmp/whitehat-evil)
check("_rw_host_path_allowed prefix-adjacent sibling -> False",
      broker._rw_host_path_allowed("/tmp/whitehat-evil/x") is False)


def test_all_policy_checks_pass():
    """pytest entrypoint: the module-level checks above populate PASS/FAIL
    at import; assert none failed (bucket-1 runner-compat conversion)."""
    assert FAIL == 0, f"{FAIL} policy checks failed (see printed FAIL lines)"


if __name__ == "__main__":
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    sys.exit(0 if FAIL == 0 else 1)
