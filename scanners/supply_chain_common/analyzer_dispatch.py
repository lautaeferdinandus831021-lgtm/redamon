"""Dispatch a job to the DIRTY analyzer, from anywhere.

The analyzer is the single entry point for every hostile-byte operation:
retire.js over target-served JS, GuardDog over registry tarballs, osv-scanner
over manifests. It holds NO secrets, so the caller (which does hold them) never
touches an attacker-authored byte.

Two callers need it and they live in different processes:

  * recon_orchestrator  - has the Docker SDK, uses ContainerManager
                          .run_supply_chain_analyzer()
  * the recon container - has no SDK; it shells out to `docker` through the
                          broker socket (DOCKER_HOST)

The hardening must be IDENTICAL either way, so the flags are defined here once
and both paths use them. Previously the recon side hand-rolled its own
`docker run` for GuardDog, which meant two copies of a security boundary that
must never drift.

Nothing here imports Docker; it only builds argv and marshals the job/artifact
files, so it is importable (and unit-testable) from every container.
"""

import json
import os
import uuid

from ._run import run_argv
from .security import validate_artifact

__all__ = [
    "ANALYZER_IMAGE", "ANALYZER_NETWORK", "JOB_MODES", "ensure_network",
    "analyzer_docker_argv", "write_job", "read_artifact", "run_analyzer_job",
]

def _env(name, default):
    """os.environ.get, but a BLANK value means "unset" rather than "empty".

    docker-compose wires every analyzer knob through as ${VAR:-}, so an operator
    who set nothing still hands each of these an empty string. Plain .get() would
    then take "" as an explicit override: an empty image name, an empty --network,
    and int("") raising ValueError in the orchestrator's constructor - i.e. the
    passthrough that exists to make the knobs work would crash-loop the service."""
    raw = os.environ.get(name)
    return raw.strip() if raw and raw.strip() else default


ANALYZER_IMAGE = _env("SUPPLY_CHAIN_ANALYZER_IMAGE",
                      "whitehat-supply-chain-analyzer:latest")

# Modes scanners/supply_chain_analyzer/entrypoint.py understands.
JOB_MODES = {"lockfile", "sbom", "dir", "js-dir", "purls"}

# Dedicated bridge the analyzer runs on - the SAME name and driver the
# orchestrator uses (ContainerManager._ensure_supply_chain_network).
#
# "Isolated" here means NO WhiteHat SERVICE IS ATTACHED, not "no internet". That
# is the documented CodeFix-sandbox pattern (README.TM.SYSTEM_OVERVIEW.md): the
# sandbox is "ephemeral, secret-free, network-isolated" and still downloads
# build dependencies. The controls that matter are no secrets, cap_drop=ALL,
# read-only rootfs, non-root, resource caps - and no reachable peer.
#
# Do NOT create this --internal: GuardDog must reach the registry, and the
# orchestrator creates the same network as a plain bridge. Two creators
# disagreeing on the driver would mean whichever ran first silently wins.
#
# Omitting --network entirely would be worse still: docker's DEFAULT bridge is
# shared by every container that does not ask for one, so the analyzer could
# reach WhiteHat peers - exactly the property this network exists to remove.
ANALYZER_NETWORK = _env("SUPPLY_CHAIN_ANALYZER_NETWORK",
                        "whitehat-supply-chain-net")

# Mirrors ContainerManager.run_supply_chain_analyzer (plan section 5.2).
# Last-resort literal: used only when the operator set nothing AND the governor
# is unreachable. NOT read from the environment at import time - see _resolve_mem.
_DEFAULT_MEM = "1500m"
_DEFAULT_PIDS = _env("SUPPLY_CHAIN_ANALYZER_PIDS", "512")
_DEFAULT_TMPFS = "size=1g,exec"

# The analyzer's tool envelope in the memory governor's profile. The governor
# multiplies it by CONTAINER_CAP_HEADROOM to produce the hard --memory value.
_ANALYZER_TOOL = "supply_chain_analyzer"


def _governed_mem():
    """The analyzer's memory ceiling from the memory governor, or None.

    WHY: this container is spawned from three processes and only ONE of them
    (the orchestrator) could reach the governor, so this module used to hardcode
    a fixed "1500m" that never shrank on a memory-starved host while every other
    WhiteHat container did. Resolving it here makes the SDK path and the broker
    path agree by construction, which is what this module exists to guarantee.

    Fail-soft and lazy on purpose: the analyzer image itself mounts this package
    but has no graph_db, and an ImportError at module scope would break it.
    """
    try:
        try:
            from graph_db import resource_governor as rg
        except ImportError:
            import resource_governor as rg   # direct (tests / alt sys.path)
        return rg.container_cap(rg.tool_container_envelope(_ANALYZER_TOOL))
    except Exception:
        return None  # governor absent/unreadable -> _DEFAULT_MEM (legacy behaviour)


def _resolve_mem():
    """The analyzer's `--memory` value: operator override > governor > literal.

    The env var is read HERE, at call time, not captured at import. Snapshotting
    it into a module constant meant an operator value that arrived after this
    module was first imported was silently dropped: the override check saw it and
    stepped aside, then the fallback constant still held the stale "1500m". The
    operator asked for 700m and docker got 1500m, with nothing logged.
    """
    override = os.environ.get("SUPPLY_CHAIN_ANALYZER_MEM")
    if override and override.strip():
        return override.strip()
    return _governed_mem() or _DEFAULT_MEM


def analyzer_docker_argv(job_scratch_host_path, sc_common_host_path, *,
                         image=None, osv_db_volume="whitehat-osv-db",
                         network=None, allow_registry_egress=False,
                         mem=None, pids=None, tmpfs=_DEFAULT_TMPFS):
    """Build the hardened `docker run` argv for one analyzer job.

    HARDENING (must match the orchestrator's SDK call exactly):
      cap_drop=ALL, read-only rootfs, exec-able tmpfs scratch, mem/pids caps,
      and CRITICALLY no secrets in env - a full RCE inside finds no Neo4j,
      internal-API or GitHub credential.

    Network: the OSV/retire paths need NO egress at all. GuardDog needs the
    registry, so egress is opt-in and FAILS CLOSED - without an explicitly
    configured egress network the analyzer stays isolated and GuardDog simply
    finds no registry, rather than silently inheriting host networking.
    """
    net = network or ANALYZER_NETWORK
    if allow_registry_egress:
        # GuardDog needs the registry. It stays on the SAME peerless bridge by
        # default; an operator can point it elsewhere for tighter egress
        # filtering. It never falls back to docker's shared default bridge.
        net = os.environ.get("SUPPLY_CHAIN_EGRESS_NETWORK", net)

    argv = [
        "docker", "run", "--rm",
        "--cap-drop", "ALL",
        "--read-only",
        "--tmpfs", "/tmp:{}".format(tmpfs),
        "--pids-limit", str(pids or _DEFAULT_PIDS),
        "--memory", str(mem or _resolve_mem()),
        "-e", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db",
        "-e", "PYTHONUNBUFFERED=1",
        "-e", "PYTHONPATH=/app",
        "-v", "{}:/work:rw".format(job_scratch_host_path),
        "-v", "{}:/app/supply_chain_common:ro".format(sc_common_host_path),
        "-v", "{}:/osv-db:ro".format(osv_db_volume),
    ]
    argv += ["--network", net]
    argv += [
        image or ANALYZER_IMAGE,
        "sc-analyze", "--job", "/work/job.json", "--out", "/work/out.json",
    ]
    return argv


def write_job(work_dir, job):
    """Write job.json into the shared scratch dir. Returns its path."""
    mode = job.get("mode")
    if mode not in JOB_MODES:
        raise ValueError("unsupported analyzer job mode: {!r}".format(mode))
    os.makedirs(work_dir, exist_ok=True)
    path = os.path.join(work_dir, "job.json")
    with open(path, "w") as fh:
        json.dump(job, fh)
    return path


def read_artifact(work_dir):
    """Read + boundary-validate out.json. Raises on anything untrustworthy.

    This is the DIRTY -> CLEAN gate: the analyzer self-validates, and the clean
    side validates again because it must never trust a compromised analyzer.
    """
    path = os.path.join(work_dir, "out.json")
    with open(path) as fh:
        raw = json.load(fh)
    return validate_artifact(raw)


def ensure_network(name=None, runner=None):
    """Create the analyzer bridge if it is missing. Idempotent.

    Compose never creates it: by design no service is attached, and Compose
    only creates networks used by the services it starts. So both spawn paths
    create-if-missing.

    A PLAIN bridge, matching ContainerManager._ensure_supply_chain_network. Not
    --internal: GuardDog must reach the registry, and a second creator using a
    different driver would silently win the race for the same network name.
    """
    name = name or ANALYZER_NETWORK
    run = runner or run_argv
    res = run(["docker", "network", "inspect", name], timeout=30)
    if res.get("exit_code") == 0:
        return name
    run(["docker", "network", "create", "--driver", "bridge", name], timeout=60)
    return name


def run_analyzer_job(job, work_dir, sc_common_host_path, *,
                     job_scratch_host_path=None, image=None,
                     osv_db_volume="whitehat-osv-db", network=None,
                     allow_registry_egress=False, timeout=600, runner=None):
    """Write the job, run the analyzer, return {artifact, exit_code, error}.

    `work_dir` is where THIS process writes job.json / reads out.json.
    `job_scratch_host_path` is the same directory as the DOCKER DAEMON sees it
    (they differ under docker-in-docker); defaults to work_dir when identical -
    which is the case for /tmp/whitehat, bind-mounted at the same path in the
    recon container and on the host.

    `artifact` is None when the analyzer produced nothing usable; the caller
    decides how to surface that (never as a clean result).
    """
    write_job(work_dir, job)
    if not network:
        try:
            ensure_network(runner=runner)
        except Exception:
            pass  # a missing network surfaces as a spawn error below
    argv = analyzer_docker_argv(
        job_scratch_host_path or work_dir, sc_common_host_path,
        image=image, osv_db_volume=osv_db_volume, network=network,
        allow_registry_egress=allow_registry_egress)

    res = (runner or run_argv)(argv, timeout=timeout)
    error = res.get("error")
    if error is None and res.get("exit_code") not in (0,):
        error = "analyzer exit {}: {}".format(
            res.get("exit_code"), (res.get("stderr") or "").strip()[:300])

    artifact = None
    try:
        artifact = read_artifact(work_dir)
    except Exception as exc:
        if error is None:
            error = "analyzer produced no usable artifact: {}".format(exc)

    return {"artifact": artifact, "exit_code": res.get("exit_code"), "error": error}


def new_work_dir(root="/tmp/whitehat", prefix="sc-job"):
    """A fresh scratch dir under the path both the container and the host see.

    Made world-writable on purpose: the analyzer runs as NON-ROOT (uid 1001,
    part of the hardening) while the caller is usually root, so a default
    0755 dir means the analyzer cannot write out.json and the job dies with
    PermissionError after doing all the work. The dir holds only this job's
    input/output and is removed afterwards.
    """
    path = os.path.join(root, "{}-{}".format(prefix, uuid.uuid4().hex[:8]))
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass
    return path
