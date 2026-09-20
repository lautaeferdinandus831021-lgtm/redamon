"""L2 Supply-Chain recon module (plan Phase 3.3).

Runs in GROUP 5.5 AFTER JS-recon (it consumes JS-recon output). Against the LIVE
target with no manifest, it harvests the served npm package set (source-map
mining + imports + technologies - all from data JS-recon already downloaded, so
NO new fetch and NO SSRF surface, S4), verdicts it OFFLINE with osv-scanner, and
stores a validated artifact under combined_result['supply_chain_recon'] for the
graph write (Package/MalPackageFinding MERGE, anchored to the target BaseURLs).

osv-scanner (static, offline) always runs here. GuardDog deep analysis runs too
when SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED is on: it is dispatched INTO the
hardened DIRTY analyzer image over the broker socket this container already
holds, and only ever over packages the OSV pass already flagged. retire.js runs
there too, over the JS that JS-recon already downloaded - it is the only source
that yields versioned components, so it is where most verdicts come from.

This module itself never downloads or unpacks a tarball - it holds the Neo4j
creds, the analyzer does not.
"""

import os
import shutil
import tempfile
import time

# supply_chain_common is mounted into the recon container like graph_db.
from supply_chain_common import osv_runner as _osv_runner
from supply_chain_common import guarddog_runner as _guarddog_runner
from supply_chain_common import analyzer_dispatch as _analyzer_dispatch
from supply_chain_common.artifact import (
    empty_artifact, add_osv_findings, add_guarddog_findings, to_cyclonedx,
)
from supply_chain_common.security import validate_artifact, ArtifactError
from supply_chain_common.deep_recovery import recover_invalid_deep_artifact

_OSV_DB = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/osv-db")

# Deep analysis (GuardDog) knobs. This step DOWNLOADS attacker-authored tarballs
# from the public registry, so it is opt-in, capped, and restricted to packages
# a passive OSV verdict already flagged - never a sweep of the whole set.
_DEEP_MAX_PACKAGES = int(os.environ.get("SUPPLY_CHAIN_DEEP_MAX_PACKAGES", "10"))
_DEEP_TIMEOUT = int(os.environ.get("SUPPLY_CHAIN_DEEP_TIMEOUT", "180"))
# Whole-pass ceiling. Without it the worst case is MAX_PACKAGES * TIMEOUT
# (10 x 180s = 30 min) of a recon scan blocked on a registry that is slow or
# hanging, with no way for the pipeline to make progress.
_DEEP_TOTAL_BUDGET = int(os.environ.get("SUPPLY_CHAIN_DEEP_TOTAL_BUDGET", "900"))
# retire.js pass over the served JS, inside the DIRTY analyzer.
_RETIRE_TIMEOUT = int(os.environ.get("SUPPLY_CHAIN_RETIRE_TIMEOUT", "300"))
# supply_chain_common as the DOCKER DAEMON sees it (recon mounts it read-only
# at /app/supply_chain_common; the analyzer needs the host-side path).
_SC_COMMON_PATH = os.environ.get("SUPPLY_CHAIN_COMMON_HOST_PATH", "/app/supply_chain_common")
_ANALYZER_IMAGE = os.environ.get("SUPPLY_CHAIN_ANALYZER_IMAGE",
                                 _guarddog_runner.ANALYZER_IMAGE)

# OSV ecosystem brand -> GuardDog ecosystem slug. Ecosystems GuardDog cannot
# analyse (Maven, Packagist, NuGet) are absent on purpose and get skipped.
_OSV_TO_GUARDDOG_ECO = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "go",
    "crates.io": "crates",
    "RubyGems": "rubygems",
}


def _extract_source_maps(combined_result):
    js = combined_result.get("js_recon") or {}
    return js.get("source_maps") or []


def _extract_technologies(combined_result):
    """{name, version} list from httpx/wappalyzer output.

    L2-2: the real http_probe shape is `by_url` (dict url->entry) with a
    `technologies` list of "Name:Version" STRINGS (plus a top-level
    `technologies_found` dict keyed by the same strings) - NOT a `results` list
    of {name,version} dicts. Read the right keys and split "Name:Version".
    """
    techs = []
    seen = set()
    http = combined_result.get("http_probe") or {}

    def _add_str(s):
        if not isinstance(s, str) or not s or s in seen:
            return
        seen.add(s)
        name, _, ver = s.partition(":")
        name = name.strip()
        if name:
            techs.append({"name": name, "version": (ver.strip() or None)})

    for entry in (http.get("by_url") or {}).values():
        if not isinstance(entry, dict):
            continue
        for t in (entry.get("technologies") or entry.get("tech") or []):
            if isinstance(t, str):
                _add_str(t)
            elif isinstance(t, dict) and t.get("name"):
                key = "{}:{}".format(t.get("name"), t.get("version") or "")
                if key not in seen:
                    seen.add(key)
                    techs.append({"name": t.get("name"), "version": t.get("version")})
    for t in (http.get("technologies_found") or {}):
        _add_str(t)
    return techs


def _extract_base_urls(combined_result):
    """Base URLs (scheme://netloc) to anchor harvested packages to (DEPENDS_ON).

    L2-1: reads the real `by_url` key. Normalizes each probed URL down to
    scheme://netloc so it matches the BaseURL node's `url` property (probed URLs
    may carry a path; BaseURL nodes do not).
    """
    from urllib.parse import urlparse
    urls = set()
    http = combined_result.get("http_probe") or {}
    for key, entry in (http.get("by_url") or {}).items():
        raw = None
        if isinstance(entry, dict):
            raw = entry.get("url") or entry.get("base_url")
        if not raw and isinstance(key, str):
            raw = key
        if not raw:
            continue
        try:
            p = urlparse(raw)
            urls.add("{}://{}".format(p.scheme, p.netloc) if p.scheme and p.netloc else raw)
        except Exception:
            urls.add(raw)
    return sorted(urls)


def verdict_packages(packages, *, db_path=None, osv=None):
    """Verdict a harvested package list against the offline OSV DB.

    Synthesizes a CycloneDX SBOM and scans it (osv detects components by purl).
    Returns a boundary-valid artifact. `osv` is injectable for tests.
    """
    osv = osv or _osv_runner
    db_path = db_path or _OSV_DB
    artifact = empty_artifact("js-dir")
    for pkg in packages:
        artifact["packages"].append({
            "purl": pkg.get("purl"), "name": pkg.get("name"),
            "version": pkg.get("version"), "ecosystem": pkg.get("ecosystem"),
            "source": pkg.get("source"),
        })

    if packages:
        sbom = to_cyclonedx(packages)
        tmpdir = tempfile.mkdtemp(prefix="sc-recon-")
        bom_path = os.path.join(tmpdir, "bom.cdx.json")
        try:
            import json
            with open(bom_path, "w") as fh:
                json.dump(sbom, fh)
            result = osv.run_osv_scan(bom_path, mode="sbom", db_path=db_path)
            if result.get("error"):
                artifact["errors"].append("osv: {}".format(result["error"]))
            # Only fold in the verdicts (malicious/vulnerable); packages already added.
            parsed = result.get("parsed") or {}
            add_osv_findings(artifact, {"packages": [], "malicious": parsed.get("malicious", []),
                                        "vulnerable": parsed.get("vulnerable", [])})
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    try:
        return validate_artifact(artifact)
    except ArtifactError as exc:
        safe = empty_artifact()
        safe["errors"].append("artifact validation failed: {}".format(exc))
        return validate_artifact(safe)


def flagged_specs(artifact, limit=_DEEP_MAX_PACKAGES):
    """Unique packages an OSV verdict already flagged, as GuardDog coordinates.

    Malicious first so the cap never starves the highest-signal packages.
    Returns [{ecosystem (guarddog slug), name, version, purl, osv_ecosystem}].
    """
    seen = set()
    out = []
    dropped = 0
    skipped_eco = set()
    for bucket in ("malicious", "vulnerable"):
        for f in artifact.get(bucket) or []:
            name = f.get("name")
            osv_eco = f.get("ecosystem")
            gd_eco = _OSV_TO_GUARDDOG_ECO.get(osv_eco)
            if not name:
                continue
            if not gd_eco:
                skipped_eco.add(osv_eco)
                continue
            key = (gd_eco, name, f.get("version"))
            if key in seen:
                continue
            seen.add(key)
            if len(out) >= limit:
                # Do NOT return early: keep counting so the cap is reported
                # instead of silently truncating the flagged set.
                dropped += 1
                continue
            out.append({"ecosystem": gd_eco, "name": name,
                        "version": f.get("version"), "purl": f.get("purl"),
                        "osv_ecosystem": osv_eco})
    if dropped:
        print("[!][SupplyChainRecon] deep analysis cap: {} flagged package(s) "
              "beyond SUPPLY_CHAIN_DEEP_MAX_PACKAGES={} were NOT analysed"
              .format(dropped, limit))
    if skipped_eco:
        print("[*][SupplyChainRecon] deep analysis skipped ecosystem(s) GuardDog "
              "cannot analyse: {}".format(sorted(e for e in skipped_eco if e)))
    return out


def _add_soft_error(artifact, spec, message):
    """Record an UNANALYSED package as a soft-error suspicious finding.

    The graph writer only ever reads packages/malicious/suspicious - never
    artifact["errors"] - so a failure recorded solely in `errors` is invisible
    to the operator and the package reads as behaviourally clean. Every path
    where GuardDog did not actually produce a verdict must land here.
    """
    artifact["suspicious"].append({
        "name": spec["name"], "version": spec["version"],
        "ecosystem": spec["osv_ecosystem"], "purl": spec["purl"],
        "rule": "guarddog-not-run", "severity": "low",
        "confidence": "suspicious", "message": str(message)[:2000],
        "soft_error": True,
    })
    return artifact


def deep_analyze(artifact, *, image=None, timeout=_DEEP_TIMEOUT,
                 limit=_DEEP_MAX_PACKAGES, budget=_DEEP_TOTAL_BUDGET,
                 guarddog=None, dispatch=None):
    """Behavioural (GuardDog) pass over the OSV-flagged packages.

    Runs guarddog INSIDE the hardened dirty analyzer image, spawned through the
    broker socket the recon container already holds (DOCKER_HOST). This process
    never unpacks a tarball itself: it holds the Neo4j creds, the analyzer does
    not.

    A GuardDog hit is ALWAYS `suspicious`, never a terminal malicious verdict -
    only an OSV MAL- hit is malicious. A download failure surfaces as a
    soft_error finding so a package is never silently reported clean.

    Mutates and returns `artifact` (revalidated by the caller).
    """
    gd_mod = guarddog or _guarddog_runner
    specs = flagged_specs(artifact, limit=limit)
    stats = {"scanned": 0, "suspicious": 0, "soft_errors": 0,
             "failed": 0, "skipped_budget": 0}
    if not specs:
        return artifact, stats

    started = time.monotonic()

    for spec in specs:
        label = "{}@{}".format(spec["name"], spec["version"] or "latest")

        elapsed = time.monotonic() - started
        if budget and elapsed >= budget:
            # Out of time. Every remaining package must be recorded as an
            # UNANALYSED soft error, never left looking behaviourally clean.
            stats["skipped_budget"] += 1
            stats["failed"] += 1
            _add_soft_error(artifact, spec,
                            "deep analysis budget of {}s exhausted before this "
                            "package was analysed".format(budget))
            continue

        print("[*][SupplyChainRecon] deep analysis: {}".format(label))
        try:
            res = _guarddog_via_analyzer(
                spec,
                timeout=min(timeout, max(1, int(budget - elapsed))) if budget else timeout,
                image=image, gd_mod=gd_mod, dispatch=dispatch)
        except Exception as exc:
            # A hostile coordinate (SanitizeError) or a spawn failure must not
            # discard the OSV verdicts already collected. Isolate per package,
            # and record it so the package is not silently reported clean.
            artifact["errors"].append("guarddog {}: {}".format(label, exc))
            stats["failed"] += 1
            _add_soft_error(artifact, spec, "guarddog dispatch raised: {}".format(exc))
            continue

        findings = res.get("findings") or []
        if res.get("error"):
            artifact["errors"].append("guarddog {}: {}".format(label, res["error"]))
            stats["failed"] += 1
            if not findings:
                # THE false-clean guard. A dispatch failure (docker socket
                # missing, image not pulled, timeout, non-JSON output) yields
                # zero findings. artifact["errors"] is NOT written to the graph,
                # so without this the package would show no behavioural findings
                # and read as "deep analysis ran, nothing found" - the exact
                # failure mode --no-sandbox was added to kill, one layer up.
                _add_soft_error(artifact, spec,
                                "guarddog did not run: {}".format(res["error"]))
        else:
            stats["scanned"] += 1

        add_guarddog_findings(
            artifact, findings,
            ecosystem=spec["osv_ecosystem"], name=spec["name"],
            version=spec["version"], purl=spec["purl"])
        stats["suspicious"] += sum(1 for f in findings if not f.get("soft_error"))
        stats["soft_errors"] += sum(1 for f in findings if f.get("soft_error"))

    return artifact, stats


# Import mining reads the served JS itself. Capped so a target cannot make the
# recon process hold an unbounded amount of attacker-controlled text: js_recon
# already caps each file at 5 MB, but nothing caps the file COUNT here.
#
# These are the FLOOR values only. The live caps come from `settings`, which
# project_settings.apply_memory_governor has already byte-budgeted against
# available RAM (they are genuine in-memory accumulators). Read straight from
# os.environ, as they were, they bypassed the governor entirely: it only walks
# the settings dict.
_IMPORT_MAX_FILES = int(os.environ.get("SUPPLY_CHAIN_IMPORT_MAX_FILES", "200"))
_IMPORT_MAX_BYTES = int(os.environ.get("SUPPLY_CHAIN_IMPORT_MAX_BYTES", str(64 * 1024 * 1024)))


def _import_budget(settings):
    """(max_files, max_bytes) for import mining: the governed setting when the
    caller has one, else the module default. A non-positive or non-int value is
    ignored rather than trusted, so a bad setting cannot disable the cap."""
    settings = settings or {}

    def pick(key, fallback):
        val = settings.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            return val
        return fallback

    return (pick("SUPPLY_CHAIN_IMPORT_MAX_FILES", _IMPORT_MAX_FILES),
            pick("SUPPLY_CHAIN_IMPORT_MAX_BYTES", _IMPORT_MAX_BYTES))


def _read_js_contents(combined_result, settings=None):
    """Raw JS text for import mining, from the dir js_recon preserved.

    mine_import_packages was written and tested but never received any input:
    run_supply_chain_recon called harvest_packages WITHOUT js_contents, so the
    whole import-mining source was dead in the pipeline.

    This is PURE string parsing (a regex for bare `import`/`require`
    specifiers) - the same risk class as the source-map mining that already
    happens in this process. Nothing is executed and nothing is fetched: the
    bytes were downloaded by js_recon, so there is no new target traffic and no
    SSRF surface (S4).
    """
    js = (combined_result or {}).get("js_recon") or {}
    work_dir = js.get("work_dir")
    if not work_dir or not os.path.isdir(work_dir):
        return []

    max_files, max_bytes = _import_budget(settings)
    contents = []
    total = 0
    try:
        names = sorted(os.listdir(work_dir))
    except OSError:
        return []
    for name in names:
        if len(contents) >= max_files or total >= max_bytes:
            break
        if not name.lower().endswith(".js"):
            continue
        path = os.path.join(work_dir, name)
        try:
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            if total + size > max_bytes:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                contents.append(fh.read())
            total += size
        except OSError:
            continue
    return contents


def _guarddog_via_analyzer(spec, *, timeout, image=None, gd_mod=None,
                           dispatch=None, sc_common_path=None):
    """One GuardDog package, through the SAME analyzer job contract as retire.js.

    This replaces a hand-rolled `docker run --entrypoint guarddog`. Keeping two
    definitions of the DIRTY spawn meant a security boundary that could drift;
    now every hostile-byte operation goes through analyzer_dispatch, which also
    gives GuardDog the egress-fails-closed behaviour.

    Returns the same {findings, error} shape scan_package did, so the caller is
    unchanged.
    """
    ad = dispatch or _analyzer_dispatch
    gd = gd_mod or _guarddog_runner
    job_dir = ad.new_work_dir(prefix="sc-guarddog")
    try:
        res = ad.run_analyzer_job(
            {"mode": "purls", "target": "/work",
             "deep_analysis": True,
             "guarddog_packages": [{"ecosystem": spec["ecosystem"],
                                    "name": spec["name"],
                                    "version": spec["version"]}]},
            job_dir, sc_common_path or _SC_COMMON_PATH,
            image=image, allow_registry_egress=True, timeout=timeout)
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)

    artifact = res.get("artifact")
    if artifact is None:
        return {"findings": [], "error": res.get("error") or "analyzer produced no artifact"}

    # The analyzer already normalized GuardDog output into `suspicious`; map it
    # back to the finding shape deep_analyze folds in.
    findings = []
    for s in artifact.get("suspicious") or []:
        findings.append({
            "package": s.get("name"), "version": s.get("version"),
            "rule": s.get("rule"), "severity": s.get("severity"),
            "confidence": "suspicious", "message": s.get("message") or "",
            "soft_error": bool(s.get("soft_error")),
        })
    inner = [e for e in (artifact.get("errors") or []) if str(e).startswith("guarddog")]
    return {"findings": findings,
            "error": res.get("error") or (inner[0][:300] if inner else None)}


def _cleanup_js_work_dir(combined_result):
    """Delete the JS dir js_recon preserved for us.

    js_recon skips its own rmtree when supply-chain recon is enabled, so this
    stage owns the bytes and must not leak them: they are attacker-served and
    they sit in /tmp/whitehat, which is shared with the host.
    """
    js = (combined_result or {}).get("js_recon") or {}
    work_dir = js.get("work_dir")
    if not work_dir:
        return
    try:
        shutil.rmtree(work_dir, ignore_errors=True)
    finally:
        js["work_dir"] = None


def retire_js_harvest(combined_result, *, sc_common_path=None, timeout=_RETIRE_TIMEOUT,
                      dispatch=None):
    """retire.js over the JS that JS-recon already downloaded, via the analyzer.

    Returns (artifact_or_None, stats). The JS bytes are attacker-served, so they
    are NEVER parsed in this process: the job runs inside the hardened DIRTY
    analyzer, which holds no credentials, and only a boundary-validated artifact
    comes back.

    This is the one L2 source that produces a NAME **and a VERSION** from the
    served bytes. Source-map mining yields names with no version (unverdictable)
    and the technology path only covers the 15-entry alias table, so without
    this most of a real target's dependency set can never be verdicted at all.
    """
    ad = dispatch or _analyzer_dispatch
    stats = {"ran": False, "packages": 0, "malicious": 0, "vulnerable": 0,
             "error": None}

    js = combined_result.get("js_recon") or {}
    work_dir = js.get("work_dir")
    if not work_dir:
        stats["error"] = ("no JS work dir (js_recon did not preserve it - is "
                          "SUPPLY_CHAIN_RECON_ENABLED set before JS recon runs?)")
        return None, stats
    if not os.path.isdir(work_dir):
        stats["error"] = "JS work dir vanished: {}".format(work_dir)
        return None, stats

    job_dir = ad.new_work_dir(prefix="sc-retire")
    try:
        res = ad.run_analyzer_job(
            {"mode": "js-dir", "target": _in_work(job_dir, work_dir)},
            job_dir, sc_common_path or _SC_COMMON_PATH, timeout=timeout)
    except Exception as exc:
        stats["error"] = "retire dispatch failed: {}".format(exc)
        return None, stats
    finally:
        # The job dir holds a COPY of attacker-served JS on host-shared
        # /tmp/whitehat. Leaving it behind leaks target bytes and grows without
        # bound across scans.
        shutil.rmtree(job_dir, ignore_errors=True)

    stats["error"] = res.get("error")
    artifact = res.get("artifact")
    if artifact is None:
        return None, stats

    stats["ran"] = True
    # The analyzer exits 0 even when retire.js itself failed; that failure is
    # recorded inside the artifact. Surface it, or the pass reports ran=True
    # with no error and reads as "scanned, found nothing".
    inner = [e for e in (artifact.get("errors") or []) if str(e).startswith("retire")]
    if inner and not stats.get("error"):
        stats["error"] = inner[0][:300]
    stats["packages"] = len(artifact.get("packages") or [])
    stats["malicious"] = len(artifact.get("malicious") or [])
    stats["vulnerable"] = len(artifact.get("vulnerable") or [])
    return artifact, stats


def _in_work(job_dir, js_dir):
    """Expose the JS dir to the analyzer under its /work mount.

    The analyzer only ever sees `job_dir` bound at /work, so the downloaded JS
    must live inside it. A symlink would dangle across the mount boundary, so
    the files are copied - they are small (JS_RECON caps each file at 5 MB) and
    this keeps the analyzer's view of the filesystem to exactly one directory.
    """
    dest = os.path.join(job_dir, "js")
    shutil.copytree(js_dir, dest, dirs_exist_ok=True)
    # retire.js writes its report (_retire_out.json) INTO the directory it
    # scans, and the analyzer runs as non-root (uid 1001) while this process is
    # root - so a default 0755 copy makes retire die with EACCES after doing all
    # the work. Verified: "EACCES: permission denied, open
    # '/work/js/_retire_out.json'" at reporting.js:110.
    try:
        os.chmod(dest, 0o777)
    except OSError:
        pass
    return "/work/js"


def _pkg_identity(pkg):
    """The key a package is deduped on: (ecosystem, name) - NOT the purl.

    A purl embeds the version, so purl-keying treats `pkg:npm/lodash` and
    `pkg:npm/lodash@4.17.4` as two different packages. They are one library
    seen by two sources, and keeping both puts two Package nodes in the graph
    for it.
    """
    return (pkg.get("ecosystem"), pkg.get("name"))


def merge_artifacts(base, extra):
    """Fold an analyzer artifact into the running one, deduping by identity.

    Packages dedup on (ecosystem, name) with the VERSIONED sighting winning;
    findings dedup on (purl, advisory_id) - the same key the graph writer
    MERGEs on, so what the graph would collapse is collapsed here too and the
    summary counts stay honest.

    The version-preferring rule mirrors harvest_packages, which already applies
    it across its own three sources. It matters most exactly here: retire.js is
    the only source that reads a version out of the served bytes, so the
    package it upgrades is routinely one wappalyzer or source-map mining
    already contributed WITHOUT a version. Deduping on the purl string would
    keep both - an unverdictable `pkg:npm/lodash` next to the verdicted
    `pkg:npm/lodash@4.17.4`.
    """
    if not extra:
        return base
    # Index by identity so a versioned sighting can REPLACE a versionless one
    # that is already in the list, not merely be skipped or appended.
    by_identity = {}
    for idx, pkg in enumerate(base.get("packages") or []):
        by_identity.setdefault(_pkg_identity(pkg), idx)

    for pkg in extra.get("packages") or []:
        key = _pkg_identity(pkg)
        idx = by_identity.get(key)
        if idx is None:
            by_identity[key] = len(base["packages"])
            base["packages"].append(pkg)
            continue
        prev = base["packages"][idx]
        # Best evidence wins: a concrete version beats no version. Two
        # DIFFERENT concrete versions keep first-seen - the harvest side is
        # the one that already deduped its own sources, so it is not
        # second-guessed here.
        if pkg.get("version") and not prev.get("version"):
            base["packages"][idx] = pkg

    for bucket in ("malicious", "vulnerable", "suspicious"):
        seen = {(f.get("purl"), f.get("advisory_id") or f.get("rule"))
                for f in base.get(bucket) or []}
        for f in extra.get(bucket) or []:
            key = (f.get("purl"), f.get("advisory_id") or f.get("rule"))
            if key in seen:
                continue
            seen.add(key)
            base[bucket].append(f)

    for err in extra.get("errors") or []:
        base["errors"].append(err)
    return base


def run_supply_chain_recon(combined_result, settings=None):
    """Harvest + verdict; store combined_result['supply_chain_recon']. Returns
    the mutated combined_result (pipeline convention)."""
    settings = settings or {}
    from recon.helpers.supply_chain.harvest import harvest_packages

    source_maps = _extract_source_maps(combined_result)
    technologies = _extract_technologies(combined_result)
    base_urls = _extract_base_urls(combined_result)

    js_contents = _read_js_contents(combined_result, settings)
    packages = harvest_packages(source_maps=source_maps,
                                technologies=technologies,
                                js_contents=js_contents)
    # Ecosystem allow-filter. Matched EXACTLY against the harvested ecosystem,
    # so the UI (SupplyChainReconSection) stores canonical OSV names.
    # An allow-set that is empty AFTER parsing means "no filter": before this,
    # a whitespace-only value ("  ") was truthy but parsed to an empty set, so
    # it silently dropped EVERY harvested package instead of dropping none.
    # NOTE: this filters the harvested set only - the retire.js pass merges into
    # the artifact further down and is deliberately not filtered (it is npm-only
    # and is where most real verdicts come from).
    ecos = settings.get("SUPPLY_CHAIN_RECON_ECOSYSTEMS")
    if ecos:
        raw = ecos.split(",") if isinstance(ecos, str) else list(ecos)
        allow = {str(e).strip() for e in raw if str(e).strip()}
        if allow:
            packages = [p for p in packages if p.get("ecosystem") in allow]

    artifact = verdict_packages(packages, db_path=_OSV_DB)

    # retire.js over the served JS, inside the DIRTY analyzer. This is the only
    # source that yields versioned components, so it is where most real verdicts
    # come from; it is folded in BEFORE the flagged-package selection below so
    # deep analysis can triage what it finds.
    retire_stats = None
    if settings.get("SUPPLY_CHAIN_RECON_RETIRE_ENABLED", True):
        try:
            retire_art, retire_stats = retire_js_harvest(combined_result)
            if retire_art:
                artifact = merge_artifacts(artifact, retire_art)
                artifact = validate_artifact(artifact)
            elif retire_stats.get("error"):
                # Never silently clean: if the pass could not run, say so.
                artifact["errors"].append("retire: {}".format(retire_stats["error"]))
        except Exception as exc:
            print("[!][SupplyChainRecon] retire.js pass failed: {}".format(exc))
            artifact["errors"].append("retire.js pass failed: {}".format(exc))
        finally:
            _cleanup_js_work_dir(combined_result)
    else:
        _cleanup_js_work_dir(combined_result)

    if retire_stats:
        print("[+][SupplyChainRecon] retire.js: ran={} packages={} malicious={} "
              "vulnerable={}{}".format(
                  retire_stats["ran"], retire_stats["packages"],
                  retire_stats["malicious"], retire_stats["vulnerable"],
                  " error=" + str(retire_stats["error"]) if retire_stats.get("error") else ""))

    # Deep behavioural analysis (GuardDog), opt-in. Runs only over packages the
    # offline OSV pass already flagged, inside the hardened dirty analyzer.
    deep_stats = None
    if settings.get("SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED"):
        try:
            artifact, deep_stats = deep_analyze(artifact)
            # Re-validate: GuardDog output is attacker-influenced (rule messages
            # quote package source), so it must clear the boundary gate too.
            artifact = validate_artifact(artifact)
        except ArtifactError as exc:
            # D1: dropping the WHOLE suspicious list here made every package the
            # deep pass touched read behaviourally clean again - including the
            # soft-error markers that exist precisely to prevent that. The
            # salvage logic is shared with L1 so the two cannot drift again;
            # they already did once, and L1 kept the wholesale wipe.
            print("[!][SupplyChainRecon] deep analysis artifact invalid: {}".format(exc))
            artifact = recover_invalid_deep_artifact(
                artifact, exc, validate=validate_artifact,
                flagged_specs=flagged_specs, add_soft_error=_add_soft_error)
        except Exception as exc:
            print("[!][SupplyChainRecon] deep analysis failed: {}".format(exc))
            artifact["errors"].append("deep analysis failed: {}".format(exc))

    # D: typosquat detection over the harvested names. Runs BEFORE the incident
    # enrichment below so a typosquat finding whose package IS in the catalog
    # picks up its own incident context in the same pass - it used to run after,
    # so those findings silently never got one. Pure string work, no network.
    try:
        from recon.helpers.supply_chain.typosquat import detect_typosquats
        from supply_chain_common.intel import load_intel as _load_intel

        ts_findings, ts_stats = detect_typosquats(
            artifact.get("packages") or [],
            intel=_load_intel(),
            fuzzy_enabled=bool(settings.get("SUPPLY_CHAIN_TYPOSQUAT_ENABLED")),
        )
        if ts_findings:
            artifact["suspicious"].extend(ts_findings)
        print("[+][SupplyChainRecon] typosquat: checked={} catalog={} fuzzy={} "
              "(fuzzy_enabled={})".format(
                  ts_stats["checked"], ts_stats["catalog_hits"],
                  ts_stats["fuzzy_hits"], ts_stats["fuzzy_enabled"]))
        if not ts_stats["catalog_available"]:
            artifact["errors"].append(
                "sca-intel: typosquat catalog lookup did not run "
                "(catalog unavailable)")
    except Exception as exc:
        print("[!][SupplyChainRecon] typosquat detection failed: {}".format(exc))
        artifact["errors"].append("typosquat detection failed: {}".format(exc))

    # Incident context (B). MUST come after the LAST validate_artifact above:
    # the incident_* properties are deliberately absent from the artifact
    # allowlist, so enriching before the gate would fail validation. This is the
    # ordering that keeps the DIRTY->CLEAN boundary closed - nothing may add
    # fields before the last gate, and this is a trusted LOCAL dictionary join
    # with no network and no new findings.
    try:
        from supply_chain_common.intel import enrich_findings, load_intel

        _intel = load_intel()
        enrich_findings(artifact, _intel)
        if not _intel.available:
            print("[!][SupplyChainRecon] incident intel unavailable; findings "
                  "carry no incident context")
    except Exception as exc:
        # C7 again: record that the pass did not run, never fail the scan for it.
        print("[!][SupplyChainRecon] incident enrichment failed: {}".format(exc))
        artifact["errors"].append("incident enrichment failed: {}".format(exc))

    # A2: malicious-host correlation. Gated by its own setting, and inert anyway
    # unless the parent Supply-Chain Recon toggle is on, since this runs inside
    # that module. Reads only nodes/files the pipeline already has.
    intel_correlation = None
    if settings.get("SCA_INTEL_CORRELATION_ENABLED", True):
        try:
            from recon.main_recon_modules.sca_intel_correlate import correlate_hosts

            intel_correlation = correlate_hosts(combined_result, base_urls)
            hits = len(intel_correlation["correlations"])
            if not intel_correlation["available"]:
                print("[!][SupplyChainRecon] incident catalog unavailable; "
                      "malicious-host correlation did NOT run")
                artifact["errors"].append(
                    "sca-intel: malicious-host correlation did not run "
                    "(catalog unavailable)")
            else:
                print("[+][SupplyChainRecon] host correlation: checked={} matched={}"
                      .format(intel_correlation["checked"], hits))
        except Exception as exc:
            print("[!][SupplyChainRecon] host correlation failed: {}".format(exc))
            artifact["errors"].append("host correlation failed: {}".format(exc))

    combined_result["supply_chain_recon"] = {
        "artifact": artifact,
        "base_urls": base_urls,
        "intel_correlation": intel_correlation,
        "summary": {
            "packages": len(artifact["packages"]),
            "malicious": len(artifact["malicious"]),
            "vulnerable": len(artifact["vulnerable"]),
            "suspicious": len(artifact["suspicious"]),
            "deep_analysis": deep_stats,
        },
    }
    print("[+][SupplyChainRecon] packages={} malicious={} vulnerable={} suspicious={}".format(
        len(artifact["packages"]), len(artifact["malicious"]),
        len(artifact["vulnerable"]), len(artifact["suspicious"])))
    if deep_stats:
        print("[+][SupplyChainRecon] deep analysis: scanned={} suspicious={} "
              "soft_errors={} failed={} skipped_budget={}".format(
                  deep_stats["scanned"], deep_stats["suspicious"],
                  deep_stats["soft_errors"], deep_stats["failed"],
                  deep_stats["skipped_budget"]))
    return combined_result
