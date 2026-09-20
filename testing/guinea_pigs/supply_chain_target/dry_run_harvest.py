"""Dry-run the REAL L2 chain against the guinea pig, without the full app.

Runs inside the whitehat-recon image with recon/, supply_chain_common/ and the
offline OSV DB mounted, exactly as recon_orchestrator mounts them for a real
scan. Feeds a minimal combined_result through the production functions:

    run_js_recon  ->  run_supply_chain_recon

and prints the resulting artifact. Use it to regenerate expected_results.yaml
and to debug a harvest without waiting on a full pipeline run.

Not part of the assertion path: validate_supply_chain_recon.py checks Neo4j
after a real scan. This is the fast inner loop.

Usage (from the repo root):
    ./guinea_pigs/supply_chain_target/run_dry_run.sh
"""

import json
import os
import sys

TARGET = os.environ.get("SC_TARGET_URL", "http://192.88.99.10")
HTTPX_JSON = os.environ.get("SC_HTTPX_JSON", "/work/httpx.json")

sys.path.insert(0, "/app")


def build_http_probe():
    """Reconstruct the http_probe block shape from raw httpx JSONL.

    Mirrors what recon/main_recon_modules/http_probe.py assembles: by_url
    entries carrying a `technologies` list of "Name:Version" strings, plus the
    top-level technologies_found dict keyed by the same strings.
    """
    by_url = {}
    technologies_found = {}
    with open(HTTPX_JSON) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            url = d.get("url")
            if not url:
                continue
            techs = d.get("tech") or []
            by_url[url] = {
                "url": url,
                "host": d.get("host"),
                "status_code": d.get("status_code"),
                "title": d.get("title"),
                "technologies": techs,
            }
            for t in techs:
                technologies_found.setdefault(t, []).append(url)
    return {"by_url": by_url, "technologies_found": technologies_found}


def _apply_katana_exclusions(urls):
    """Drop URLs the real crawler would never hand to js_recon.

    Mirrors recon/helpers/resource_enum/katana_helpers.py: a plain case-insensitive substring
    match of KATANA_EXCLUDE_PATTERNS against the whole URL. Reads the shipped
    default straight out of recon/project_settings.py so the dry run can never
    drift from what a real scan sees.
    """
    from recon.project_settings import DEFAULT_SETTINGS
    patterns = [p.lower() for p in DEFAULT_SETTINGS.get("KATANA_EXCLUDE_PATTERNS", [])]
    kept, dropped = [], []
    for url in urls:
        low = url.lower()
        hit = [p for p in patterns if p in low]
        (dropped if hit else kept).append((url, hit))
    if dropped:
        print("\n[!] excluded by KATANA_EXCLUDE_PATTERNS (a real scan drops these too):")
        for url, hit in dropped:
            print("      %-52s %s" % (url.replace(TARGET, ""), hit))
    print("[*] %d/%d candidate JS URLs survive the crawler exclusions"
          % (len(kept), len(urls)))
    return [u for u, _ in kept]


def main():
    from recon.main_recon_modules.js_recon import run_js_recon
    from recon.main_recon_modules.supply_chain_recon import run_supply_chain_recon

    # The JS URLs katana/resource_enum would discover from the target's HTML.
    #
    # These MUST be filtered through the real KATANA_EXCLUDE_PATTERNS. Feeding
    # the raw list here is what hid a whole broken path once: the guinea pig
    # served its bundles under /static/js/, the shipped exclusion list drops
    # anything containing "/static/", and a real scan therefore discovered ONE
    # js file and mined ZERO source maps - while this dry run reported 111
    # packages and a green harvest. If a path is unreachable in production it
    # must be unreachable here too.
    candidates = [
        TARGET + "/axios@1.14.1/axios.min.js",
        TARGET + "/js/jquery-3.4.1.min.js",
        TARGET + "/js/vue-2.6.10.min.js",
        TARGET + "/js/bootstrap-5.3.3.min.js",
        TARGET + "/js/lodash.custom.js",
        TARGET + "/js/moment.min.js",
        TARGET + "/js/react-18.2.0.min.js",
        TARGET + "/js/angular-1.8.3.min.js",
        TARGET + "/js/d3.min.js",
        TARGET + "/js/backbone.js",
        TARGET + "/js/underscore.js",
        TARGET + "/assets/app.7f3c2a.js",
        TARGET + "/assets/deep-vendor.js",
        # retire.js filecontent banners. Deliberately anonymous paths: retire.js
        # identifies these by CONTENT, so nothing about the URL hints at the
        # library. That is the whole point - the technology path cannot see them.
        TARGET + "/assets/tpl-engine.js",
        TARGET + "/assets/util-belt.js",
        TARGET + "/assets/bind-lib.js",
        TARGET + "/assets/fresh-lib.js",
        # Source-map discovery variants (one mechanism each).
        TARGET + "/assets/hdrmap.js",
        TARGET + "/assets/probemap.js",
        TARGET + "/assets/inlinemap.js",
        TARGET + "/assets/multiline.js",
        TARGET + "/assets/badmap.js",
        # A2 fixture: the bundle whose CALL SHAPES yield the IOC hosts as
        # endpoints, which js_recon turns into external_domains.
        TARGET + "/assets/vendor-telemetry.js",
    ]
    discovered = _apply_katana_exclusions(candidates)

    combined = {
        "domain": "192.88.99.10",
        "resource_enum": {"discovered_urls": discovered},
        "http_probe": build_http_probe(),
        "metadata": {"project_id": "dryrun", "modules_executed": []},
    }

    settings = {
        "JS_RECON_ENABLED": True,
        "JS_RECON_SOURCE_MAPS": True,
        "JS_RECON_MAX_FILES": 100,
        "JS_RECON_CONCURRENCY": 5,
        "JS_RECON_TIMEOUT": 120,
        "JS_RECON_DEPENDENCY_CHECK": False,   # would hit the npm registry
        "JS_RECON_VALIDATE_KEYS": False,
        "JS_RECON_VALIDATE_ENDPOINTS": False,
        "SUPPLY_CHAIN_RECON_ENABLED": True,
        "SUPPLY_CHAIN_RECON_ECOSYSTEMS": "npm",
        # Deep behavioural analysis (GuardDog). Off unless SC_DEEP=1, because it
        # downloads real tarballs from the npm registry and costs ~60s/package.
        "SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED":
            os.environ.get("SC_DEEP") == "1",
    }

    combined = run_js_recon(combined, settings=settings)

    maps = (combined.get("js_recon") or {}).get("source_maps") or []
    print("\n=== JS RECON ===")
    print("source maps found:", len(maps))
    for m in maps:
        print("  %s -> %d source_files (files_count=%d)"
              % (m.get("map_url"), len(m.get("source_files") or []),
                 m.get("files_count", -1)))

    combined = run_supply_chain_recon(combined, settings=settings)

    block = combined["supply_chain_recon"]
    art = block["artifact"]

    print("\n=== BASE URLS (DEPENDS_ON anchors) ===")
    for u in block["base_urls"]:
        print(" ", u)

    print("\n=== PACKAGES (%d) ===" % len(art["packages"]))
    for p in sorted(art["packages"], key=lambda x: x["purl"]):
        print("  %-46s source=%s" % (p["purl"], p.get("source")))

    print("\n=== MALICIOUS (%d)  -> becomes MalPackageFinding ===" % len(art["malicious"]))
    for m in art["malicious"]:
        print("  %s  %s" % (m.get("purl"), m.get("advisory_id")))

    print("\n=== VULNERABLE (%d)  -> JSON only, NO graph node ===" % len(art["vulnerable"]))
    for v in art["vulnerable"]:
        print("  %s  %s" % (v.get("purl"), v.get("advisory_id")))

    print("\n=== SUSPICIOUS (%d)  -> GuardDog, verdict=suspicious ===" % len(art["suspicious"]))
    by_rule = {}
    for s in art["suspicious"]:
        key = (s.get("name"), s.get("version"), s.get("rule"),
               s.get("severity"), s.get("soft_error"))
        by_rule[key] = by_rule.get(key, 0) + 1
    for (name, ver, rule, sev, soft), n in sorted(by_rule.items(), key=lambda x: str(x[0])):
        print("  %-16s %-8s %-38s sev=%-6s soft_error=%s  x%d"
              % (name, ver or "-", rule, sev, soft, n))
    if block["summary"].get("deep_analysis"):
        print("  deep_analysis stats:", block["summary"]["deep_analysis"])

    print("\n=== ERRORS ===")
    for e in art["errors"]:
        print("  ", e)

    out = os.environ.get("SC_DRYRUN_OUT", "/work/dryrun_artifact.json")
    with open(out, "w") as fh:
        json.dump(block, fh, indent=2, sort_keys=True)
    print("\nwrote", out)


if __name__ == "__main__":
    main()
