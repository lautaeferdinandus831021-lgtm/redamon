"""Supply-Chain recon (L2) guinea pig - deterministic HTTP target.

Serves a static surface engineered so that EVERY branch of the L2 harvest chain
fires exactly once, with a known expected outcome. Pure stdlib, no deps.

Two independent harvest paths feed L2, and this target drives both:

  A. technologies -> purl   (the ONLY version-bearing source in the pipeline)
     httpx's wappalyzergo reads <script src> paths and emits "Name:Version"
     strings. recon/helpers/supply_chain/harvest.py maps a fixed alias table of
     display-names to npm names; everything else is dropped (no invented purls).

  B. source-map mining      (names only, never versions)
     js_recon downloads the app bundles, follows //# sourceMappingURL, and
     stores map["sources"][:100] as source_files. harvest mines
     node_modules/(@scope/)?<pkg> out of those paths.

  C. retire.js              (name AND version, from the bytes themselves)
     The downloaded JS is handed to retire.js inside the DIRTY analyzer, which
     matches `filecontent` signatures. This is the only path that can verdict a
     package the 15-entry alias table has never heard of - and the only one
     that can put a VERSION on a library the other two saw versionless.

Two paths, A and C, can report the SAME library, and that overlap is
deliberate: lodash arrives versionless from A and versioned from C, so the
target also proves the merge collapses them into one Package node.

Nothing here is intelligent: the bytes are fixed, so the verdicts are fixed.
See README.md for the endpoint -> pipeline-step map and expected_results.yaml
for the assertions.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SC_TARGET_PORT", "80"))

# X-Powered-By value. Port 80 = Express (alias, no version). Port 8080 =
# "Next.js 13.4.7", which wappalyzergo parses WITH a version
# (x-powered-by: ^Next\.js ?([0-9.]+)?), giving pkg:npm/next@13.4.7 - a
# versioned alias reached through a header rather than a script path. The two
# cannot share one response: the Express pattern is anchored at ^, so a
# combined value would only ever match the first.
POWERED_BY = os.environ.get("SC_POWERED_BY", "Express")

# Second surface. Same IP, different port, so the scan yields TWO BaseURL
# nodes and update_graph_from_supply_chain_recon exercises its per-BaseURL
# anchoring loop rather than the single-anchor case.
ALT_PORT = int(os.environ.get("SC_ALT_PORT", "8080"))
ALT_POWERED_BY = os.environ.get("SC_ALT_POWERED_BY", "Next.js 13.4.7")

# --------------------------------------------------------------------------
# Path A: technologies. Every <script src> below is shaped to match a specific
# wappalyzergo fingerprint. The version in the PATH is what httpx reports.
# --------------------------------------------------------------------------
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WhiteHat Supply-Chain Target</title>
<meta name="generator" content="WordPress 6.1">

<!-- MALICIOUS: axios 1.14.1 is covered by OSV MAL-2026-2307 (live, not
     withdrawn). This is the one and only package in the alias table with a
     real malicious advisory, so it is the sole source of a malicious verdict.

     It doubles as the GuardDog SOFT-ERROR proof: npm unpublished 1.14.1 (as
     registries do with malicious releases), so guarddog cannot download it and
     emits errors["download-package"]. That must surface as a soft_error
     finding, NEVER as a silent clean. -->
<script src="/axios@1.14.1/axios.min.js"></script>

<!-- VULNERABLE (CVE/GHSA only): must appear in the JSON artifact's
     `vulnerable` list but must NOT become a graph node.

     These two are ALSO the GuardDog deep-analysis proof findings. Deep
     analysis only ever runs over packages an OSV verdict already flagged, so
     a package has to be vulnerable/malicious to reach it at all. Both are
     frozen published versions, so their rule hits are deterministic:
       jquery 3.4.1 -> 4 rules (1 medium: threat-runtime-obfuscation-general)
       vue    2.6.10 -> 3 rules (all low: capability-*)
     Verified against GuardDog 3.0.1 on 2026-08-07. -->
<script src="/js/jquery-3.4.1.min.js"></script>
<script src="/js/vue-2.6.10.min.js"></script>

<!-- CLEAN + versioned: a Package node with a version and zero findings. -->
<script src="/js/bootstrap-5.3.3.min.js"></script>

<!-- CLEAN + versioned, second case, and the plain `react` alias. -->
<script src="/js/react-18.2.0.min.js"></script>

<!-- ALIAS RENAME: httpx reports "AngularJS:1.8.3"; _TECH_NPM_ALIASES maps the
     display name `angularjs` to the npm package `angular` (NOT @angular/core,
     which is the `angular` display name). Proves the rename, and angular 1.8.3
     is OSV-flagged so it also reaches GuardDog - where it fires
     threat-runtime-obfuscation-steganography, the only HIGH severity tier
     (severity_for_rule matches the "steganography" marker). -->
<script src="/js/angular-1.8.3.min.js"></script>

<!-- VERSIONLESS aliases: harvested as inventory, cannot be OSV-verdicted. -->
<script src="/js/lodash.custom.js"></script>
<script src="/js/moment.min.js"></script>
<script src="/js/d3.min.js"></script>
<script src="/js/backbone.js"></script>

<!-- DETECTED BUT NOT AN ALIAS: httpx reports "Underscore.js"; it is absent
     from _TECH_NPM_ALIASES so no purl may be invented for it. -->
<script src="/js/underscore.js"></script>

<!-- App bundles: the source-map path (B). Under /assets/ because the shipped
     KATANA_EXCLUDE_PATTERNS drops anything containing "/static/", so a bundle
     served there is never crawled and never mined. -->
<script src="/assets/app.7f3c2a.js"></script>
<script src="/assets/deep-vendor.js"></script>

<!-- PATH C: retire.js. The ONLY source that reads a NAME **and a VERSION**
     out of the served bytes, so it is the only one whose packages are
     verdictable without appearing in the 15-entry alias table.

     Detection is by file CONTENT, so the paths below are deliberately
     anonymous - nothing about "/assets/tpl-engine.js" says handlebars. That
     is the point: the technology path could never have found these.

     Every name here must dodge KATANA_EXCLUDE_PATTERNS (no ".min.js", no
     "jquery", no "/vendor/", no "chunk."), or the file is never crawled,
     never downloaded, and retire.js never sees it. -->
<script src="/assets/tpl-engine.js"></script>   <!-- handlebars 4.0.5 -->
<script src="/assets/util-belt.js"></script>    <!-- lodash 4.17.4 -->
<script src="/assets/bind-lib.js"></script>     <!-- knockout 3.4.0 -->
<script src="/assets/fresh-lib.js"></script>    <!-- knockout 3.5.1: clean, negative control -->

<!-- SOURCE-MAP DISCOVERY VARIANTS. js_recon has four independent ways to find
     a map; each bundle below exercises exactly one, and each contributes a
     uniquely-named package so the graph says which mechanism fired. -->
<script src="/assets/hdrmap.js"></script>       <!-- SourceMap: response header -->
<script src="/assets/probemap.js"></script>     <!-- no hint at all -> {url}.map probe -->
<script src="/assets/inlinemap.js"></script>    <!-- //# sourceMappingURL=data:...base64 -->
<script src="/assets/multiline.js"></script>    <!-- /*# sourceMappingURL=... */ -->
<script src="/assets/badmap.js"></script>       <!-- malformed map -> must be ignored -->

<!-- FEATURE A2 (malicious-host correlation). The IOC hosts are referenced as
     STRINGS INSIDE this bundle, never as <script src>, so js_recon mines them
     into external_domains without ever fetching them. Every host is under
     .test (RFC 6761: guaranteed not to resolve), so nothing leaves the box. -->
<script src="/assets/vendor-telemetry.js"></script>
</head>
<body>
<h1>WhiteHat Supply-Chain Target</h1>
<p>Deterministic L2 validation surface.</p>
<ul>
  <li><a href="/assets/app.7f3c2a.js">app bundle</a></li>
  <li><a href="/assets/deep-vendor.js">deep chunk</a></li>
  <li><a href="/about.html">about</a></li>
</ul>
</body>
</html>
"""

ABOUT_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>About</title></head>
<body><h1>About</h1><p>Second page so katana has something to crawl.</p>
<a href="/">home</a></body></html>
"""

ROBOTS = "User-agent: *\nAllow: /\n"

# --------------------------------------------------------------------------
# Path B: source maps.
# --------------------------------------------------------------------------

# app.7f3c2a.js.map - the "normal" mining cases plus the hostile-name rejects.
APP_SOURCES = [
    # Not a package: no node_modules segment, must be ignored entirely.
    "webpack:///./src/index.js",
    "webpack:///./src/components/App.jsx",

    # Plain unscoped package.
    "webpack:///./node_modules/left-pad/index.js",

    # Scoped package -> purl must url-encode the '@' as %40.
    "webpack:///./node_modules/@babel/runtime/helpers/typeof.js",

    # Same package as the versioned technology hit. Proves the version-
    # preferring dedup: this versionless sighting must LOSE to axios@1.14.1.
    "webpack:///./node_modules/axios/lib/core/Axios.js",

    # Another plain package, sanity volume. ALSO a fixture-catalog hit
    # (npm/is-odd -> GP-PKG-ISODD): versionless and OSV-clean, so the only way
    # it can carry a finding is the catalog direct-hit in typosquat detection.
    "webpack:///./node_modules/is-odd/index.js",

    # FEATURE D, fuzzy branch: one edit from "lodash" without being it, and the
    # fixture catalog also labels it a typosquat of lodash (GP-TYPO-001). The
    # catalog hit is what fires with the toggle OFF; the edit-distance branch
    # would find it too once supplyChainTyposquatEnabled is on.
    "webpack:///./node_modules/lodahs/index.js",

    # --- hostile names: every one must be dropped by sanitize_name ---
    "webpack:///./node_modules/../../etc/passwd",        # '..' traversal
    "webpack:///./node_modules/-rf/index.js",            # leading '-' (CLI flag)
    "webpack:///./node_modules/evil;whoami/index.js",    # shell metacharacter
    "webpack:///./node_modules/back`tick`/index.js",     # backtick
]

# deep-vendor.js.map - nested node_modules + the source_files[:100] cap.
# js_recon stores sources[:100], so index 99 is the last one that survives.
_NESTED = "webpack:///./node_modules/outer-pkg/node_modules/inner-pkg/index.js"
DEEP_SOURCES = (
    # index 0: nested. findall() must yield BOTH outer-pkg and inner-pkg.
    [_NESTED]
    # indexes 1..98: filler, to push the boundary out to index 99.
    + ["webpack:///./node_modules/filler-%03d/index.js" % i for i in range(98)]
    # index 99: the last surviving entry.
    + ["webpack:///./node_modules/within-cap-edge/index.js"]
    # index 100+: past the cap. MUST NOT appear in the graph.
    + ["webpack:///./node_modules/beyond-cap-pkg/index.js"]
    + ["webpack:///./node_modules/also-beyond-%02d/index.js" % i for i in range(19)]
)


# One package per discovery mechanism, so the graph proves WHICH one fired.
_VARIANT_SOURCES = {
    "hdrmap": "via-header",
    "probemap": "via-path-probe",
    "inlinemap": "via-inline-data",
    "multiline": "via-multiline-comment",
    "badmap": "must-not-appear",          # negative control
}


def _sourcemap(sources, file_name):
    """A v3 source map. js_recon requires 'version' plus a 'sources' list."""
    return {
        "version": 3,
        "file": file_name,
        "sourceRoot": "",
        "sources": sources,
        "names": [],
        "mappings": "AAAA",
    }


def _bundle(name, map_name):
    """A JS bundle that points at its own source map."""
    return (
        "/* %s - WhiteHat supply-chain guinea pig bundle */\n"
        "(function(){var a=1;window.__SC_TARGET__='%s';})();\n"
        "//# sourceMappingURL=%s\n" % (name, name, map_name)
    )


# Stub library files. Content is irrelevant (versions come from the PATH), but
# they must exist and return 200 so js_recon/katana do not log misses.
def _stub(label):
    return "/* %s stub - WhiteHat guinea pig */\nvar __x=0;\n" % label


# --------------------------------------------------------------------------
# Path C: retire.js filecontent banners.
#
# Each string below matches a real `filecontent` extractor in retire.js's
# jsrepository-v5.json. Verified against retire.js v5.4.3 + the offline OSV DB
# on 2026-08-07 - the version numbers are chosen for what they PROVE, so do not
# bump them casually:
#
#   handlebars 4.0.5  19 advisories spanning critical/high/medium/low. Proves
#                     (a) coverage NO other path has - handlebars is absent
#                     from _TECH_NPM_ALIASES, so without retire.js it is
#                     invisible - and (b) the full severity ladder in
#                     _vuln_severity, not just one tier.
#   lodash 4.17.4     8 advisories, and lodash IS in the alias table - reached
#                     versionless via /js/lodash.custom.js. Proves the UPGRADE:
#                     an unverdictable `pkg:npm/lodash` becomes the verdicted
#                     `pkg:npm/lodash@4.17.4`, and merge_artifacts must collapse
#                     the two into ONE Package node rather than keeping both.
#   knockout 3.4.0    1 advisory. A second not-in-the-alias-table case, cheap.
#   knockout 3.5.1    NEGATIVE CONTROL. retire.js identifies it and reports
#                     NOTHING, because its JSON reporter emits only components
#                     that carry vulnerabilities - a clean version is
#                     indistinguishable from an unrecognised file. It must
#                     contribute no package and no finding. If this one ever
#                     shows up, retire.js changed behaviour and the "retire is
#                     not an inventory source" note in retire_runner is stale.
# --------------------------------------------------------------------------
# FEATURE A2 surface. Four hosts, each proving a different matcher branch:
#   cdn.gp-skimmer.test        exact domain hit           -> GP-HOST-001
#   a.gp-wildcard.test         wildcard suffix hit        -> GP-HOST-003
#   gp-wildcard.test           the apex itself: NO hit (suffix is ".gp-wildcard.test")
#   cdn.gp-clean.test          not in the catalog: NO hit (negative control)
# telemetry.gp-exfil.test carries a javascript: URL in the catalog, so it also
# proves the render sites refuse a hostile link.
VENDOR_TELEMETRY_JS = """\
/* vendor telemetry shim - fixture for supply-chain host correlation.
   Each URL sits inside a CALL SHAPE js_recon's endpoint extractor recognises
   (_REST_PATTERNS: fetch(...), axios.get(...), ...). An object-literal value
   like `cdn: "https://..."` is NOT extracted - the first draft of this fixture
   used exactly that and produced zero endpoints, which is why the correlation
   silently reported checked=1 matched=0. */
function boot() {
  // exact domain hit -> GP-HOST-001
  axios.get("https://cdn.gp-skimmer.test/lib/analytics.min.js");
  // exact domain hit, and its catalog record carries a javascript: URL
  fetch("https://telemetry.gp-exfil.test/collect", {method: "POST"});
  // wildcard suffix hit (.gp-wildcard.test) -> GP-HOST-003
  fetch("https://a.gp-wildcard.test/edge/loader.js");
  // NEGATIVE CONTROL: the apex itself must NOT match a ".gp-wildcard.test" suffix
  fetch("https://gp-wildcard.test/not-a-match");
  // NEGATIVE CONTROL: absent from the catalog entirely
  fetch("https://cdn.gp-clean.test/vendor/ok.js");
}
"""

RETIRE_BANNERS = {
    # `Handlebars.VERSION = "(version)";`
    "tpl-engine": '/* template engine */\nvar Handlebars={};\n'
                  'Handlebars.VERSION = "4.0.5";\n',
    # `/*[\s*!]+(?:@license)?[\s*]+(?:Lo-Dash|lodash|Lodash) v?(version) lodash.com/license`
    "util-belt": '/**\n * @license\n * lodash 4.17.4 lodash.com/license\n */\n'
                 'var _=function(){return 1;};\n',
    # `(?:\*|//) Knockout JavaScript library v(version)`
    "bind-lib": '// Knockout JavaScript library v3.4.0\n'
                '// (c) The Knockout.js team\nvar ko={};\n',
    # Same extractor, a version with no known vulnerabilities.
    "fresh-lib": '// Knockout JavaScript library v3.5.1\n'
                 '// (c) The Knockout.js team\nvar ko={};\n',
}


def _variant_map(key):
    """A one-package source map for a discovery-variant bundle."""
    return _sourcemap(
        ["webpack:///./node_modules/%s/index.js" % _VARIANT_SOURCES[key]],
        "%s.js" % key)


def _inline_data_uri():
    """base64 data: URI carrying the inline source map.

    js_recon decodes this BEFORE is_url_safe_to_probe, so it is the one
    discovery path that needs no second fetch at all (sourcemap.py:106-114).
    """
    import base64
    raw = json.dumps(_variant_map("inlinemap")).encode("utf-8")
    return "data:application/json;base64," + base64.b64encode(raw).decode("ascii")


# A map missing the mandatory "version" key. js_recon requires version + a
# sources list, so this must be REJECTED and contribute no package.
_BAD_MAP = json.dumps({"file": "badmap.js", "sources": [
    "webpack:///./node_modules/%s/index.js" % _VARIANT_SOURCES["badmap"]]})


ROUTES = {
    "/": ("text/html; charset=utf-8", INDEX_HTML),
    "/index.html": ("text/html; charset=utf-8", INDEX_HTML),
    "/about.html": ("text/html; charset=utf-8", ABOUT_HTML),
    "/robots.txt": ("text/plain; charset=utf-8", ROBOTS),

    # Path A stubs.
    "/axios@1.14.1/axios.min.js": ("application/javascript", _stub("axios 1.14.1")),
    "/js/jquery-3.4.1.min.js": ("application/javascript", _stub("jquery 3.4.1")),
    "/js/vue-2.6.10.min.js": ("application/javascript", _stub("vue 2.6.10")),
    "/js/bootstrap-5.3.3.min.js": ("application/javascript", _stub("bootstrap 5.3.3")),
    "/js/react-18.2.0.min.js": ("application/javascript", _stub("react 18.2.0")),
    "/js/angular-1.8.3.min.js": ("application/javascript", _stub("angularjs 1.8.3")),
    "/js/lodash.custom.js": ("application/javascript", _stub("lodash")),
    "/js/moment.min.js": ("application/javascript", _stub("moment")),
    "/js/d3.min.js": ("application/javascript", _stub("d3")),
    "/js/backbone.js": ("application/javascript", _stub("backbone")),
    "/js/underscore.js": ("application/javascript", _stub("underscore")),

    # Path C: retire.js filecontent banners (see RETIRE_BANNERS).
    "/assets/tpl-engine.js": ("application/javascript", RETIRE_BANNERS["tpl-engine"]),
    "/assets/util-belt.js": ("application/javascript", RETIRE_BANNERS["util-belt"]),
    "/assets/bind-lib.js": ("application/javascript", RETIRE_BANNERS["bind-lib"]),
    "/assets/fresh-lib.js": ("application/javascript", RETIRE_BANNERS["fresh-lib"]),

    # FEATURE A2: URLs mined out of JS content by js_recon -> external_domains
    # -> sca_intel_correlate matches them against the fixture catalog.
    "/assets/vendor-telemetry.js": ("application/javascript", VENDOR_TELEMETRY_JS),

    # Source-map discovery variants.
    "/assets/hdrmap.js": ("application/javascript",
                          "/* hdrmap - map advertised via the SourceMap header */\nvar a=1;\n"),
    "/assets/hdrmap.js.map": ("application/json", json.dumps(_variant_map("hdrmap"))),
    "/assets/probemap.js": ("application/javascript",
                            "/* probemap - NO hint; js_recon must probe {url}.map */\nvar a=1;\n"),
    "/assets/probemap.js.map": ("application/json", json.dumps(_variant_map("probemap"))),
    "/assets/inlinemap.js": ("application/javascript",
                             "/* inlinemap */\nvar a=1;\n//# sourceMappingURL=" + _inline_data_uri() + "\n"),
    "/assets/multiline.js": ("application/javascript",
                             "/* multiline */\nvar a=1;\n/*# sourceMappingURL=multiline.js.map */\n"),
    "/assets/multiline.js.map": ("application/json", json.dumps(_variant_map("multiline"))),
    "/assets/badmap.js": ("application/javascript",
                          "/* badmap */\nvar a=1;\n//# sourceMappingURL=badmap.js.map\n"),
    "/assets/badmap.js.map": ("application/json", _BAD_MAP),

    # Path B bundles + maps.
    "/assets/app.7f3c2a.js": (
        "application/javascript", _bundle("app.7f3c2a.js", "app.7f3c2a.js.map")),
    "/assets/app.7f3c2a.js.map": (
        "application/json",
        json.dumps(_sourcemap(APP_SOURCES, "app.7f3c2a.js"))),
    "/assets/deep-vendor.js": (
        "application/javascript", _bundle("deep-vendor.js", "deep-vendor.js.map")),
    "/assets/deep-vendor.js.map": (
        "application/json",
        json.dumps(_sourcemap(DEEP_SOURCES, "deep-vendor.js"))),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def _send(self, body=b"", ctype="text/plain", status=200, head_only=False,
              extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Alias table entry reached through a HEADER rather than a script path.
        # Port 80 advertises Express (versionless); port 8080 advertises
        # Next.js WITH a version, so the header route is proven both ways.
        self.send_header("X-Powered-By", POWERED_BY)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _route(self, head_only=False):
        path = self.path.split("?", 1)[0]
        hit = ROUTES.get(path)
        if hit is None:
            self._send(b"not found", "text/plain", 404, head_only)
            return
        ctype, text = hit
        extra = None
        # Discovery variant: advertise the map via the SourceMap response
        # header instead of a //# comment (sourcemap.py::check_sourcemap_header).
        if path == "/assets/hdrmap.js":
            extra = {"SourceMap": "/assets/hdrmap.js.map"}
        self._send(text.encode("utf-8"), ctype, 200, head_only, extra)

    def do_GET(self):
        self._route(head_only=False)

    # js_recon's source-map fetcher issues HEAD before GET and treats 404/410
    # as a definite miss, so HEAD must answer correctly.
    def do_HEAD(self):
        self._route(head_only=True)

    def log_message(self, fmt, *args):
        print("[sc-target] %s - %s" % (self.address_string(), fmt % args), flush=True)


class AltHandler(Handler):
    """Port 8080 surface. Same routes, different X-Powered-By.

    It must live on the SAME IP as port 80: with no port-scan results httpx
    derives its targets from the host and probes 80/443 plus
    8080/8000/8888/3000/5000/9000, all against that one address. A second
    container on a different IP would simply never be probed.
    """

    def _send(self, body=b"", ctype="text/plain", status=200, head_only=False,
              extra_headers=None):
        extra = dict(extra_headers or {})
        # Overrides POWERED_BY for this port only.
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", ALT_POWERED_BY)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def main():
    import threading

    alt = ThreadingHTTPServer(("0.0.0.0", ALT_PORT), AltHandler)
    threading.Thread(target=alt.serve_forever, daemon=True).start()
    print("[sc-target] alt surface on 0.0.0.0:%d (X-Powered-By: %s) -> "
          "second BaseURL node" % (ALT_PORT, ALT_POWERED_BY), flush=True)

    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("[sc-target] listening on 0.0.0.0:%d (X-Powered-By: %s)"
          % (PORT, POWERED_BY), flush=True)
    print("[sc-target] %d routes, app map=%d sources, deep map=%d sources"
          % (len(ROUTES), len(APP_SOURCES), len(DEEP_SOURCES)), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
