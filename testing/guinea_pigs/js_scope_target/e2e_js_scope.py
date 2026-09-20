"""Drive a real full recon against the JS scope lab through the webapp API.

Creates an IP-mode project on 192.88.97.10, uploads uploads/scope-lab-upload.js,
starts the full pipeline and waits for it to finish. Prints the project id for
verify_js_scope.py. Signs in the way testing/e2e/tests/auth.ts does: an HS256
session cookie minted from AUTH_SECRET in the repo .env, so no password is held.

    docker run --rm --network host -v "$PWD:/repo:ro" -w /repo --entrypoint python \\
        whitehat-agent:latest testing/guinea_pigs/js_scope_target/e2e_js_scope.py \\
        --user-id <admin user id>
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# Everything a fast, JS-focused run does not need. jsluice and hakrawler are off
# because they extract endpoints from JS too, and would blur which tool wrote
# what. The capture proxy is off because its egress path is not assumed to
# reach the lab bridge; the OSINT sources are off because they would query
# third-party services about the lab address.
PROJECT_SETTINGS = {
    "ipMode": True,
    "targetIps": ["192.88.97.10"],
    "scanModules": ["port_scan", "http_probe", "resource_enum"],
    "naabuCustomPorts": "80",
    "naabuTopPorts": "",
    "jsReconEnabled": True,
    "jsReconIncludeArchivedJs": False,
    "katanaEnabled": True,
    "katanaDepth": 2,
    "hakrawlerEnabled": False,
    "jsluiceEnabled": False,
    "arjunEnabled": False,
    "captureProxyEnabled": False,
    "masscanEnabled": False,
    "nmapEnabled": False,
    "nucleiEnabled": False,
    "subjackEnabled": False,
    "nucleiTakeoversEnabled": False,
    "takeoverCertValidationEnabled": False,
    "tlsxEnabled": False,
    "bannerGrabEnabled": False,
    "aiSurfaceReconEnabled": False,
    "securityCheckEnabled": False,
    "cveLookupEnabled": False,
    "mitreEnabled": False,
    "whoisEnabled": False,
    "shodanEnabled": False,
    "urlscanEnabled": False,
    "otxEnabled": False,
    "subdomainDiscoveryEnabled": False,
    "scaIntelCorrelationEnabled": False,
    "portScanAiPortCatalogEnabled": False,
    "masscanAiPortCatalogEnabled": False,
    "nmapAiVersionRegexEnabled": False,
    "httpProbeAiHeaderScanEnabled": False,
    "httpProbeAiFaviconHashEnabled": False,
    "httpProbeAiTitleDetectionEnabled": False,
    "httpProbeAiWappalyzerEnabled": False,
    "resourceEnumAiClassifierEnabled": False,
    "resourceEnumAiPathClassifierEnabled": False,
    "resourceEnumAiRagPathFlagEnabled": False,
    "resourceEnumAiParamInjectableFlagEnabled": False,
    "resourceEnumAiToolArgPathEnabled": False,
    "domainReconAiTxtHintEnabled": False,
    "domainReconAiNsHintEnabled": False,
}


def _env_value(key: str) -> str:
    with open(os.path.join(REPO, ".env")) as f:
        for line in f:
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip("'\"")
    raise SystemExit(f"{key} not found in .env")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint_cookie(user_id: str, ttl: int = 3 * 3600) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": user_id, "role": "admin",
                                  "iat": now, "exp": now + ttl}).encode())
    data = f"{header}.{payload}"
    sig = hmac.new(_env_value("AUTH_SECRET").encode(), data.encode(), hashlib.sha256).digest()
    return f"{data}.{_b64url(sig)}"


def run_partial(s: requests.Session, webapp: str, project_id: str, timeout: int) -> int:
    """Phase 2: a partial JS recon on a user URL the full run never saw."""
    # Same two calls as PartialReconModal: it reads the domain from graph-inputs.
    inputs = s.get(f"{webapp}/api/recon/{project_id}/graph-inputs/JsRecon", timeout=30)
    domain = (inputs.json() if inputs.ok else {}).get("domain") or ""
    r = s.post(f"{webapp}/api/recon/{project_id}/partial", json={
        "tool_id": "JsRecon",
        "graph_inputs": {"domain": domain},
        "include_graph_targets": True,
        "user_targets": {"urls": ["http://192.88.97.10:8080/static/partial.js"],
                         "url_attach_to": None},
    }, timeout=120)
    if r.status_code >= 400:
        print(f"[!] partial start refused: {r.status_code} {r.text[:500]}", flush=True)
        return 1
    run_id = r.json().get("run_id", "")
    print(f"[+] partial JsRecon started (run {run_id})", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = s.get(f"{webapp}/api/recon/{project_id}/partial/{run_id}/status", timeout=30).json()
        if state.get("status") in ("completed", "error"):
            print(f"[{'+' if state['status'] == 'completed' else '!'}] partial {state['status']}"
                  f"{': ' + str(state.get('error')) if state.get('error') else ''}", flush=True)
            return 0 if state["status"] == "completed" else 1
        time.sleep(5)
    print(f"[!] partial timed out after {timeout}s")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--webapp", default="http://localhost:3000")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--partial", metavar="PROJECT_ID",
                    help="run phase 2 (partial JsRecon) on an existing lab project")
    args = ap.parse_args()

    s = requests.Session()
    # A header, not the cookie jar: the jar silently withholds a cookie set for
    # a bare 'localhost' domain, and every call then answers 401.
    s.headers["Cookie"] = f"whitehat-auth={mint_cookie(args.user_id)}"

    if args.partial:
        return run_partial(s, args.webapp, args.partial, args.timeout)

    name = f"JS scope lab {time.strftime('%Y-%m-%d %H:%M:%S')}"
    r = s.post(f"{args.webapp}/api/projects", json={"name": name, **PROJECT_SETTINGS}, timeout=60)
    r.raise_for_status()
    project_id = r.json()["id"]
    print(f"[+] project {project_id} ({name})", flush=True)

    with open(os.path.join(HERE, "uploads", "scope-lab-upload.js"), "rb") as f:
        r = s.post(f"{args.webapp}/api/js-recon/{project_id}/upload",
                   files={"file": ("scope-lab-upload.js", f, "application/javascript")}, timeout=60)
    r.raise_for_status()
    print("[+] uploaded scope-lab-upload.js", flush=True)

    r = s.post(f"{args.webapp}/api/recon/{project_id}/start", json={"mode": "new"}, timeout=120)
    if r.status_code >= 400:
        print(f"[!] start refused: {r.status_code} {r.text[:500]}", flush=True)
        return 1
    print(f"[+] recon started ({r.status_code})", flush=True)

    deadline = time.time() + args.timeout
    last = None
    while time.time() < deadline:
        state = s.get(f"{args.webapp}/api/recon/{project_id}/status", timeout=30).json()
        view = (state.get("status"), state.get("current_phase"))
        if view != last:
            print(f"    {time.strftime('%H:%M:%S')} {view[0]}  {view[1] or ''}", flush=True)
            last = view
        if state.get("status") in ("completed", "error"):
            print(f"[{'+' if state['status'] == 'completed' else '!'}] recon {state['status']}"
                  f"{': ' + str(state.get('error')) if state.get('error') else ''}", flush=True)
            print(f"PROJECT_ID={project_id}")
            return 0 if state["status"] == "completed" else 1
        time.sleep(10)
    print(f"[!] timed out after {args.timeout}s; PROJECT_ID={project_id}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
