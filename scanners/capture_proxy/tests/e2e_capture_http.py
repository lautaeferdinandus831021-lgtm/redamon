#!/usr/bin/env python3
"""
REAL end-to-end capture-proxy test: launches an actual `mitmdump -s
capture_addon.py`, sends live HTTP through it, and asserts the resulting spool
record's inline / offload / metadata-only decision. Validates the WHOLE chain:
    CAPTURE_* env -> WhiteHatCapture.__init__ -> request/response hooks ->
    classify_family -> decide_body -> _offload -> spool JSON + /bodies blob.

Structure:
  PART A  Differential per-parameter tests: for EACH knob, run a baseline vs a
          changed config against the SAME request and assert the specific A->B
          delta the parameter is supposed to cause.
  PART B  Full content-type family coverage: one request per family, asserting
          each family's Recommended-default destination over the wire.

Runs INSIDE the whitehat-capture-proxy image (needs mitmproxy). See
run_e2e_capture_http.sh. Standalone: exits 0 (all pass) / 1 (any fail).

The target is 127.0.0.1, so each proxy relaxes the loopback + private egress
checks (Python treats 127.0.0.1 as .is_private); every other guard stays on.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # capture_proxy/
ADDON = str(ROOT / "capture_addon.py")

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
WOFF2_MAGIC = b"wOF2"
# path -> (content_type, body_bytes)
TARGET_ROUTES = {
    "/small-html": ("text/html; charset=utf-8", b"<html>hi small</html>"),
    "/big-html":   ("text/html; charset=utf-8", b"<html>" + b"A" * 100_000 + b"</html>"),
    "/data.json":  ("application/json", b'{"user":"admin","token":"secret-value-1234"}'),
    "/app.js":     ("application/javascript", b"console.log('hello world script')"),
    "/image.png":  ("image/png", PNG_MAGIC + b"\x00\x01\x02" * 40),
    # .woff2 MISLABELED as octet-stream (real-world case): must reclassify by ext.
    "/font.woff2": ("application/octet-stream", WOFF2_MAGIC + b"\x00\x01" * 80),
    "/clip.mp4":   ("video/mp4", b"\x00\x00\x00\x18ftypmp42" + b"\x11" * 60),
    "/tone.mp3":   ("audio/mpeg", b"ID3" + b"\x22" * 60),
    "/report.pdf": ("application/pdf", b"%PDF-1.4\n" + b"P" * 60),
    "/bundle.zip": ("application/zip", b"PK\x03\x04" + b"Z" * 60),
    "/blob.bin":   ("application/octet-stream", b"\x07" * (2 * 1024 * 1024)),  # 2 MB, no ext
    "/echo":       ("text/plain", b"ok echoed"),
}


class TargetHandler(BaseHTTPRequestHandler):
    def _serve(self):
        route = self.path.split("?", 1)[0]
        ct, body = TARGET_ROUTES.get(route, ("text/plain", b"not found"))
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_POST = _serve

    def log_message(self, *a):
        pass


def start_target() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class Proxy:
    """A mitmdump subprocess with a fresh spool/bodies dir and given CAPTURE_* env."""

    def __init__(self, env_overrides: dict):
        self.dir = tempfile.mkdtemp(prefix="e2e-cap-")
        self.spool = os.path.join(self.dir, "spool")
        self.bodies = os.path.join(self.dir, "bodies")
        os.makedirs(self.spool, exist_ok=True)
        os.makedirs(self.bodies, exist_ok=True)
        self.port = _free_port()
        self.env = {
            **os.environ,
            "CAPTURE_SPOOL_DIR": self.spool,
            "CAPTURE_BODIES_DIR": self.bodies,
            "CAPTURE_EGRESS_BLOCK_LOOPBACK": "false",
            "CAPTURE_EGRESS_BLOCK_PRIVATE": "false",
            **env_overrides,
        }
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["mitmdump", "--quiet", "--set", "connection_strategy=lazy",
             "--set", "stream_large_bodies=5m",
             "--listen-host", "127.0.0.1", "--listen-port", str(self.port), "-s", ADDON],
            env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT),
        )
        if not _wait_port(self.port):
            raise RuntimeError("proxy did not come up")
        time.sleep(0.5)
        return self

    def __exit__(self, *a):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def request(self, target_port: int, path: str, data: bytes | None = None,
                content_type: str | None = None):
        url = f"http://127.0.0.1:{target_port}{path}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.port}"}))
        headers = {"Content-Type": content_type} if content_type else {}
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data else "GET")
        with opener.open(req, timeout=10) as r:
            r.read()

    def records(self, expect: int = 1, timeout: float = 8.0) -> dict:
        """Poll the spool until `expect` records are present (or timeout); {path: rec}."""
        end = time.time() + timeout
        out = {}
        while time.time() < end:
            for name in os.listdir(self.spool):
                if not name.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(self.spool, name)) as f:
                        rec = json.load(f)
                except (OSError, ValueError):
                    continue
                out[rec.get("path")] = rec
            if len(out) >= expect:
                break
            time.sleep(0.2)
        return out

    def one(self, target_port: int, path: str, **kw) -> dict:
        """Send one request, return its spool record (or {})."""
        self.request(target_port, path, **kw)
        return self.records(expect=1).get(path, {})

    def blob_exists(self, sha) -> bool:
        return bool(sha) and os.path.exists(os.path.join(self.bodies, sha))


# ── Assertions. Spool keys: {pfx}Body / {pfx}BodyRef / {pfx}BodySize / {pfx}BodySha
FAILS: list[str] = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILS.append(f"{name} :: {detail}")


def dest(proxy, rec, pfx="resp") -> str:
    """Classify a record's actual storage destination: inline | disk | meta | none."""
    body, ref = rec.get(f"{pfx}Body"), rec.get(f"{pfx}BodyRef")
    sha, size = rec.get(f"{pfx}BodySha"), rec.get(f"{pfx}BodySize")
    if body is not None and ref is None:
        return "inline"
    if body is None and ref is not None and rec.get(f"{pfx}BodySha") == ref and proxy.blob_exists(ref):
        return "disk"
    if body is None and ref is None and size and size > 0 and sha is not None:
        return "meta"
    return "none"


def expect_dest(proxy, rec, want, pfx="resp", label=""):
    got = dest(proxy, rec, pfx)
    check(f"{label}: {pfx} -> {want}", got == want, f"got {got} rec={{'{pfx}Body': {rec.get(f'{pfx}Body') is not None}, 'ref': {rec.get(f'{pfx}BodyRef')}, 'size': {rec.get(f'{pfx}BodySize')}}}")


def main() -> int:
    tport = start_target()
    print(f"target http server on 127.0.0.1:{tport}")

    print("\n=== PART A: differential per-parameter (baseline -> changed) ===")

    # P1 CAPTURE_PROXY_MAX_BODY_KB: text routing threshold (disk <-> DB).
    print("\nP1 CAPTURE_PROXY_MAX_BODY_KB (big text: disk -> inline)")
    with Proxy({"CAPTURE_PROXY_MAX_BODY_KB": "64"}) as p:
        expect_dest(p, p.one(tport, "/big-html"), "disk", label="cap=64 (100KB text)")
    with Proxy({"CAPTURE_PROXY_MAX_BODY_KB": "200"}) as p:
        expect_dest(p, p.one(tport, "/big-html"), "inline", label="cap=200 (100KB text)")

    # P2 CAPTURE_PROXY_STORE_BODIES: master switch (inline -> meta).
    print("\nP2 CAPTURE_PROXY_STORE_BODIES (small text: inline -> meta)")
    with Proxy({"CAPTURE_PROXY_STORE_BODIES": "true"}) as p:
        expect_dest(p, p.one(tport, "/small-html"), "inline", label="store=true")
    with Proxy({"CAPTURE_PROXY_STORE_BODIES": "false"}) as p:
        expect_dest(p, p.one(tport, "/small-html"), "meta", label="store=false")

    # P3 CAPTURE_STORE_REQ_BODIES: request direction gate (req inline -> meta, resp intact).
    print("\nP3 CAPTURE_STORE_REQ_BODIES (request body: inline -> meta; response intact)")
    for val, want in (("true", "inline"), ("false", "meta")):
        with Proxy({"CAPTURE_STORE_REQ_BODIES": val}) as p:
            rec = p.one(tport, "/echo", data=b"user=admin&pw=hunter2xx", content_type="application/x-www-form-urlencoded")
            expect_dest(p, rec, want, pfx="req", label=f"store_req={val}")
            expect_dest(p, rec, "inline", pfx="resp", label=f"store_req={val} (resp unaffected)")

    # P4 CAPTURE_STORE_RESP_BODIES: response direction gate (resp inline -> meta, req intact).
    print("\nP4 CAPTURE_STORE_RESP_BODIES (response body: inline -> meta; request intact)")
    for val, want in (("true", "inline"), ("false", "meta")):
        with Proxy({"CAPTURE_STORE_RESP_BODIES": val}) as p:
            rec = p.one(tport, "/echo", data=b"user=admin&pw=hunter2xx", content_type="application/x-www-form-urlencoded")
            expect_dest(p, rec, want, pfx="resp", label=f"store_resp={val}")
            expect_dest(p, rec, "inline", pfx="req", label=f"store_resp={val} (req unaffected)")

    # P5 CAPTURE_MAX_STORE_MB: hard ceiling (disk -> meta) for an oversized body.
    print("\nP5 CAPTURE_MAX_STORE_MB (2MB binary:disk -> meta over ceiling)")
    base = {"CAPTURE_BODY_RULES": json.dumps({"binary": "disk"})}
    with Proxy({**base, "CAPTURE_MAX_STORE_MB": "5"}) as p:
        expect_dest(p, p.one(tport, "/blob.bin"), "disk", label="ceiling=5MB (2MB blob)")
    with Proxy({**base, "CAPTURE_MAX_STORE_MB": "1"}) as p:
        expect_dest(p, p.one(tport, "/blob.bin"), "meta", label="ceiling=1MB (2MB blob)")

    # P6 CAPTURE_BODY_RULES: per-family policy override (image across all 4 policies).
    print("\nP6 CAPTURE_BODY_RULES image policy (meta / disk / auto / inline)")
    for pol, want in (("meta", "meta"), ("disk", "disk"), ("auto", "disk"), ("inline", "inline")):
        with Proxy({"CAPTURE_BODY_RULES": json.dumps({"image": pol})}) as p:
            expect_dest(p, p.one(tport, "/image.png"), want, label=f"image rule={pol}")

    print("\n=== PART B: full content-type family classification (Recommended defaults) ===")
    # One proxy, Recommended defaults, one request per family; assert each destination.
    FAMILY_EXPECT = [
        ("/small-html", "inline", "text -> inline"),
        ("/data.json", "inline", "json -> inline"),
        ("/app.js", "inline", "script -> inline"),
        ("/image.png", "meta", "image -> meta"),
        ("/font.woff2", "meta", "font(octet+ext) -> meta"),
        ("/clip.mp4", "meta", "video -> meta"),
        ("/tone.mp3", "meta", "audio -> meta"),
        ("/report.pdf", "disk", "document -> disk"),
        ("/bundle.zip", "disk", "archive -> disk"),
        ("/blob.bin", "disk", "binary -> disk"),
    ]
    with Proxy({}) as p:
        for path, _, _ in FAMILY_EXPECT:
            p.request(tport, path)
        recs = p.records(expect=len(FAMILY_EXPECT), timeout=12)
        for path, want, label in FAMILY_EXPECT:
            expect_dest(p, recs.get(path, {}), want, label=label)

    print("\n=== PART C: robustness (garbage numeric env must not crash the proxy) ===")
    # A malformed CAPTURE_MAX_STORE_MB / MAX_BODY_KB is parsed in __init__, OUTSIDE
    # the response-hook guard; it must fall back to defaults, not crash-load the
    # addon and silently kill capture.
    with Proxy({"CAPTURE_MAX_STORE_MB": "not-a-number", "CAPTURE_PROXY_MAX_BODY_KB": "bogus"}) as p:
        rec = p.one(tport, "/small-html")
        # Default cap (64KB) still applies -> small text inlines normally.
        expect_dest(p, rec, "inline", label="garbage numeric env falls back to defaults")

    print("\n" + ("=" * 62))
    if FAILS:
        print(f"E2E FAILED: {len(FAILS)} check(s) failed")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("E2E PASSED: every parameter's specific effect verified over real HTTP")
    return 0


if __name__ == "__main__":
    sys.exit(main())
