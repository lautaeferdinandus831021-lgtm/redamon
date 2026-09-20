"""
Helpers shared by the capture-proxy addon and the ingest worker: header
normalization, cheap passive detections, body inline/offload decisions,
spool-record shaping, and mount-point preflight.

Kept free of any mitmproxy import so it is unit-testable on its own; the addon
adapts a live flow into these plain inputs.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

AUTH_REQUEST_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")


def ensure_dir_writable(path: str) -> str:
    """makedirs(path), but turn an EACCES into an actionable, self-describing error.

    The spool volume is shared with a ROOT writer: the orchestrator materialises
    /spool/.capture-config.json into it. Docker copies an image's ownership onto a
    named volume only while that volume is still EMPTY, so once the root-owned
    writer has touched it first, the mount point stays root:root 0755 and this
    process (uid 10001, read-only rootfs) cannot mkdir inside it.

    Both capture containers run with restart=unless-stopped, so a bare EACCES
    traceback here is indistinguishable from a crash loop. Name the volume, the
    uid, the actual mode, and the one-line repair instead.
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        if e.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
            raise
        parent = os.path.dirname(path.rstrip("/")) or "/"
        try:
            st = os.stat(parent)
            owner = f"uid={st.st_uid} gid={st.st_gid} mode={oct(st.st_mode & 0o777)}"
        except OSError:
            owner = "not statable"
        raise RuntimeError(
            f"cannot create {path}: the mounted volume at {parent} is not writable by "
            f"this process (running as uid={os.getuid()}; {parent} is {owner}). A "
            f"root-owned writer most likely initialised the named volume before this "
            f"container first mounted it, so Docker never applied the image's "
            f"ownership. Repair without data loss:\n"
            f"  docker run --rm -v whitehat_capture_spool:/spool alpine chmod 0777 /spool"
        ) from e
    return path


def normalize_headers(items) -> Dict[str, Any]:
    """Lowercase header names; collapse duplicates (e.g. Set-Cookie) to a list.

    `items` is an iterable of (name, value) pairs — mitmproxy's Headers yields
    exactly that, preserving duplicates, which is why we take pairs rather than
    a dict.
    """
    out: Dict[str, Any] = {}
    for name, value in items:
        key = str(name).strip().lower()
        if not key:
            continue
        if key in out:
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        else:
            out[key] = value
    return out


def cookie_flag_issues(set_cookie) -> List[Dict[str, Any]]:
    issues = []
    values = set_cookie if isinstance(set_cookie, list) else [set_cookie]
    for cookie in values:
        if not cookie:
            continue
        low = str(cookie).lower()
        missing = [flag for flag, tok in
                   (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
                   if tok not in low]
        if missing:
            name = str(cookie).split("=", 1)[0].strip()[:64]
            issues.append({"cookie": name, "missing": missing})
    return issues


def reflected_params(query: str, req_body: Optional[str], resp_body: Optional[str]) -> bool:
    """Cheap reflected-input signal: any non-trivial query/body param value that
    appears verbatim in the response body (an XSS/SSTI/open-redirect lead)."""
    if not resp_body:
        return False
    haystack = resp_body
    from urllib.parse import parse_qsl
    candidates = []
    if query:
        candidates += [v for _, v in parse_qsl(query.lstrip("?"))]
    if req_body:
        try:
            candidates += [v for _, v in parse_qsl(req_body)]
        except (ValueError, TypeError):
            pass
    for v in candidates:
        if v and len(v) >= 4 and v in haystack:
            return True
    return False


def passive_signals(req_headers: Dict[str, Any], resp_headers: Dict[str, Any],
                    query: str, req_body: Optional[str], resp_body: Optional[str]) -> Dict[str, Any]:
    set_cookie = resp_headers.get("set-cookie")
    return {
        "hasSetCookie": bool(set_cookie),
        "hadAuth": any(h in req_headers for h in AUTH_REQUEST_HEADERS),
        "reflectedParams": reflected_params(query, req_body, resp_body),
        "securityHeadersMissing": [h for h in SECURITY_HEADERS if h not in resp_headers],
        "cookieFlagIssues": cookie_flag_issues(set_cookie) if set_cookie else [],
    }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Body-storage policy ─────────────────────────────────────────────────────
# Each captured body is routed to exactly ONE destination:
#   inline -> stored in the Postgres column   (agent + human readable, fast)
#   disk   -> full bytes offloaded to /bodies  (human/UI readable only)
#   meta   -> bytes dropped, only size + sha256 kept
# The operator maps each content-type FAMILY to a POLICY in {auto,inline,disk,meta}.
# `auto` reproduces size-based routing: small text -> DB, everything else -> disk.

VALID_POLICIES = frozenset({"auto", "inline", "disk", "meta"})

# Families whose `auto` policy is size-based-text (small -> inline). Everything
# else under `auto` always offloads: binary is never inlined into the DB column.
_TEXT_FAMILIES = frozenset({"text", "json", "script", "other"})

# Recommended default policy map (shipped default): keep useful text/data, drop
# render-noise media, keep leak-worthy downloads to disk. Operator JSON merges
# OVER this. Every classifiable family MUST appear here so it is a valid key.
DEFAULT_BODY_RULES: Dict[str, str] = {
    "text": "auto",       # html / css / xml / csv / plain
    "json": "auto",       # json / form-urlencoded / graphql  (the juicy API data)
    "script": "auto",     # javascript / ecmascript
    "image": "meta",      # render noise
    "font": "meta",       # render noise
    "video": "meta",      # render noise
    "audio": "meta",      # render noise
    "document": "disk",   # pdf / office / rtf  (leak evidence; agent can't read, human can)
    "archive": "disk",    # zip / gz / tar / 7z  (source / backup disclosure)
    "binary": "disk",     # octet-stream / wasm / serialized  (deserialization, downloads)
    "other": "auto",      # unknown -> treat as small text
}

# Content-type substring -> family (checked in order; first hit wins). "binary"
# is last among application/* so real files (font/image/... mislabeled as
# octet-stream) get a chance to be reclassified by extension below.
_CT_FAMILY = (
    ("font", ("font/", "application/font", "application/vnd.ms-fontobject", "x-font")),
    ("image", ("image/",)),
    ("video", ("video/",)),
    ("audio", ("audio/",)),
    ("document", ("application/pdf", "application/msword", "officedocument",
                  "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
                  "application/rtf", "text/rtf", "application/vnd.oasis")),
    ("archive", ("application/zip", "application/gzip", "application/x-gzip",
                 "application/x-tar", "application/x-7z", "application/x-rar",
                 "application/x-bzip", "application/x-xz", "application/x-compress")),
    ("script", ("javascript", "ecmascript")),
    ("json", ("json", "x-www-form-urlencoded", "graphql")),
    ("text", ("text/", "xml", "html", "csv")),
    ("binary", ("application/octet-stream", "application/wasm",
                "application/x-protobuf", "java-serialized", "x-msgpack",
                "application/x-binary")),
)

# Filename-extension -> family fallback, for servers that mislabel content
# (e.g. a .woff2 served as application/octet-stream, seen in the wild).
_EXT_FAMILY: Dict[str, str] = {
    "woff": "font", "woff2": "font", "ttf": "font", "otf": "font", "eot": "font",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "webp": "image",
    "bmp": "image", "ico": "image", "avif": "image", "svg": "image", "tif": "image", "tiff": "image",
    "mp4": "video", "webm": "video", "mov": "video", "avi": "video", "mkv": "video", "m4v": "video",
    "mp3": "audio", "wav": "audio", "ogg": "audio", "flac": "audio", "m4a": "audio", "aac": "audio",
    "pdf": "document", "doc": "document", "docx": "document", "xls": "document", "xlsx": "document",
    "ppt": "document", "pptx": "document", "rtf": "document", "odt": "document", "ods": "document",
    "zip": "archive", "gz": "archive", "tgz": "archive", "tar": "archive", "7z": "archive",
    "rar": "archive", "bz2": "archive", "xz": "archive",
    "js": "script", "mjs": "script", "json": "json",
    "html": "text", "htm": "text", "css": "text", "txt": "text", "xml": "text", "csv": "text",
    "wasm": "binary", "bin": "binary", "exe": "binary", "dll": "binary", "so": "binary", "dat": "binary",
}


def _ext_family(path) -> Optional[str]:
    """Family from a URL path's filename extension, or None."""
    p = str(path or "").split("?", 1)[0].split("#", 1)[0]
    dot = p.rfind(".")
    if dot == -1 or dot < p.rfind("/"):
        return None
    return _EXT_FAMILY.get(p[dot + 1:].lower())


def classify_family(content_type, path=None) -> str:
    """Classify a body into a storage family from its Content-Type, falling back
    to the URL's filename extension (which rescues octet-stream-mislabeled files)."""
    ct = str(content_type or "").lower().split(";", 1)[0].strip()
    for family, markers in _CT_FAMILY:
        if any(m in ct for m in markers):
            if family == "binary":
                # octet-stream & friends are a catch-all; trust the extension if
                # it names a concrete kind (the woff2-as-octet-stream case).
                ext_fam = _ext_family(path)
                if ext_fam:
                    return ext_fam
            return family
    # No content-type signal: fall back to the extension, else "other".
    return _ext_family(path) or "other"


def parse_body_rules(raw) -> Dict[str, str]:
    """Merge an operator override (JSON string or dict of family->policy) OVER the
    Recommended defaults. Unknown families / invalid policies are ignored so a bad
    value can never produce an invalid rule (fail safe)."""
    rules = dict(DEFAULT_BODY_RULES)
    if not raw:
        return rules
    try:
        override = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (ValueError, TypeError):
        return rules
    if not isinstance(override, dict):
        return rules
    for fam, pol in override.items():
        fam, pol = str(fam).lower(), str(pol).lower()
        if fam in DEFAULT_BODY_RULES and pol in VALID_POLICIES:
            rules[fam] = pol
    return rules


def decide_body(raw: Optional[bytes], *, family: str, rules: Dict[str, str],
                inline_cap_bytes: int, max_store_bytes: int,
                store: bool) -> Tuple[Optional[str], Optional[str], int, Optional[str]]:
    """
    Route one body to inline (DB) / offload (disk) / metadata-only.

    Returns (inline_text, body_ref_sha, size, sha):
      - store off or empty body            -> metadata only
      - family policy 'meta'               -> metadata only
      - size > max_store_bytes (if capped) -> metadata only (hard ceiling)
      - policy 'disk'                      -> offload
      - policy 'inline'                    -> DB if <= inline cap, else offload
      - policy 'auto'                      -> DB if text-family and <= cap, else offload
    `max_store_bytes <= 0` means no ceiling. Offloaded bodies dedup by sha.
    """
    if raw is None:
        return (None, None, 0, None)
    size = len(raw)
    sha = sha256_hex(raw) if size else None
    if not store or size == 0:
        return (None, None, size, sha)
    policy = rules.get(family, "auto")
    if policy == "meta":
        return (None, None, size, sha)
    if max_store_bytes > 0 and size > max_store_bytes:
        return (None, None, size, sha)
    if policy == "disk":
        return (None, sha, size, sha)
    if policy == "inline":
        if size <= inline_cap_bytes:
            return (raw.decode("utf-8", errors="replace"), None, size, sha)
        return (None, sha, size, sha)
    # auto
    if family in _TEXT_FAMILIES and size <= inline_cap_bytes:
        return (raw.decode("utf-8", errors="replace"), None, size, sha)
    return (None, sha, size, sha)


def build_record(*, ctx_token: Optional[str], method: str, scheme: str, host: str,
                 port: int, path: str, query: str, req_headers: Dict[str, Any],
                 resp_headers: Dict[str, Any], status_code: Optional[int],
                 req_body_inline: Optional[str], req_body_ref: Optional[str], req_body_size: int,
                 req_body_sha: Optional[str], resp_body_inline: Optional[str],
                 resp_body_ref: Optional[str], resp_body_size: int, resp_body_sha: Optional[str],
                 http_version: Optional[str], is_tls: bool, tls_version: Optional[str],
                 target_ip: Optional[str], response_time_ms: Optional[int],
                 started_at: str, blocked: bool = False, in_scope: bool = True,
                 error_text: Optional[str] = None) -> Dict[str, Any]:
    """Assemble the opaque spool record. `ctx_token` is carried VERBATIM — the
    proxy never decodes or verifies it (it holds no key); traffic-ingest does."""
    sig = passive_signals(req_headers, resp_headers, query, req_body_inline, resp_body_inline)
    return {
        "ctx_token": ctx_token,
        "method": method, "scheme": scheme, "host": host, "port": port,
        "path": path, "query": query or None,
        "reqHeaders": req_headers, "respHeaders": resp_headers,
        "statusCode": status_code,
        "reqBody": req_body_inline, "reqBodyRef": req_body_ref,
        "reqBodySize": req_body_size, "reqBodySha": req_body_sha,
        "reqContentType": req_headers.get("content-type"),
        "respBody": resp_body_inline, "respBodyRef": resp_body_ref,
        "respBodySize": resp_body_size, "respBodySha": resp_body_sha,
        "respContentType": resp_headers.get("content-type"),
        "httpVersion": http_version, "isTls": is_tls, "tlsVersion": tls_version,
        "targetIp": target_ip, "responseTimeMs": response_time_ms,
        "blocked": blocked, "inScope": in_scope, "errorText": error_text,
        "startedAt": started_at,
        **sig,
    }
