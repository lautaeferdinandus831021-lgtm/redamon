"""Per-class minimum proof, common auto-close patterns, and overclaim traps.

Ported from claude-kit's `gotchas` skill. The point is the same one: a class
claim is checked against what the PoC actually shows BEFORE it ships, because
the cheap failure modes (a WAF block called "SQLi confirmed", a redirect called
"account takeover", a self-XSS) are the ones that get a report closed.

Consumed twice: injected for the class the session is working on (see
`build_gotchas_block`), and surfaced through the `report_review` tool's
`gotchas` mode when the agent wants to check a specific class.
"""
from __future__ import annotations

import re

# Canonical class names. Anything an agent or a project setting writes is
# normalized onto one of these (see resolve_class).
CLASSES: tuple[str, ...] = (
    "XSS",
    "SQLi",
    "SSRF",
    "IDOR / BOLA",
    "CSRF",
    "RCE",
    "SSTI",
    "XXE",
    "Open Redirect",
    "Auth Bypass",
    "Information Disclosure",
    "Race Condition",
    "CORS Misconfiguration",
    "Path Traversal / LFI",
)

GOTCHAS: dict[str, dict[str, tuple[str, ...]]] = {
    "XSS": {
        "minimum_proof": (
            "JS execution on the TARGET origin (`alert(document.domain)` proves it)",
            "Injection context stated: HTML body / attribute / JS / CSS / URL / JSON",
            "Type stated: reflected / stored / DOM",
        ),
        "common_na": (
            "`alert(1)` on a `null` origin, a sandboxed iframe, or a `data:`/`blob:` URL",
            "Self-XSS",
            "HTML injection with no JS execution, unless tied to a real attack",
            "XSS via a Markdown/template renderer the target does not actually use",
            "`javascript:` href that requires the victim to paste the URL manually",
        ),
        "overclaim_traps": (
            "Session theft claimed while the cookie is HttpOnly - JS cannot read it",
            "Account takeover claimed without a PoC that takes over an account",
            "CSP bypass claimed without showing the CSP header and the bypass used",
        ),
    },
    "SQLi": {
        "minimum_proof": (
            "Data extraction: a sentinel value, table name, or DB version returned",
            "Time-based: a controlled `SLEEP(n)` payload, several runs at varying `n`",
            "Boolean-based: a controlled true/false oracle with a response differential",
        ),
        "common_na": (
            "A WAF blocked the payload - that is a block, not an injection",
            "An error message mentioning SQL with no controlled injection",
            "A generic HTTP 500 on quote characters (it could be many things)",
            "A leaked DB banner/version without proving injection",
        ),
        "overclaim_traps": (
            "`Full database compromise` without dumping a controlled sentinel row",
            "Post-exploitation to `prove` reach (`xp_cmdshell`, `INTO OUTFILE`, "
            "file writes): prove the primitive, describe the impact, stop",
        ),
    },
    "SSRF": {
        "minimum_proof": (
            "An inbound request observed on an endpoint you control, with the inbound log",
            "For blind SSRF: time-based confirmation against several controlled hosts",
            "Reach demonstrated: an internal hostname, cloud metadata, a localhost "
            "service, or protocol smuggling (`file://`, `gopher://`, `dict://`)",
            "If data was exfiltrated, the internal response body shown",
        ),
        "common_na": (
            "DNS resolution only - that proves a lookup, not an HTTP request",
            "Blind SSRF to your own domain with no reach demonstrated (webhooks, "
            "link previews and image proxies make outbound requests legitimately)",
            "SSRF restricted to public domains",
            "A request blocked by WAF / library / network policy",
        ),
        "overclaim_traps": (
            "Cloud metadata access without the metadata response body",
            "Internal network scan without one successful internal hit",
            "Blind SSRF rated High/Critical without demonstrated reach",
        ),
    },
    "IDOR / BOLA": {
        "minimum_proof": (
            "Two accounts you control, A and B",
            "Account A reads / modifies / deletes a resource belonging to B",
            "The response containing B's data is shown, with B's identifier visible",
        ),
        "common_na": (
            "Sequential or predictable IDs asserted without showing actual access",
            "Reading your own data through someone else's identifier",
            "Resources that are public by design",
            "Admin endpoints reachable only by admins (that is not broken)",
        ),
        "overclaim_traps": (
            "`Mass account takeover` without the takeover primitive shown on B",
            "Single-account discovery with cross-tenant impact claims and no second "
            "tenant tested",
            "A non-guessable identifier (random UUIDv4, HMAC, long opaque token) "
            "scored as if IDs were enumerable: if an attacker cannot discover a "
            "victim's ID at scale, the vector is AC:H - say where the ID would "
            "come from, and do not claim mass exploitation from a resource whose "
            "ID you already knew",
        ),
    },
    "CSRF": {
        "minimum_proof": (
            "A working PoC page that, visited by an authenticated victim, performs "
            "the sensitive action",
            "The action is genuinely sensitive (state change, privilege grant, data "
            "modification - not logout, not search)",
            "SameSite cookie status verified: `Lax` blocks most cross-site POSTs, "
            "so the PoC must work despite it",
        ),
        "common_na": (
            "CSRF on logout, search, or another low-impact action",
            "`No CSRF token present` without showing exploitation",
            "`SameSite=Lax/Strict` cookies blocking the cross-site request",
        ),
        "overclaim_traps": (
            "Account takeover via CSRF without a chain that actually takes one over",
            "Severity rated by mechanism instead of by the forced action: a "
            "reversible low-value change (cart item, UI preference, display name) "
            "is Low even with a perfect PoC. High needs a sensitive action: "
            "email/password change, fund transfer, privilege grant, data deletion",
        ),
    },
    "RCE": {
        "minimum_proof": (
            "In-band command output (`id`, `whoami`, `hostname`)",
            "Or an out-of-band callback carrying a unique payload-specific marker",
            "Or the injection point and payload shown literally",
        ),
        "common_na": (
            "`Suspicious behaviour` on payload submission with no command execution",
            "A stack trace mentioning `system()`/`exec()` without controlled execution",
            "RCE inferred from a vulnerable dependency without proving reachability "
            "in the application's code path",
        ),
        "overclaim_traps": (
            "`Full server compromise` without the privilege level: prove execution "
            "with a harmless marker and stop - do not pivot, escalate, move "
            "laterally or read other users' data to demonstrate reach",
            "RCE that is really code execution in a sandboxed context (a browser "
            "eval is XSS; a sandboxed template engine is not RCE)",
        ),
    },
    "SSTI": {
        "minimum_proof": (
            "Template syntax evaluated (`{{7*7}}` -> `49`, `<%= 7*7 %>` -> `49`)",
            "Engine identified (Jinja2, Twig, Velocity, Freemarker, ...)",
            "Sandbox escape shown if the engine is sandboxed",
            "For RCE impact: the RCE minimum proof above",
        ),
        "common_na": (
            "`{{7*7}}` reflected as a literal string (no evaluation)",
            "Math evaluation in a sandboxed expression engine with no escape path",
        ),
        "overclaim_traps": (
            "`{{7*7}}` -> `49` in a CLIENT-side framework (Angular, Vue) is CSTI, "
            "not server-side SSTI: its impact is XSS, so prove JS execution and "
            "report it as XSS - never as server RCE",
        ),
    },
    "XXE": {
        "minimum_proof": (
            "An external entity defined and resolved",
            "File read: the content of a known file returned",
            "Or OOB: a callback carrying file content base64'd, or a named entity",
        ),
        "common_na": (
            "An XML parser that accepts external DTD references but resolves no entities",
            "An error mentioning entity processing without a controlled file read",
        ),
        "overclaim_traps": (
            "Never demonstrate XXE with an entity-expansion bomb (billion laughs / "
            "quadratic blowup): that is DoS against the target, excluded by most "
            "programs and a rules violation. Prove it with a controlled file read "
            "or an OOB callback",
        ),
    },
    "Open Redirect": {
        "minimum_proof": (
            "One URL that redirects to a domain you control",
            "The mechanism sits on a security-relevant path: auth callback, OAuth "
            "`redirect_uri`, password reset, login flow",
            "A chain showing real impact (OAuth token theft, credential phishing "
            "riding the target's domain reputation)",
        ),
        "common_na": (
            "Open redirect on a non-sensitive path with no chain",
            "A redirect that needs the victim to paste a URL manually",
            "Same-origin redirects",
        ),
        "overclaim_traps": (
            "Token/code theft via an OAuth `redirect_uri` you cannot PoC: if "
            "proving the leak needs an authenticated account or the IDP's real "
            "consent flow, the impact is theoretical and non-reproducible - report "
            "the redirect you can prove (typically Low) and say the ATO chain is "
            "unverified",
        ),
    },
    "Auth Bypass": {
        "minimum_proof": (
            "A specific endpoint or flow reached without the required auth state",
            "The endpoint is sensitive (admin, paid feature, another user's data)",
            "The bypass mechanism shown (request manipulation, missing header, "
            "modified parameter, parser confusion)",
        ),
        "common_na": (
            "An endpoint that returns data also available unauthenticated by design",
            "`Bypass` using test credentials the program intentionally exposes",
            "Public endpoints documented as public",
            "Reaching a protected ROUTE that only renders the client-side app "
            "shell: loading /admin and seeing the SPA bundle is not a bypass - "
            "show a protected action or data actually returned without auth",
        ),
        "overclaim_traps": (
            "`The page loads` is not an impact; the API calls behind it still "
            "returning 401/403 is the thing being bypassed",
        ),
    },
    "Information Disclosure": {
        "minimum_proof": (
            "The exact location the secret was found (file, URL, decompiled path)",
            "The secret is STILL VALID - one authenticated call succeeding with it, "
            "with the secret redacted in the report",
            "The concrete access it grants: what data or action the credential unlocks",
        ),
        "common_na": (
            "Public/publishable keys that are meant to be client-side: Google Maps "
            "browser keys, Firebase `apiKey` config, Stripe `pk_...`, Sentry DSNs, "
            "reCAPTCHA site keys, analytics tokens - a leak is only a finding if "
            "you prove a real, unintended capability",
            "Expired, revoked or already-rotated credentials",
            "`A key is present in the JS` with no test that it is live or privileged",
            "Placeholder / example values (`sk_test_...`, `changeme`, documented "
            "sample keys)",
        ),
        "overclaim_traps": (
            "Reporting the PRESENCE of a secret as the impact: the impact is what "
            "it does when used, so identify what it authenticates and (safely) "
            "confirm it works",
            "Treating any long random string as a leaked secret",
        ),
    },
    "Race Condition": {
        "minimum_proof": (
            "A broken invariant under concurrency: the same operation in parallel "
            "produces a result impossible sequentially (a one-time coupon applied "
            "N times, a balance credited twice, a single-use token consumed twice)",
            "The concurrency method stated: single-packet attack (HTTP/2 last-byte "
            "sync), Turbo Intruder, or parallel clients - with the request count",
            "Before/after state shown: the pre-state, the burst, and the PERSISTED "
            "post-state that proves the invariant broke",
        ),
        "common_na": (
            "`Sent 100 requests fast, several succeeded` with no broken invariant - "
            "on an endpoint with no per-user limit those are just successes",
            "Duplicate submissions to an idempotent endpoint (no state effect)",
            "Response-time jitter mistaken for a race",
            "A rate-limit bypass with no concrete state impact (that is a "
            "rate-limit finding, often not in scope on its own)",
            "Hammering that degrades the service: that is DoS, not a race PoC",
        ),
        "overclaim_traps": (
            "Double-spend / balance inflation from two `200`s without the persisted "
            "state changing - the proof is the final ledger, not the status codes",
            "One lucky duplicate reported as reliable exploitation: state the win "
            "rate and attempts",
            "Scaling the burst to thousands of requests to `prove` it: a small "
            "concurrent burst that breaks the invariant is the proof, and volume "
            "past that is abuse",
        ),
    },
    "CORS Misconfiguration": {
        "minimum_proof": (
            "The response reflects an attacker-controlled `Origin` in "
            "`Access-Control-Allow-Origin` AND returns "
            "`Access-Control-Allow-Credentials: true`",
            "The endpoint returns session-authenticated, sensitive data tied to the "
            "victim's cookies",
            "A working PoC page on the attacker origin that does "
            "`fetch(url, {credentials:'include'})`, reads the response cross-origin "
            "and shows the victim's actual data - not just the headers",
        ),
        "common_na": (
            "`ACAO: *` WITHOUT `ACAC: true` - the browser refuses to send "
            "credentials to a wildcard origin, so no credentialed read exists",
            "A reflected `Origin` on an endpoint returning only public data",
            "`ACAC: true` with a fixed, trusted `ACAO` (not reflected)",
            "Preflight (`OPTIONS`) reflecting the origin while the real GET/POST "
            "does not, or the real body carrying nothing sensitive",
            "`null` origin allowed with no PoC (exploiting `null` needs a sandboxed "
            "iframe - show it working)",
            "An API authenticated by a bearer token in a header: CORS reflection "
            "does not hand over the token and the browser will not attach it "
            "cross-origin, so there is no credentialed session to steal",
        ),
        "overclaim_traps": (
            "`Account takeover via CORS` without a PoC page that reads victim data: "
            "name the endpoint and show the data",
            "High severity from header reflection alone - no credentialed "
            "sensitive-data read means no impact",
        ),
    },
    "Path Traversal / LFI": {
        "minimum_proof": (
            "A file OUTSIDE the intended directory retrieved, content shown",
            "The exact parameter and payload shown literally, including the "
            "encoding that worked (`../`, `%2e%2e%2f`, `....//`, absolute path)",
            "Traversal (arbitrary read) and LFI (include/execute) kept distinct: if "
            "code execution is claimed, show the executed output",
        ),
        "common_na": (
            "Reading a file inside the intended served directory (that is by design)",
            "403/404/500 on `../` payloads with no file returned - an error is not a read",
            "A filename reflected in an error message with no content disclosure",
            "Retrieving a non-sensitive file with no security value",
            "A payload visibly blocked or normalized by the framework or WAF",
        ),
        "overclaim_traps": (
            "`Arbitrary file read = RCE` without a demonstrated execution path: "
            "LFI->RCE needs a proven include-and-execute primitive (log/session "
            "poisoning, a wrapper chain) - otherwise report file disclosure",
            "`Any file on the server` inferred from one `/etc/passwd`: state what "
            "the process user can actually read, and a private key or app secret "
            "is what proves impact",
            "Dumping many sensitive files to `prove` reach - one representative "
            "file proves it",
        ),
    },
}


# Detection tokens, longest/most specific first (matched against a lowercased
# haystack of a skill id, a class name, a report body or a draft). Order matters:
# "idor" before "auth", "ssrf" before "rce" style prefix collisions.
_ALIASES: tuple[tuple[str, str], ...] = (
    ("path_traversal", "Path Traversal / LFI"),
    ("path traversal", "Path Traversal / LFI"),
    ("directory traversal", "Path Traversal / LFI"),
    ("lfi", "Path Traversal / LFI"),
    ("file_inclusion", "Path Traversal / LFI"),
    ("open_redirect", "Open Redirect"),
    ("open redirect", "Open Redirect"),
    ("openredirect", "Open Redirect"),
    ("information_disclosure", "Information Disclosure"),
    ("information disclosure", "Information Disclosure"),
    ("info_disclosure", "Information Disclosure"),
    ("secret_leak", "Information Disclosure"),
    ("secret leak", "Information Disclosure"),
    ("sensitive_data", "Information Disclosure"),
    ("race_condition", "Race Condition"),
    ("race condition", "Race Condition"),
    ("concurrency", "Race Condition"),
    ("cors", "CORS Misconfiguration"),
    ("idor", "IDOR / BOLA"),
    ("bola", "IDOR / BOLA"),
    ("bfla", "Auth Bypass"),
    ("broken_access", "Auth Bypass"),
    ("access_control", "IDOR / BOLA"),
    ("auth_bypass", "Auth Bypass"),
    ("auth bypass", "Auth Bypass"),
    ("sqli", "SQLi"),
    ("sql_injection", "SQLi"),
    ("sql injection", "SQLi"),
    ("sql", "SQLi"),
    ("xss", "XSS"),
    ("cross-site scripting", "XSS"),
    ("cross site scripting", "XSS"),
    ("ssrf", "SSRF"),
    ("server-side request", "SSRF"),
    ("ssti", "SSTI"),
    ("xxe", "XXE"),
    ("xml external", "XXE"),
    ("rce", "RCE"),
    ("csrf", "CSRF"),
    ("cross-site request forgery", "CSRF"),
    ("deserialization", "RCE"),
    ("command_injection", "RCE"),
    ("code_injection", "RCE"),
    ("template_injection", "SSTI"),
    ("file_upload", "RCE"),
    ("mass_assignment", "IDOR / BOLA"),
)

# WhiteHat attack_path_type -> the classes whose gotchas apply to that technique.
ATTACK_PATH_CLASSES: dict[str, tuple[str, ...]] = {
    "xss": ("XSS",),
    "sql_injection": ("SQLi",),
    "ssrf": ("SSRF",),
    "rce": ("RCE", "SSTI"),
    "xxe": ("XXE",),
    "path_traversal": ("Path Traversal / LFI",),
    "access_control": ("IDOR / BOLA", "Auth Bypass"),
    "crypto_attack": (),
    "cve_exploit": (),
    "brute_force_credential_guess": (),
    "denial_of_service": (),
    "phishing_social_engineering": (),
}


def resolve_class(name: str) -> str | None:
    """Map a class name, skill id, or attack path onto a canonical class.

    Returns None when nothing matches - the caller says "no class-specific
    reference" rather than guessing one.
    """
    if not name:
        return None
    raw = str(name).strip()
    if not raw:
        return None
    if raw in GOTCHAS:
        return raw
    if raw in ATTACK_PATH_CLASSES:
        classes = ATTACK_PATH_CLASSES[raw]
        return classes[0] if classes else None
    hay = raw.lower().replace("-", "_")
    for token, cls in _ALIASES:
        if token in hay:
            return cls
    return None


def classes_for_attack_path(attack_path_type: str) -> tuple[str, ...]:
    """Classes whose gotchas apply to a WhiteHat attack path (possibly empty)."""
    if not attack_path_type:
        return ()
    if ":" in attack_path_type:  # user_skill:<id>
        resolved = resolve_class(attack_path_type.split(":", 1)[1])
        return (resolved,) if resolved else ()
    classes = ATTACK_PATH_CLASSES.get(attack_path_type)
    if classes is not None:
        return classes
    resolved = resolve_class(attack_path_type)
    return (resolved,) if resolved else ()


def detect_classes(text: str) -> tuple[str, ...]:
    """Classes a report body appears to claim, in canonical order.

    Deliberately generous: a false positive costs one extra reference block,
    while a missed class is the exact failure the gotchas exist to prevent.
    """
    if not text:
        return ()
    hay = str(text).lower()
    found = []
    for token, cls in _ALIASES:
        if cls in found:
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", hay):
            found.append(cls)
    return tuple(c for c in CLASSES if c in found)


def get_gotchas(cls: str) -> dict[str, tuple[str, ...]] | None:
    canonical = resolve_class(cls)
    return GOTCHAS[canonical] if canonical else None


def build_gotchas_block(classes) -> str:
    """Render the gotchas for the given classes. '' when there are none."""
    resolved = []
    for cls in classes or ():
        canonical = resolve_class(cls)
        if canonical and canonical not in resolved:
            resolved.append(canonical)
    if not resolved:
        return ""
    resolved.sort(key=lambda c: CLASSES.index(c))

    lines = ["## Class-specific proof requirements (check the evidence against these)", ""]
    for cls in resolved:
        entry = GOTCHAS[cls]
        lines.append(f"### {cls}")
        for label, key in (
            ("Minimum proof", "minimum_proof"),
            ("Common N/A (auto-close)", "common_na"),
            ("Overclaim traps", "overclaim_traps"),
        ):
            lines.append(f"**{label}**")
            lines += [f"- {item}" for item in entry[key]]
        lines.append("")
    return "\n".join(lines).rstrip()


__all__ = [
    "ATTACK_PATH_CLASSES",
    "CLASSES",
    "GOTCHAS",
    "build_gotchas_block",
    "classes_for_attack_path",
    "detect_classes",
    "get_gotchas",
    "resolve_class",
]
