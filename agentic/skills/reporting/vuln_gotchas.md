---
name: Vulnerability Class Gotchas
description: Per-class minimum proof, common auto-close (N/A) patterns and impact-overclaim traps for XSS, SQLi, SSRF, IDOR/BOLA, CSRF, RCE, SSTI, XXE, open redirect, auth bypass, information disclosure, race conditions, CORS and path traversal/LFI. Load before claiming a class.
---

# Vulnerability Class Gotchas

For each class: **minimum proof** (what the evidence must show before the class
can be claimed), **common N/A** (the false positives that get a report closed),
and **overclaim traps** (impact claims that need extra evidence).

Load only the section matching the class being claimed. `report_review`
returns the same content:

```
report_review mode: "gotchas" vulnerability_class: "IDOR"
```

> Scope: this is a claim gate, not a scanning playbook. If the primitive found
> fails the minimum proof, the correct output is "not yet a finding, here is what
> would prove it" — not a downgraded version of the claim.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Gather the primitive | `execute_curl` | The exact request/response that will be pasted into the report. |
| Read recorded findings | `query_graph` | Check the evidence already attached to the finding before re-testing. |
| Multi-step / timing proof | `execute_code` | Races, oracles and iterative extraction that raw requests cannot express. |
| Visual proof | `execute_playwright` | Client-side execution, alert dialogs, rendered state. |
| Class reference | `report_review` | `mode="gotchas"` for one class at a time. |

---

## XSS

**Minimum proof**

- JS execution on the **target origin** (`alert(document.domain)` proves it).
- Injection context stated: HTML body / attribute / JS / CSS / URL / JSON.
- Type stated: reflected / stored / DOM.

**Common N/A**

- `alert(1)` on a `null` origin, a sandboxed iframe, or a `data:`/`blob:` URL.
- Self-XSS.
- HTML injection with no JS execution, unless tied to a real attack.
- XSS via a Markdown/template renderer the target does not use.
- A `javascript:` href that needs the victim to paste the URL.

**Overclaim traps**

- Session theft claimed while the cookie is `HttpOnly` — JS cannot read it.
- Account takeover without a PoC that takes over an account.
- CSP bypass without the header and the bypass used.

---

## SQLi

**Minimum proof** (one of)

- Data extraction: sentinel value, table name or DB version returned.
- Time-based: controlled `SLEEP(n)`, several runs at varying `n`.
- Boolean-based: a controlled true/false oracle with a differential.

**Common N/A**

- A WAF blocking the payload — the WAF blocked; that is all.
- An error mentioning SQL with no controlled injection.
- A generic 500 on quote characters.
- A leaked DB banner without proving injection.

**Overclaim traps**

- "Full database compromise" without a controlled sentinel row.
- Post-exploitation to "prove" impact: a confirmed injection is enough. Dumping
  the database, chaining to `xp_cmdshell`/`INTO OUTFILE`, or writing files goes
  past proof into damage and can breach the program rules. Prove the primitive,
  describe the impact, stop.

---

## SSRF

**Minimum proof**

- An inbound request observed on an endpoint you control (the inbound log).
- Blind SSRF: time-based confirmation against several controlled hosts.
- Reach demonstrated: an internal hostname, cloud metadata (169.254.169.254), a
  localhost service, or protocol smuggling (`file://`, `gopher://`, `dict://`).
  A callback hit alone is not reach.
- If data was exfiltrated, the internal response body shown.

**Common N/A**

- DNS resolution only — a lookup, not an HTTP request.
- Blind SSRF to an attacker-controlled domain with no reach demonstrated.
- SSRF restricted to public domains.
- A request blocked by WAF/library/network policy.

**Overclaim traps**

- Cloud metadata claimed without the metadata response body.
- "Internal network scan" without one successful internal hit.
- Blind SSRF rated High/Critical without demonstrated reach — typically Low.

---

## IDOR / BOLA

**Minimum proof**

- Two accounts you control, A and B.
- A reads/modifies/deletes a resource belonging to B.
- The response with B's data shown, with B's identifier visible.

**Common N/A**

- Predictable IDs asserted without showing actual access.
- Reading your own data via someone else's ID.
- Resources public by design.
- Admin endpoints reachable only by admins.

**Overclaim traps**

- "Mass account takeover" without the primitive shown on B.
- Single-account discovery with cross-tenant claims and no second tenant tested.
- A non-guessable identifier (random UUIDv4, HMAC, long opaque token) scored as
  if IDs were enumerable. If a victim's ID cannot be discovered at scale,
  exploitation needs the ID to leak elsewhere — score `AC:H`, state where the ID
  would come from, and do not claim mass exploitation from a resource whose ID
  you already knew.

---

## CSRF

**Minimum proof**

- A working PoC page that, visited by an authenticated victim, performs the
  sensitive action.
- The action is genuinely sensitive (state change, privilege grant, data
  modification — not logout, not search).
- SameSite status verified: `Lax` blocks most cross-site POSTs, so the PoC must
  work despite it.

**Common N/A**

- CSRF on logout, search or another low-impact action.
- "No CSRF token present" without exploitation.
- `SameSite=Lax/Strict` blocking the cross-site request.

**Overclaim traps**

- "Account takeover via CSRF" without a chain that takes one over.
- Severity rated by mechanism instead of the forced action: a reversible
  low-value change (cart item, UI preference, display name) is **Low** even with
  a perfect PoC. High needs a genuinely sensitive action.

---

## RCE

**Minimum proof** (one of)

- In-band command output (`id`, `whoami`, `hostname`).
- An out-of-band callback with a unique payload-specific marker.
- The injection point and payload shown literally.

**Common N/A**

- "Suspicious behaviour" on payload submission with no command execution.
- A stack trace mentioning `system()`/`exec()` without controlled execution.
- RCE via a vulnerable dependency without proving reachability in the
  application's code path.

**Overclaim traps**

- "Full server compromise" without the privilege level. Prove execution with a
  harmless marker and stop — do not pivot, escalate privileges, move laterally,
  read other users' data or run destructive commands to "demonstrate" reach.
- RCE that is really sandboxed code execution (a browser-side eval is XSS).

---

## SSTI

**Minimum proof**

- Template syntax evaluated (`{{7*7}}` -> `49`, `<%=7*7%>` -> `49`).
- Engine identified (Jinja2, Twig, Velocity, Freemarker, ...).
- Sandbox escape shown if the engine is sandboxed.
- For RCE impact: the RCE minimum proof.

**Common N/A**

- `{{7*7}}` reflected as a literal string.
- Math eval in a sandboxed expression engine with no escape path.

**Server-side vs client-side**

`{{7*7}}` -> `49` in a **client-side** framework (Angular, Vue) is **CSTI**, not
server-side SSTI. Its impact is XSS: prove JS execution and report it as XSS,
never as server RCE.

---

## XXE

**Minimum proof**

- An external entity defined and resolved.
- File read: the content of a known file returned (e.g. `/etc/passwd`).
- Or OOB: a callback with file content base64'd, or a named entity.

**Common N/A**

- A parser that accepts external DTD references but resolves no entities.
- An error mentioning entity processing with no controlled file read.

**Do not**

- Demonstrate with an entity-expansion bomb (billion laughs / quadratic blowup):
  that is DoS against the target, excluded by most programs and a rules
  violation. Use a controlled file read or an OOB callback.

---

## Open Redirect

**Minimum proof**

- A single URL that redirects to a domain you control.
- The mechanism sits on a security-relevant path: auth callback, OAuth
  `redirect_uri`, password reset, login flow.
- A chain showing real impact (OAuth token theft, credential phishing riding the
  target's domain reputation).

**Common N/A**

- Open redirect on a non-sensitive path with no chain.
- A redirect needing the victim to paste a URL manually.
- Same-origin redirects.

**Overclaim traps**

- Token/code theft via an OAuth `redirect_uri` you cannot PoC. If proving the
  leak needs an authenticated account or the IDP's real consent flow, the impact
  is theoretical and non-reproducible: report the redirect you can prove
  (typically Low) and say the ATO chain is unverified.

---

## Auth Bypass

**Minimum proof**

- A specific endpoint or flow reached without the required auth state.
- The endpoint is sensitive (admin, paid feature, another user's data).
- The bypass mechanism shown (request manipulation, missing header, modified
  parameter, parser confusion).

**Common N/A**

- An endpoint returning data that is unauthenticated by design.
- "Bypass" using test credentials the program exposes on purpose.
- Public endpoints documented as public.
- Reaching a protected **route** that only renders the client-side app shell:
  loading `/admin` and seeing the SPA bundle is not a bypass — you must show a
  protected action or data actually returned without auth.

---

## Information Disclosure / Secret Leak

**Minimum proof**

- The exact location the secret was found (file, URL, decompiled path).
- The secret is **still valid**: one authenticated call succeeding with it, with
  the secret redacted in the report.
- The concrete access it grants.

**Common N/A**

- Public/publishable keys meant to be client-side: Google Maps browser keys,
  Firebase `apiKey` config, Stripe `pk_...`, Sentry DSNs, reCAPTCHA site keys,
  analytics tokens. A leak is only a finding if a real, unintended capability is
  proven.
- Expired, revoked or rotated credentials.
- "A key is present in the JS" with no test that it is live or privileged.
- Placeholder/test values (`sk_test_...`, `changeme`, documented samples).

**Overclaim traps**

- Reporting the presence of a secret as the impact: the impact is what it does
  when used. Identify what it authenticates and confirm it works (safely).
- Treating any long random string as a leaked secret.

---

## Race Condition

**Minimum proof**

- A broken invariant under concurrency: the same operation in parallel produces
  a result impossible sequentially (a one-time coupon applied N times, a balance
  credited twice, a single-use token consumed twice).
- The concurrency method stated: single-packet attack (HTTP/2 last-byte sync),
  Turbo Intruder, or parallel clients — with the number of concurrent requests.
- Before/after state shown: the pre-state, the burst, and the persisted
  post-state that proves the invariant broke.

**Common N/A**

- "Sent 100 requests fast, several succeeded" with no broken invariant.
- Duplicate submissions to an idempotent endpoint.
- Response-time jitter mistaken for a race.
- A rate-limit bypass with no concrete state impact (often out of scope alone).
- Hammering that degrades the service — that is DoS, not a race PoC.

**Overclaim traps**

- Double-spend/balance inflation from two `200`s without the persisted state
  changing. The proof is the final ledger, not the status codes.
- One lucky duplicate reported as reliable exploitation: state the win rate.
- Scaling the burst to thousands of requests to "prove" it: volume past the
  small burst that breaks the invariant is abuse, not evidence.

---

## CORS Misconfiguration

**Minimum proof**

- The response reflects an attacker-controlled `Origin` in
  `Access-Control-Allow-Origin` **and** returns
  `Access-Control-Allow-Credentials: true`.
- The endpoint returns session-authenticated, sensitive data tied to the victim's
  cookies.
- A working PoC page on the attacker origin doing
  `fetch(url, {credentials:'include'})`, reading the response cross-origin and
  showing the victim's actual data — not just the headers.

**Common N/A** (most CORS reports die here)

- `ACAO: *` **without** `ACAC: true`: the browser refuses to send credentials to
  a wildcard origin, so no credentialed read is possible.
- A reflected `Origin` on an endpoint returning only public data.
- `ACAC: true` with a fixed, trusted `ACAO`.
- Preflight reflecting the origin while the real request does not.
- `null` origin allowed with no PoC (exploiting `null` needs a sandboxed iframe).
- An API authenticated by a bearer token in a header: CORS reflection does not
  hand over the token and the browser will not attach it cross-origin.

**Overclaim traps**

- "Account takeover via CORS" without a PoC page reading victim data. Name the
  endpoint and show the data.
- High severity from header reflection alone: no credentialed sensitive read
  means no impact.

---

## Path Traversal / LFI

**Minimum proof**

- A file **outside** the intended directory retrieved, content shown
  (`/etc/passwd`, `win.ini`, an app config or source file the endpoint must not
  serve).
- The exact parameter and payload shown literally, including the encoding that
  worked (`../`, `%2e%2e%2f`, `....//`, absolute path).
- Traversal (arbitrary read) and LFI (include/execute) kept distinct. If code
  execution is claimed, show the executed output.

**Common N/A**

- Reading a file inside the intended served directory (that is by design).
- `403`/`404`/`500` on `../` with no file returned — an error is not a read.
- A filename reflected in an error message with no content disclosure.
- Retrieving a non-sensitive file.
- A payload visibly blocked or normalized by the framework or WAF.

**Overclaim traps**

- "Arbitrary file read = RCE" without a demonstrated execution path: LFI -> RCE
  needs a proven include-and-execute primitive (log/session poisoning, a wrapper
  chain). Otherwise report file disclosure.
- "Any file on the server" inferred from one `/etc/passwd`: state what the
  process user can actually read — a private key or app secret proves impact.
- Dumping many sensitive files to "prove" reach: one representative sensitive
  file proves it.

---

## Class not listed?

Hold the claim to the general evidence bar (a replayable PoC, impact only as
demonstrated, CVSS base metrics only) and explain the impact model in the first
paragraph, since a reader will not have a class-specific mental model to fall
back on.
