# Web Cache Poisoning — Guinea Pig (end-to-end validation target)

A deliberately vulnerable, **real** web-cache setup for validating the WhiteHat WCP
module (`recon/cache_scan`) end to end. It is a real nginx shared cache in front of
a deliberately vulnerable Flask origin, with one crawlable endpoint per pipeline
feature so you can watch every step of the module work (or fail) against a genuine
cache — not a mock.

```
 attacker / scanner ─▶  nginx  (real shared cache, URL-keyed)  ─▶  Flask origin (vulnerable)
                        :9090                                       :5000
                                            └─ :9091 direct ───────▶ (bypasses nginx; silent-cache test only)
```

- **`:9090`** — the realistic target. nginx caches per-URL (so `?rdmncb=` busters
  isolate), forwards the poison headers unkeyed, and the origin trusts them.
- **`:9091`** — the origin **directly** (no proxy). Used **only** for the silent /
  frozen-`Date` behavioural-oracle test, because reverse proxies (nginx) rewrite the
  `Date` header on every response and would defeat that one detection path.

---

## 1. Run it

```bash
cd testing/guinea_pigs/web-cache-poisoning
docker compose up -d --build
open http://localhost:9090/          # landing page links every test endpoint
```

Tear down: `docker compose down`.

### Point a WhiteHat scan at it

The scan containers run on a Docker network, so the easiest reliable reachability is
to attach the cache container to the WhiteHat network and target it by name:

```bash
docker network connect whitehat-network wcp-guinea-cache
# now reachable from scan containers as:  http://wcp-guinea-cache/
```

Then create a project with **target = `wcp-guinea-cache`** (or `http://wcp-guinea-cache`),
apply the **Web Cache Poisoning** preset, and run recon. The landing page links all
endpoints, so the crawler (Katana/Hakrawler) discovers them and they become
`resource_enum` endpoints the WCP module targets.

Alternatively, target the host gateway from containers: `http://172.17.0.1:9090`
(or your host LAN IP). WCVS runs `--net=host`, so it reaches `localhost:9090` directly.

For a **focused** run you can skip discovery and use partial recon → **WebCachePoison**
with the explicit URL list (see §4).

---

## 2. What each endpoint validates (the pipeline map)

Every response was smoke-tested. `cacheable` = the origin sends `Cache-Control:
public, max-age` so nginx stores it (poisonable); negative controls send `no-store`.

### Step 1b — Cache oracle (`oracle.py`): each emits one cache signal

| Endpoint | Signal | Oracle branch exercised |
|---|---|---|
| `/oracle/cache-control` | `Cache-Control: public, max-age` | cache-eligible by directive |
| `/oracle/age` | `Age: 137` | served-from-cache (`saw_hit`) |
| `/oracle/cf-cache-status` | `CF-Cache-Status: HIT` | status-token (Cloudflare) |
| `/oracle/x-cache` | `X-Cache: HIT` | status-token (generic) |
| `/oracle/via` | `Via: 1.1 varnish` | presence header (cache layer) |
| `/oracle/x-served-by` | `X-Served-By` + `X-Cache-Hits` | Fastly fingerprint |
| `/oracle/vary` | `Vary: X-Forwarded-Host` | keyed-header capture |
| `/oracle/no-store` | `Cache-Control: no-store` | **NEGATIVE** → not cacheable → skipped |
| `/oracle/cf-dynamic` | `CF-Cache-Status: DYNAMIC` + private | **NEGATIVE** → not cacheable |
| `/silent/page` (**:9091**) | none; frozen `Date` | behavioural silent-cache fallback |

### Step 3/4 — Reflected poisoning (canary echoed → confirmed by reflection)

| Endpoint | Unkeyed header | Reflected into | Impact class |
|---|---|---|---|
| `/poison/xfh-redirect` | `X-Forwarded-Host` | `Location:` (302) | `open_redirect` |
| `/poison/xfh-script` | `X-Forwarded-Host` | `<script src>` | `stored_xss` |
| `/poison/x-host-link` | `X-Host` | `<link href>` | `stored_xss` |
| `/poison/x-forwarded-server` | `X-Forwarded-Server` | body | `reflected` |
| `/poison/x-original-url` | `X-Original-URL` | body | `reflected` |
| `/poison/x-rewrite-url` | `X-Rewrite-URL` | body | `reflected` |

### Step 4 — Differential / non-reflective poisoning (behaviour change, no marker)

| Endpoint | Trigger | Change | Differential dim → impact |
|---|---|---|---|
| `/diff/proto-redirect` | `X-Forwarded-Proto: https` | 200 → 301 redirect | `location` → `open_redirect` |
| `/diff/status-dos` | any host header | 200 → 403 | `status` → `dos` (CPDoS) |
| `/diff/body-banner` | any host header | body → "MAINTENANCE" | `body` |

### Step 3 — Framework packs (fingerprint-gated)

| Endpoint | Fingerprint | Vector |
|---|---|---|
| `/fw/nextjs` | `X-Powered-By: Next.js`, `__NEXT_DATA__` | `x-invoke-status: 5xx` → error render (CPDoS) |
| `/fw/nuxt` | `__NUXT__`, `X-Powered-By: Nuxt` | `/_payload.json` path confusion |
| `/fw/remix` | `__remixContext`, `X-Powered-By: Remix` | `?_data=` data-request reflection |

### Step 5 — Negative controls (must be **Rejected** → proves low false-positive rate)

| Endpoint | Why it must NOT be flagged |
|---|---|
| `/safe/keyed-xfh` | nginx folds `X-Forwarded-Host` **into the cache key** → poison never served to a header-less victim |
| `/safe/no-reflect` | cacheable but ignores all headers → nothing to poison |
| `/safe/dynamic` | body changes every request → baseline unstable → differential FP-guard must suppress |
| `/safe/reflect-no-store` | reflects the header but `no-store` → never cached → can't persist |

---

## 3. ⚠️ Critical finding this harness already surfaced

Before even running the pipeline, a 2-minute test against this real cache exposed a
genuine gap in the native confirmer.

The confirmer ([confirm.py](../../../recon/cache_scan/confirm.py)) does **baseline first,
then poisons the *same* cache-buster**. Against a real cache the baseline warms the
slot with a clean response, so the poison request (unkeyed header → same key) gets a
cache **HIT** and never reaches the origin → **false negative**.

Reproduce against this guinea pig:

```bash
# A) Attacker order (poison FIRST) — REAL poisoning works:
curl -s -D- -o/dev/null "http://localhost:9090/poison/xfh-redirect?rdmncb=A" -H "X-Forwarded-Host: evil.example" | grep -i location
#   Location: https://evil.example/welcome   (MISS, cached)
curl -s -D- -o/dev/null "http://localhost:9090/poison/xfh-redirect?rdmncb=A" | grep -i location
#   Location: https://evil.example/welcome   (HIT — victim gets the poison) ✅

# B) Module order (BASELINE first) — detection defeated:
curl -s -D- -o/dev/null "http://localhost:9090/poison/xfh-redirect?rdmncb=B" | grep -i location
#   Location: https://guinea.local/welcome   (MISS, caches CLEAN)
curl -s -D- -o/dev/null "http://localhost:9090/poison/xfh-redirect?rdmncb=B" -H "X-Forwarded-Host: evil.example" | grep -i location
#   Location: https://guinea.local/welcome   (HIT on the cached clean — poison never lands) ❌
```

**Implication.** WCVS (poison-first) should still surface these as candidates, but the
native confirmer will likely **Reject** real reflected poisonings it actually warmed
away. The fix is to **poison first** (or use a *separate* buster for the baseline vs the
poison+check), so the poison request is a fresh MISS that reaches the origin and the
clean check then HITs the poisoned slot. This guinea pig is exactly the regression
target to verify that fix against.

---

## 4. How to read a run, step by step

Tail the recon job logs and the guinea-pig logs side by side:

```bash
docker compose -f testing/guinea_pigs/web-cache-poisoning/docker-compose.yml logs -f backend
#   [backend] GET /poison/xfh-redirect?rdmncb=...  XFH=...  -> 302
#   A log line == the request reached the ORIGIN (a cache MISS). No line == served from
#   cache (a HIT). This tells you exactly when a poison landed vs was warmed away.
```

Expected pipeline observations:

1. **Targets (Step 0):** the crawler finds the 26 endpoints from the landing page →
   they appear in `resource_enum`; the WCP target list is built from them.
2. **WCVS (Step 1):** breadth sweep surfaces candidates on the `/poison/*` and
   `/diff/*` URLs (poison-first, so it can land the poison).
3. **Oracle (Step 1b):** `/oracle/*` URLs report `cacheable: true` with the matching
   indicator; `/oracle/no-store` and `/oracle/cf-dynamic` report **not cacheable**
   (skipped); `/silent/page` (on :9091) is caught by the frozen-`Date` fallback.
4. **Confirm (Step 4):** watch whether reflected `/poison/*` vectors persist. Per §3,
   expect the native confirmer to under-report until the poison-ordering fix lands.
5. **Score (Step 5):** confirmed findings become `Vulnerability {source:'cache_poisoning'}`
   nodes; `/safe/*` must produce **none**.

### Partial-recon quick list (skip discovery)

Paste these into partial recon → **WebCachePoison** (prefix with the reachable base,
e.g. `http://wcp-guinea-cache`):

```
/poison/xfh-redirect
/poison/xfh-script
/poison/x-host-link
/poison/x-original-url
/diff/proto-redirect
/diff/status-dos
/diff/body-banner
/fw/nextjs
/safe/keyed-xfh
/safe/no-reflect
/safe/dynamic
```

---

## 5. Files

| File | Role |
|---|---|
| `backend/app.py` | Flask origin: all endpoints + landing page + frozen-Date silent cache |
| `backend/Dockerfile`, `requirements.txt` | origin image (Flask + waitress) |
| `nginx/default.conf` | real shared cache: URL-keyed; keyed-header negative control |
| `docker-compose.yml` | backend + nginx; `:9090` cache, `:9091` direct origin |

> ⚠️ Intentionally vulnerable. Run only on a local/trusted Docker host. Never expose
> `:9090`/`:9091` to an untrusted network.
