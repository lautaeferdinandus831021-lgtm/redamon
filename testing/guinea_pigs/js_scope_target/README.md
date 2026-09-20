# `js_scope_target`: WhiteHat guinea pig for JS recon endpoint scope

Proves, against a real full recon and a real partial run, how JS recon writes
the endpoints it extracts from JavaScript:

- an endpoint on a project host becomes an `Endpoint` owned by its `BaseURL`
  (`BaseURL -[:HAS_ENDPOINT]-> Endpoint`), like every other tool's endpoints;
- a URL on any other host (a payment API, a CDN, a lab host outside the
  project) never becomes an `Endpoint` or a `BaseURL`;
- nothing that already exists is deleted, and endpoints written before the
  scope check are not fetched again.

## Layout

| Container | Address | Role |
|---|---|---|
| `whitehat-js-scope-target` | `192.88.97.10` ports 80 and 8080 | the project's only target |
| `whitehat-js-scope-outsider` | `192.88.97.20` port 80 | reachable, never a target; logs every request |

`192.88.97.0/24` is in the deprecated 6to4 relay prefix, for the same reason as
[`supply_chain_target`](../supply_chain_target/README.md#why-this-target-is-not-on-127001):
JS recon fetches through an SSRF guard that rejects every private and TEST-NET
range, and Python treats this prefix as global. Nothing leaves the host.

The run uses **IP mode**. Domain mode would need the lab names to resolve in
public DNS: the DNS phase uses dnspython, which ignores `/etc/hosts`, and the
recon container has no `extra_hosts`. The domain-mode scope rules (a subdomain
JS recon discovers itself, an RoE-excluded name, a filtered subdomain list) are
covered by unit tests in `tests/test_js_recon_graph_ingestion.py`.

## Cases

`static/app.js`, found by Katana on the target's home page:

| Case | In the JS | Expected in the graph |
|---|---|---|
| E1 | `fetch('/api/users')` | `GET http://192.88.97.10/api/users`, owned |
| E2 | `fetch("http://192.88.97.10/api/orders")` | `GET http://192.88.97.10/api/orders`, owned |
| E3 | `fetch("http://192.88.97.10:8080/api/admin")` | owned by a `BaseURL http://192.88.97.10:8080` that only JS recon knew about (naabu scans port 80 only) |
| E4 | `"/graphql"` | `POST http://192.88.97.10/graphql`, owned |
| E5 | `new WebSocket("ws://192.88.97.10/socket")` | `WS http://192.88.97.10/socket`, owned by the origin of its handshake |
| X1 | `fetch("https://api.payments-vendor.test/v1/charges")` | no Endpoint; recorded as an `ExternalDomain` (source `js_recon`) |
| X2 | `fetch("http://192.88.97.20/api/partner")` | no Endpoint; an `ExternalDomain`; no request reaches the outsider |
| X3 | `apiUrl: "https://api.payments-vendor.test/v2"` | nothing (the whole URL used to land in `path` under the target) |
| X4 | `"https://cms.vendor-content.test/graphql"` | nothing |
| X5 | `new WebSocket("wss://push.vendor-realtime.test/live")` | nothing |

`uploads/scope-lab-upload.js`, uploaded through the JS recon upload API:

| Case | In the JS | Expected |
|---|---|---|
| U1 | `fetch('/api/upload-only')` | `baseurl: 'upload'`, no `BaseURL` |
| U2 | `fetch("http://192.88.97.10/api/from-upload")` | owned by `http://192.88.97.10` |
| U3 | `fetch("https://api.payments-vendor.test/v1/refunds")` | nothing |

Phase 2, a partial JS recon run with `static/partial.js` on `:8080` as a user
URL, after `seed_legacy_endpoint.cypher` planted a pre-fix endpoint on
`https://legacy-vendor.test` with a muted human-triaged vulnerability, a
parameter and an agent chain finding:

| Case | Expected |
|---|---|
| P1 `fetch('/api/partial-only')` | owned by `http://192.88.97.10:8080` |
| P2 `fetch("https://api.payments-vendor.test/v3/partial")` | nothing |
| legacy endpoint | untouched with all three links, and not re-fetched (the run logs `Dropped 1 out-of-scope graph URL(s)`) |

## Run

From the repo root. `lab` is a function rather than a `$RUN` string because the
repo path can contain a space, which an unquoted variable splits.

```bash
(cd testing/guinea_pigs/js_scope_target && docker compose up -d --build)
lab() { docker run --rm --network host -v "$PWD:/repo:ro" -w /repo --entrypoint python \
          whitehat-agent:latest "testing/guinea_pigs/js_scope_target/$@"; }
SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Phase 1: full recon (about a minute)
lab e2e_js_scope.py --user-id <admin user id>          # prints PROJECT_ID=<id>
lab verify_js_scope.py --project-id <id>
docker logs --since "$SINCE" whitehat-js-scope-outsider  # only the "listening" line

# Phase 2: legacy data + partial run
NEO4J_PASSWORD=$(grep '^NEO4J_PASSWORD=' .env | cut -d= -f2- | tr -d "\"'")
docker exec -i whitehat-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  -P "uid => '<user id>'" -P "pid => '<id>'" < testing/guinea_pigs/js_scope_target/seed_legacy_endpoint.cypher
lab e2e_js_scope.py --user-id <admin user id> --partial <id>
lab verify_js_scope.py --project-id <id> --expect-partial --expect-legacy
```

The partial container is removed seconds after it finishes; to read its log
(`Dropped N out-of-scope graph URL(s)`, the `endpoints_out_of_scope` stat),
`docker logs -f` the `whitehat-partial-recon-<id>-*` container while it runs.

`e2e_js_scope.py` signs in with a session cookie minted from `AUTH_SECRET` in
the repo `.env` (the same way `testing/e2e/tests/auth.ts` does) and drives only
public webapp routes: create project, upload, start, poll.
