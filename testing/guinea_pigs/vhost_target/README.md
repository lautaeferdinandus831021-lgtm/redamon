# vhost_target - VHost & SNI Enumeration harness

Three virtual hosts on a single address. Which one answers is decided only by the
`Host` header (L7) or the TLS SNI name (L4), and none of the hidden ones exists
in any DNS zone. That is the situation the module is built for, and the situation
where the graph most easily records something untrue.

## What it serves

| Addressed as | Reply | Why it is here |
|---|---|---|
| the IP itself (no name) | `404`, 33 bytes | The baseline every candidate is compared against |
| `admin.vhostlab.test` | `200`, ~311 bytes | The hidden panel: in scope, in no zone file. Differs from the baseline in both status and length, which is the anomaly |
| `jenkins.vhostlab.test` | `200`, ~250 bytes | A second hidden panel, so a test needing the node to exist beforehand does not have to borrow the one that proves a fresh node is flagged unconfirmed |
| `partner.cohost.test` | `200`, ~180 bytes | A co-hosted third party. Same frontend, somebody else's domain |
| any other name | `404`, 33 bytes | Matches the baseline, so it must never become a finding. Also what the module's control probes see |

Both ports answer: `80` plain and `443` with a self-signed certificate generated
at build time, so the SNI half of the module has something to lie to. No key
material is committed.

## Run it

```bash
cd testing/guinea_pigs/vhost_target
docker compose up -d --build
```

The lab sits on the `whitehat-vhostlab` bridge. Its address:

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  whitehat-vhost-target
```

## What it validates

[`recon/tests/test_vhost_sni_guinea_pig_live.py`](../../../recon/tests/test_vhost_sni_guinea_pig_live.py)
drives the real module against this lab and writes the real graph, then asserts
what the graph ended up saying:

- the hidden vhost is found, and names the lab does not serve are not reported;
- no `RESOLVES_TO` edge is invented, because answering a Host header is not a DNS
  record, while a genuine DNS edge on another IP is left untouched;
- the in-scope panel owns its finding, is flagged `has_dns_records=false`, and
  hangs under its parent `Domain`, so the documented "hidden admin panels" query
  still returns it;
- the co-hosted name never becomes a `Subdomain`, and its finding hangs off the
  `IP` instead of floating free;
- nothing the run produced is left without an owner, and a second run changes
  nothing.

Run it from a container attached to `whitehat-vhostlab`, with `VHOST_LAB_IP` and
the `NEO4J_*` variables set. It skips cleanly when either is missing.

> ⚠️ Local Docker host only. Never expose these ports to an untrusted network.
