# WhiteHat Neo4j Graph Schema

## Overview

This document defines the Neo4j graph database schema for storing reconnaissance data.
The schema is designed to enable attack chain analysis by connecting all discovered assets,
services, technologies, and vulnerabilities in a navigable graph structure.

---

## 🎯 Design Principles

1. **Hierarchical Ownership**: All nodes trace back to a Domain with `user_id` and `project_id`
2. **Attack Surface Mapping**: Every potential entry point is modeled (ports, URLs, parameters)
3. **Technology-Vulnerability Linkage**: Technologies connect to known CVEs for risk assessment
4. **No Redundancy**: Information stored once, relationships handle connections
5. **Query Efficiency**: Optimized for path traversal (attack chains)
6. **Multi-Tenant Isolation**: Every ENTITY node has `user_id` + `project_id` for
   tenant filtering. The three GLOBAL REFERENCE labels are the deliberate
   exception - see below.

---

## Where the schema itself lives

**This document no longer lists node labels, their properties, or the
relationships between them.** It used to, and that was the problem: the same
facts were written out three times - here, in the text-to-cypher prompt, and in
`graph_db/schema.py` - so adding a node type meant editing all three, and
forgetting one failed in silence. No error, just an agent that could never
query the new node type, or a documented property that nothing writes.

There is now one declaration.

| What you want | Where it is |
|---|---|
| Every label, property and relationship, with meaning | `graph_db/schema_sections.md` |
| The same, parsed into fields a program can read | `graph_db/schema_catalog.py` |
| A label's uniqueness key (its MERGE identity) | `graph_db/schema_keys.py` |
| The rendered document an agent is served | `render_schema()` in `graph_db/schema_render.py` |

### Reading it

```bash
# the whole schema, as the agent sees it
python3 -c "from graph_db.schema_render import render_schema; print(render_schema())"

# one label
python3 -c "from graph_db.schema_render import render_label; print(render_label('Subdomain'))"

# a label's properties as data
python3 -c "from graph_db.schema_catalog import label_properties; print(label_properties('Subdomain'))"
```

Or ask the running agent, which serves the same content over both surfaces:
the `graph_schema` tool in a chat session, or `graph_schema` over the inbound
MCP server. Neither needs a database.

### Changing it

Edit `graph_db/schema_sections.md`, then re-seed:

```bash
python3 tooling/scripts/seed_schema_catalog.py
```

`graph_db/schema.py` renders its `CREATE CONSTRAINT` statements from
`schema_keys.py`, so a new label's uniqueness key is declared once and the
database follows.

### Constraints and indexes

The DDL is generated too, and `init_schema` applies all of it on every
scan-container spawn and every agent graph call. Every statement is guarded by
`IF NOT EXISTS` / `IF EXISTS`, so it is idempotent.

| | Count | Source |
|---|---|---|
| `CREATE CONSTRAINT` | 45 | rendered by `schema.build_constraints()` from `schema_keys.py` |
| `CREATE INDEX` | 79 | `TENANT_INDEXES` + `ADDITIONAL_INDEXES` in `schema.py` |
| `DROP` (legacy) | 43 | `DROP_LEGACY_CONSTRAINTS` in `schema.py` |

```bash
# exactly what the database gets, in order
docker compose exec agent python -c "
from graph_db.schema import DROP_LEGACY_CONSTRAINTS, CONSTRAINTS, TENANT_INDEXES, ADDITIONAL_INDEXES
for s in DROP_LEGACY_CONSTRAINTS + CONSTRAINTS + TENANT_INDEXES + ADDITIONAL_INDEXES: print(s)"
```

This file used to carry that listing verbatim. It was accurate - checked name
by name at removal, 78 index names and 43 drops matching the code exactly - but
being accurate was never the point: it was a copy that had to be maintained by
hand, and the next label added would have been the one nobody remembered to add
here.

**Renaming a constraint is a migration, not a refactor.** A same-name
`CREATE ... IF NOT EXISTS` against a database that still holds the old
constraint is a silent no-op, so a changed key needs a new name AND a matching
entry in `DROP_LEGACY_CONSTRAINTS`.

### What stops it drifting again

Four tests, and they fail rather than warn:

- every label declared in `schema_keys.py` has catalog documentation
- every relationship and property the CODE writes is documented
  (`recon/tests/test_graph_writes_documented.py`, hermetic, runs in CI)
- every relationship and property in a LIVE graph is documented
  (`recon/tests/test_schema_catalog.py`, skips without a database)
- no query reads a relationship nothing writes - this one found a real bug,
  a modal reporting zero because it read `HAS_SERVICE` where every writer
  creates `RUNS_SERVICE`

### What this document still covers

The parts a generator cannot produce: why the graph is shaped the way it is,
the multi-tenant strategy, the `Muted` label's rationale, and how Scan Timeline
versions live in Postgres rather than in the graph.

For query GUIDANCE - how to phrase a traversal, which node types to union, the
gotchas - read the text-to-cypher prompt's rule sections in
`agentic/prompts/base.py`, which is what the agent is actually instructed with.

## 🌍 Global Reference Nodes (CVE, MitreData, Capec)

`CVE`, `MitreData` and `Capec` are the public NVD/MITRE catalogue, not findings.
They are UNIQUE on their natural id (`c.id`, `m.id`, `cap.capec_id`), so there is
exactly ONE node per CVE for the whole database, shared by every project that
finds it. They carry **no** `user_id` / `project_id`.

```cypher
// entity node - tenant-scoped
MERGE (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})

// reference node - natural id ONLY, never a tenant key
MERGE (c:CVE {id: $cve_id})
  ON CREATE SET c.source = 'nuclei'        // provenance: first writer wins
```

Three rules follow from that, each of which was a real defect:

1. **Never stamp a tenant on one.** `SET c += props` with `user_id`/`project_id`
   in the dict made the last project to touch a CVE its owner, and every
   project-scoped delete then removed the shared node along with every other
   project's links to it.
2. **Never key a MERGE on the tenant triple.** `MERGE (c:CVE {id, user_id,
   project_id})` collides with the uniqueness constraint on `id` and raises
   `ConstraintValidationFailed` whenever the CVE already exists.
3. **Never delete one by project.** Project wipes exclude these labels and then
   sweep the nodes no project can REACH any more. Reachability, not degree: the
   catalogue is internally linked as `CVE -> MitreData -> Capec`, so an
   unreferenced CVE still holds its CWE.

Reading them is by traversal, not by tenant filter. `graph_db/tenant_filter.py`
exempts these labels from injection - a filter on an unstamped node matches
nothing - but only for a pattern that names reference labels ONLY, and only in a
query that carries a tenant-scoped pattern of its own:

```cypher
MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id, c.cvss   // ✅
MATCH (c:CVE) RETURN c.id                                            // ❌ refused
```

The `idx_cve_tenant` / `idx_mitredata_tenant` / `idx_capec_tenant` indexes
indexed a property these nodes no longer carry, so `init_schema` drops them:
they are listed in `DROP_LEGACY_CONSTRAINTS` (`graph_db/schema.py`) and go on the
next connection to any existing database.

---

## 🔇 The `Muted` Label (suppressed findings)

`Muted` is the one label that is **added to** a node rather than being its type.
When an operator suppresses a finding as noise it keeps its functional label and
gains this one, so a suppressed Nuclei finding is `:Vulnerability:Muted`.

```cypher
// mute   - add the label, keep the type
MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
SET v:Muted, v.muted = true, v.muted_at = datetime(), v.muted_by = $uid

// unmute - lossless, nothing was destroyed
MATCH (v:Vulnerability:Muted {id: $id, user_id: $uid, project_id: $pid})
REMOVE v:Muted, v.muted, v.muted_at, v.muted_by, v.muted_reason
```

**Only finding-bearing nodes may be muted.** `Vulnerability`, `JsReconFinding`,
`Secret`, `MultiscannerFinding`, `GithubSecret`, `GithubSensitiveFile`,
`MalPackageFinding`, `ExploitGvm`. Asset and reference nodes (`IP`, `Port`,
`Domain`, `Endpoint`, `CVE`, ...) are context: muting one would orphan the real
findings hanging off it.

### Why add a label instead of swapping it

Adding is what makes unmute lossless and what makes mute survive a re-scan.
Recon re-runs `MERGE (v:Vulnerability {id, user_id, project_id})`, which still
matches a `:Vulnerability:Muted` node, refreshes its scan properties and leaves
the mute intact. Had mute *replaced* the functional label, that MERGE would match
nothing and create a second, un-muted duplicate of the same finding, because
`vulnerability_tenant_unique` is on `:Vulnerability(id, user_id, project_id)`
and the duplicate would satisfy it.

### The single-label convention this bends, and its price

Everywhere else in this schema a node has exactly ONE label, because the graph
renderer and several aggregations take `labels[0]` and **Neo4j does not order
labels**. A muted node is dual-labelled, so its `labels[0]` is nondeterministic.

That is safe only because of a containment rule that must hold for every read
path: **no `labels[0]` consumer ever receives a muted node.** Excluding `:Muted`
is therefore a correctness requirement, not only a visibility one - a reader that
forgets the filter both leaks a suppressed finding and may mis-type it as
`"Muted"`. The one legitimate reader of muted nodes is the Triage page's Muted
table, which derives the type as `[l IN labels(n) WHERE l <> 'Muted'][0]` and
never uses `labels[0]`.

### Invisibility is enforced at the tenant chokepoint

`graph_db/tenant_filter.py` rewrites every node pattern to carry the tenant keys;
the same rewrite now also excludes `Muted`, so the guarantee rides on the
mechanism that already covers every query shape the agent can emit:

```cypher
MATCH (v:Vulnerability)  ->  MATCH (v:Vulnerability&!Muted {user_id: .., project_id: ..})
MATCH (n)                ->  MATCH (n:!Muted {user_id: .., project_id: ..})
MATCH (n:A|B)            ->  MATCH (n:(A|B)&!Muted {user_id: .., project_id: ..})
```

A query that names the label itself is refused rather than scoped, so the agent
has no vocabulary for mute at all:

```cypher
MATCH (v:Vulnerability&!Muted {...}) RETURN v   // ✅ what injection produces
MATCH (n:Muted) RETURN n                        // ❌ refused: reserved label
MATCH (v:Vulnerability) WHERE NOT v:Muted ...   // ❌ refused: exclusion is automatic
```

Readers that hand-write their own Cypher and never reach `scope_query` are
separate enforcement sites and must exclude `:Muted` themselves: the `/graph`
loader (`webapp/src/app/api/graph/liveRead.ts`), the fixed-op node-type query
(`agentic/api.py` `_GRAPH_TYPES_CYPHER`), analytics, insights and reports.

## 🏗️ Multi-Tenant AWS Scalability Strategy

This schema uses **Logical Partitioning with Composite Indexes** for multi-tenant isolation.
Every node type includes `user_id` and `project_id` properties with composite indexes.

### Why This Approach?

```
┌─────────────────────────────────────────────────────────────────┐
│                    Single Neo4j Database                        │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  User A     │  │  User B     │  │  User C     │  ...        │
│  │  Project 1  │  │  Project 1  │  │  Project 1  │             │
│  │  Project 2  │  │  Project 2  │  │  Project 2  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                 │
│  Composite Constraints: (fields, user_id, project_id) IS UNIQUE │
│  Query Pattern: Always filter by tenant FIRST                   │
└─────────────────────────────────────────────────────────────────┘
```

### Query Pattern (CRITICAL)

All queries **MUST** start by filtering on `user_id` and `project_id` to leverage indexes:

```cypher
// ✅ CORRECT - Uses composite index, scans only tenant's data
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
-[:HAS_SUBDOMAIN]->(s:Subdomain)
-[:RESOLVES_TO]->(ip:IP)
-[:HAS_PORT]->(p:Port)
RETURN d, s, ip, p

// ❌ WRONG - Full graph scan, affects all tenants
MATCH (v:Vulnerability {severity: 'critical'})
RETURN v
```

### AWS Deployment Architecture

```
Node.js API (EKS/ECS Fargate)
        │
        ├── ElastiCache Redis ─── Query caching per tenant
        │
        └── Neo4j AuraDB / Neo4j on EC2
                │
                └── Composite indexes on (user_id, project_id)
```

### Scaling Path

| Phase | Users | Strategy | AWS Services |
|-------|-------|----------|--------------|
| MVP | 0-100 | Single DB + Indexes | ECS Fargate, Neo4j AuraDB |
| Growth | 100-1K | Read Replicas | EKS, AuraDB Professional |
| Scale | 1K+ | Sharded by User Pools | EKS Multi-AZ, Neo4j Cluster |

---

## 📝 Notes for Implementation

1. **Deduplication**: Before creating nodes, check if they exist (MERGE vs CREATE)
2. **Timestamps**: Store as Neo4j datetime type for proper querying
3. **Arrays**: Neo4j supports array properties (tags, references, etc.)
4. **Large Text**: Keep descriptions under 10KB, store curl_command and request/response separately if needed
5. **Batch Import**: For large scans, use APOC procedures for batch imports

---

## 🕰️ Scan Timeline (versions live in Postgres, NOT in the graph)

**The Neo4j schema does not change for the Scan Timeline.** There is no version
node, no version property, and no `:VERSION_OF` relationship — nothing in this
document is modified by the feature.

### The model

- The **live Neo4j graph IS the current version.** It behaves exactly as before:
  a full recon wipes and rebuilds it. Everything that reads or writes the graph
  (the agent, partial recon, the ~30 RedZone/analytics endpoints, saved views)
  therefore sees whichever version is *active*, unchanged.
- A **past version is a saved snapshot**: the project's subgraph, serialized and
  gzipped into Postgres. Past versions are read-only and never present in Neo4j,
  so old data can never reach the agent or an analytics query.
- Snapshots are taken **before** a new full scan overwrites the graph — and only
  when the user chooses to keep it (the "new version vs overwrite" modal).

### Postgres models

| Model | Purpose |
|---|---|
| `ScanVersion` | One point-in-time identity for the recon graph. `isCurrent = true` on exactly one row per project — that row IS the live graph and has `snapshot = null`. A frozen (past) version carries `snapshot` bytes. `@@unique([projectId, seq])` keeps numbering from forking. |
| `ScanJob` | Run history: `trigger` (manual/scheduled), `mode`, `status` (queued/running/completed/failed/canceled/deferred_ram), who started it, timings, `ramReason`. `kind` records WHICH scan the row is for (`full_recon` \| `partial_recon` \| `gvm` \| `github_hunt` \| `trufflehog` \| `supply_chain` \| `supply_chain_repo` \| `ai_attack`) — before it, a directly-started non-recon run had no record at all. `runId` is the orchestrator run id for the kinds that allow several concurrent runs per project (`partial_recon`, `ai_attack`), and is empty for the one-per-project kinds. |
| `ScanSchedule` | A future/recurring full scan: `once` / `interval` / `cron` (UTC), plus the `scanMode` to use for the previous graph. |

`Project` also gains the activation lock columns `activation_state`,
`activation_started_at`, `activation_version_id` (see below).

### Snapshot payload shape

Snapshots are stored in the **export (restore-fidelity) format**, not the UI
render shape, because a snapshot must be restorable back into Neo4j:

```jsonc
// gzip( JSON ) in ScanVersion.snapshot
{
  "nodes": [
    { "labels": ["Subdomain"], "properties": { /* ALL properties, incl. project_id/user_id */ },
      "_exportId": "<uuid>" }
  ],
  "relationships": [
    { "startExportId": "<uuid>", "endExportId": "<uuid>", "type": "RESOLVES_TO", "properties": {} }
  ]
}
```

The graph screen renders a version by converting this to the same
`{ nodes, links }` payload `/api/graph` returns, so the canvas, the clustering and
the node/link tables are unchanged.

**Agent session nodes are excluded.** The AttackChain family (`AttackChain`,
`ChainStep`, `ChainFinding`, `ChainDecision`, `ChainFailure`) is *agent-run* state,
not recon state: it is filtered out of every capture, and preserved (not deleted)
when a version is activated. Chains stay conversation-scoped exactly as documented
in the Attack Chain Graph section above.

### Activation (switching the active version)

Viewing a version only renders its bytes. **Activating** it swaps the live graph:

1. freeze the outgoing current version *from the live graph* (not from its old
   stored bytes — partial recon may have edited it since),
2. delete the live recon graph **excluding the AttackChain family**, and restore
   the target version through the same code path the project import uses,
3. only then move the `isCurrent` pointer, and invalidate the graph cache.

A failure in step 1 aborts before anything is deleted; a failure in step 2 leaves
both endpoints intact in Postgres, so the activation is simply retriable.

Activation holds a **project activation lock** (`Project.activation_state`) and is
mutually exclusive with a full scan, a partial recon run, an agent session, and the
scan scheduler — in both directions.

**Only the recon graph is versioned.** GVM/secret-scan output files, remediations,
reports and captured HTTP traffic are project-level and always reflect the latest
scan, whichever version is active.

---

## 🔮 Future Extensions (Not Implemented Yet)
- GVMScan, GVMVulnerability, DetectedProduct, OSFingerprint nodes (GVM integration - designed but not yet created by code; GVM vulns currently stored as Vulnerability nodes with source="gvm"; Traceroute nodes now implemented)
- `Screenshot` nodes linking to stored images

---
