---
name: add-partial-recon
description: >
  Adding partial-recon support for a tool: running a single pipeline phase
  on demand from the workflow graph, reading its inputs from the existing Neo4j
  graph and merging results back. The input-node map decides the modal UI, and
  some input types must never be manually entered.
  Trigger: adding a tool to partial recon; a new recon/partial_recon_modules/*.py;
  editing SECTION_INPUT_MAP in nodeMapping.ts; wiring the partial-recon modal or a
  single-phase re-run.
license: MIT
metadata:
  author: whitehat
  version: "1.0.0"
  scope: [recon]
  auto_invoke:
    - "Adding partial-recon support for a recon tool"
    - "Editing SECTION_INPUT_MAP or the partial-recon modal wiring"
---

## When to Use

- Making an existing recon tool runnable as a single on-demand phase from the graph.

For adding the tool to the full pipeline, use `recon-tool-integration`. For the
graph write itself, use `graph-db-writes`. This skill is the partial-recon path:
graph-sourced inputs, the modal, and the single-phase re-run.

---

## Critical Rules

- **NEVER let partial-recon results create duplicate nodes.** Partial runs merge
  into the **existing** graph and must dedup via `MERGE` on the tenant triple -
  see `graph-db-writes`. Partial and full share the same graph.
- **NEVER expose a graph-only input type as a manual textarea.** `SECTION_INPUT_MAP`
  in [nodeMapping.ts](../../webapp/src/components/projects/ProjectForm/nodeMapping.ts)
  lists what the tool reads from the graph, but only the types that make sense for
  manual entry get a user field. Types like `Port` and `Endpoint` come from the
  graph only and must not be hand-entered.
- **ALWAYS wire the shared entry so it works in BOTH the full pipeline AND partial
  recon.** Partial recon is spawned as a **separate** container from the full
  pipeline (`recon_orchestrator/container_manager.py`); hook the shared entry
  function once so both inherit (see `recon-ai-enrichment` for the same rule).
- **ALWAYS mirror the reference impl matching your tool's input shape**, not an
  arbitrary one: Naabu (`Subdomain` + `IP`), Masscan (`IP` only), Nmap
  (`IP` + `Port`), Katana (`URL`). The input-node shape drives the whole wiring.

---

## Input-node shape -> reference impl

| Tool reads | User enters | Mirror |
| --- | --- | --- |
| Subdomain + IP | Subdomain + IP (two textareas) | Naabu |
| IP only | IP (one textarea) | Masscan |
| IP + Port | IP (Port from graph) | Nmap |
| BaseURL | URL (maps to a BaseURL node) | Katana |

## Commands

```bash
# recon/*.py is spawned fresh per job (volume-mounted) - no rebuild
./whitehat.sh test unit                    # recon + root-recon sections
```

## Resources

- [docs/readmes/coding_agent_prompts/PROMPT.ADD_PARTIAL_RECON.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_PARTIAL_RECON.md) - full walkthrough, modal UI, input validation, reference impls
- Related skills: `recon-tool-integration`, `graph-db-writes`, `recon-ai-enrichment`
