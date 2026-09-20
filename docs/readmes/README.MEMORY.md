# RedAmon Agent Memory

Persistent, project-scoped memory for the agent, with an automatic capture
pipeline, a self-improvement pass, and an auditable timeline.

It follows the model of [agentmemory](https://github.com/rohitg00/agentmemory)
— observations with confidence scoring and a lifecycle, a knowledge graph of
entities, hybrid recall, auto-capture hooks — implemented agent-side so it needs
no new dependency in the baked `redamon-agent` image and no external service to
work.

```
agentic/
  memory/                      the subsystem (stdlib only)
    config.py                  env-driven settings, read at CALL time
    models.py                  MemoryRecord / MemoryEvent + the event vocabulary
    scoring.py                 priors, reinforcement, half-life decay, states
    store.py                   SQLite: memories + events + graph edges
    search.py                  BM25 keyword recall + entity/graph fusion
    timeline.py                rendering (project / one memory / self-improvement)
    self_improve.py            reflect: distil, promote, resolve contradictions
    auto_update.py             capture -> reinforce -> decay -> reflect
    entities.py                entity extraction (graph nodes)
    agentmemory_client.py      optional best-effort mirror to an agentmemory server
  memory_tools.py              the 4 agent tools (in-process, non-MCP)
  memory_hook.py               the 4 seams into the agent loop
```

## Why it lives agent-side

Memory is RedAmon's own operational record. Routing it through the target-facing
Kali worker would put it in the least-trusted zone for no benefit, and a Prisma
project setting would be invisible on every EXISTING project (`fetch_agent_settings`
replaces the stored settings blob rather than merging it). So: an in-process
module over SQLite, configured by environment, phase-agnostic at runtime.

## The four tools

| Tool | What it is for |
| --- | --- |
| `memory_recall` | Search what this project already learned. Run it FIRST in a session and before re-deriving anything. `scope`: auto / facts / lessons / playbook / tools / notes. |
| `memory_save` | Write a durable note for future sessions — an operator preference, a conclusion, a confirmed dead end. Not raw tool output (captured for you). |
| `memory_timeline` | When memory changed: created / reinforced / decayed / promoted / archived / self_improve, with confidence deltas. Scope `memory` = one memory's full life; `self_improvement` = only self-review. |
| `memory_reflect` | Run a self-improvement pass now. Also runs on its own. |

Recalled text is wrapped in the unforgeable `<<<UNTRUSTED_MEMORY ...>>>` boundary
(`prompt_safety.wrap_untrusted`): it contains digests of output a scanned target
influenced, so it is data, never instructions.

## Session seams

Both ends of a session are wired into the graph:

* **Start** — `initialize_node` recovers the playbook digest once per session
  (`memory_hook.session_context_text`, wrapped as untrusted data), stores it on
  the state, and `think_node` prepends it to every system prompt for the rest of
  the session. It sits below the stealth rules and the report discipline in
  priority.
* **End** — `generate_response_node` (the terminal node) runs
  `memory_hook.session_end_pass`: decay, then a reflection pass. A run cancelled
  before reaching it (Stop, deleted conversation, emergency stop) is covered by
  the cancellation path in `websocket_api._run_orchestrator_query`.

Both are fail-open, and the digest is empty (so nothing is injected) when memory
is off or the project has learned nothing yet.

## Auto-update (capture)

Every tool outcome is captured — after the embedded-error flip and the error
classification have run, so a `success=True` with a Playwright timeout inside is
remembered as the failure it is. The hook is wired in **both**
`execute_tool_node.py` and `execute_plan_node.py`; those files duplicate that
tail, and capturing only one makes memory work interactively while silently
losing plan-wave outcomes.

What is stored is the SHAPE of the call: tool, phase, success, and a compressed
digest (ANSI stripped, spinner noise dropped, error/vuln/credential-ish lines
kept first, bounded length). A full tool response can be megabytes of target
data; keeping it verbatim would make memory a second copy of every scan.

Each observation also:

* **reinforces** a matching memory instead of adding a near-duplicate (same
  project + kind + normalized text = one row, higher confidence, higher rank);
* **links** to recently related memories when they share entities, which is what
  lets a later recall reach a memory with no keyword overlap;
* **counts** toward the periodic reflection pass.

`fs_*`, `job_*` and `memory_*` calls are deliberately not captured: housekeeping
would drown the record, and a memory tool observing itself would make memory
traffic its own dominant content.

## Lifecycle and confidence

* Priors by kind: a distilled lesson starts above a raw observation.
* Reuse raises confidence proportionally to the remaining headroom (asymptotic,
  never a linear ramp to 1.0).
* Idle memories decay on a half-life (`MEMORY_DECAY_HALF_LIFE_DAYS`, default 30d);
  a decay never drives confidence to exactly 0. Decay runs on a sweep, not on the
  capture counter: at session end and on an explicit `memory_reflect`. A sweep
  applies only the idleness no earlier sweep accounted for, so a project with
  several sessions in one day does not decay several times for one idle day.
* States: `candidate` → `active` → `archived`. An archived memory is never
  resurrected by decay alone — but seeing the same observation again revives it
  as a candidate, because a repeat is evidence it was archived too early.

## Self-improvement

Deterministic, no LLM call, every conclusion auditable against the timeline:

1. **Distil** — per-tool reliability from captured outcomes ("execute_nuclei
   failed 4/5 recent calls here"). Fewer than 3 attempts is not a conclusion, and
   the middle band (20–60% failure) stays silent: "about half the time" is noise.
2. **Promote** — a lesson/note recalled 3+ times with confidence ≥ 0.5 graduates
   to `playbook`, the tier the session-start digest injects and
   `memory_recall(scope="playbook")` answers from.
3. **Resolve contradictions** — two lessons about one subject with opposite
   polarity cannot both be true; the weaker is ARCHIVED, never deleted, so the
   reversal stays visible on the timeline.
4. **Mark the pass** — a `self_improve` event, so lessons never appear from
   nowhere.

## Timeline

Append-only. Every mutation writes an event, so the timeline keeps what the
current text no longer shows: a confidence that was once 0.9 and decayed, a
lesson superseded by its opposite, what each reflection pass changed. Truncation
drops the oldest entries and says how many — a silent truncation would read as
"that is the whole history".

## Optional: mirror to an agentmemory server

The local store is always the source of truth. Set `AGENTMEMORY_URL` to also
write memories to a running agentmemory server (REST, default port 3111) and, on
`memory_recall(include_mirror=true)`, import anything it has that this project
does not. Imported hits are joined by `redamon_memory_id` so a mirror round-trip
cannot inflate a memory's use count.

Every mirror call is best-effort and never raises: an unreachable second memory
server is not a reason for an agent tool call to fail.

## Configuration

Read from the environment at call time (no rebuild-time coupling):

| Variable | Default | Meaning |
| --- | --- | --- |
| `MEMORY_ENABLED` | `true` | Master switch |
| `MEMORY_AUTO_UPDATE` | `true` | Auto-capture tool outcomes |
| `MEMORY_SELF_IMPROVE` | `true` | Run reflection passes |
| `MEMORY_SELF_IMPROVE_EVERY` | `10` | Observations between periodic passes (0 turns the periodic pass off; the session-end pass still runs) |
| `MEMORY_DB_PATH` | `/workspace/.memory/memory.db` | Store location (falls back to `~/.redamon/memory/`) |
| `MEMORY_RECALL_LIMIT` | `8` | Default recall size |
| `MEMORY_DECAY_HALF_LIFE_DAYS` | `30` | Idle half-life |
| `MEMORY_REINFORCE_BOOST` | `0.15` | Confidence gained per reuse |
| `MEMORY_ACTIVE_MIN_CONFIDENCE` | `0.35` | Promotion threshold |
| `MEMORY_ARCHIVE_MAX_CONFIDENCE` | `0.15` | Archival threshold |
| `MEMORY_ARCHIVE_AFTER_DAYS` | `120` | Idle days before a weak memory is archived |
| `MEMORY_MAX_INJECT_CHARS` | `3000` | Playbook digest size |
| `MEMORY_OBSERVATION_MAX_CHARS` | `600` | Stored observation length |
| `MEMORY_TOOL_OUTPUT_CHARS` | `400` | Digest length per tool call |
| `AGENTMEMORY_URL` | *(unset)* | Enables the mirror when set |
| `AGENTMEMORY_TOKEN` | *(unset)* | Bearer token for the mirror |
| `AGENTMEMORY_SAVE_PATH` / `AGENTMEMORY_RECALL_PATH` | `/memories`, `/memories/search` | Mirror endpoints |

## Testing

```bash
./agentic/run_tests.sh              # the gate, inside redamon-agent
```

* `tests/test_memory_core.py` — store, dedup/reinforcement, tenant isolation,
  scoring/lifecycle, hybrid search, entities, timeline (stdlib only).
* `tests/test_memory_self_improve.py` — distillation thresholds, promotion,
  contradiction archival, timeline marker (stdlib only).
* `tests/test_memory_agent_surface.py` — registry completeness, phase access,
  the prompt renderers actually offering the tools, the tool coroutines, the
  hook wiring in both execute nodes, and the two session seams: the digest
  recovered at init (project-scoped, wrapped as data, empty for a new project)
  and the end-of-session pass, including that a second sweep in the same day
  does not decay twice (agent dependency set).

`agentic/` is baked into the image: after any change here,
`docker compose build agent && docker compose up -d agent`.

## Related

* Root ruleset: [`AGENTS.md`](../../AGENTS.md); component rules: [`agentic/AGENTS.md`](../../agentic/AGENTS.md)
* How to actually use it in a session, inspect the store and tune it: [`README.USAGE.md`](README.USAGE.md)
* The evidence/report discipline layer that reviews what this memory recovered: [`README.REPORT_KIT.md`](README.REPORT_KIT.md)
* Adding a tool the agent can call: skill `agentic-tool-integration`
* Per-project settings cascade (if memory ever becomes a UI toggle): skill `project-settings-cascade`
