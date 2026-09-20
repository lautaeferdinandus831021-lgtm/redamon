# RedAmon Report Discipline (report_kit)

The evidence bar the agent is held to while it investigates and when it writes
up: never invent facts, never claim impact that was not demonstrated, prove the
primitive instead of exercising it, and score CVSS 3.1 with base metrics only.

It follows the model of YesWeHack's
[claude-kit](https://github.com/yeswehack/claude-kit) — an always-on discipline
layer plus on-demand `write` / `triage` / `gotchas` skills — implemented
agent-side so it needs no new dependency in the baked `redamon-agent` image and
no external service to work.

```
agentic/
  report_kit/                  the subsystem (stdlib only)
    config.py                  env switches, read at CALL time
    rules.py                   always-on discipline + the report structure
    gotchas.py                 per-class minimum proof / common N/A / overclaim traps
    cvss.py                    CVSS 3.1 base scoring + metric-vs-evidence checks
    slop.py                    deterministic AI-slop detection
    triage.py                  verdict + buckets, and the renderer
  report_tools.py              the report_review tool (in-process, non-MCP)
  report_hook.py               the four seams into the agent loop
  skills/reporting/            the on-demand skills (write / triage / gotchas)
```

## Why it lives agent-side

Report discipline is the agent reviewing its own work: it reads a draft the
agent itself composed and sends no traffic at all. Routing it through the
target-facing Kali worker would put it in the least-trusted zone for no benefit,
and a Prisma project setting would be invisible on every EXISTING project
(`fetch_agent_settings` replaces the stored settings blob rather than merging
it). So: an in-process module over the environment, phase-agnostic at runtime.

## The three surfaces

| Surface | Where | What it does |
| --- | --- | --- |
| Always-on rules | `think_node` prepends `DISCIPLINE_RULES` to the system prompt | The bar applies while the agent is still investigating — the reference's session-start hook, expressed in the agent loop. |
| Report-time block | `generate_response_node` appends `build_report_block(...)` to the full-report prompt | Report structure + the gotchas for the class this session worked on. |
| `report_review` tool | registered by the orchestrator, listed in every phase | The agent can run `triage` / `gotchas` / `structure` / `cvss` on a draft mid-session. |
| On-demand skills | `agentic/skills/reporting/*.md` | `write`, `triage` and `gotchas` as loadable skills, in the same catalog as every other agent skill. |

## The four modes of `report_review`

| Mode | Use it for | Returns |
| --- | --- | --- |
| `triage` | Before `action="complete"` on a session that reports a finding | The reference's verdict block: `VERDICT: READY TO SUBMIT / NEEDS FIXES / DO NOT SUBMIT`, Critical / Major / Minor fixes, and what to keep. |
| `gotchas` | Before claiming a class | Minimum proof, common auto-close (N/A) patterns and overclaim traps for that class. |
| `structure` | When the write-up has no shape yet | The required sections in order, per-section rules, and the sections to omit. |
| `cvss` | When a severity is claimed | The CVSS 3.1 base score, plus a flag for every metric that contradicts a precondition you stated. |

It never rewrites the draft. Every answer names what is unsupported and what
would fix it — a review that silently turns an unverified claim into plausible
prose is the exact failure the layer exists to prevent.

## What the triage pass checks

1. **Scope.** With the program's scope text supplied, hosts named in the draft
   are matched against it; a host that is not in scope is a DO NOT SUBMIT. With
   no scope supplied the pass reports *itself* unverified rather than assuming
   the asset is in scope. (Example/documentation hosts are ignored, and a draft
   naming more than five hosts gets one instruction to check them all rather
   than a wall of noise.)
2. **Slop.** Deterministic text rules ported from the reference's AI-slop
   checklist: theoretical-only impact, invented-fact shapes (unverified CVEs,
   unfingerprinted versions), placeholder PoCs, structural tics
   (Introduction/Background/Conclusion around a one-step bug), OWASP
   boilerplate, and "impact claimed with no matching evidence anywhere in the
   draft". Negation is honoured, so an honest "we did not achieve X" is not a
   claim.
3. **PoC quality.** A draft with no replayable request, response, curl command
   or fenced block has no PoC — that is Critical, not a style note.
4. **CVSS.** Base score from the official formula, Temporal/Environmental
   metrics flagged as the reader's to weigh, and the four mismatches that
   matter: `PR:N` against a real auth gate, `UI:N` when the victim must act,
   `S:C` without a trust-boundary crossing, `AC:L` on a non-guessable
   identifier.

The verdict follows claude-kit's rule: any Critical → DO NOT SUBMIT, any Major
→ NEEDS FIXES, otherwise READY TO SUBMIT with the list of what to keep.

## The report self-check

After the final report is generated, the same triage pass runs over it and is
appended as a fenced `## Report self-check` section — **only when it found
something**, and never for the `summary` / `conversational` tiers. It is a
machine review of the report, not part of the finding, so the reader can see
which claims are still unproven instead of taking them on trust.

## Configuration

Read from the environment at call time (no rebuild-time coupling). The agent
service has an `env_file`, so a value set in `.env` reaches it:

| Variable | Default | Meaning |
| --- | --- | --- |
| `REDAMON_REPORT_DISCIPLINE` | `true` | Inject the always-on rules into the think prompt |
| `REDAMON_REPORT_DISCIPLINE_REPORT_BLOCK` | `true` | Append structure + gotchas to the report prompt |
| `REDAMON_REPORT_DISCIPLINE_AUTOCHECK` | `true` | Append the machine self-check to the finished report |
| `REDAMON_REPORT_DISCIPLINE_MAX_FLAGS` | `12` | Cap on flags the self-check renders |

## Testing

```bash
./agentic/run_tests.sh              # the gate, inside redamon-agent
```

* `tests/test_report_kit.py` — the rules text, the class reference and its
  attack-path mapping, CVSS scores (`9.8`, `10.0`, `3.1`, `0.0`) and metric
  mismatches, the slop rules including their negation handling, and triage
  verdicts for a clean draft, an out-of-scope host and a sloppy one.
* `tests/test_report_kit_agent_surface.py` — registry completeness, phase
  access, the menu renderers actually offering the tool, every mode of the tool
  through the real coroutine and through `PhaseAwareToolExecutor`, the fail-open
  seams, the node wiring, and that the three reporting skills are discoverable
  through the real skill loader.

`agentic/` is baked into the image: after any change here,
`docker compose build agent && docker compose up -d agent`. New skill files are
discovered at runtime from the baked directory; no code change is needed to add
another one.

## Related

* Root ruleset: [`AGENTS.md`](../../AGENTS.md); component rules: [`agentic/AGENTS.md`](../../agentic/AGENTS.md)
* How to actually use it in a session (the four modes, the skill import, the switches): [`README.USAGE.md`](README.USAGE.md)
* The agent's persistent memory, which this layer complements: [`README.MEMORY.md`](README.MEMORY.md)
* Adding a skill the agent loads on demand: skill `add-community-skill`
* Adding a tool the agent can call: skill `agentic-tool-integration`
