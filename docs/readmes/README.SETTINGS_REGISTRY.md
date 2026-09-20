# The recon settings registry

Every parameter of the recon pipeline is described once, in
[`recon_settings/registry.yaml`](../../recon_settings/registry.yaml). Before it,
the same facts lived in eighteen places kept aligned by hand.

This page is why it exists and what it guarantees. For the parameters
themselves, read the generated
[Project Settings Registry](https://github.com/samugit83/redamon/wiki/Project-Settings-Registry)
wiki page; for how to add one, the `project-settings-cascade` skill.

---

## The split

Prisma stays the source of truth for the database, so it owns which columns
exist, their type and their `@default()`. The registry never restates any of
those: the build joins them. Copying a default in would create a third
definition of a value that already has two, which is the drift this removes
rather than adds.

| Lives in | Holds |
| --- | --- |
| `webapp/prisma/schema.prisma` | existence, type, `@default()`, `@map` |
| `recon_settings/registry.yaml` | `runtime_key`, `bounds`, `validator`, `zero_means`, `fallback`, `coerce`, `unit`, `tool`, `phase`, `traffic`, `roe_capped`, `governor`, `stealth`, `mcp`, `readable`, `meaning`, and the `tools:` blocks |
| a Postgres row | one project's actual values |

Descriptions never enter the database. A description is identical for every
project, so it is metadata about the schema rather than data about a project;
storing it in Postgres would mean a migration to fix a typo and would force the
recon pipeline — Python, in a container spawned per scan — to take a database
dependency just to know what a field means. It also preserves a property the MCP
surface advertises: `describe_recon_settings` answers when Postgres and Neo4j
are both down.

```
schema.prisma  ──> column + @default() ──┐
                                          ├──> the settings a scan runs with
Postgres row   ──> this project's values ┘

registry.yaml ──build──> registry.json ──> describe_recon_settings   (no DB)
                                      ├──> the MCP write validation
                                      ├──> the engagement rate cap
                                      ├──> the memory governor tables
                                      ├──> the stealth profile
                                      ├──> the /defaults payload
                                      ├──> the queued-job fingerprint
                                      └──> the generated wiki reference
```

## The build

```bash
python3 tooling/scripts/extract_recon_registry.py   # draft entries for new columns
python3 recon_settings/build.py                     # YAML -> JSON, validated
python3 recon_settings/build.py --check             # what the gate runs
cd webapp && npm run docs:settings                  # regenerate the wiki page
```

Two artifacts, one build: `recon_settings/registry.json` for Python and
`webapp/src/lib/reconSettings/registry.json` for TypeScript. Two copies exist
because a scan container mounts `recon/` and never `webapp/`, and the webapp
build tree cannot import across its own root. They are byte-compared by a test,
so they cannot diverge.

The extractor is a TOP-UP, not a generator. It is idempotent: anything already
curated wins, and only what is missing is filled in. Everything it drafts is a
starting point, because no extraction can tell whether a `meaning` is TRUE or
whether a bound is right.

## Three keys that exist because uniformity is a lie

520 of the 525 settings mappings are byte-identical in form, which is what makes
this tractable. The other five carry semantics a naive generator would erase.

**`zero_means: unlimited`.** Five rate fields treat `0` as unlimited, which is
the FASTEST value available rather than the slowest: `ffufRate`,
`arjunRateLimit`, `purednsRateLimit`, `webCachePoisonMaxRpsPerHost` and the
column-less `ORIGIN_DISCOVERY_RATE`. Two failures follow from missing it.
Writing `bounds: {min: 1}` makes the shipped default unrepresentable, so a
caller cannot restore it. And an agent reading `unit: rps` with no further hint
will reasonably conclude 0 is the gentlest setting, then write it onto a 3 rps
engagement and run unlimited — a scope violation produced by the documentation.
So the `meaning` repeats it in words, and a build test checks that it does.

**`fallback: falsy`.** `project.get(k, D)` returns a stored `0` or `""`;
`project.get(k) or D` replaces any falsy value with the default. Three mappings
use the second form, so an operator who sets an empty list gets the default back
rather than an empty list.

**`coerce: int | strip`.** `FOFA_MAX_RESULTS` and `UNCOVER_MAX_RESULTS` wrap in
`int()`; `TARGET_DOMAIN` calls `.strip()`. Small, and the code has to do it.

## Ordering is load-bearing

`recon/project_settings.py` documents its own pass order:

> Applied AFTER stealth/RoE so those low-resource profiles win first, then the
> governor tightens further under live memory pressure.

A change that reorders stealth, the RoE capper and the memory governor produces
different effective settings with nothing failing. The golden master is what
proves it did not.

## The golden master

`recon/tests/test_golden_master.py` resolves twenty-two synthetic projects
through the full settings path and compares every key and value against a
committed baseline. Comparing generated FILES catches almost nothing: a
generator can emit a perfectly plausible mapping that is byte-different in a way
no diff flags, and every risk here shows up only in the VALUE a scan runs with.

Each case catches a named risk: every numeric at its minimum, at its maximum and
at zero; every list and string empty; RoE on with a 3 rps ceiling and RoE off;
stealth alone and stealth with RoE; IP mode and domain-batch mode; a hostile
container image; an escaping wordlist path.

Baselines are regenerated only by an explicit script, never by a test run,
because a baseline a test can rewrite is not a baseline:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/repo" -w /repo/recon \
  -e PYTHONPATH=/repo:/repo/recon -e HOME=/tmp --entrypoint sh whitehat-recon \
  -c 'python /repo/recon/tests/regen_golden_settings.py'
git diff recon/tests/fixtures/golden_settings/
```

Every line of that diff is a value some scan will run with. `-u` is not
optional: without it the container writes the baselines as root and the host
cannot rewrite them afterwards.

## What the tests guarantee, precisely

The structure cannot drift. The content still needs a human reading it: no test
can verify that a `meaning` is true, and a field documented as "requests per
second" that is really a thread count passes every one of them. The same goes
for a bound that is wrong but within type — `max: 10000` on a tool that breaks
above 500 is green everywhere.

What they do catch:

| Layer | What fails the build |
| --- | --- |
| self-consistency | a duplicate runtime key, an out-of-enum value, `min >= max`, a name whose unit disagrees with it, an active `rps` field with no engagement cap, a settable field with no bound or validator |
| against Prisma | a column with no entry, an entry with no column, a default outside its own bounds, a numeric defaulting to 0 with no `zero_means` |
| runtime | every capped rate at its extremes and at zero resolving at or below the ceiling, every image field pinning a hostile value, every path field dropping an escaping one, the governor never raising what an earlier pass lowered |
| composition | every field `describe_recon_settings` advertises accepting a real write, every field it does not advertise being refused BY NAME, every disposition behaving as documented in both directions |
| tool surfaces | an image nothing pulls, a module that does not import, an isolated wrapper that is not callable, a form section that does not exist, a graph label no tool produces |
| docs | the wiki reference regenerating byte-identically, the narrative page's parameter count matching the registry, no scope blurb making a claim the registry contradicts |

The composition tier is the highest-value one, and the reason is worth stating:
every layer can be individually truthful while the COMPOSED answer misleads the
caller. `describe_recon_settings` can correctly report a registry that
`filterReconSettings` correctly enforces, and the pair can still disagree about
one field — which an agent discovers by being refused for something it was just
told it could do.

## What this closed

Three live defects, each invisible from every angle except the resolved value.

**The engagement rate ceiling had three bypasses.** The capper walked a
hardcoded list of fifteen runtime keys. `takeoverRateLimit` and
`jsluiceVerifyRateLimit` were settable over MCP and in neither that list nor the
zero-handling set, so a token holding only `recon:settings` could run 500 and
1000 rps against a project whose operator had set 3. `purednsRateLimit` WAS in
the cap list, which made it look covered: its default is 0, 0 means unlimited,
and `0 > 3` is False. `webCachePoisonMaxRpsPerHost` has the same default and was
in neither. Both lists are registry queries now, and an `rps` field with
`traffic: active` and no `roe_capped` fails the build.

**A project had no rate ceiling unless someone switched one on.** `roeEnabled`
defaults false and `roeGlobalMaxRps` defaults 0. Survivable while three of
fifteen rate fields were reachable; load-bearing once all of them are.
`engagementKind` closes it for new projects: a `third_party` engagement must
carry a non-zero ceiling AND a record of what authorized it, and `start_recon`
refuses otherwise — at the shared start path, so the scheduler and the queue
dispatcher are covered too. Existing rows read as `internal` and are flagged
rather than blocked, because turning the whole estate red at once is not a fix.

**`/defaults` sent nine keys under names no column has.** A snake-to-camel
conversion cannot recover an intercap, so `CRIMINALIP_ENABLED` became
`criminalipEnabled`. Those settings never reached a new project form at all, and
the ProjectForm's workaround for the adjacent bug — only applying a key already
present — is what hid it. The column name comes from the registry now.
