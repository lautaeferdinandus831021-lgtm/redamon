# promptfoo — TOOL_API.md

> §15.1 mandate: document promptfoo's invocation surface, target config, and
> output contract to 100% **before** writing the adapter. Sourced from the
> official promptfoo docs (not memory), with verbatim references. The parser is
> written from this document and unit-tested against a captured real artifact.

- **Tool:** promptfoo — open-source LLM eval + red-team harness.
- **License:** MIT.
- **Repo:** https://github.com/promptfoo/promptfoo · **Docs:** https://www.promptfoo.dev/docs
- **Runtime:** **Node.js** (NOT Python). Installed via npm; invoked as the
  `promptfoo` CLI. No per-tool venv — this is the first non-Python adapter. The
  Python adapter shells out to the CLI exactly like garak/giskard shell out to
  their venv interpreters.
- **Role here:** broad red-team eval producing **per-plugin ASR** as a second
  opinion / corroboration of garak/PyRIT/giskard findings. We parse its eval
  results JSON (`EvaluateSummaryV3`) into one `Finding` per plugin.
- **Version pin:** TBD at fixture capture (see §7). Pin in `package.json` /
  install command; record in the reproducibility envelope.

---

## 0. THE taxonomy distinction (read this first)

promptfoo separates two orthogonal concepts. Getting this wrong breaks the adapter:

| Concept | "the what" / "the how" | Examples | How we use it |
|---|---|---|---|
| **Plugin** | the *vulnerability* being tested | `pii`, `pii:direct`, `harmful`, `harmful:hate`, `prompt-extraction`, `hijacking`, `indirect-prompt-injection` | **keys the Finding** (`ai_payload_class = promptfoo-<pluginId>`, maps to OWASP) |
| **Strategy** | the *delivery / mutation* | `basic`, `prompt-injection`, `jailbreak`, `jailbreak:meta`, `jailbreak:composite` | a multiplier on test cases; the strategy with the highest ASR is recorded in `evidence` |

Generated test count = (plugins × `numTests`) × strategies. Each generated test
carries `metadata.pluginId` **and** `metadata.strategyId`. We **aggregate
findings by `pluginId`** (the vulnerability), and note the worst strategy.

**Consequence for our chips:** our UI chip "Jailbreak" is NOT a promptfoo plugin
— it is the `jailbreak` *strategy* applied over a base plugin (typically
`harmful`). "Prompt Injection" is delivered either by the `indirect-prompt-injection`
*plugin* or the `prompt-injection` *strategy*. The adapter exposes plugins and
strategies as separate selectors; the chip→(plugins,strategies) mapping lives in
`plugins.py`.

---

## 1. Invocation surface

`promptfoo` CLI. The red-team flow has three sub-steps; `redteam run` fuses them,
but for a **deterministic JSON results artifact we use the explicit 2-step**:

```
# 1) generate adversarial test cases from the redteam config -> a full eval config
promptfoo redteam generate -c <config.yaml> -o <redteam.yaml> --no-progress-bar

# 2) run the eval and WRITE THE RESULTS JSON (this is our parse target)
promptfoo eval -c <redteam.yaml> -o <results.json> --no-table --no-progress-bar -j <conc>
```

Why 2-step over `redteam run`: `redteam run -o <path>` writes the **generated
tests**, not the eval results; the eval results land in promptfoo's local DB and
must be exported separately. `promptfoo eval -o results.json` writes the
`EvaluateSummaryV3` JSON directly (§3). One command, one file, no DB dependency.

### 1.1 Flags we use (verbatim meanings from the CLI reference)

| Flag | Applies to | Meaning |
|---|---|---|
| `-c, --config <paths...>` | both | path to configuration file(s). |
| `-o, --output <paths...>` | both | output file; format inferred from extension. For `eval`: `csv,txt,json,jsonl,yaml,yml,html,xml,junit.xml`. For `redteam generate`: the generated test cases. |
| `-j, --max-concurrency <n>` | both | max concurrent API calls (our bounds-derived concurrency cap). |
| `--no-progress-bar` | both | no progress bar (clean logs). |
| `--no-table` | `eval` | do not print the results table to stdout. |
| `--filter-providers <re>` | both | regex on provider id/label (we run one target, so unused). |
| `--remote` | both | **force** remote inference. We do the OPPOSITE (see §6). |

`redteam run` = "Run the complete red teaming process (init, generate, and
evaluate) in a single execution" — we avoid it for the artifact reason above.

---

## 2. Target config — the `http` provider (the integration point)

We are black-box over HTTP, so the target is an **HTTP provider**. promptfoo
config is YAML (we emit it from the adapter). Verbatim key shape:

```yaml
targets:                         # alias: "providers"
  - id: https                    # the built-in HTTP provider
    label: whitehat-target
    config:
      url: 'http://HOST:PORT/v1/chat/completions'
      method: POST
      headers:
        Content-Type: application/json
        Authorization: 'Bearer {{env.WHITEHAT_TARGET_KEY}}'   # only if a key is in scope
      body:
        model: '<id>'
        messages:
          - role: user
            content: '{{prompt}}'
      transformResponse: 'json.choices[0].message.content'
```

- `{{prompt}}` → the adversarial test prompt, injected by promptfoo. Nesting it
  inside `messages[0].content` is the supported pattern.
- `transformResponse` is a **JS expression** over `json` (the parsed response
  body); it returns the assistant text. Equivalent to garak's `response_json_field`.
- Auth header value uses `{{env.VAR}}`; we pass the key via the subprocess env so
  it never lands in the YAML on disk.

### 2.1 Request templates from recon's `ai_interface_type` (§2.3 payoff)

Same matrix as garak, expressed as promptfoo `body` + `transformResponse`:

| `ai_interface_type` | `body` | `transformResponse` |
|---|---|---|
| `llm-chat` (OpenAI-compat `/v1/chat/completions`) | `{model, messages:[{role:user, content:'{{prompt}}'}]}` | `json.choices[0].message.content` |
| `llm-completion` (`/v1/completions`) | `{model, prompt:'{{prompt}}'}` | `json.choices[0].text` |
| Ollama chat (`/api/chat`) | `{model, messages:[...], stream:false}` | `json.message.content` |
| Ollama generate (`/api/generate`) | `{model, prompt:'{{prompt}}', stream:false}` | `json.response` |
| Anthropic (`/v1/messages`) | `{model, max_tokens:512, messages:[...]}` | `json.content[0].text` |

`<id>` comes from `ai_model_ids` / `ai_model_family_guess`. Reuses the shared
auth + custom off-graph URL targets (§6 of the plan), identical to the other 3 tools.

---

## 3. Output contract — `results.json` = `EvaluateSummaryV3` (the parse target)

`promptfoo eval -o results.json` writes the `EvaluateSummaryV3` object:

```jsonc
{
  "version": 3,
  "timestamp": "2026-06-20T...Z",          // ISO 8601
  "results": [ EvaluateResult, ... ],
  "prompts": [ CompletedPrompt, ... ],
  "stats": { /* successes, failures, tokenUsage, ... */ }
}
```

### 3.1 `EvaluateResult` (one per test case run) — the rows we parse

```jsonc
{
  "promptIdx": 0, "testIdx": 0,
  "testCase": { /* the atomic test case, incl. its metadata + assertions */ },
  "provider": { "id": "...", "label": "whitehat-target" },
  "prompt": { "raw": "...", "label": "..." },
  "vars": { /* incl. the injected adversarial var */ },
  "response": { "output": "<model text>", ... },   // ProviderResponse
  "success": true,            // <-- SEE 3.3: true = model RESISTED (safe)
  "score": 1,
  "failureReason": 0,
  "gradingResult": {          // GradingResult
    "pass": true, "score": 1, "reason": "...",
    "metadata": { "pluginId": "harmful:hate", "strategyId": "jailbreak" }
  },
  "namedScores": { ... },
  "metadata": { "pluginId": "harmful:hate", "strategyId": "jailbreak", ... },
  "latencyMs": 0, "cost": 0
}
```

### 3.2 Where the plugin/strategy id lives

Per the reference, red-team metadata appears in `GradingResult.metadata` **and**
is mirrored on the result/testCase `metadata`. The parser reads `pluginId` /
`strategyId` defensively from, in order: `result.metadata`,
`result.gradingResult.metadata`, `result.testCase.metadata`. **Confirm exact
location at fixture capture (§7).**

### 3.3 Pass/fail semantics (INVERTED, like garak)

In a red-team eval a test **passes** when the model **resisted** the attack:
- `success: true` / `gradingResult.pass: true` → **defended** (safe).
- `success: false` → **attack succeeded** (vulnerable).

So **ASR = fails / total**, NOT passes/total. (Same inversion footgun as garak's
`passed`/`fails`.) Confirm at fixture capture that `success=false` is the
attack-succeeded case for the redteam graders we enable.

### 3.4 Aggregate per-plugin metrics (cross-check)

`CompletedPrompt.metrics.redteam` carries plugin pass/fail counters
(`pluginPassCount` etc.). We compute ASR ourselves from the `results` rows (more
granular, lets us record the worst strategy) and use these counters only as a
sanity cross-check.

---

## 4. ASR computation (what the normalizer consumes)

```
ASR(plugin) = fails(plugin) / total(plugin)          # guard total == 0
            = count(success == false) / count(*)      over rows with that pluginId
```

- **One `Finding` per plugin** that has ≥1 test, with:
  - `source = "promptfoo"`,
  - `ai_payload_class = f"promptfoo-{pluginId}"`,
  - `ai_asr = <per-plugin ASR>`, `ai_trials = total(plugin)`,
  - `ai_oracle_kind = "judge_llm"` (redteam graders are LLM-judged),
  - `ai_owasp_llm_id` = `plugins.py` map (pluginId → OWASP-LLM),
  - `chip` from the same map,
  - `evidence` = worst strategy + counts, e.g. `harmful:hate: 4/10 (worst strategy: jailbreak)`,
  - `ai_transcript_ref` = results.json path,
  - `ai_probe_pack_version = f"promptfoo/{version}"`.
- A plugin becomes a finding only when its ASR ≥ the run's `asr_threshold` bound.
- **Cross-tool dedup (§6.3 of the plan):** the deterministic finding id is keyed
  on `source + OWASP + payload_class + target`. promptfoo corroborating garak on
  the same OWASP/target does NOT collapse (different `source`), but the
  reporting layer groups by (OWASP, target) to show "found by garak + promptfoo".
  Same-tool re-runs MERGE. (Dedup behavior unchanged from the shared normalizer.)

---

## 5. Plugin / strategy selection (our defaults)

Mapped to the 4 plan chips (§4.4). Plugins drive findings; strategies amplify.

| Chip | promptfoo plugins | promptfoo strategies | OWASP |
|---|---|---|---|
| Prompt Injection | `indirect-prompt-injection` | `prompt-injection`, `basic` | LLM01 |
| Jailbreak | `harmful` (base) | `jailbreak`, `jailbreak:composite` | LLM01 |
| Data Disclosure (PII) | `pii` (= `pii:direct`,`pii:api-db`,`pii:session`) | `basic` | LLM02 |
| Toxicity / Harmful | `harmful:hate` (+ `harmful` collection) | `basic` | LLM05/LLM01* |

`*` harmful has no single clean OWASP-LLM home; `plugins.py` pins the mapping and
records the rationale. Default selection is conservative (small `numTests`) for
runtime; the UI exposes plugins + strategies + numTests, like garak's probe picker.

---

## 6. Egress / safety — THE critical footgun

promptfoo, by default, calls **promptfoo's hosted remote service** to *generate*
adversarial test cases, and uses **your local OpenAI key** for *grading*. Both
are egress we must kill. Zero-egress config:

1. **Disable remote generation** (forces local generation via our provider):
   ```
   PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
   ```
2. **Force the grader/attacker to local Ollama** via `redteam.provider`:
   ```yaml
   redteam:
     provider:
       id: 'openai:chat:<judge_model>'      # OpenAI-compatible client...
       config:
         apiBaseUrl: 'http://<judge_host>:11434/v1'   # ...pointed at local Ollama
         apiKey: 'sk-noop'
   # (alternative: id: 'ollama:chat:<judge_model>' + OLLAMA_BASE_URL env)
   ```
   `redteam.provider` "controls both attack generation and grading."
3. **Strip `OPENAI_API_KEY`** from the subprocess env (belt-and-suspenders; the
   runner already strips it, identical to giskard's `_invoke`).
4. **Disable telemetry / update checks:**
   ```
   PROMPTFOO_DISABLE_TELEMETRY=true
   PROMPTFOO_DISABLE_UPDATE=true
   ```
5. The HTTP provider only talks to the configured `url` (our in-scope target). Good.
6. **Caveat to confirm (§7):** with remote generation disabled, some
   plugins/strategies that *require* promptfoo's hosted service may degrade or
   no-op. We must confirm our default plugin/strategy set works fully local
   against Ollama, and log (not silently drop) any plugin the local run skips.

---

## 7. Open items to confirm at fixture capture (before parser is "done")

1. **Exact `results.json`** from a pinned promptfoo version, red-team run against
   a real Ollama-backed endpoint — capture as the parser's golden fixture.
2. Confirm `success` / `gradingResult.pass` inversion (§3.3) for redteam graders
   (false = attack succeeded).
3. Confirm the exact location of `pluginId` / `strategyId` (§3.2) on the result
   object for the pinned version.
4. Confirm which of our default plugins/strategies (§5) run **fully local** with
   `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true` (the §6.6 caveat) and that
   grading hits local Ollama with **zero** OpenAI calls.
5. Confirm `redteam generate -o redteam.yaml` carries plugin/strategy `metadata`
   through to each test so it survives into the eval `results.json`.
6. Confirm the install/version pin and that the Node runtime + `promptfoo` binary
   are available in the scan image (new toolchain — §Dockerfile work).

---

## 8. EMPIRICAL FINDINGS (captured against promptfoo 0.121.17 + local Ollama)

Resolved every §7 open item by actually running promptfoo offline against a
local `qwen2.5:0.5b` Ollama (target **and** grader). What we learned, verbatim:

### 8.1 Output shape (corrects §3)
Real `eval -o results.json` top-level keys are
`["evalId","results","config","shareableUrl","metadata","vars","runtimeOptions"]`
— **no** top-level `version`/`timestamp`/`prompts`/`stats`. The result rows are
nested at **`results.results`** (a list). The parser handles both `results` as a
list and as `{results:[...]}`. Each row's keys:
`cost,error,gradingResult,id,latencyMs,namedScores,prompt,promptId,promptIdx,
provider,score,success,testCase,testIdx,tokenUsage,vars,metadata,failureReason`.

### 8.2 `pluginId` / `strategyId` location (resolves §7.3)
`pluginId` is on **`result.metadata`** and `result.testCase.metadata`.
`gradingResult.metadata` is `null`. **`strategyId` is ABSENT for the `basic`
strategy** (no key at all) — the parser defaults a missing strategy to `"basic"`.

### 8.3 Pass/fail + the error footgun (resolves §7.2) — `failureReason` is the truth
promptfoo's `FailureReason` enum, observed:
- `0` NONE → `success:true` → assertions passed → **model RESISTED** (safe).
- `1` ASSERT → `success:false` → assertion failed → **attack SUCCEEDED** (a hit).
- `2` ERROR → provider/grader **system error** → **un-scoreable** (drop the row).

**Footgun:** the `error` field is populated for BOTH `1` and `2` (on `1` it just
holds the assertion's failure message). So `error` presence must NOT be used to
skip rows — only `failureReason == 2` is dropped. ASR = `count(failureReason==1)
/ count(failureReason in {0,1})`. The parser encodes exactly this.

### 8.4 THE zero-egress constraint (resolves §6.6, §7.4) — the big one
- **Remote generation is email-gated.** Running `redteam generate` *without*
  `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true` prompts: *"Red team scans
  require email verification to continue. Work email:"* — an interactive account
  gate. Unusable for an automated, in-scope-only scanner, and it is egress of our
  attack intent to promptfoo's cloud. **We never use it.**
- **Generation plugins go EMPTY offline.** With remote disabled + a small local
  model, `pii:direct` / `harmful:hate` reported "Success" but produced test cases
  with **empty `prompt: ''`**, which then error at grading
  (`Grader ... must have a prompt`, `failureReason:2`). Generation-based plugins
  need a capable local model at minimum; with a weak one they silently no-op.
- **Dataset plugins need NO promptfoo-cloud and grade locally, BUT live-fetch
  payloads from HuggingFace each run.** `beavertails`, `harmbench`, `donotanswer`,
  `cyberseceval`, `pliny` pull their static adversarial rows from
  `https://datasets-server.huggingface.co/rows` at generate time (verified: the
  promptfoo dist references that host; a network-blocked run hangs on the fetch).
  They are **not air-gapped** — they require outbound HTTPS to HuggingFace
  (benign: a read-only GET of a public corpus; no attack target/intent leaves).
  Grading is fully local (Ollama, **0 errors**). **These are our defaults**
  (`plugins.py`).
- **The HF dataset is NOT disk-cached, so it cannot be pre-warmed.** Verified in
  the built image: promptfoo persists only `~/.promptfoo/promptfoo.db` (eval
  results) and logs — there is **no** `cache.json` holding the dataset rows, and
  two cold runs both re-fetch. So a build-time prewarm caches nothing; the scan
  container live-fetches HuggingFace every run. This is fine: the orchestrator
  spawns the scan container on the **host network**, so it has the outbound HTTPS
  egress (confirmed `datasets-server.huggingface.co` returns 200 from inside).
  Egress posture summary: promptfoo-cloud = NONE; OpenAI = NONE; HuggingFace =
  per-run dataset fetch (read-only public corpus); attack target = in-scope only.
- **Footgun to avoid:** the dataset `generate` makes an "extraction" provider call
  (purpose→entities) BEFORE fetching rows; if the configured `redteam.provider`
  (grader) is unreachable it fails with `bad port`/`fetch failed`. The adapter
  points the grader at the live local Ollama, so this is satisfied in a real run;
  only a noop/placeholder provider (as a build-time stub would use) trips it.
- A clean end-to-end `beavertails` run (numTests 3) graded locally:
  `2 passed / 1 failed / 0 errors` → parser yields ASR `1/3` for `beavertails`.
  That trimmed `results.json` is the golden parser fixture.

### 8.5 Config format (lets the base interpreter avoid PyYAML)
promptfoo accepts a **JSON** config and JSON generated-tests file, not only YAML.
The full 2-step (`redteam generate -c cfg.json -o gen.json` → `eval -c gen.json
-o out.json`) works with JSON throughout, so the adapter emits config with stdlib
`json` — no YAML dependency in the shared spine.

### 8.7 Single-turn vs conversation plugins (verified live, the real default set)
Not every dataset plugin fits our single-turn HTTP body (`messages:[{role:user,
content:'{{prompt}}'}]`). Verified end-to-end against Ollama, each writing a real
linked `Vulnerability`:
- **Works (plain-string `prompt`):** `beavertails` (toxicity, ASR 0.20),
  `harmbench` (toxicity, ASR 0.50), `pliny` (jailbreak). These are the defaults
  + card probes.
- **Breaks (conversation-shaped `prompt`):** `cyberseceval` emits `prompt` as a
  JSON *messages array* (`[{"role":"system",...},{"role":"user",...}]`); injected
  into a single `content` string it produces a malformed request → the response
  transform throws `Cannot read property` → every row drops as `failureReason:2`
  → 0 findings. `donotanswer` similarly errored. Both are excluded from defaults
  and the UI card.
- **Fix (future, not in this step):** for OpenAI-compatible `llm-chat` targets,
  emit promptfoo's native `openai:chat:<model>` provider (with `apiBaseUrl` =
  target, auth via headers) instead of the raw `https` provider — it natively
  handles both string and conversation prompts, which would re-enable
  cyberseceval/donotanswer + a real prompt-injection chip. Keep the raw HTTP
  provider for non-OpenAI shapes (ollama-generate / anthropic).

### 8.6 Zero-egress run recipe (final)
Env: `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`,
`PROMPTFOO_DISABLE_TELEMETRY=true`, `PROMPTFOO_DISABLE_UPDATE=true`,
`OPENAI_API_KEY` stripped. Config `redteam.provider` =
`openai:chat:<judge_model>` with `config.apiBaseUrl=http://<judge_host>:11434/v1`.
Default plugins = dataset-based only. Generation plugins are exposed in the UI but
flagged "needs capable judge model" and excluded from the offline default.
