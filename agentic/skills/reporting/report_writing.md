---
name: Report Writing
description: Structure and per-section format for a penetration-test finding report, with the sections to omit. Use when writing up a confirmed finding, checking a draft's structure, or reviewing a report that is missing sections.
---

# Report Writing

Use this when a finding is confirmed and it needs to be written up. The job is to
shape the draft from **facts that were actually gathered** — the request, the
response, the observed effect — and to ask rather than fill the gap when
something is missing.

The machine-checkable half is `report_review(mode="structure")`; the evidence bar
itself is always on, so nothing here overrides it.

> Scope: this structures what was proven on the engagement. It does not raise a
> finding's severity, and it does not turn a lead into a finding.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Pull the recorded evidence | `query_graph` | Findings, endpoints, parameters and their properties — the report must match what is recorded. |
| Replay the PoC | `execute_curl` | Raw request/response beats prose; quarantine the exact call you will paste. |
| Read staged artifacts | `fs_read` / `fs_list` | Screenshots, saved responses and payload files under the workspace. |
| Capture visual proof | `execute_playwright` | When the finding is visual (alert dialog, rendering, UI state). |
| Check the structure | `report_review` | `mode="structure"` returns the sections below; `mode="triage"` verdicts the draft. |

## Required body sections (in order)

1. **Description**
2. **Discovery**
3. **Proof of Concept (PoC)**
4. **Exploitation**
5. **Impact**
6. **Remediation** *(optional)*
7. **References** *(usually omit)*

If a required section has no content, say what evidence is missing instead of
writing around the gap.

---

## 1. Description

- 1-3 sentences: what the bug is, factual and specific.
- Do not define the vulnerability class here and do not paste a CWE line — the
  class metadata carries the CWE.

```
Good: Reflected XSS in /search via the q parameter. The parameter is echoed
      unescaped into the HTML response body.
Bad:  A 5-line explanation of what XSS is, ending in (CWE-79).
```

## 2. Discovery

- The testing narrative: what you tried, what you noticed, what made you dig in.
- Lab-notes style. Dead ends and friction are credible signals — keep them.

```
Good: Fuzzing the search endpoint, I noticed <script> was filtered but
      <svg/onload=...> was not. Once I confirmed the reflection landed in the
      HTML body, I tested alert(document.domain) to check same-origin execution.
Bad:  A polished narrative with no failed attempts and no dead ends.
```

## 3. Proof of Concept (PoC)

- Raw HTTP request/response preferred — the reader can paste it into Repeater.
- A complete `execute_curl` command is acceptable: headers, cookies, body.
- Screenshot when the proof is visual, always paired with the request that
  produced it.
- Sanitize: `[REDACTED]` for session tokens, third-party PII and unrelated
  headers. Sanitize, never fabricate.
- Include only the requests strictly necessary to reproduce — cut recon noise.
- Do not wrap the PoC in a script unless it genuinely needs one (a multi-step
  chain, a timing window, thousands of iterations). For a bug provable in one or
  two requests, the raw requests are the better artifact.

A PoC is valid only if a reader with zero prior context can replay it from
scratch.

## 4. Exploitation

- Numbered steps, one observable action each, no inference required.
- State preconditions up front: anonymous or authenticated, which role, required
  victim interaction, browser/environment.
- Show expected vs actual at the step where the bug manifests.

```
Preconditions: standard authenticated user (any role), no special privileges.

1. Send GET https://target.tld/search?q=<svg/onload=alert(1)>
2. Observe: alert(1) fires in the response page.
   Expected: the payload HTML-encoded in the response.
```

## 5. Impact

- Only what was demonstrated, bottom-up from the PoC: "I executed X, observed Y
  at Z."
- No "could", "may", "potentially", "with the right conditions".
- If only reflection was proven, do not claim execution.
- Never longer than the PoC.

```
Good: Arbitrary JS execution in the victim's browser in the target.tld origin.
      I demonstrated reading document.cookie and exfiltrating it to a
      controlled endpoint (PoC step 4).
Bad:  Could lead to full account takeover and exfiltration of sensitive data.
```

## 6. Remediation (optional)

Include only when the fix is specific to this code path or is trivially correct
("HTML-encode the `q` parameter before reflection in /search"). Generic advice
("validate user input", "use parameterized queries") adds nothing — omit it
instead of padding.

## 7. References (optional, usually omit)

Add only for a specific vendor advisory or the exact write-up a chain relies on.
One line per reference, no commentary. The class/CVE metadata already covers the
rest.

---

## Metadata fields

- **Title** — `<class> in <location> via <param/header>`, under 100 characters,
  no marketing words.
- **Affected asset** — the exact URL/host/component tested, verified against the
  configured target (not a lookalike, not a sister domain).
- **Severity / CVSS** — CVSS 3.1, **base metrics only**. Give the full base
  vector and justify each metric from what was verified. Leave Temporal and
  Environmental metrics out; `report_review(mode="cvss")` scores the vector and
  flags metric/precondition mismatches.

## Sections to omit

- Introduction / Background (collapse into Description)
- Executive summary (Description covers it)
- Multi-paragraph CWE/OWASP explanations
- Conclusion (the report ends at the last real section)
- Acknowledgements / About the researcher
- Generic mitigation paragraphs

## Anti-patterns to check before completing

- Sections present but empty, `TBD`, or "see PoC".
- Steps that say "trigger the vulnerability" instead of an observable action.
- Impact longer than the PoC.
- A severity vector that contradicts the stated preconditions.
- Repro steps that reference a screenshot instead of giving the request.

## Hard rules

- Draft from the facts gathered for THIS engagement; never extrapolate to fill a
  gap. If the URL, payload, response or observed behaviour is not in hand, ask
  for it or mark it unverified.
- Never fill an empty section with plausible text — empty is honest.
- Do not auto-add Remediation or References just because a slot exists.
- When asked "is this ready?", the answer comes from `report_review(mode="triage")`,
  not from optimism.
