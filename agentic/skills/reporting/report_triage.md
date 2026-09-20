---
name: Report Triage
description: Self-validates a finding or report draft before it is submitted, returning a verdict (READY TO SUBMIT / NEEDS FIXES / DO NOT SUBMIT) with concrete fixes. Use before completing a session that reports a finding, or before claiming a class.
---

# Report Triage

Adopt the stance of a strict senior triager reviewing the draft **before**
submission. Catch what a real triager would catch, while the evidence is still
in reach and the claim can still be fixed or dropped.

The machine pass is `report_review(mode="triage")` — it is deterministic, so the
verdict is reproducible and every flag points back at the phrase that caused it.
This skill is the reasoning behind it: what to look at, in what order, and what
each verdict means.

> Scope: triage judges what the draft demonstrates. It never rewrites the draft
> and never awards credit for evidence that is not in it.

## Required inputs

- The draft: the finding or report text.
- The program's scope page / rules of engagement.

If the scope is missing, **say so** — do not infer it from a domain name. Run the
pass with `report_review(mode="triage", scope="...")` when it is available;
without it the scope verdict is explicitly unverified rather than assumed clean.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Run the verdict | `report_review` | `mode="triage"`, pass `draft` + `scope`; add the precondition flags you established. |
| Score / check the vector | `report_review` | `mode="cvss"` plus `auth_gate`, `victim_interaction`, `trust_boundary`, `non_guessable_id`. |
| Check a class claim | `report_review` | `mode="gotchas"` for the minimum proof of the class claimed. |
| Confirm what is recorded | `query_graph` | A claim the graph contradicts is a drafting error, not a finding. |
| Re-verify a claim | `execute_curl` | Cheaper than shipping an unverified sentence: replay it and paste the response. |

## Output format

```
VERDICT: [READY TO SUBMIT | NEEDS FIXES | DO NOT SUBMIT]

## Critical (blocks submission)
- [issue] -> [fix]

## Major (needs fixing)
- [issue] -> [fix]

## Minor (cleanup)
- [issue] -> [fix]

## What's good
- [things to keep]
```

`report_review` returns exactly this shape, plus the base score when a vector is
present. Omit empty sections except `VERDICT` and `What's good`.

## Triage flow

Run the checks in this order. Stop early only when a critical scope failure makes
the rest moot.

### 1. Scope

**Critical (DO NOT SUBMIT)**

- The asset (domain, IP, app) is not in the in-scope list or a matching wildcard.
- A staging/preview/dev environment that is not explicitly listed.
- An acquired or sister-company domain that looks related but is not named.
- The class is excluded: missing security headers, SPF/DKIM/DMARC, self-XSS,
  low-impact CSRF (logout, search), clickjacking on non-sensitive pages,
  rate-limiting without meaningful impact, raw scanner output.
- Testing violated the rules: DoS / load testing, mass PII download, credential
  bruteforce, account spam, social engineering, out-of-window testing.
- The engagement's Rules of Engagement or Stealth Mode forbade the technique
  used — that prohibition wins even when the finding is real.

**Major**

- The severity claim exceeds the program's cap for the class.
- A gray-area asset with no pre-approval and no boundary-case note.

### 2. Evidence (the slop pass)

Every claim is checked against the evidence in the draft:

- **Invented facts** — endpoints, parameters, versions, headers or CVE IDs that
  were never observed. A CVE that does not resolve, or does not describe this
  bug, is the fastest route to a closed report.
- **Theoretical-only impact** — "could lead to", "may allow", "an attacker with
  the right conditions" without proof. This is Critical when it is the only
  impact statement.
- **PoC that is not a PoC** — pseudocode, placeholder payloads
  (`?payload=<XSS>`), "and you will get...", steps that skip the interesting part
  with "..." or "as shown above", screenshots described but not attached.
- **Impact not demonstrated** — an ATO claim with no account taken over, an RCE
  claim with no command output, a database claim with no row.
- **Boilerplate and structural tics** — multi-paragraph class definitions,
  pasted generic mitigations, Introduction/Background/Conclusion scaffolding
  around a one-step bug, "In conclusion" phrasing.
- **Confidence without evidence** — a Critical/High rating with no demonstrated
  impact, or a max-severity CVSS vector defaulted onto a bug it does not fit.
- **Suspiciously clean narrative** — no attempts, no dead ends, no friction.
  Real exploitation rarely reads that clean, and reviewers know it.

### 3. PoC quality

A PoC is valid only if a triager with **no prior knowledge** can replay it.

**Critical**

- No working PoC — description or pseudocode instead of a concrete reproduction.
- The claimed impact is not what the PoC shows.
- A chain with a link that was never demonstrated.

**Major**

- Preconditions not stated (auth state, role, browser, external setup).
- Requests/payloads described rather than shown.
- Expected vs actual not shown at the step where the bug manifests.

**Minor**

- Cleanup notes missing for a stateful PoC (uploaded files, created accounts,
  stored payloads).
- Smart quotes or unicode normalization breaking a copy-pasteable payload.

### 4. Class gotchas

When a class is claimed (XSS, SQLi, SSRF, IDOR/BOLA, CSRF, RCE, SSTI, XXE, open
redirect, auth bypass, information disclosure, race condition, CORS, path
traversal/LFI), check the evidence against that class's minimum proof, common
auto-close patterns and overclaim traps:

```
report_review mode: "gotchas" vulnerability_class: "SSRF"
```

A primitive that fails the minimum proof is a lead, not a finding — say so and
state what would prove it.

## Verdict rules

- Any Critical finding -> **DO NOT SUBMIT**.
- Any Major finding, or an unverified scope -> **NEEDS FIXES**.
- Nothing above -> **READY TO SUBMIT**, and say what to keep.

## Hard rules

- **Never invent** facts about the target or the vulnerability. If it cannot be
  verified from the draft plus the artifacts, say so.
- **Never rewrite** the draft for the author. Point at issues; the fixes belong
  to whoever signs the report.
- **Never approve** a PoC that cannot be mentally replayed step by step.
- **No false reassurance.** Bluntness now beats a rejected report later — and an
  honest "not yet a finding, here is what would prove it" is a valid outcome.
