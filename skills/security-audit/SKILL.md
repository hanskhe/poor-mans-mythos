---
name: security-audit
description: >
  This skill should be used when the user asks to "run a security audit",
  "audit this repo for security issues", "do a full security review of the codebase",
  "check the codebase for vulnerabilities", "scan for security problems", or
  "find security issues in this project". It performs a five-phase multi-agent
  audit: reconnaissance, file classification, per-file review, scenario-driven
  cross-file review, finding validation, and coverage analysis. Do NOT use for
  reviewing only the current branch's changes — the built-in security-review
  skill handles that case.
version: 0.2.0
---

# Security Audit Skill

Perform a full, multi-agent security audit of a repository. The audit runs in five phases:

0. **Recon** — establish project context, auth model, entry points.
1. **Classify** — sort files into review / skim / skip.
2. **Review** — per-file (2a) + scenario-driven cross-file (2b) parallel review.
3. **Validate** — cluster findings, validate each cluster against the actual code.
4. **Coverage** — explicit statement of what was checked, what wasn't, and where confidence is low.

All intermediate and final output is written to `.security-audit/` in the repo root. The first thing the skill does on every run is ensure that directory contains a `.gitignore` containing `*` so findings (which may quote real secrets verbatim from the code) cannot be committed.

The skill is **token-heavy by design**. Phase 2a and 2b both run; their findings overlap, then deduplicate. Don't shortcut this.

**Cost expectations.** Real audits spend significant tokens. As a rough order of magnitude, a single scenario agent on a medium codebase ran ~180K tokens in our reference test; per-file reviewer agents averaged ~50K. A full audit on a ~1,000-file repo with 10 scenarios and 50–100 reviewed files plus validation can easily reach **several million tokens**. The model the user has selected at runtime drives the bill — recommend `/model opus` for quality but warn the user this is a reasoning-heavy multi-agent run before they invoke. State this expectation in the recon summary you give the user, before Phase 1 begins.

---

## Phase 0: Reconnaissance and Threat Model

### 0.1 Set up output directory and stage references

```bash
mkdir -p .security-audit/refs
```

Then write `.security-audit/.gitignore` with the single line `*` so the audit's outputs cannot be committed.

**Stage the reference files into the audit workspace.** Subagents inherit the audited repo's cwd, not the plugin's install path, so they cannot resolve `references/X.md`. Copy all seven reference files from this skill's `references/` directory into `.security-audit/refs/`:

- `recon-checklist.md`
- `risk-rating-guide.md`
- `owasp-top10.md`
- `owasp-api-top10.md`
- `severity-rubric.md`
- `finding-format.md`
- `scenarios.md`

When this skill is loaded, the harness prefixes SKILL.md with a line like `Base directory for this skill: <path>`. That path is the skill's install location — use it. Stage the files in a single `cp` via Bash:

```bash
SKILL_REFS=<base-directory>/references   # take from the harness's "Base directory for this skill:" line
for f in recon-checklist risk-rating-guide owasp-top10 owasp-api-top10 severity-rubric finding-format scenarios; do
  cp "$SKILL_REFS/$f.md" .security-audit/refs/$f.md
done
```

Do this once at the start of every audit run — never assume a previous run staged them. From this point on, every agent prompt refers to `.security-audit/refs/X.md` exclusively.

**Why `cp` and not Read+Write.** The harness deduplicates Read calls within a session: if the orchestrator has already read a reference file earlier in this conversation (e.g. while inspecting the skill during development), a second Read returns "Wasted call" without the content, and Write would have nothing to copy. `cp` via Bash sidesteps this. Use Read+Write only as a fallback if `cp` is unavailable.

**Sanity-check after staging.** Run:

```bash
for f in recon-checklist risk-rating-guide owasp-top10 owasp-api-top10 severity-rubric finding-format scenarios; do
  test -f .security-audit/refs/$f.md || { echo "STAGING FAILED: refs/$f.md missing" >&2; exit 1; }
done
```

If any reference file is missing, abort the audit immediately and report the failure to the user. Every downstream agent depends on these paths resolving — silent staging failure produces empty agent outputs that look like "no findings."

### 0.2 Build the recon document

Read `.security-audit/refs/recon-checklist.md` and follow it. Produce `.security-audit/recon.md` with all required sections filled (write `Unknown` rather than skipping a section).

Order of operations:
1. Read project markers in parallel: `README*`, language-specific manifests (`package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`), `Dockerfile*`, `docker-compose*.yml`, `.github/workflows/*`, top-level config files.
2. Detect framework conventions from imports and file structure.
3. Map routes by grepping for the framework's routing primitives.
4. Locate auth enforcement points (middleware, decorators, guards).
5. Find outbound HTTP call sites.
6. Run the threat-model dialog (next step) for what couldn't be inferred.

### 0.3 Threat-model dialog

Per `.security-audit/refs/recon-checklist.md`, ask the user only the questions whose answers cannot be inferred from the README or code. Ask in priority order; stop when context is filled.

The first question — the asset question — is almost always required:

> "Before I dig in: what's the highest-impact thing an attacker could do here? Read which data, take which action, or impersonate whom? This anchors how I'll judge severity."

Follow with the user-base, out-of-scope, and sensitive-data questions only if not answerable from materials already on disk.

### 0.4 Save and announce

Write `.security-audit/recon.md`. Briefly summarize to the user (one short paragraph) what you found: stack, auth model, entry-point count, anything notable. Then proceed to Phase 1 without asking permission — this is a single audit run, not a confirmation gate.

---

## Phase 1: File Classification

### 1.1 Enumerate files

```bash
find . -type f \
  ! -path './.git/*' \
  ! -path './node_modules/*' \
  ! -path './vendor/*' \
  ! -path './.venv/*' \
  ! -path './venv/*' \
  ! -path './dist/*' \
  ! -path './build/*' \
  ! -path './out/*' \
  ! -path './.next/*' \
  ! -path './target/*' \
  ! -path './coverage/*' \
  ! -path './.security-audit/*' \
  ! -name '*.lock' \
  ! -name 'package-lock.json' \
  ! -name 'yarn.lock' \
  ! -name 'pnpm-lock.yaml' \
  ! -name 'Cargo.lock' \
  ! -name 'poetry.lock' \
  ! -name 'Gemfile.lock' \
  ! -name 'composer.lock' \
  ! -name 'go.sum' \
  | sort
```

Filter out binary files: for any file whose extension isn't already classified, run `file --mime-encoding <path>` and skip if encoding is `binary`.

### 1.2 Classify into three buckets

Read `.security-audit/refs/risk-rating-guide.md` and apply it. Most files classify by path / extension alone (no read needed). Read content only for files that don't classify cheaply.

**Default-promote to review:** any file appearing in `recon.md`'s entry-point list.

### 1.3 Write rankings

Write `.security-audit/file-rankings.md` in the format specified at the bottom of `risk-rating-guide.md`:

```markdown
# File Classification

Generated: <ISO timestamp>
Total files: <N>
Review: <count> · Skim: <count> · Skip: <count>

## Review (<count>)
- <path> — <one-line reason>
...

## Skim (<count>)
- <path> — <reason>
...

## Skip (<count>)
<grouped — list rules applied, e.g. "node_modules/**: 4,219 files">
```

### 1.4 Ask user

Show the user:
- Total files found.
- Counts in each bucket.
- The full Review list if it's ≤ 30 entries; otherwise the top 30 plus a count of remaining.

Then ask:

> "Phase 1 complete. <N> files in Review. How many would you like me to cover in the per-file pass?
> Enter a number, or 'all' to review the whole list. (Phase 2b runs across the whole repo regardless.)"

If the user enters a number, take the top N by classification confidence, then alphabetical. The remaining Review files are not lost — Phase 2b's scenario agents grep across the entire repo regardless of this number.

---

## Phase 2a: Per-File Review

### 2a.1 Spawn agents

For each selected Review file, spawn one subagent in parallel. Pass all Agent calls in a single message when count ≤ 15; for larger sets, batch in groups of 10–15.

**Each agent must be given Read, Grep, and Bash tools** (use the `general-purpose` subagent_type, which has these). The agent prompt:

```
You are a security auditor reviewing one file in a larger codebase. You have Read, Grep,
and Bash tools — use them. Do not limit your investigation to the named file.

## Project context
Read .security-audit/recon.md before anything else. It tells you the framework, auth model,
entry points, and trust boundaries.

## File to review
<repo-relative path>

## Reference files (read on demand)
- .security-audit/refs/owasp-top10.md — apply to all files.
- .security-audit/refs/owasp-api-top10.md — apply additionally if this file is an API/route/middleware/webhook/HTTP-client file (recon.md tells you which).
- .security-audit/refs/severity-rubric.md — required for assigning severity.
- .security-audit/refs/finding-format.md — required for output. Follow it exactly.

## Your task
1. Read the file.
2. For every potential issue, follow data flow outward: where does input come from?
   Where does it go? What sanitization, escaping, parameterization, or authz check
   happens between source and sink? Use Grep to locate callers, callees, middleware,
   and config that affects this file. Use Read on whatever is relevant.
3. For each confirmed issue, emit a ---FINDING--- block per finding-format.md.
   Set the Source field to: 2a:<the file path you were assigned>
4. If you find nothing, emit exactly: NO FINDINGS

## What to look for
- Every applicable category from the OWASP Top 10.
- Every applicable category from the OWASP API Top 10 (if applicable).
- Logic errors exploitable via sequence, race, or business-flow abuse.
- Misuse cases — legitimate features turned against the system.
- Insecure defaults and missing controls.

## What NOT to do
- Do not invent vulnerabilities. If you can't trace exploitability, lower Confidence
  rather than fabricate a chain.
- Do not flag style issues, deprecated-but-safe patterns, or generic "could be better"
  observations. This is a security audit, not code review.
- Do not embed long quotes from OWASP references in your output. Cite by category code.
```

### 2a.2 Collect 2a findings

Concatenate all agent outputs. Parse `---FINDING--- ... ---END FINDING---` blocks. Write to `.security-audit/raw-findings-2a.md`.

---

## Phase 2b: Scenario-Driven Review

### 2b.1 Spawn one agent per scenario

Read `.security-audit/refs/scenarios.md` and spawn one agent per scenario (S1 through S10). All run in parallel — single message with all Agent calls. Each agent has Read, Grep, Bash tools.

The agent prompt:

```
You are a security auditor running a single attack scenario across the entire repository.
You have Read, Grep, and Bash tools — use them aggressively.

## Project context
Read .security-audit/recon.md before anything else.

## Scenario
<paste the scenario's section from .security-audit/refs/scenarios.md verbatim>

## Reference files
- .security-audit/refs/owasp-top10.md and .security-audit/refs/owasp-api-top10.md — for category mapping.
- .security-audit/refs/severity-rubric.md — for severity.
- .security-audit/refs/finding-format.md — for output format.

## Your task
1. Run the scenario. Adapt grep patterns to this project's actual language and conventions
   (recon.md tells you what stack you're on).
2. For each candidate hit, investigate enough to confirm or rule out exploitability.
   Read the file, find callers, check middleware, inspect config — whatever the scenario needs.
3. Emit one ---FINDING--- block per distinct issue. If a single root cause appears in many
   places, file once on the canonical site and list call sites in References:.
   Set the Source field to: 2b:S<your scenario number, e.g. 2b:S3>
4. End with exactly two lines:
     Scenario: <S#> <name>
     Findings: <count>
   followed by a Notes: line if you found nothing or if there's coverage caveat worth recording
   (per the "When a scenario produces no findings" section of scenarios.md).
```

### 2b.2 Collect 2b findings

Concatenate. Write findings to `.security-audit/raw-findings-2b.md`. Capture the trailing `Scenario:` / `Findings:` / `Notes:` lines into `.security-audit/coverage-2b.md` for use in Phase 4.

---

## Phase 2c: Deduplication

Two findings are duplicates if **all** of:
- Same file path.
- Line ranges overlap.
- Same OWASP category (or both `N/A` for the same vuln class as judged by title).

Merge duplicates: keep the higher-Severity finding; if equal, keep the higher-Confidence one; if still equal, keep the longer `Detail`. Append the discarded finding's `References:` to the kept one.

Write merged output to `.security-audit/findings-merged.md`. Show the user a summary:

> "Phase 2 complete. Per-file pass: <X> findings. Scenario pass: <Y> findings. After dedup: <Z>.
> Severity breakdown: Critical <a>, High <b>, Medium <c>, Low <d>.
> How many would you like me to validate? Enter a number (top first by severity then file path), or 'all'."

---

## Phase 3: Clustered Validation

### 3.1 Cluster

Group selected findings into clusters where the same root cause likely produces multiple findings. Cluster keys (in order of preference):
1. Same `(OWASP category, file)` → one cluster.
2. Same `(OWASP category, directory)` → one cluster (only when individual files are small or clearly share helpers).
3. Otherwise, one cluster per finding.

Aim for ~3–10 findings per cluster. A 50-finding flat list becomes ~10 clusters; a 5-finding list stays as 5 clusters.

### 3.2 Spawn one validator per cluster

All validators run in parallel. Each has Read, Grep, Bash tools.

```
You are a security finding validator with full repo access. You have Read, Grep, and Bash —
use them to confirm or refute each finding in this cluster.

## Project context
Read .security-audit/recon.md.

## Cluster
The following findings are believed to share a root cause or context. Validate each.

<paste the raw findings in this cluster — one ---FINDING--- block per finding>

## Reference files
- .security-audit/refs/severity-rubric.md
- .security-audit/refs/finding-format.md (Phase 3 — Validated Finding section)

## Your task
For each finding in the cluster:
1. Read the cited file at the cited lines.
2. Trace the data flow as described in the finding's DataFlow field. Confirm or refute
   each step. If refuted, identify which step blocks the attack and why.
3. Look for cross-cutting protections the original reviewer may have missed: middleware,
   decorators, schema validators, ORM-level escaping, output encoding, CSP, the
   framework's default behavior on the relevant primitive.
4. If the finding is real but a different finding in this cluster is the canonical
   instance, mark it Status: Duplicate and set DuplicateOf.
5. Recompute severity using severity-rubric.md decision factors.
6. Emit one ---VALIDATED--- block per ORIGINAL raw finding (even when several map to a
   duplicate). Follow finding-format.md exactly.

## What good looks like
- Reasoning cites concrete file:line references for the claim.
- Fix names a specific function or symbol to change, not generic advice.
- A False Positive verdict explains exactly which protection blocks the attack.
- Severity changes are anchored in impact / accessibility / prerequisites.
```

### 3.3 Collect

Parse `---VALIDATED--- ... ---END VALIDATED---` blocks. Write to `.security-audit/validated-findings.md`.

---

## Phase 4: Coverage Pass

### 4.1 Compose coverage statement

Build `.security-audit/coverage.md` by combining:
- For each scenario S1–S10: the `Scenario:` / `Findings:` / `Notes:` summary the agent produced, plus how many of those findings were Confirmed in Phase 3.
- For each OWASP Top 10 category: which scenarios touched it, how many findings landed in it, how many were Confirmed.
- A short list of explicit gaps:
  - Files in Review that the user opted to skip (truncation).
  - Scenarios that returned zero findings without confidence (the agent's `Notes:` flagged uncertainty).
  - Categories of attack the scenario list doesn't cover (state explicitly: this audit does not exhaustively cover physical attacks, social engineering, dependency CVE matching beyond manifests, runtime-only behaviors).

This is generated by the orchestrator (the skill itself) — no agent needed. Templates:

```markdown
# Audit Coverage

## Scenarios
| Scenario | Findings raised | Confirmed | Notes |
|----------|-----------------|-----------|-------|
| S1 Injection sinks | <n> | <n> | <agent's notes if any> |
| S2 IDOR / BOLA | <n> | <n> | ... |
...

## OWASP Top 10 (2025) coverage
| Category | Findings | Confirmed | Touched by scenarios |
|----------|----------|-----------|----------------------|
| A01 Broken Access Control | <n> | <n> | S2, S3, S5 |
...

## Files not reviewed in Phase 2a
<list, with risk classification>

## Out of scope
<from recon.md>

## Known limitations
- This audit relies on static reading. Behaviors that emerge only at runtime (config
  pulled from secret store, feature flags) are not exercised.
- Dependency CVE matching is not run; only manifest patterns are flagged.
- No dynamic analysis, fuzzing, or live exploitation.
```

---

## Final Report

Write `.security-audit/report-<YYYY-MM-DD>.md`:

```markdown
# Security Audit Report

**Repository:** <repo name>
**Date:** <ISO date>
**Stack:** <from recon.md>
**Files classified:** <total>
**Files reviewed in Phase 2a:** <N>
**Findings raised:** <raw count>
**Findings validated:** <validated count>
**Findings confirmed:** <confirmed count>

---

## Executive Summary

| Severity | Confirmed | Downgraded/Upgraded | False Positives | Duplicates |
|----------|-----------|---------------------|-----------------|------------|
| Critical | X | X | X | X |
| High | X | X | X | X |
| Medium | X | X | X | X |
| Low | X | X | X | X |
| **Total** | **X** | **X** | **X** | **X** |

If any Critical findings exist, list their titles here in a short bullet list so the user sees them above the fold.

---

## Confirmed Findings

### Critical

#### [C1] <Title>
- **File:** `path/to/file.py:42-51`
- **OWASP:** A05:2025 Injection
- **CWE:** CWE-89
- **Severity:** Critical (was: Critical) — Confidence: High

```language
<excerpt verbatim>
```

**Detail:** <from raw finding>
**Validation:** <from validated finding's Reasoning>
**Fix:** <from validated finding's Fix>
**Data flow:** <from raw finding's DataFlow>

---

### High
... (same structure)

### Medium
... (same structure)

### Low
... (same structure)

---

## Adjusted Findings (severity changed during validation)

Brief table — title, file, original → adjusted severity, why.

---

## False Positives

| # | File | Issue | Reason dismissed |
|---|------|-------|------------------|
| 1 | `path` | Title | Reasoning |

---

## Coverage

<contents of .security-audit/coverage.md>

---

## Files Not Reviewed

<list with reason: classification, user truncation, out-of-scope>
```

---

## Closing message

After writing the report:

> "Security audit complete. Report saved to `.security-audit/report-<date>.md`.
> Confirmed: <c-crit> Critical, <c-high> High, <c-med> Medium, <c-low> Low.
> <fp> dismissed as false positives. <dup> de-duplicated.
> Coverage and gaps are documented in the report."

If there are Critical findings, surface them above this summary so the user sees them immediately.

---

## Notes for the orchestrator

- Subagents do not share context. Every reviewer/validator/scenario agent must be given the path to `.security-audit/recon.md` and told to read it first. Do not paraphrase recon into the prompt.
- Subagents inherit the audited repo's cwd, not this skill's install path. That is why Phase 0 stages reference files into `.security-audit/refs/`. Every reference path passed to an agent must be `.security-audit/refs/X.md`, never `references/X.md`.
- Do not embed full file contents into agent prompts. Agents have Read; let them read.
- Do not embed the OWASP reference files into agent prompts. Agents read them on demand.
- Findings may quote real secret values from the code. The `.security-audit/.gitignore` written in Phase 0 prevents commits — do not relax it.
- The skill is intentionally token-heavy. Do not skip Phase 2b to save cost, do not skip Phase 4 to save time. The user accepted the cost when they invoked the skill.
