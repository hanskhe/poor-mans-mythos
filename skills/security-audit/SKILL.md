---
name: security-audit
description: >
  This skill should be used when the user asks to "run a security audit",
  "audit this repo for security issues", "do a full security review of the codebase",
  "check the codebase for vulnerabilities", "scan for security problems", or
  "find security issues in this project". It performs a three-phase multi-agent
  scan of every file in the repository: risk ranking, parallel file review by
  dedicated agents, and finding validation before producing a final report.
  Do NOT use for reviewing only the current branch's changes — the built-in
  security-review skill handles that case.
version: 0.1.0
---

# Security Audit Skill

Perform a full, multi-agent security audit of a repository. The audit runs in three phases:
rank files by risk, review the most dangerous files in parallel, then validate each finding.

All intermediate and final output is written to a `.security-audit/` folder in the repo root.

---

## Phase 1: File Discovery and Risk Ranking

### 1.1 Enumerate files

Run the following to get a list of all candidate files, excluding noise:

```bash
find . -type f \
  ! -path './.git/*' \
  ! -path './node_modules/*' \
  ! -path './vendor/*' \
  ! -path './.venv/*' \
  ! -path './venv/*' \
  ! -path './dist/*' \
  ! -path './build/*' \
  ! -path './.security-audit/*' \
  ! -name '*.lock' \
  ! -name 'package-lock.json' \
  ! -name 'yarn.lock' \
  ! -name 'Cargo.lock' \
  ! -name 'poetry.lock' \
  ! -name 'go.sum' \
  | sort
```

Also exclude binary files. For each file in the list, check with:
```bash
file --mime-encoding <path>
```
Skip files where the encoding is `binary`.

### 1.2 Read and rate each file

Read the content of every remaining file. Consult `references/risk-rating-guide.md` for
the rating criteria. Assign each file a rating from 0 to 5.

When rating files, also consider whether the file is API-related (route handlers, middleware,
controllers, webhook processors, outbound HTTP clients). API files warrant at least a 3 by
default and should be reviewed against `references/owasp-api-top10.md` in Phase 2.

### 1.3 Save rankings

Create the `.security-audit/` directory and write `.security-audit/file-rankings.md`:

```markdown
# File Risk Rankings

Generated: <ISO timestamp>

## Risk 5
- path/to/file.py — <one-line reason>

## Risk 4
- path/to/file.js — <one-line reason>

## Risk 3
...

## Risk 2
...

## Risk 1
...

## Risk 0
...
```

### 1.4 Ask the user how many files to review

Show the user:
- Total files found
- Count at each risk level (5, 4, 3, 2, 1, 0)

Then ask:

> "I've ranked all files. How many would you like me to review in depth?
> I'll start with the highest-risk files (rating 5) and work downward.
> Enter a number, or 'all' to review everything rated 1 or above."

If the user enters 'all', include everything rated 1–5. If the user enters a number N,
take the top N files sorted by rating descending, then alphabetically within each rating.

---

## Phase 2: Parallel Security Review

### 2.1 Spawn one agent per file

For each selected file, spawn a subagent using the Agent tool. Run agents in parallel
(pass all Agent calls in a single message if the count is manageable; batch in groups of
10–15 for larger sets to avoid overwhelming the system).

Each agent receives this prompt (fill in the placeholders):

```
You are a security reviewer. Your task is to find security vulnerabilities in a single file.

File path: <FILEPATH>

File content:
<FILE CONTENT>

Review this file thoroughly for security issues using the OWASP Top 10:

<CONTENTS OF references/owasp-top10.md>

If this file is an API route handler, controller, middleware, webhook processor, or outbound
HTTP client, also apply the OWASP API Security Top 10:

<CONTENTS OF references/owasp-api-top10.md>

Look for:
1. Every applicable OWASP Top 10 category
2. Every applicable OWASP API Security Top 10 category (for API files)
3. Logic errors that could be exploited (race conditions, TOCTOU, business logic abuse)
4. Misuse cases — ways an attacker could use a legitimate feature for harm
5. Insecure defaults or missing security controls

For each issue found, report it in exactly this format:

---FINDING---
File: <filepath>
Lines: <line number or range, e.g. 42 or 38-51>
Issue: <short title, max 10 words>
Severity: Critical | High | Medium | Low
OWASP: <category code and name from Top 10 or API Top 10, or "N/A">
Detail: <2-4 sentences explaining the vulnerability and why it is dangerous>
---END FINDING---

If you find no issues, respond with exactly: NO FINDINGS
```

### 2.2 Collect findings

Gather all agent responses. Parse out every `---FINDING--- ... ---END FINDING---` block.

Write all findings to `.security-audit/raw-findings.md`:

```markdown
# Raw Findings

Generated: <ISO timestamp>
Files reviewed: <N>
Total findings: <M>

---FINDING---
...
---END FINDING---

---FINDING---
...
---END FINDING---
```

### 2.3 Ask how many findings to validate

Show the user:
- Number of files reviewed
- Total findings broken down by severity (Critical: X, High: Y, Medium: Z, Low: W)

Ask:

> "Phase 2 complete. Found <M> potential issues across <N> files.
> How many would you like me to validate? I'll start with Critical, then High, Medium, Low.
> Enter a number, or 'all' to validate everything."

If the user enters a number N, take the top N findings sorted by severity (Critical first),
then by file path within each severity level.

---

## Phase 3: Finding Validation

### 3.1 Spawn one validation agent per finding

For each selected finding, spawn a subagent. Run in parallel (batch in groups of 10–15).

Each agent receives this prompt:

```
You are a security finding validator. Your task is to determine whether a reported
security finding is real, and whether its severity is correctly assessed.

ORIGINAL FINDING:
<FINDING BLOCK>

SURROUNDING CODE CONTEXT:
<Read 20 lines before and after the flagged line range from the original file>

Investigate this finding carefully:
1. Is this a real vulnerability, or a false positive? (Consider: is the input actually
   untrusted? Is there sanitization happening elsewhere? Is this code reachable?)
2. If real, is the severity accurate? Should it be higher or lower, and why?
3. Are there mitigating factors that reduce exploitability?

Respond in exactly this format:

---VALIDATED---
Status: Confirmed | False Positive | Downgraded | Upgraded
Original Severity: <severity from finding>
Adjusted Severity: <new severity, or same if unchanged>
Reasoning: <2-5 sentences explaining your conclusion>
---END VALIDATED---
```

### 3.2 Write the final report

Create `.security-audit/report-<YYYY-MM-DD>.md`:

```markdown
# Security Audit Report

**Repository:** <repo name or path>
**Date:** <date>
**Files ranked:** <total>
**Files reviewed:** <N>
**Findings validated:** <M>

---

## Executive Summary

| Severity | Confirmed | False Positives |
|----------|-----------|-----------------|
| Critical | X         | Y               |
| High     | X         | Y               |
| Medium   | X         | Y               |
| Low      | X         | Y               |
| **Total**| **X**     | **Y**           |

---

## Confirmed Findings

### Critical

#### [C1] <Issue title>
- **File:** `path/to/file.py`
- **Lines:** 42–51
- **OWASP:** A03: Injection
- **Detail:** <detail from finding>
- **Validation:** <reasoning from validator>

...

### High
...

### Medium
...

### Low
...

---

## False Positives

| # | File | Issue | Reason dismissed |
|---|------|-------|-----------------|
| 1 | `path/to/file.py` | Issue title | Reasoning |

---

## Files Not Reviewed

<If the user chose fewer files than were ranked, list the skipped files here with their risk rating.>
```

---

## Closing

After writing the report, tell the user:

> "Security audit complete. Report saved to `.security-audit/report-<date>.md`.
> Found <N confirmed> confirmed issues (<critical> Critical, <high> High, <medium> Medium, <low> Low).
> <M> potential issues were dismissed as false positives."

If there are Critical findings, highlight them explicitly so the user knows to act immediately.
