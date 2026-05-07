# Finding Format

This file defines the exact output format for security findings produced by the audit. Both reviewer agents (Phase 2) and validator agents (Phase 3) must follow these formats verbatim — they are parsed mechanically.

Severity values come from `severity-rubric.md` and must be one of: `Critical`, `High`, `Medium`, `Low`.

---

## Phase 2 — Raw Finding (reviewer output)

Use this exact block. The fences and field labels are required.

```
---FINDING---
File: <repo-relative path, e.g. src/api/users.py>
Lines: <single line number or inclusive range, e.g. 42 or 38-51>
Title: <short imperative title, max 10 words>
Severity: Critical | High | Medium | Low
Confidence: High | Medium | Low
OWASP: <category code and short name, or N/A>
CWE: <CWE-NNN, or N/A>
Source: <provenance tag — see "Source field" below>
Excerpt:
```<language>
<the offending code, ideally 3-15 lines, kept verbatim from the file>
```
Detail: <2-4 sentences explaining the vulnerability, the data flow / trust boundary involved, and why it is dangerous in this application's context>
DataFlow: <one line tracing source → sink, e.g. `req.body.id (handler:42) → buildQuery() (db.py:18) → db.execute (db.py:25)`. Use `N/A` if the finding is configuration-only and has no data flow.>
References: <comma-separated repo-relative file paths the agent inspected to reach this conclusion, beyond the primary file. May be empty.>
---END FINDING---
```

### Source field

The `Source` field carries provenance and is required. The orchestrator uses it to build the Phase 4 coverage table.

- Phase 2a per-file agents emit: `Source: 2a:<repo-relative-file-path>` — the file the agent was assigned. Always exactly one per finding.
- Phase 2b scenario agents emit: `Source: 2b:S<scenario-number>` — e.g. `Source: 2b:S3` for the function-level authz scenario.
- Phase 2c dedup may merge a 2a finding with a 2b finding. The merged finding records both, comma-separated: `Source: 2a:src/api/users.py, 2b:S2`.

Rules for reviewers:

- Emit one block per distinct finding. Do not bundle unrelated issues into one block.
- If the same root cause appears in multiple files (e.g. a shared insecure helper called from many routes), report it once on the helper and list the call sites under `References:`.
- `Severity` must be chosen using `severity-rubric.md`. If unsure between two levels, pick the lower and explain in `Detail`.
- `Confidence` is *your* belief that this is a real issue, not its severity. Use `Low` when you suspect but cannot confirm without more context.
- `OWASP` must reference either the OWASP Top 10 (e.g. `A05: Injection`) or the API Top 10 (e.g. `API1:2023 BOLA`). Use `N/A` only for findings outside both lists (e.g. business logic abuse not covered by either).
- `CWE` should be the most specific applicable identifier (e.g. `CWE-89` for SQL injection, `CWE-918` for SSRF, `CWE-352` for CSRF). Use `N/A` if no CWE fits.
- `Excerpt` must be verbatim from the file. Do not paraphrase. Include enough context for a reader to understand without opening the file. If the issue spans more than ~15 lines, excerpt the most damning part and reference the full range in `Lines`.
- `DataFlow` is mandatory for any finding involving untrusted data. Configuration-only issues (e.g. permissive CORS) may use `N/A`.

If a reviewer finds nothing, they emit exactly:

```
NO FINDINGS
```

---

## Phase 3 — Validated Finding (validator output)

Validators receive a raw finding plus the ability to investigate the repo. They emit one of these blocks per finding handled. When a cluster is validated together, they emit one block per *original raw finding*, not one per cluster.

```
---VALIDATED---
OriginalFile: <copied from the raw finding>
OriginalLines: <copied from the raw finding>
OriginalTitle: <copied from the raw finding>
OriginalSource: <copied from the raw finding's Source field>
Status: Confirmed | False Positive | Downgraded | Upgraded | Duplicate
OriginalSeverity: <severity from the raw finding>
AdjustedSeverity: <new severity, or same as original if Status is Confirmed without change>
Reasoning: <2-5 sentences. Must include either: (a) the data-flow trace that confirms exploitability, or (b) the specific reason this is not exploitable as reported. Cite file paths and line numbers when referring to other code.>
Fix: <1-2 sentences naming the concrete change to make. Reference the symbol or function that should change, not just "validate input".>
Excerpt:
```<language>
<verified offending code — refresh from the file in case the original excerpt was inaccurate>
```
DuplicateOf: <only present when Status is Duplicate. Set to the OriginalTitle of the canonical finding.>
---END VALIDATED---
```

Rules for validators:

- `Status: Confirmed` means the finding is real and severity is correct. `Upgraded` / `Downgraded` mean real but severity changed. `False Positive` means not real or not exploitable. `Duplicate` means real but already covered by another finding (set `DuplicateOf` and pick the most informative finding as canonical).
- Validators must investigate beyond the original ±N lines. Use Read and Grep to confirm whether sources are actually untrusted, whether sanitization runs, whether middleware is registered, whether routes are reachable. State the result in `Reasoning`.
- When changing severity, anchor the new level in `severity-rubric.md` decision factors (impact / accessibility / prerequisites).
- `Fix` is mandatory on `Confirmed`, `Upgraded`, and `Downgraded`. Omit on `False Positive` and `Duplicate`. Be specific: "use parameterized query via `db.exec(query, [user_id])` instead of f-string interpolation in `users.py:get_invoice`" — not "sanitize input".
- Validators may *combine* duplicates but must not silently drop findings. Every raw finding chosen for validation must produce one validated block.

---

## Final Report Format

Aggregated by the orchestrator (the skill itself, not an agent). See `SKILL.md` for the report template. Each Confirmed finding in the report carries: title, file, lines, severity, OWASP, CWE, excerpt, detail, validation reasoning, and fix.
