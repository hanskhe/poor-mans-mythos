# Finding Format

The exact output formats for audit findings. Scripts parse them mechanically, so:

- Put each label at the start of its line: `File: src/x.py`, not `**File:**` or `- File:`.
- Keep each field on one line. The exception is `Excerpt`, which is a fenced code block on the lines after `Excerpt:`.
- Start every block with its opening marker line and end it with its closing marker line.

Severity values come from `severity-rubric.md` and must be one of `Critical`, `High`, `Medium`, `Low`.

---

## Raw finding (Phase 2a reviewers, Phase 2b scenario agents)

```
---FINDING---
File: <repo-relative path, e.g. src/api/users.py>
Lines: <single line number or inclusive range, e.g. 42 or 38-51>
Title: <short imperative title, max 10 words>
Severity: Critical | High | Medium | Low
Confidence: High | Medium | Low
OWASP: <category code and short name, e.g. A05:2025 Injection or API1:2023 BOLA, or N/A>
CWE: <CWE-NNN, or N/A>
Source: <2a:<assigned file path> | 2b:S<scenario number>>
Excerpt:
```<language>
<the offending code, ideally 3-15 lines, verbatim from the file>
```
Detail: <2-4 sentences: the vulnerability, the data flow or trust boundary involved, and why it is dangerous in this application>
DataFlow: <one line tracing source → sink, e.g. `req.body.id (handler.py:42) → build_query() (db.py:18) → db.execute (db.py:25)`, or N/A for configuration-only issues>
References: <comma-separated repo-relative paths inspected beyond the primary file; may be empty>
---END FINDING---
```

Rules:

- Emit one block per distinct finding. Do not bundle unrelated issues.
- If the same root cause appears in several files (a shared insecure helper called from many routes), report it once on the helper and list the call sites under `References:`.
- Choose `Severity` with `severity-rubric.md`. If unsure between two levels, pick the lower one and say why in `Detail`.
- `Confidence` is your belief that the issue is real, not its severity. Use `Low` when you suspect an issue but cannot confirm it without more context.
- `OWASP` references the OWASP Top 10 (e.g. `A05:2025 Injection`) or the API Top 10 (e.g. `API1:2023 BOLA`). Use `N/A` only for findings outside both lists.
- `CWE` is the most specific applicable identifier (e.g. `CWE-89`, `CWE-918`, `CWE-352`).
- `Excerpt` is verbatim, never paraphrased. If the issue spans more than ~15 lines, excerpt the most damning part and give the full range in `Lines`.
- `DataFlow` is mandatory for any finding involving untrusted data.
- Do not add an `ID:`. IDs are assigned when findings are merged.

A reviewer that finds nothing writes exactly:

```
NO FINDINGS
```

### How findings are merged (Phase 2c, scripted)

Two findings are duplicates when they cite the same file, their line ranges overlap, and they share an OWASP category. Findings marked `N/A` are merged only when they also share a CWE. The kept finding is the one with the higher severity, then higher confidence, then the longer `Detail`. The `Source` and `References` of all merged findings are combined. Merged findings get IDs `F001`, `F002`, … ordered by severity, then file.

---

## Validated finding (Phase 3 validators)

Validators get a cluster of merged findings, each with an `ID:`. They write one block per ID:

```
---VALIDATED---
ID: <the finding's ID, e.g. F012>
Status: Confirmed | False Positive | Downgraded | Upgraded | Duplicate
AdjustedSeverity: <severity after validation; same as the original if unchanged>
DuplicateOf: <ID of the canonical finding; only when Status is Duplicate>
Reasoning: <2-5 sentences: either the data-flow trace that confirms exploitability, or the specific reason the finding is not exploitable as reported. Cite file:line.>
Fix: <1-2 sentences naming the concrete change and the function or symbol to change; omit for False Positive and Duplicate>
Excerpt: unchanged
---END VALIDATED---
```

Do not copy the original file, lines, title or severity; the report script joins them by ID. Write `Excerpt: unchanged` when the original excerpt is accurate. Only when it was wrong, replace that line with `Excerpt:` followed by a fenced block of the corrected code.

Rules:

- `Confirmed`: real, and the severity is right. `Upgraded` / `Downgraded`: real, but the severity changed. `False Positive`: not real or not exploitable. `Duplicate`: real, but already covered by another finding in the cluster.
- Investigate beyond the cited lines. Use Read and Grep to establish whether sources are really untrusted, whether sanitization runs, whether middleware is registered, and whether routes are reachable. State what you found in `Reasoning`.
- When changing severity, anchor the new level in the rubric's decision factors (impact, accessibility, prerequisites).
- Be specific in `Fix`: "use a parameterized query via `db.exec(query, [user_id])` instead of f-string interpolation in `users.py:get_invoice`", not "sanitize input".
- Every ID in the cluster gets exactly one block. Never drop a finding silently.

---

## Final report

`scripts/report.sh` assembles the report from the merged findings and the validated blocks.
