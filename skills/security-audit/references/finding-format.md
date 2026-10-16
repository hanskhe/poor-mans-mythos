# Finding Format

Agents write their results as YAML files that `scripts/audit.py` reads. Write valid YAML: put code in `|` block scalars, and quote any value that starts with a special character (`` ` ``, `*`, `&`, `!`, `{`, `[`, `%`, `@`) or contains `: `.

Severity values come from `severity-rubric.md` and must be one of `Critical`, `High`, `Medium`, `Low`.

---

## Raw findings (Phase 2a reviewers, Phase 2b scenario agents)

```yaml
scenario: S3 Function-level authorization   # scenario agents only
notes: >-                                   # scenario agents only
  1-3 sentences: what you searched for, how many candidates you examined,
  and any uncertainty or area you could not cover.
findings:
  - file: src/api/users.py          # repo-relative path
    lines: 38-51                    # single line or inclusive range
    title: Short imperative title, max 10 words
    severity: High                  # Critical | High | Medium | Low
    confidence: High                # High | Medium | Low
    owasp: A05:2025 Injection       # or API1:2023 BOLA, or N/A
    cwe: CWE-89                     # or N/A
    excerpt: |
      the offending code, ideally 3-15 lines, verbatim from the file
    detail: 2-4 sentences on the vulnerability, the data flow or trust boundary involved, and why it is dangerous here.
    dataflow: "req.body.id (handler.py:42) → build_query() (db.py:18) → db.execute (db.py:25)"
    references: [src/api/routes.py, src/db.py]   # other files inspected; may be empty
```

A reviewer that finds nothing writes `findings: []`.

Rules:

- One entry per distinct finding. Do not bundle unrelated issues.
- If the same root cause appears in several files (a shared insecure helper called from many routes), report it once on the helper and list the call sites under `references`.
- Choose `severity` with `severity-rubric.md`. If unsure between two levels, pick the lower one and say why in `detail`.
- `confidence` is your belief that the issue is real, not its severity. Use `Low` when you suspect an issue but cannot confirm it without more context.
- `owasp` references the OWASP Top 10 (e.g. `A05:2025 Injection`) or the API Top 10 (e.g. `API1:2023 BOLA`). Use `N/A` only for findings outside both lists.
- `cwe` is the most specific applicable identifier (e.g. `CWE-89`, `CWE-918`, `CWE-352`).
- `excerpt` is verbatim, never paraphrased, and without Markdown fences. If the issue spans more than ~15 lines, excerpt the most damning part and give the full range in `lines`.
- `dataflow` is mandatory for any finding involving untrusted data; `N/A` for configuration-only issues.
- Do not add an `id` or a `source`. The script assigns IDs and knows which agent wrote each file.

### How findings are merged (Phase 2c, scripted)

Two findings are duplicates when they cite the same file, their line ranges overlap, and they share an OWASP category. Findings marked `N/A` are merged only when they also share a CWE. The kept finding is the one with the higher severity, then higher confidence, then the longer `detail`. The sources and references of all merged findings are combined. Merged findings get IDs `F001`, `F002`, … ordered by severity, then file, and are written to `.security-audit/work/findings.yaml`.

---

## Verdicts (Phase 3 validators)

Validators get a cluster file: a YAML list of merged findings, each with an `id`. They write a list with one verdict per ID:

```yaml
- id: F012
  status: Confirmed               # Confirmed | False Positive | Downgraded | Upgraded | Duplicate
  severity: High                  # severity after validation; same as the original if unchanged
  duplicate_of: F009              # only when status is Duplicate
  reasoning: 2-5 sentences, either the data-flow trace that confirms exploitability or the specific reason the finding is not exploitable as reported. Cite file:line.
  fix: 1-2 sentences naming the concrete change and the function or symbol to change; omit for False Positive and Duplicate.
  excerpt: |                      # only when the original excerpt was wrong
    the corrected code
```

Do not copy the original file, lines, title or severity; the report script joins them by ID.

Rules:

- `Confirmed`: real, and the severity is right. `Upgraded` / `Downgraded`: real, but the severity changed. `False Positive`: not real or not exploitable. `Duplicate`: real, but already covered by another finding in the cluster.
- Investigate beyond the cited lines. Use Read and Grep to establish whether sources are really untrusted, whether sanitization runs, whether middleware is registered, and whether routes are reachable. State what you found in `reasoning`.
- When changing severity, anchor the new level in the rubric's decision factors (impact, accessibility, prerequisites).
- Be specific in `fix`: "use a parameterized query via `db.exec(query, [user_id])` instead of f-string interpolation in `users.py:get_invoice`", not "sanitize input".
- Every ID in the cluster gets exactly one verdict. Never drop a finding silently.

---

## Final report

`scripts/audit.py report` assembles the report from `findings.yaml` and the verdicts.
