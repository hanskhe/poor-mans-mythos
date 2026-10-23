# Evals

End-to-end evals check whether full audits find planted vulnerabilities and leave safe look-alikes alone. Each run costs a full audit (see [Cost](../README.md#cost)). Run them before a release, and after any change to a prompt, an agent definition, a reference file or `SKILL.md`.

## Cases

The fixtures are deliberately vulnerable, but every planted bug stays inside the app: no code execution, no access to files outside the app, and no outbound requests. Don't run them anyway; the audit only reads the code. Nothing installs their dependencies either (no `pnpm install` or `uv sync`, and no install scripts), so running the evals is safe. The real costs are money, since each case is a full audit, and network access to PyPI for `audit.py`.

| Case | Fixture | Planted | Decoys |
|---|---|---|---|
| `fastapi-notes` | FastAPI / SQLite notes service (uv) | SQLi, IDOR, `is_admin` mass assignment, admin without role check, unbounded import, hard-coded session secret + debug | allowlisted ORDER BY, owner-scoped delete, capped `limit`, `yaml.safe_load` |
| `next-shop` | Next.js shop with API routes (pnpm) | `decodeJwt`, `proxy.ts` matcher gap, invoice IDOR, `role` mass assignment, ReDoS | order ownership check, escaped product search, allowlisted account update |
| `react-journal` | Carefully written React + Vite client (pnpm) | none | measures false positives: sanitized `dangerouslySetInnerHTML`, same-origin `?next=` redirect, origin-checked `postMessage` |

Each case runs the skill against `fixture/` in a fresh workspace. The prompt pre-answers the skill's questions so the run is unattended, and tells it to keep the working files. The `llm` graders read `.security-audit/report-*.md`: one grader per planted bug (recall), one per decoy (precision), and one for severity calibration. The graders in `case.yaml` are the ground truth. Nothing under `fixture/` hints at the answers, so keep it that way: no comments that name the bug, and no names like `vuln_`.

## Running

```bash
claude plugin eval . --tag e2e --ablation none --allow-tools Bash Write Edit \
  --judge-model sonnet --threshold 0 -j 3
```

- First time? Start with `--case fastapi-notes --keep-temp` and read the report before running the whole suite.
- `--case fastapi-notes` runs one case, and `--runs 3` repeats each case to average out variance (the default here is one run per case).
- `--ablation none` skips the no-plugin baseline arm, which would double the cost. Drop it to see how much the plugin adds over plain Claude.
- `--threshold 0` stops the command failing just because a case scores below 1.0. The scores are what you compare.
- `--max-cost-usd <n>` caps spend, and `--keep-temp` keeps each run's workspace and trace for debugging.

Results go to `evals/results/<timestamp>/` (git-ignored) as `aggregate-result.json` plus an HTML report with a pass/fail row per grader. To check a change, run the suite before and after it and compare per-grader pass rates. A planted bug that used to be found and no longer is, or a decoy that starts being confirmed, is a regression.

### Known blockers on managed machines

- **`--plugin-dir is disabled by your organization's managed settings (disableSideloadFlags)`**: the eval loads the plugin from this folder, and the org policy forbids that. Either get the flag lifted, or target the installed plugin (`claude plugin eval poor-mans-mythos@poor-mans-mythos`). The second option evaluates the *installed* copy, so reinstall from the local directory marketplace after each change.
- **`A shell tool (Bash or PowerShell) was granted but this machine cannot confine it`**: the harness won't run Bash unsandboxed, and the audit needs Bash for `audit.py`. Run from a normal terminal, not from inside another sandboxed session.
- `audit.py` installs its dependencies with `uv` on first run, which needs network access to PyPI from inside the eval sandbox.

## Adding a case

1. Create `evals/<name>/fixture/` with a small, realistic app. Plant bugs that match one of the scenarios in `skills/security-audit/references/scenarios.md`, and add at least one safe look-alike per bug class.
2. Copy a `case.yaml` and adjust the prompt's threat-model answers.
3. Write one `llm` grader per planted bug and per decoy. Name the file, the function, the approximate line and the CWE, and say that only confirmed, upgraded or downgraded findings count.
4. Run it once with `--keep-temp` and read the report. If a grader fails, decide whether the plugin missed the bug or the criteria are too strict.
