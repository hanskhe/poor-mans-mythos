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
version: 0.3.0
allowed-tools:
  - Bash(${CLAUDE_SKILL_DIR}/scripts/*)
  - Edit(.security-audit/**)
---

# Security Audit Skill

Perform a full, multi-agent security audit of a repository. The audit runs in five phases:

0. **Recon**: establish project context, auth model, entry points, and a route map.
1. **Classify**: sort files into review / skim / skip.
2. **Review**: per-file (2a) and scenario-driven cross-file (2b) review, in parallel.
3. **Validate**: cluster findings, then validate each cluster against the actual code in a fresh context.
4. **Coverage and report**: what was checked, what wasn't, and where confidence is low.

Everything goes to `.security-audit/` in the repo root, which gets a `.gitignore` containing `*`. Findings may quote real secrets verbatim from the code, so they must never be committed. The reader's files sit at the top level: `report-<date>.md`, `coverage.md`, `recon.md` and `file-rankings.md`. Everything else, including `findings.yaml`, is what agents and steps pass to each other and lives in `.security-audit/work/`, which `audit.py clean` deletes at the end.

The skill is **token-heavy by design**. Phases 2a and 2b both run, and their findings overlap before deduplication. Don't shortcut this.

## How this skill spends tokens

The work happens in subagents. Your job as orchestrator is to run the phases, talk to the user, and spawn agents, while keeping your own context small. Every token in your context is re-sent on every later turn, and an audit has many turns.

- **Agents write their results to files and reply with one line.** Scripts in `${CLAUDE_SKILL_DIR}/scripts/` merge, deduplicate, cluster and assemble the report from those files.
- **Never Read or retype findings.** Don't open anything in `work/` other than files you write yourself (that includes `findings.yaml`), nor the report, and never copy finding text into a prompt or a file. The scripts print everything you need to show the user. (After the audit, if the user asks about one finding, `grep -A20 'id: F012' .security-audit/work/findings.yaml` is fine until you clean up.)
- **Spawn prompts are two lines.** The agent definitions carry all instructions. Don't add any, and don't paste recon, references or file contents into prompts. Agents read what they need.
- **One script, `scripts/audit.py`, runs every step.** It is a Python script that `uv` runs with its dependencies. Run it from the repo root exactly as written below, without quoting or rewriting the path, so the skill's `allowed-tools` rule matches. If it fails with "permission denied", run it as `uv run --script <script> ...`.

## Agents

The plugin ships three agent types:

| Phase | `subagent_type` | Effort | Spawn prompt |
|---|---|---|---|
| 2a | `poor-mans-mythos:file-reviewer` | medium | `File: <path>` / `Output: <file>` |
| 2b | `poor-mans-mythos:scenario-runner` | high | `Scenario: S<n>` / `Output: <file>` |
| 3 | `poor-mans-mythos:finding-validator` | high | `Cluster: <file>` / `Output: <file>` |

Each agent is restricted to Read, Grep, Glob, Bash and Write, with no MCP tools and no CLAUDE.md, and inherits the session's model. To change a model or effort level, edit the frontmatter in `${CLAUDE_PLUGIN_ROOT}/agents/`.

**Fallback.** If these agent types are not available, use `general-purpose` with this prompt: `Read ${CLAUDE_PLUGIN_ROOT}/agents/<name>.md and follow its body as your instructions.` followed by the same two lines. It works the same way but costs more, because a general-purpose agent loads every tool.

**Cost expectations.** As an order of magnitude from v0.2 reference runs: a scenario agent used ~180K tokens and a per-file reviewer ~50K. A full audit of a ~1,000-file repo can reach **several million tokens**. v0.3 reduces this, but there is no new baseline yet; every run now records subagent usage in the report. Before Phase 1 begins, tell the user to expect a reasoning-heavy, multi-agent run.

---

## Phase 0: Reconnaissance and Threat Model

### 0.1 Set up the workspace

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py init
```

This creates `.security-audit/`, writes the `.gitignore`, clears any working state a previous run left in `.security-audit/work/` (earlier reports are kept), stages the reference files that agents read into `.security-audit/work/refs/`, and splits the scenarios into one file each. If it exits non-zero, abort and report the error. Every agent depends on those files.

### 0.2 Build the recon document

Read `${CLAUDE_SKILL_DIR}/references/recon-checklist.md` and follow it to produce `.security-audit/recon.md`, including the **route map**. Every agent starts from this document, so time spent here saves each agent from re-deriving it. Use Grep with line numbers and read only the relevant regions, never whole directories. Everything you read stays in your context for the rest of the audit.

### 0.3 Threat-model dialog

Per the checklist, ask the user only the questions you cannot answer from the README or the code, in priority order. The asset question is almost always needed:

> "Before I dig in: what's the highest-impact thing an attacker could do here? Read which data, take which action, or impersonate whom? This anchors how I'll judge severity."

Ask the user-base, out-of-scope and sensitive-data questions only if materials already on disk don't answer them.

### 0.4 Save and announce

Write `.security-audit/recon.md`. Give the user one short paragraph: stack, auth model, number of entry points and routes, anything notable, and the cost expectation. Then continue to Phase 1 without asking.

---

## Phase 1: File Classification

### 1.1 Scan

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py scan
```

The script enumerates the files (git-tracked plus untracked, excluding ignored files) and applies the path rules from `references/risk-rating-guide.md`. It greps the remaining files for risky primitives and prints the ones that need your decision, together with the primitives seen.

### 1.2 Decide and override

If the scan lists files needing a decision, or recon identified out-of-scope or vendored code, read `${CLAUDE_SKILL_DIR}/references/risk-rating-guide.md` ("Files needing a decision" and "Special cases"). Decide each listed file from its path and the primitives listed. Use `head -n 30` on several files in one Bash call only where that isn't enough. Write all decisions to `.security-audit/work/class-overrides.tsv`, one `bucket<TAB>path<TAB>reason` line each. Leave out files you'd default up to review anyway; finalize promotes undecided files to review.

### 1.3 Finalize

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py finalize
```

This promotes files referenced in `recon.md`, applies your overrides, and writes `file-rankings.md` and `file-classes.tsv`. It prints the counts and the top 30 Review files in priority order.

### 1.4 Ask the user

Show the counts and the Review list the script printed, then ask:

> "Phase 1 complete. <N> files in Review. How many would you like me to cover in the per-file pass?
> Enter a number, or 'all' to review the whole list. (Phase 2b runs across the whole repo regardless.)"

Then run:

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py select <N|all>
```

It writes `phase2a-files.tsv` and prints each selected file with its output path.

---

## Phase 2: Review (2a and 2b in parallel)

### 2.1 Spawn

Spawn the 2b and 2a agents together. Use one `scenario-runner` per scenario listed by `audit.py init`, and one `file-reviewer` per line of `phase2a-files.tsv`. Keep at most ~20 agents running at once, the default concurrency limit, and send each batch in a single message. Prompts are exactly:

```
Scenario: S3
Output: .security-audit/work/findings/2b-S3.yaml
```

```
File: src/routes/users.py
Output: .security-audit/work/findings/2a-004-src__routes__users.py.yaml
```

Copy the output path for each file from what `audit.py select` printed.

### 2.2 Record usage

When agents complete, record what their results report, in one call per batch: phase, label, total tokens, tool uses (use `-` if unknown).

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py usage 2b S3 182340 77 2a src/routes/users.py 48120 31
```

### 2.3 Collect and deduplicate (Phase 2c)

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py collect
```

The script parses all agent output files, merges duplicates mechanically (same file, overlapping lines, same OWASP category; see `finding-format.md`), assigns IDs `F001…` in severity order, and prints the summary. If it reports `MISSING` or `UNPARSEABLE` output, resume that agent once to write its output in the required format (SendMessage, if available), or spawn a replacement, and then re-run `audit.py collect`. If the output still can't be recovered, carry on; the report lists the gap.

Show the user the printed summary, then ask:

> "How many would you like me to validate? Enter a number (top first by severity, then file path), or 'all'."

---

## Phase 3: Clustered Validation

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py cluster <N|all>
```

The script groups the selected findings by (category, file). It then merges single findings that share a category and directory, and splits clusters larger than 10. For each cluster it prints the input and output paths. Spawn one `finding-validator` per cluster, all in parallel, within the concurrency limit:

```
Cluster: .security-audit/work/clusters/C01.yaml
Output: .security-audit/work/validated/C01.yaml
```

Validators run in a fresh context deliberately: they see the raw finding but none of the reviewer's reasoning trail. Record their usage with `audit.py usage 3 C01 <tokens> <tool uses> ...`.

---

## Phase 4: Coverage and Final Report

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py report "<one-line stack summary, e.g. Django 5 / Postgres / Celery>"
```

This writes `.security-audit/coverage.md` and `.security-audit/report-<date>.md`. The report contains the executive summary, confirmed findings by severity (excerpt, detail, validation, fix, data flow), adjusted findings, false positives, duplicates, unvalidated findings, coverage (per scenario, which pass found what, OWASP and API Top 10 tables, gaps, out of scope, limitations), and token usage.

Then, optionally, Edit the report's `## Auditor Notes` section with at most five bullets of cross-cutting observations that aren't findings, such as a systemic pattern behind several findings or an area recon flagged that no agent could reach. Don't restate findings.

## Closing message

Relay the summary the script printed: the report path, confirmed counts by severity, false positives, duplicates, unvalidated findings, and any warnings. If there are Critical findings, put their titles first, above the summary.

## Clean up

The report is rebuilt from the working state, so clean up only once the user is done with this run. If any findings are unvalidated, end the closing message with:

> "<N> findings weren't validated. Validate more before I remove the working files? Enter a number, 'all', or 'no'."

If they want more, re-run Phase 3 with the new number and then Phase 4. Otherwise, or if every finding was validated, run:

```bash
${CLAUDE_SKILL_DIR}/scripts/audit.py clean
```

It deletes `.security-audit/work/` and keeps the top-level files listed above. Tell the user in one line what was kept.

---

## Notes for the orchestrator

- Subagents run with the audited repo as their working directory. They read `.security-audit/recon.md` and `.security-audit/work/refs/*`, never the plugin's `references/` directory. That's why `audit.py init` stages the files.
- Agents use the Write tool for their output file. If the session prompts for each write, the user can approve edits for the session once.
- The `.security-audit/.gitignore` written by `audit.py init` keeps quoted secrets out of commits. Never relax it.
- The skill is intentionally token-heavy. Don't skip Phase 2b to save cost, and don't skip Phase 4 to save time.
- If an agent's reply runs past one line, don't answer it or repeat it. Its output file is what counts. The user accepted the cost when they invoked the skill. The savings come from not repeating work, not from doing less of it.
