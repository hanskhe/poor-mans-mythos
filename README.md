<p align="center">
  <img src="logo.png" alt="The Poor Man's Mythos" width="300" />
</p>

# Poor Man's Mythos

[Claude Mythos](https://red.anthropic.com/2026/mythos-preview/) is Anthropic's restricted AI model built specifically for finding and exploiting security vulnerabilities. It's genuinely impressive — it has discovered zero-days in every major OS and browser, and compressed years of security auditing into weeks. Anthropic decided it was too dangerous for public access, so it's gated behind [Project Glasswing](https://www.anthropic.com/glasswing), an invite-only industry consortium for organizations maintaining critical software.

We are not one of those organizations.

So here's this instead: a Claude Code plugin that uses regular Claude to do a best-effort security audit of your repo. It won't find 27-year-old kernel bugs. But it will map your application's attack surface, classify every file by risk, run parallel reviewers across files and across attack scenarios, validate each finding against the actual code, and produce an explicit coverage statement so you know what *wasn't* checked. For most projects, that's probably enough.

## Installation

```
/plugin marketplace add hanskhe/poor-mans-mythos
/plugin install poor-mans-mythos@poor-mans-mythos
```

## Usage

```
Run a security audit on this repo
```

Claude runs a five-phase audit. All output (recon, file rankings, raw findings, validated findings, coverage, and the final report) lands in `.security-audit/`. A `.gitignore` is auto-written so findings — which may quote real secrets verbatim from your code — never end up in commits.

## How it works

1. **Recon** — detects framework, auth model, entry points, outbound surface, and trust boundaries. Asks one or two threat-model questions to anchor severity. Output: `recon.md`.
2. **Classify** — sorts every file into review / skim / skip. Entry points default to review. Output: `file-rankings.md`.
3. **Review** — two passes run in parallel:
   - **Per-file:** one agent per Review file. Each has Read/Grep/Bash and follows data flow across files.
   - **Scenario-driven:** one agent per attack class — injection, IDOR/BOLA, function-level authz, SSRF, auth/middleware ordering, crypto, deserialization, resource consumption, logging, and exception handling. Each agent grep-walks the whole repo asking the question an attacker would.
4. **Validate** — findings are clustered by root cause; one validator agent per cluster confirms or refutes each finding, marks duplicates, adjusts severity against a published rubric, and attaches a concrete fix.
5. **Coverage** — explicit statement of which scenarios ran, which OWASP categories were touched, which files were skipped, and where confidence is low. The report is honest about its blind spots.

Findings carry severity (Critical/High/Medium/Low, rubric-anchored), CWE, OWASP category, a verbatim code excerpt, source provenance, a one-line data-flow trace, and a fix recommendation that names the function or symbol to change.

## Cost

This is a token-heavy multi-agent skill. As rough orders of magnitude from a real reference run: a scenario agent burns ~180K tokens, a per-file reviewer averages ~50K, and a full audit on a 1,000-file repo with all ten scenarios and validation can reach **several million tokens**. Run `/model opus` before invoking for the best quality; the bill scales with the model you've selected.

## License

MIT
