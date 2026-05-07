# File Classification Guide

Phase 1 sorts every file into one of three buckets. The point is to narrow Phase 2's per-file pass to the files that matter, fast.

Three buckets:

- **review** — high-likelihood vuln surface. Each gets a Phase 2a agent.
- **skim** — read for context but no dedicated agent. Phase 2b scenario agents may grep into them.
- **skip** — out of scope (no vulns possible, generated, vendored, or otherwise irrelevant).

When uncertain between two buckets, pick the higher one (review > skim > skip).

---

## How to classify, fast

The cheap pass classifies most files by **path / extension / location alone** — no read needed. Read content only for files that survive the cheap pass and aren't yet decided.

### Skip — by path or name (no read needed)

- `*.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `Gemfile.lock`, `composer.lock`, `go.sum`.
- `node_modules/**`, `vendor/**`, `.venv/**`, `venv/**`, `.git/**`, `dist/**`, `build/**`, `out/**`, `.next/**`, `target/**`, `coverage/**`, `.security-audit/**`.
- `*.md`, `*.rst`, `*.txt`, `LICENSE*`, `CHANGELOG*` — documentation. (Exception: a README that documents auth flows can be useful in Phase 0; that's recon, not Phase 1.)
- Static assets: `*.png`, `*.jpg`, `*.jpeg`, `*.gif`, `*.svg`, `*.ico`, `*.webp`, `*.woff`, `*.woff2`, `*.ttf`, `*.otf`, `*.mp4`, `*.mp3`, `*.pdf`.
- Compiled / minified outputs: `*.min.js`, `*.min.css`, `*.map`, anything inside detected build directories.
- Generated code marked with a "do not edit" header at the top — confirm with a header read only.
- Binary files (detect with `file --mime-encoding <path>` returning `binary`).

### Skim — by path or name (no read needed)

- Test files: `**/*.test.*`, `**/*.spec.*`, `**/test_*.py`, `**/__tests__/**`, `tests/**`, `spec/**`. Tests are not attack surface but document expected behavior — read in Phase 2b only when a scenario hits the code under test.
- Build / tooling configs: `webpack.config.*`, `vite.config.*`, `babel.config.*`, `jest.config.*`, `tsconfig*.json`, `eslint*.config.*`, `prettier*`, `.editorconfig`. Skim the top of files like `next.config.*` and `nuxt.config.*` — they sometimes hide security headers or rewrites worth reviewing.
- Translations / i18n bundles: `locales/**`, `i18n/**`, `*.po`, `*.pot`.
- Type-only declaration files: `*.d.ts` with no implementation.
- Documentation that contains snippets: `examples/**`, `docs/**` with code samples — only relevant if a scenario chases through them.

### Review — by path or name (no read needed, default-promote)

These default to `review` because of their position in the application:

- Anything identified as an **entry point in `recon.md`** (route handler, controller, webhook, queue consumer, CLI entry).
- Authentication / authorization modules: paths matching `auth*`, `session*`, `jwt*`, `oauth*`, `login*`, `password*`, `permissions*`, `policy*`, `rbac*`, `acl*`, `middleware*`.
- Cryptography modules: paths matching `crypto*`, `encrypt*`, `cipher*`, `hash*`, `signing*`, `tokens*`.
- API / route definitions: `routes/**`, `controllers/**`, `handlers/**`, `endpoints/**`, `views/**` (when used for routing), `pages/api/**`, `app/api/**`.
- Database / ORM access layers: `models/**`, `repositories/**`, `db/**`, `dao/**`, files with names like `queries.*`, `database.*`.
- File upload handlers, deserializers, template renderers.
- Manifests for dependency review: `package.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`. Reviewers inspect for unpinned versions and known-bad packages.
- Infrastructure-as-code and container build files: `Dockerfile*`, `docker-compose*.yml`, `*.tf`, `*.tfvars`, `serverless.yml`, `cloudformation.yaml`, GitHub Actions workflows under `.github/workflows/**` (CI secrets, action pinning).

### Files needing a content read

Anything not classified by the rules above. Read enough to decide:

- Does the file handle untrusted input directly? → review.
- Does it perform crypto, deserialization, shell-out, file I/O with user-influenced paths, template rendering with variables? → review.
- Does it transform data that *might* have come from outside, but only via an internal pipeline? → skim.
- Pure logic, types, constants, no external data, no I/O? → skim or skip depending on whether scenarios might reference it.

A file with one risky function and ten benign ones is `review` — Phase 2a will focus on the risky part.

---

## Special cases

- **Test files for security-relevant code**: `skim`, not `review`. They're not attack surface, but they document what the developers *think* is enforced — useful when a scenario needs to confirm whether a check exists at all. A reviewer who finds an authz check absent from production code can grep tests to see whether it was ever asserted.
- **Vendored / third-party code committed to the repo**: skip unless the user explicitly includes it in scope. State this in `recon.md` "Out-of-scope".
- **Generated clients** (OpenAPI / GraphQL codegen): skip the generated code, but `review` the generator config.
- **Migrations** (`migrations/**`, `db/migrate/**`): usually `skim`. Promote to `review` if migrations contain raw SQL with embedded data, drop policies that disable RLS, or grant statements.
- **Environment example files** (`.env.example`, `.env.sample`): `skim`. They reveal the secrets surface but typically contain placeholders.
- **Secret-bearing files committed to the repo** (`.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx`, `*.jks`, `credentials.json`, `service-account*.json`): `review`. The reviewer agent will inspect contents and emit a finding if real values are present.
- **Shell scripts** in `scripts/**`, `bin/**`: `review` if they execute user-influenced data, take CLI args, or run in CI with secrets; otherwise `skim`.

---

## Output

Phase 1 writes `.security-audit/file-rankings.md`:

```markdown
# File Classification

Generated: <ISO timestamp>
Total files: <N>
Review: <count> · Skim: <count> · Skip: <count>

## Review (<count>)
- <path> — <one-line reason>
- ...

## Skim (<count>)
- <path> — <reason>
- ...

## Skip (<count>)
<grouped — list rules applied, not every file. e.g. "node_modules/**: 4,219 files">
```

After writing, ask the user how many `Review` files to cover in Phase 2a. Default = all. The `Skim` and `Skip` lists are not user-prompted — they're informational for traceability.

---

## What this guide does *not* do

It does not assign severity. It does not predict findings. It only sorts files by the cost/value of dedicating a reviewer agent to them. Severity is set in Phase 2 against `severity-rubric.md`.
