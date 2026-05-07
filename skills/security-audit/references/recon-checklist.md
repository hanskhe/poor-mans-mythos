# Reconnaissance Checklist (Phase 0)

Phase 0 establishes the project context that every later phase depends on. The output is a single file, `.security-audit/recon.md`, that is loaded into the prompt of every reviewer and validator agent.

Goal: a reviewer agent that opens `recon.md` should know, in under one minute of reading, what kind of application this is, what protects it, and where attackers will aim.

---

## Required output sections

`recon.md` must contain these sections, in this order. Every section must be filled — write `Unknown` rather than skipping.

### 1. One-line description

What this application *does*, in one sentence. Pulled from the README if available, otherwise inferred from the code, otherwise asked of the user.

### 2. Stack

- **Languages:** primary + any significant secondary.
- **Framework(s):** web framework, ORM, auth library, frontend framework if relevant.
- **Runtime / hosting:** detected from `Dockerfile`, `docker-compose.yml`, `Procfile`, `serverless.yml`, `wrangler.toml`, IaC files, CI configs. State `Unknown` if absent.
- **Data stores:** databases, caches, queues mentioned in code or config.

### 3. Authentication & authorization

- **Auth scheme:** sessions / JWT / OAuth (which provider) / API key / SSO / none.
- **Where enforced:** middleware? framework decorator? per-handler check? *Name the file(s)*.
- **Roles / scopes:** list what the code recognizes (admin, user, anonymous, custom roles).
- **Public surface:** which routes / endpoints are reachable without authentication. List them by path.

### 4. Entry points

A flat list of every place external input enters the system. For each, give path/identifier and the file where it's defined.

- HTTP routes (REST or GraphQL) — list method + path + handler file.
- Webhook receivers.
- Queue consumers / pub-sub subscribers.
- Scheduled jobs (cron) that read external data.
- CLI entry points that take user input.
- WebSocket / SSE handlers.
- File upload endpoints.

This list is the single most useful artifact for Phase 2b. Be thorough.

### 5. Outbound surface

Every place the application makes outbound network calls. SSRF and unsafe-third-party-API issues live here.

- HTTP clients used (which library, with what config — does it follow redirects?).
- Specific outbound destinations called from code (third-party APIs).
- Whether URLs are user-supplied anywhere (link previews, profile pictures, webhook callbacks, "import from URL" features).

### 6. Trust boundaries

A short paragraph naming what is trusted vs untrusted in this codebase. Examples:
- "Anything from `req.body` / `req.query` is untrusted."
- "Data read from the `users` table is treated as trusted after auth — but the `bio` field is rendered into HTML emails."
- "Internal queue payloads are *assumed* trusted; if an attacker can write to the queue, they bypass all input validation."

This section is often where logic-bug intuition lives. Make it explicit.

### 7. Highest-value assets

What an attacker would want, ordered roughly by value. Pulled from the threat-model dialog or inferred. Examples:
- "User PII (name, email, phone) and password hashes."
- "Payment card data (claimed: stored only via Stripe tokens — verify in code)."
- "Admin ability to impersonate users (admin-as-user feature in `admin/users.py`)."

### 8. Out-of-scope

Anything the user explicitly excluded, plus any vendored / generated code the audit will skip. Phase 1 must respect this.

---

## How to populate

Work in this order:

1. **Read project markers** in parallel: `README*`, `package.json`, `pyproject.toml`, `requirements.txt`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`, `Dockerfile`, `docker-compose*.yml`, `.github/workflows/*`, top-level config (`next.config.*`, `nuxt.config.*`, `vite.config.*`, `webpack.config.*`).
2. **Detect framework conventions** from imports / file structure (e.g. Express `app.use`, Django `urls.py`, Rails `routes.rb`, FastAPI `@app.get`, NestJS controllers, Next.js `app/` or `pages/`).
3. **Map routes** by grepping for the framework's routing primitives. Examples:
   - Express: `\.(get|post|put|patch|delete|all)\(['\"]`
   - FastAPI: `@\w+\.(get|post|put|patch|delete)`
   - Django: file `urls.py` and `urlpatterns`
   - Rails: `config/routes.rb`
   - Spring: `@(Get|Post|Put|Delete|Request)Mapping`
4. **Locate auth enforcement.** Grep for: `middleware`, `before_action`, `@login_required`, `requireAuth`, `verifyJWT`, `passport.authenticate`, `current_user`, `IsAuthenticated`, `Authorize`. Identify the file that owns the check.
5. **Find outbound HTTP calls.** Grep for HTTP client usage in the project's language: `requests.`, `httpx.`, `fetch(`, `axios.`, `http.Get`, `HttpClient`, `urllib`, `Net::HTTP`.
6. **Run the threat-model dialog** (next section) for what couldn't be inferred.

---

## Threat-model dialog — questions in priority order

Ask the user only the questions whose answers cannot be confidently inferred from the README or code. Always ask in priority order; stop when the necessary context is filled.

1. **Asset question** (highest priority, often required):
   *"What's the highest-impact thing an attacker could do here — read which data, take which action, or impersonate whom?"*
   This anchors severity. Without it, the audit guesses; with it, the audit calibrates.

2. **User base question** (often inferable from README):
   *"Who uses this — public internet users, paying customers, or internal employees only?"*
   Public exposure changes how Critical/High shake out.

3. **Out-of-scope question** (skip if README has been thorough):
   *"Anything I should skip — vendored code, accepted risks, sub-projects you don't own?"*
   Saves Phase 1 churn.

4. **Sensitive data question** (only if not obvious from code):
   *"Does this app handle anything regulated — payments, health data, credentials for other systems?"*
   Affects which findings get pushed to Critical.

If the README answers a question already, do not re-ask it. State the inferred answer in `recon.md` and note it was inferred, not asked.

---

## Anti-patterns to avoid

- **Don't list every file.** `recon.md` is a map, not an index. Phase 1 produces the file index.
- **Don't paraphrase OWASP.** Don't restate the categories. Reference them by code only when listing entry points or trust boundaries that map to a category.
- **Don't speculate about vulns yet.** Phase 0 builds the map. Phase 2 finds the bugs. Discipline matters — speculation in `recon.md` biases later agents.
- **Don't truncate the entry-point list.** A missed route is a missed audit.
