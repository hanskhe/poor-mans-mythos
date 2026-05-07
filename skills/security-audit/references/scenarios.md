# Attack Scenarios (Phase 2b)

Phase 2a reviews files. Phase 2b reviews **questions** — the kind an attacker would ask. Each scenario below is a prompt for a single agent that runs Grep across the whole repo, follows leads, and reports findings in the standard format (`finding-format.md`).

Every scenario agent receives:

- `recon.md` (project context, entry-point list).
- `references/owasp-top10.md` and `references/owasp-api-top10.md` (read on demand).
- `references/severity-rubric.md` and `references/finding-format.md`.
- Read, Grep, Bash tools.

Scenarios are designed to be run in parallel. They will overlap with Phase 2a findings — that's fine; deduplication happens before validation.

Grep patterns below are starters. Reviewers must adapt them to the project's actual language / framework / conventions, which they learn from `recon.md`. A pattern that finds nothing is a signal to look harder, not to stop.

---

## S1. Injection sinks → trust boundaries

**Question:** For every place the application sends data to an interpreter (SQL, shell, template, LDAP, XPath, NoSQL, raw eval), can untrusted input reach it without parameterization or escaping?

**Find sinks (start patterns — adapt to language):**
- SQL: `\.execute\(`, `\.query\(`, `\.raw\(`, `cursor\.execute`, `db\.exec`, `Sequel\.`, `ActiveRecord::Base.connection.execute`, `db\.Query`, f-string / template literal interpolation immediately followed by `SELECT|INSERT|UPDATE|DELETE`.
- Shell: `subprocess\.(run|Popen|call)`, `os\.system`, `child_process\.(exec|spawn)`, `Runtime\.getRuntime\(\)\.exec`, backticks in shell-capable languages, `shell=True` in Python.
- Template: `render_template_string`, `Template\(`, `eval`, `Function\(`, `Mustache\.render` with user data, `dangerouslySetInnerHTML`.
- NoSQL: `\$where`, `\$regex` with user input, MongoDB `find\(\{[^}]*req\.`.
- LDAP: `ldap.*search` with string concatenation including a request value.
- XPath: `xpath\(.+\$|xpath\(.+\+|evaluate\(.+req\.`.

**For each sink:** trace inputs back to a source. Sources include `req.body`, `req.query`, `req.params`, `req.headers`, request body parsers, message payloads, file contents read from upload paths, third-party API responses (external = untrusted in this audit, per OWASP API10).

**Confirm:** is there parameterization, escaping, or schema validation between source and sink? If not, emit a finding with `DataFlow` filled in.

**Ignore:** sinks where the only inputs are constants, environment variables, or values from the project's own configuration.

---

## S2. Object-level authorization (IDOR / BOLA)

**Question:** For every handler that accepts an object identifier from the request and reads or modifies that object, does the code verify the caller owns or is permitted to access that object?

**Find candidate handlers:**
- Route definitions where the path contains a parameter (`/:id`, `/{id}`, `/<int:id>`, `/{slug}`).
- Handlers that fetch by primary key: `findById`, `find_by`, `get_object_or_404`, `Model.find\(`, `db\.query.+WHERE id =`, `db.first(:id)`.
- Mutations that take an ID: `update_by_id`, `delete\(.+id`, `Model.destroy\(`.

**For each candidate:** does the query include a tenant/user/owner constraint (`AND user_id = :current_user`)? Or is there an explicit ownership check (`if obj.owner_id != current_user.id: 403`) before the response? If neither, emit a finding.

**Especially flag:** sequential integer IDs (easier to enumerate), endpoints that bulk-return objects (forgetting per-object check is common), and mutation methods (DELETE/PUT) where authz was added to GET but not to the destructive verbs.

---

## S3. Function-level authorization (admin / privileged paths)

**Question:** For every endpoint or function intended for admins / specific roles, is the role gate present, correct, and reached on every request method?

**Find candidates:**
- Path patterns: `/admin/`, `/internal/`, `/manage/`, `/staff/`, `/owner/`, anything in `recon.md` flagged as admin.
- Function names: `admin_*`, `*_admin`, `manage_*`, `create_invite`, `change_role`, `delete_user`, `impersonate`.

**For each:** is there an explicit role check (`if user.role != 'admin': 403`, `@admin_required`, `IsAdminUser`, `AuthorizeAttribute(Roles="Admin")`)? Is the check at the right layer — middleware mounted on the right path, decorator applied, etc.?

**Bypass patterns to confirm absent:**
- The check exists for `GET` but not `POST`/`DELETE` on the same resource.
- The check is in the controller but the route is also exposed via a different file (e.g. internal API) without the check.
- The role is read from a request-supplied value (`req.headers['x-role']`) rather than the session.

---

## S4. Server-Side Request Forgery (SSRF)

**Question:** For every outbound HTTP request, can an attacker influence the destination URL?

**Find outbound calls (consult `recon.md` outbound surface section first):**
- `requests\.(get|post|put|delete|head)`, `httpx\.`, `urllib\.request\.urlopen`, `aiohttp\.`, `fetch\(`, `axios\.`, `http\.Client`, `Net::HTTP`, `HttpClient`, `RestTemplate`.

**For each call where the URL might come from a request:** does the code allowlist domains/schemes/ports? Does it block private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `::1`, `fc00::/7`, IPv4-mapped IPv6, DNS rebinding via `0.0.0.0`)? Does it resolve and re-check after redirect-following? Does it disable redirect-following entirely?

**Common vulnerable surfaces:**
- Webhook receivers / outbound webhooks.
- "Import from URL" features.
- Profile picture / avatar URLs that the server fetches.
- Link previews / unfurling.
- PDF or screenshot generation services.
- Any feature where `req.body.url` or `req.body.callback_url` is fetched server-side.

**Cloud metadata test:** does the code permit `http://169.254.169.254/`, `http://metadata.google.internal/`, `http://100.100.100.200/`? If not blocked, treat as exploitable on cloud-hosted apps.

---

## S5. Authentication enforcement & middleware ordering

**Question:** For every route that should require authentication, does the auth middleware actually run for that route under all HTTP methods?

**Find candidates:** every route from `recon.md`'s entry-point list except those listed under "Public surface."

**For each:** trace from the route registration to the auth check. Confirm:
- The middleware is mounted on the path, not bypassed by a more specific route registered earlier.
- Express: `app.use('/api', auth); app.get('/api/...', handler)` is fine, but `app.get('/api/public', handler)` registered before the `/api` mount may bypass auth.
- Django: `@login_required` decorators are present on the view, or the URL is inside a path with an auth-requiring parent.
- Rails: `before_action :authenticate_user!` is in the controller and not skipped via `skip_before_action`.
- FastAPI / NestJS: dependency injection or guards are declared on the path operation.

**Especially flag:**
- Routes that exist but aren't listed in `recon.md`'s "Public surface" *or* protected list — likely undocumented and unprotected.
- `OPTIONS`, `HEAD` handlers that bypass auth and leak information.
- Health-check / debug endpoints (`/healthz`, `/debug`, `/metrics`, `/swagger`, `/graphql` introspection in prod) that reveal more than they should.

---

## S6. Cryptographic primitives

**Question:** Where the application performs hashing, encryption, signing, or random generation, are the primitives appropriate and used correctly?

**Find usages:**
- Hash: `hashlib\.(md5|sha1|sha256)`, `MessageDigest\.getInstance\("(MD5|SHA-1)"\)`, `crypto\.createHash\('(md5|sha1)'\)`, `Digest::(MD5|SHA1)`.
- Encryption: `AES`, `Cipher\.getInstance`, `crypto\.createCipher`, `Fernet`, `nacl\.`, `bcrypt`, `argon2`, `scrypt`, `pbkdf2`.
- Random: `Math\.random`, `random\.(random|randint|choice)`, `rand\(`, `Random\.new`.
- JWT: `jwt\.(encode|decode|sign|verify)`, `jsonwebtoken\.`, `jose\.`.

**For each, confirm:**
- Passwords use Argon2id / bcrypt / scrypt — never raw SHA family, never MD5.
- Symmetric encryption uses AEAD (AES-GCM, ChaCha20-Poly1305) with unique IVs/nonces. ECB mode is always wrong. CBC requires HMAC.
- Random tokens for security purposes use a CSPRNG (`secrets`, `crypto.randomBytes`, `crypto/rand`) — never `Math.random` or non-secure `random`.
- JWT verification specifies an expected algorithm; never accept `none`. Symmetric secrets are not predictable; asymmetric keys are not weak.
- Keys / IVs / salts are not hardcoded.

---

## S7. Untrusted deserialization

**Question:** Where the application deserializes data from outside its own runtime, can the resulting object instantiate arbitrary classes or trigger code execution?

**Find usages:**
- Python: `pickle\.loads`, `marshal\.loads`, `yaml\.load\(` (without `Loader=SafeLoader`), `dill\.`.
- Java: `ObjectInputStream`, `XMLDecoder`, `readObject`, `XStream` without allowlist.
- PHP: `unserialize\(`.
- Ruby: `Marshal\.load`, `YAML\.load` (not `YAML.safe_load`).
- Node: any `eval`, `Function\(`, `vm\.runInThisContext`, `serialize-javascript` reverse, `node-serialize`.
- JWT `none` algorithm acceptance.
- Cookie / header values used as object instantiation hints.

**Confirm:** the source is untrusted (request body / cookie / header / queue payload that an attacker can write to). Internal in-process serialization is fine.

---

## S8. Resource consumption / abuse

**Question:** Where can a single request cause disproportionate resource use (CPU, memory, money, third-party rate limits)?

**Find candidates:**
- Pagination params: `limit`, `pageSize`, `count`, `take`, `top` — does the server cap them?
- File uploads: max size enforced? At edge or in app?
- Loops driven by request data: `for item in req.body.items` — bounded?
- GraphQL: query depth / complexity limits?
- Regex compiled from user input or matched against unbounded user input (ReDoS).
- Outbound calls triggered per-request (email, SMS, paid APIs) — rate-limited per-user?
- Background jobs enqueued from a single request — unbounded?

**Confirm:** the cap exists and is server-enforced (not just client-side).

---

## S9. Logging & data exposure

**Question:** What does the app log, and what does it expose in errors?

**Find:**
- Log statements that include `password`, `token`, `secret`, `authorization`, `cookie`, `ssn`, `credit_card`.
- Log statements that include entire request objects: `log(req)`, `log(request.body)`.
- Error handlers that return stack traces, file paths, query strings, or exception messages to clients (`return str(e)`, `res.send(error.stack)`).
- User-controlled input written to logs without newline / control char sanitization (log injection, log forging).

**Also confirm absent — auth events that should be logged:**
- Login success / failure / lockout.
- Authorization denials.
- Privilege escalation attempts.
- Password change / reset.
- High-value transactions.

Missing logging on these is `Low` severity unless the user has flagged compliance concerns in recon.

---

## S10. Mishandling exceptional conditions

**Question:** When something goes wrong, does the system fail closed and clean up?

**Find:**
- Broad catches that swallow: `except: pass`, `catch (Exception) {}`, `rescue => e; nil`.
- Auth checks inside try/catch where the catch grants access ("fail open" — `try { authorize() } catch { return next() }`).
- Database transactions / file handles / network sockets opened without `finally` / context manager / `defer`.
- Long-running operations without timeout (`requests.get(url)` with no `timeout=`, `setTimeout` patterns missing).
- Multi-step operations that don't roll back on partial failure.
- Null / nil dereferences reachable via crafted input (specifically: optional chaining missing on data from request → field assumed present).

**Confirm:** the pattern is reachable from external input, not just an internal helper.

---

## How an agent runs a scenario

1. Read `recon.md` end-to-end.
2. Read this scenario's section.
3. Execute the relevant Greps. Adapt patterns to the project's language and conventions.
4. For each candidate hit, inspect the file and follow the trail (callers, callees, registered middleware, schema definitions, ORM models — whichever the scenario needs).
5. Emit one `---FINDING---` block per distinct issue. If the same root cause appears in many places, file once with `References:` listing the call sites.
6. End the response with a single line: `Scenario: <S#> <name>` followed by `Findings: <count>`. This is parsed by the orchestrator.

---

## When a scenario produces no findings

Emit:

```
Scenario: <S#> <name>
Findings: 0
Notes: <1-3 sentences on what was checked, what was searched for, and any uncertainty. e.g. "Found 14 SQL sinks; all use parameterized queries via Knex placeholders. Two raw().select() usages exist (file:line) — both interpolate only constants. Not reviewed: dynamic ORDER BY clauses (none located via grep)."
```

The `Notes:` field feeds Phase 4 coverage. A scenario with zero findings is *information*, not silence.
