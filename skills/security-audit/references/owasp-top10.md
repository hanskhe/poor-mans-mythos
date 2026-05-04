# OWASP Top 10 (2025) — Security Review Checklist

Use this as the primary framework when reviewing files for security issues.
For each category, consider whether the code creates, worsens, or fails to mitigate the risk.

**2025 changes from 2021:** Security Misconfiguration moved up to #2; two new categories
(A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions); Injection
dropped to #5; XSS was folded into other categories.

---

## A01:2025 — Broken Access Control

The #1 risk in 100% of tested applications. Policies restricting user actions to their
intended permissions are missing, inconsistent, or bypassable.

Look for:
- Functions that fetch or modify resources using a caller-supplied ID without verifying ownership
- IDOR — `GET /invoices/{id}` or `DELETE /documents/{id}` without an ownership check
- Privilege escalation — a user can change their own role, access admin endpoints, or skip auth steps
- Authorization checked at the endpoint level only, not per object or per property
- CORS misconfiguration allowing credentialed requests from untrusted origins
- Default-allow logic — code that grants access unless explicitly denied (fragile; should be deny-by-default)
- JWT or session token manipulation enabling identity spoofing
- Missing functional access control on HTTP methods (GET is checked, DELETE is not)

---

## A02:2025 — Security Misconfiguration

Moved from #5 to #2. Present in 100% of tested applications. Affects every layer of the stack.

Look for:
- Debug mode, verbose stack traces, or internal paths exposed to clients
- Default credentials or API keys not changed
- Unnecessary HTTP methods enabled (TRACE, PUT, DELETE where not needed)
- Permissive CORS (`Access-Control-Allow-Origin: *` with credentials allowed)
- Missing or misconfigured security headers (HSTS, X-Content-Type-Options, Cache-Control on sensitive responses)
- Unnecessary features enabled (GraphQL introspection, `/actuator`, admin UIs, directory listing)
- Cloud storage or service permissions broader than required
- Sensitive data returned in error messages (DB schema, file paths, internal IPs)
- Hardcoded secrets, tokens, or credentials in configuration or source

---

## A03:2025 — Software Supply Chain Failures

New in 2025 (expanded from A06:2021 "Vulnerable and Outdated Components"). Scope now covers
the entire dependency ecosystem: third-party libraries, build tools, CI/CD pipelines, and
distribution infrastructure.

Look for:
- Dependencies without pinned versions (floating `^`, `~`, `*`) — vulnerable to version hijacking
- No Software Bill of Materials (SBOM) or dependency manifest audit
- Transitive dependencies not tracked or scanned
- CI/CD pipelines pulling from unverified or unpinned external sources
- Lack of signature verification on downloaded artifacts or packages
- Single developer able to deploy to production without oversight (no separation of duties)
- Outdated or unmaintained libraries, especially security-critical ones (auth, crypto, serialization)
- Missing automated CVE scanning in the build pipeline

Note: Flag suspicious patterns in manifests (`package.json`, `requirements.txt`, `Cargo.toml`,
`go.mod`). Full validation requires running `npm audit`, `pip-audit`, `cargo audit`, etc.

---

## A04:2025 — Cryptographic Failures

Dropped from #2 to #4, but still critical. Weak or absent cryptography directly causes data exposure.

Look for:
- Passwords hashed with MD5, SHA-1, or SHA-256 without salt (use Argon2, bcrypt, scrypt)
- Sensitive data transmitted over HTTP instead of HTTPS
- Hardcoded cryptographic keys or secrets in source code
- Weak random number generation for security tokens (`Math.random()`, `random.random()` — use `secrets`/`crypto`)
- Symmetric encryption using ECB mode or reused IVs
- Deprecated algorithms: DES, RC4, RSA < 2048-bit, TLS 1.0/1.1
- Sensitive responses cached without `Cache-Control: no-store`
- Encryption without authentication (no AEAD — use AES-GCM, ChaCha20-Poly1305)
- Secrets logged or included in error messages

---

## A05:2025 — Injection

Dropped from #3 to #5, but present in 100% of tested applications. Untrusted data
sent to an interpreter as part of a command or query.

Look for:
- SQL injection — string concatenation or f-string interpolation into SQL queries instead of parameterized queries
- Command injection — user input passed to `exec`, `system`, `subprocess(shell=True)`, `child_process.exec`, etc.
- LDAP injection — user input included in LDAP filter strings
- Template injection (SSTI) — user-controlled data rendered through a template engine without escaping
- NoSQL injection — unsanitized objects used in MongoDB `$where`, `$regex`, `$lookup`, etc.
- XPath injection — user input interpolated into XPath expressions
- XML/XXE — external entity references in XML parsers that haven't disabled DTD processing
- ORM injection — raw SQL fragments passed through ORM escape hatches (`raw()`, `execute()`)

---

## A06:2025 — Insecure Design

Dropped from #4 to #6. Architectural flaws that cannot be fixed by correct implementation alone.
Distinguishable from implementation bugs: the design itself is the problem.

Look for:
- No rate limiting on authentication, password reset, or high-value action endpoints
- No account lockout, CAPTCHA, or bot detection on sensitive operations
- Business logic that can be abused: applying discounts multiple times, skipping required workflow steps, replaying transactions
- No multi-factor authentication path for sensitive operations (payment, account deletion, privilege change)
- Security questions used as an authentication factor (deprecated; easily researched or guessed)
- Missing abuse case handling — code only considers the happy path, not adversarial input
- Insufficient tenant or role segregation baked into the data model

---

## A07:2025 — Authentication Failures

Maintained. Failures in verifying user identity and managing sessions correctly.

Look for:
- No rate limiting or lockout on login or password-reset endpoints (enables credential stuffing and brute force)
- Weak password policy — accepting short, common, or default passwords
- Session IDs exposed in URLs (end up in logs, referrers, browser history)
- Session not invalidated or regenerated after login (session fixation)
- No session invalidation on logout
- "Remember me" tokens that are long-lived, predictable, or stored insecurely
- Missing re-authentication for sensitive operations (password change, fund transfer, account deletion)
- Username enumeration — different responses for "user not found" vs "wrong password"
- Insecure password reset flows (guessable tokens, long validity windows, no single-use enforcement)
- Passwords stored in plain text, with reversible encryption, or with weak hashing

---

## A08:2025 — Software or Data Integrity Failures

Maintained. Failures to verify the integrity of software updates, critical data, and CI/CD pipelines
within your own environment (supply chain issues at the ecosystem level are in A03).

Look for:
- Deserialization of untrusted data without schema/type validation (pickle, Java serialization, PHP `unserialize`, YAML `load`)
- Auto-update mechanisms that don't verify signatures before applying updates
- Plugins, libraries, or modules loaded from untrusted or unverified locations at runtime
- CI/CD pipelines that pull and execute code from external sources without integrity checks
- Objects deserialized from cookies, headers, or request bodies and used without validation
- Improperly controlled modification of dynamically-determined object attributes (mass assignment variant)

---

## A09:2025 — Security Logging and Alerting Failures

Maintained (renamed: "Monitoring" → "Alerting" to emphasize that undetected events are the failure).
Without adequate logging and alerts, attacks go undetected and incident response is impossible.

Look for:
- Authentication events (login, logout, failure) not logged
- Authorization failures not logged
- High-value or irreversible transactions not logged
- Logs that include sensitive data (passwords, tokens, PII, full credit card numbers)
- Log injection — user-controlled input included in log messages without sanitization (newlines, ANSI codes)
- No alerting thresholds for repeated failures or anomalous patterns
- Logs not protected against tampering (append-only, integrity-checked)
- Log retention too short for forensic analysis

---

## A10:2025 — Mishandling of Exceptional Conditions

New in 2025. Applications that fail to handle unexpected states, resource exhaustion, or errors
gracefully create vulnerabilities through undefined behavior, information disclosure, or denial of service.

Look for:
- Broad `catch` blocks that swallow exceptions silently and leave the system in an unknown state
- Unclosed resources (DB connections, file handles, sockets) after exceptions — leads to resource exhaustion
- Incomplete transaction rollback in multi-step processes — partial state corruption
- Sensitive information exposed in exception messages returned to clients
- Missing input validation allowing unbounded values (no max size on arrays, strings, files, pagination)
- "Fail open" error handling — an exception causes access to be granted rather than denied
- NULL/nil dereference paths reachable via crafted input
- No timeout or resource quota on long-running or externally-dependent operations
- Rate limiting and resource quotas absent on computationally expensive paths

---

## Beyond the Top 10

- **Logic errors**: Code correct in isolation but exploitable in sequence (race conditions, TOCTOU, business workflow abuse)
- **Trust boundary violations**: Data crossing from untrusted to trusted zones without sanitization
- **Insecure defaults**: Features requiring opt-in security rather than opt-out (e.g. escaping disabled by default)
- **Denial of service via input**: Regex catastrophic backtracking, deeply nested JSON, zip bombs
