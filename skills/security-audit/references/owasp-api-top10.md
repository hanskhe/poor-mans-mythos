# OWASP API Security Top 10 (2023) — Review Checklist

Use this when reviewing API endpoint handlers, route definitions, middleware, and any code
that processes or forwards HTTP requests. Three of the top five items are authorization
failures — pay close attention to access control at every level.

---

## API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

APIs that use object identifiers in requests without verifying ownership are the #1 API risk.

Look for:
- Object IDs in path params, query strings, headers, or body used to fetch/modify records
- No check that the authenticated user owns or has permission to access the requested object
- Sequential or guessable IDs (integers, short UUIDs) — easier to enumerate
- Authorization checked only at the endpoint level, not per-object
- Database queries like `WHERE id = :user_supplied_id` without `AND owner_id = :current_user`

Example vulnerable pattern:
```
GET /api/invoices/{id}        → returns invoice without checking ownership
DELETE /api/documents/{id}    → deletes without verifying the caller owns the document
```

---

## API2:2023 — Broken Authentication

Authentication mechanism flaws that allow token compromise or identity assumption.

Look for:
- No brute-force protection or rate limiting on login/password-reset endpoints
- Credentials or tokens transmitted in URL query parameters (end up in logs/referrers)
- JWT tokens accepted with `{"alg": "none"}` or without signature validation
- Password changes or sensitive account operations without re-authentication
- Predictable or short authentication tokens
- No account lockout after repeated failures
- GraphQL or batch endpoints that bypass per-request rate limits

Example vulnerable patterns:
```
POST /login — no rate limiting, no lockout
Accept JWT with alg=none
PUT /account — changes email without confirming current password
POST /graphql — 999 login mutations batched in one request
```

---

## API3:2023 — Broken Object Property Level Authorization

Sensitive object properties exposed in responses or modifiable via requests without authorization.
Combines "Excessive Data Exposure" (reading) and "Mass Assignment" (writing).

Look for:
- Serializing entire model/ORM objects into responses (`return user.to_json()`)
- No explicit allowlist of which fields may be returned
- Accepting all submitted fields and binding them directly to models (`user.update(params)`)
- Properties in responses that the caller shouldn't see (e.g. `is_admin`, `internal_score`, `hashed_password`)
- Hidden fields discoverable by fuzzing requests with extra keys
- Side effects from property changes not reflected in responses (write succeeds silently)

Example vulnerable patterns:
```python
return jsonify(user.__dict__)            # exposes all fields
user.update_attributes(request.json)     # mass assignment
POST /users with {"role": "admin"}       # attacker elevates own role
```

---

## API4:2023 — Unrestricted Resource Consumption

No limits on the resources a single request or user can consume, enabling DoS or cost attacks.

Look for:
- No maximum on file upload sizes
- Pagination with user-controlled `limit` parameter and no server-enforced cap
- GraphQL or batch endpoints accepting unlimited items per request
- Long-running operations with no timeout
- Endpoints triggering expensive side effects (email, SMS, thumbnail generation, PDF rendering) without rate limits
- Third-party API calls (payment, notification services) triggered without spending caps
- No memory or CPU quotas on processing tasks

Example vulnerable patterns:
```
GET /users?limit=999999
POST /graphql with 500 image upload mutations
POST /forgot-password — no rate limit → runs up SMS costs
```

---

## API5:2023 — Broken Function Level Authorization

Administrative or privileged functions accessible to users who shouldn't have access.

Look for:
- Admin endpoints without role/group checks (`/api/admin/users`, `/api/internal/config`)
- Authorization checked inconsistently — some endpoints enforce it, others don't
- HTTP method changes bypassing authorization (GET is checked, DELETE is not)
- Guessable admin URL patterns not enforced by middleware
- Invite or role-manipulation endpoints accessible to regular users
- No deny-by-default — missing explicit permission grants

Example vulnerable patterns:
```
GET /api/admin/users          → no role check
POST /api/invites/new         → any authenticated user can create admin invites
DELETE /api/reports/{id}      → no check that caller is admin or owner
```

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

Legitimate API features exploited at scale through automation to cause business harm.

Look for:
- Purchasing, booking, or reservation endpoints without velocity limits
- Referral or reward flows with no per-account cap
- No CAPTCHA or human verification on high-value operations
- No device fingerprinting or headless browser detection
- No detection of non-human usage patterns
- IP-based rate limiting only (easily bypassed with proxies)

Example vulnerable patterns:
```
POST /purchase — no per-user purchase rate limit → scalping bots
POST /register — automated bulk signup exploiting referral credits
POST /book/seat — no limit → attacker reserves all seats, releases before penalty
```

---

## API7:2023 — Server-Side Request Forgery (SSRF)

The server fetches user-supplied URLs without validation, enabling internal network access.

Look for:
- Any endpoint accepting a URL parameter that the server fetches (webhooks, import-from-URL, profile pictures, link previews)
- No allowlist of approved domains/schemes/ports
- HTTP clients configured to follow redirects without checking the destination
- URLs used directly in server-side HTTP calls: `fetch(req.body.url)`
- No blocking of internal IP ranges (`127.0.0.1`, `10.x.x.x`, `169.254.169.254`)

Example vulnerable patterns:
```python
requests.get(user_supplied_url)                     # no validation
POST /webhooks with {"callback_url": "http://169.254.169.254/latest/meta-data/"}
POST /profile with {"picture_url": "http://internal-admin:8080/config"}
```

---

## API8:2023 — Security Misconfiguration

Insecure defaults, unnecessary features, verbose errors, or missing hardening at any stack layer.

Look for:
- Debug mode or verbose stack traces enabled in production configuration
- Permissive CORS (`Access-Control-Allow-Origin: *` with credentials allowed)
- Unnecessary HTTP methods enabled (TRACE, OPTIONS, PUT, DELETE where not needed)
- Missing security headers (HSTS, X-Content-Type-Options, Cache-Control on sensitive endpoints)
- Default credentials, API keys, or secrets not rotated
- Sensitive data returned in error responses (DB schema, file paths, internal IPs)
- Debugging or introspection endpoints left reachable (`/graphql` introspection in prod, `/actuator`, `/debug`)

Example vulnerable patterns:
```
Access-Control-Allow-Origin: *  (with credentials: true)
Returning full exception stack traces to clients
GraphQL introspection enabled in production
```

---

## API9:2023 — Improper Inventory Management

Lack of visibility into running API versions, environments, and data flows to third parties.

Look for:
- Multiple API versions running with inconsistent security (v1 unpatched, v2 patched)
- Beta, staging, or test API endpoints exposed to the internet without production-level protections
- No documentation of which endpoints exist or what data they return
- Deprecated endpoints still accepting requests
- Third-party integrations where the data flow and sensitivity aren't tracked
- Production data present in non-production environments

Example vulnerable patterns:
```
api.beta.example.com — no rate limiting present in production version
/api/v1/users — deprecated but still live, missing auth middleware added in v2
Staging environment connected to production database
```

---

## API10:2023 — Unsafe Consumption of APIs

Data from third-party APIs treated as trusted and used without validation, enabling supply-chain attacks.

Look for:
- Third-party API responses inserted directly into database queries without sanitization
- No schema or type validation on external API responses
- Blind redirect following when calling third-party services
- HTTP (not HTTPS) used for external API calls
- No timeout or resource limit on outbound requests
- Third-party data rendered in UI without escaping (XSS via external data)

Example vulnerable patterns:
```python
name = third_party_response["name"]
db.execute(f"SELECT * FROM users WHERE name = '{name}'")   # SQL injection via third party

requests.get(third_party_url, allow_redirects=True)        # follows redirect to attacker server
```

---

## When to Apply This Checklist

Apply `owasp-api-top10.md` in addition to `owasp-top10.md` when reviewing:
- REST or GraphQL API route/controller files
- Middleware handling authentication or authorization
- Files that make outbound HTTP requests to third-party services
- Webhook or callback handling code
- Any file whose primary purpose is request/response handling

The general `owasp-top10.md` covers injection, crypto, and logging concerns that apply to
all code. This checklist focuses on the API-specific authorization and consumption patterns
that the general list doesn't fully address.
