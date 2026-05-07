# Severity Rubric

Apply this rubric when assigning severity in Phase 2 findings and when adjusting in Phase 3 validation. Severity must reflect realistic impact in the *current* application, not the worst conceivable abuse of the underlying primitive.

Pick severity by combining three factors:

1. **Impact** — what an attacker gains.
2. **Accessibility** — who can trigger it (unauthenticated, any user, specific role, prerequisites).
3. **Prerequisites** — chains, timing, configuration, or special data needed.

A bug that requires admin access to trigger is not Critical even if the impact is RCE. A bug an unauthenticated attacker can hit at scale gets pushed up.

---

## Critical

Reserved for issues where a single attacker action causes catastrophic loss with no meaningful prerequisites.

Qualifies if **any one** is true:

- Unauthenticated remote code execution.
- Unauthenticated SQL/NoSQL injection that returns or modifies arbitrary data.
- Unauthenticated mass-data exfiltration (e.g. dumping the user table).
- Unauthenticated account takeover affecting any user (broken password reset, JWT `alg=none` accepted, predictable session tokens).
- Unauthenticated authorization bypass on a destructive admin action (delete-all, role change for any user).
- Hardcoded production credentials or private keys committed to the repo and currently active.
- Cryptographic failure that exposes all stored sensitive data (e.g. AES-ECB on PII with a known IV pattern, passwords stored in plain text).

If authentication is required but trivial to obtain (open signup, no email verification), still treat as Critical when the post-auth impact is catastrophic.

---

## High

Severe impact, but with a meaningful gate — requires authentication, a specific role, or a non-trivial prerequisite.

Qualifies if **any one** is true:

- Authenticated IDOR / object-level authz bypass that exposes or modifies other users' data.
- Function-level authz bypass (regular user reaches admin endpoint).
- SSRF that can reach internal infra (cloud metadata, internal services) but requires authentication.
- Exploitable injection (SQL, command, template, LDAP) in a primary user flow that requires login but no special role.
- Privilege escalation (regular user → admin) within the application.
- Stored XSS in an interface used by privileged users (admin panel) where it can hijack admin sessions.
- Cryptographic weakness exposing individual sensitive items (predictable token generation for password reset).
- Deserialization of untrusted data that yields code execution or arbitrary object instantiation.

---

## Medium

Real issue with significant mitigations, narrow blast radius, or substantial prerequisites.

Qualifies if **any one** is true:

- IDOR or info disclosure where the leaked data is moderately sensitive (email addresses, partial profile, internal IDs).
- Authentication weakness without immediate compromise: missing rate limit on login, no MFA on sensitive operations, password policy too weak.
- Reflected XSS in a low-traffic page, or stored XSS in a context that doesn't reach privileged users.
- CSRF on a state-changing endpoint with non-trivial impact.
- Crypto using a weak primitive but with mitigating context (e.g. SHA-1 used for non-security purpose, or a deprecated cipher behind a feature flag).
- SSRF restricted to public destinations (no internal access).
- Open redirect on an authenticated flow.
- Verbose error responses leaking stack traces, file paths, or DB schema.
- Resource exhaustion (unbounded uploads, no pagination cap) without amplification beyond a single attacker.

---

## Low

Hardening gap, defense-in-depth issue, or theoretical problem with significant prerequisites.

Qualifies if **any one** is true:

- Missing security headers (HSTS, CSP, X-Content-Type-Options) where the absence isn't directly exploitable in the current design.
- Logging gaps (auth events not logged, sensitive operations missing audit trail) — informational unless attached to an active incident-response need.
- Information disclosure of low-sensitivity data (server version banner, framework name).
- Cookie flags missing (`Secure`, `HttpOnly`, `SameSite`) on cookies that don't carry security state.
- Inconsistent error messages that *might* enable username enumeration but with no rate limiting impact in scope.
- Theoretical race conditions where the window is small and the prerequisites are stringent.
- Outdated dependencies *without* a known exploitable CVE in the used surface.

---

## Decision flow

Use this when stuck between two levels:

1. **Can an unauthenticated attacker do this?** If yes, lean one level higher.
2. **What's the realistic blast radius — one user, all users, the whole system?** All users / system → lean higher. One user, opt-in interaction → lean lower.
3. **What does the attacker walk away with?** Code execution / mass data → Critical/High. Single record / moderate info → Medium. Clue or hint → Low.
4. **How many things need to go right for the attacker?** Zero or one prerequisite → keep severity. Multiple stacked prerequisites → drop one level.

When two factors disagree, **impact dominates accessibility**. A Critical-impact bug behind one auth gate is High, not Medium.

---

## What does not change severity

- The fact that no one has exploited it yet.
- The size of the user base ("only 100 customers").
- Whether the code is "internal" or "behind a VPN" (misconfig can change that overnight).
- The presence of WAF / cloud edge protections (skill audits the application, not the perimeter).

---

## Confidence is separate from severity

Severity = "if real, how bad." Confidence = "is it real." Findings emit both. A High-severity finding with Low confidence is *not* automatically downgraded — Phase 3 validation resolves confidence; severity stays anchored to impact.
