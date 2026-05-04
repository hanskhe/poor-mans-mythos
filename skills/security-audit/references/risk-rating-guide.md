# File Risk Rating Guide

Assign each file a risk rating from 0 (no risk) to 5 (highest risk) based on its content.
Rate based on what the file actually does, not just its extension or name.

## Rating Definitions

### Risk 5 — Critical attack surface
Files that directly handle untrusted input, authentication, authorization, cryptography,
or execution of external commands. A vulnerability here is likely exploitable.

Examples of what to look for:
- Authentication and authorization logic (login, session creation, permission checks)
- Cryptographic operations (hashing, encryption, key generation, signing)
- SQL or NoSQL query construction, especially with any variable interpolation
- Processing of user-supplied input (form data, query params, request bodies, file uploads)
- API endpoint handlers that accept external requests
- Payment processing or financial transaction logic
- `exec`, `subprocess`, `eval`, `system`, shell invocation, or equivalent
- Deserialization of data from external sources (JSON.parse of untrusted input, pickle.loads, etc.)
- Redirect logic that uses user-supplied URLs

### Risk 4 — Significant security configuration
Files that configure security-relevant behavior or handle session/identity data.
Vulnerabilities here are often exploitable with some context.

Examples:
- Environment variable and secrets handling (reading, passing, logging of sensitive values)
- Session and cookie configuration (flags, expiry, storage)
- JWT creation, parsing, or validation
- CORS, CSP, or other security header configuration
- OAuth / SSO callback handling
- Password reset flows
- Rate limiting and brute-force protection configuration
- Trust boundary definitions (what's internal vs external)

### Risk 3 — Indirect data handling
Files that process or transform data that may have originated externally,
or that perform file I/O with paths that could be user-influenced.

Examples:
- Template rendering with any variable substitution
- File read/write operations where the path or content could be influenced externally
- XML, YAML, or other structured format parsing (potential XXE, YAML bomb, etc.)
- Data serialization that includes user data
- Logging that may capture request data

### Risk 2 — Low-exposure utilities
Files that transform or process data but are insulated from direct external input.
Vulnerabilities are possible but require a chain to exploit.

Examples:
- Helper/utility functions that receive data from higher layers
- Internal data transformation pipelines
- Caching logic
- Background job processors where input comes from internal queues

### Risk 1 — Minimal exposure
Files with pure logic, no external data, and no security-sensitive operations.

Examples:
- Pure computation functions
- Data structure definitions
- Type definitions and interfaces
- Internal constants and enums
- Configuration files for build tools (webpack, babel, etc.)

### Risk 0 — No security relevance
Files that cannot contribute to a security vulnerability.

Examples:
- Static assets (images, fonts, compiled CSS)
- Documentation files (.md, .txt, .rst)
- Test fixtures and mock data
- Lock files (package-lock.json, yarn.lock, Cargo.lock, poetry.lock)
- Generated code that is never modified by hand
- `.gitignore`, `.editorconfig`, `.prettierrc`, etc.

## Rating Tips

- When in doubt between two ratings, use the higher one.
- A file with a single high-risk function earns the rating of that function, even if the rest is benign.
- Comments describing security logic don't raise risk; actual implementation does.
- Test files that test security logic are not themselves risk-5 (they don't run in production),
  but they can be useful for understanding the attack surface — rate them 1.
