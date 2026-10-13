# Auth Service API (v1)

Base URL (local): `http://localhost:4001`. Conventions (errors, headers, IDs, JWT) are in
`ecommerce-infrastructure/docs/architecture/conventions.md`.

Machine-readable spec: [`openapi/openapi.json`](../openapi/openapi.json) (OpenAPI 3.1), served at
`/openapi.json`, with Swagger UI at `/docs`. It is generated from the same Zod schemas that validate
requests (`npm run openapi:export`), and a test fails if the committed file is stale.

Status: **implemented** (Phase 2), except `/internal/v1/auth/service-token`, which arrives in Phase 3
with the first service-to-service caller.

## Endpoints

| Method | Path | Auth | Idempotency | Purpose |
|---|---|---|---|---|
| GET | `/health/live`, `/health/ready` | none | n/a | Liveness / readiness |
| GET | `/.well-known/jwks.json` | none | n/a | Public signing keys for token verification |
| POST | `/api/v1/auth/register` | none | natural (unique email) | Create customer account, send verification email |
| POST | `/api/v1/auth/login` | none | n/a | Issue access token + refresh cookie |
| POST | `/api/v1/auth/refresh` | refresh cookie + CSRF | rotation | Rotate refresh token, issue new access token |
| POST | `/api/v1/auth/logout` | refresh cookie + CSRF | idempotent | Revoke current session |
| POST | `/api/v1/auth/logout-all` | access token | idempotent | Revoke all sessions of the user |
| POST | `/api/v1/auth/verify-email` | none | idempotent | Consume email-verification token |
| POST | `/api/v1/auth/verify-email/resend` | access token | n/a | Send a new verification link |
| POST | `/api/v1/auth/forgot-password` | none | always 202 | Send reset link if account exists |
| POST | `/api/v1/auth/reset-password` | none | single-use token | Set new password, revoke all sessions |
| GET | `/api/v1/auth/me` | access token | n/a | Current user |
| GET | `/api/v1/admin/users` | admin | n/a | List/search users (cursor pagination) |
| PATCH | `/api/v1/admin/users/{userId}/status` | admin | idempotent | Suspend / activate account (revokes sessions on suspend) |
| POST | `/internal/v1/auth/service-token` | client credentials | n/a | *(Phase 3)* Short-lived service token for service-to-service calls |

## Request / response shapes

### POST /api/v1/auth/register
```json
// request
{ "email": "asha@example.com", "password": "correct horse battery staple", "fullName": "Asha Rao" }
// 201
{ "user": { "id": "uuid", "email": "asha@example.com", "fullName": "Asha Rao", "roles": ["customer"],
            "emailVerified": false, "status": "ACTIVE", "createdAt": "2026-10-13T09:30:00.000Z" } }
```
- Email is trimmed and lower-cased before validation. A database CHECK constraint enforces this too.
- Password: 12–128 characters, not a common password, and must not contain the email's local part.
  Phase 7 swaps the small built-in list for a k-anonymity breached-password check.
- Hashed with Argon2id at the OWASP minimum (m=19 MiB, t=2, p=1). That measured ~150 ms on an Apple
  M-series host and ~470 ms inside Docker Desktop. Size production CPUs so it stays under ~250 ms.
- Unknown fields are rejected (`.strict()`), so a client cannot send `"role": "ADMIN"`.
- The user row, verification token, `UserRegistered` outbox event and audit entry commit in one
  transaction. The verification email is sent afterwards. If delivery fails, registration still
  succeeds and the user can resend.

Errors: `400 VALIDATION_FAILED`, `409 EMAIL_ALREADY_REGISTERED`, `429 RATE_LIMITED`.

### POST /api/v1/auth/login
```json
// request
{ "email": "asha@example.com", "password": "..." }
// 200, plus Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth
//          Set-Cookie: csrf_token=...; Secure; SameSite=Strict; Path=/
{ "accessToken": "eyJ...", "tokenType": "Bearer", "expiresIn": 900, "user": { "...": "as above" } }
```
Errors: `401 INVALID_CREDENTIALS` (same response for unknown email and wrong password),
`403 ACCOUNT_SUSPENDED`, `429 RATE_LIMITED` (per IP and per account).

### POST /api/v1/auth/refresh
Header `X-CSRF-Token` must equal the `csrf_token` cookie. Returns the same body as login and a new
refresh cookie. Presenting an already-rotated refresh token is treated as theft: the whole
session family is revoked and `401 REFRESH_TOKEN_REUSED` is returned.

### Rate limits

| Limit | Scope | Applies to |
|---|---|---|
| 30 requests / minute | per client IP | register, login, verify-email, resend, forgot/reset password |
| 5 **failed** logins / 15 minutes | per target email (normalized) | login |

Counters are in memory, which is correct for one instance. Phase 7 moves them to Redis for multiple
instances. Behind a load balancer, set `TRUST_PROXY_HOPS=1` so the client IP is taken from
`X-Forwarded-For`, but only from that one trusted hop.

### POST /api/v1/auth/forgot-password
`{ "email": "..." }` returns **202 always**, whether or not the account exists (no account
enumeration). The lookup and email happen **after** the response is sent, so response time does
not reveal whether the account exists either. Requesting a new link invalidates older ones. The link is
delivered via Notification's internal REST endpoint (Phase 4; Mailpit directly until then), never via a queue.

### POST /api/v1/auth/reset-password
`{ "token": "...", "newPassword": "..." }` returns 204. The token is single-use and expires
after 30 minutes. Only its SHA-256 hash is stored. All sessions are revoked.

### GET /api/v1/admin/users
Query: `?limit=20&cursor=...&q=email-or-name&status=ACTIVE|SUSPENDED&role=customer|admin`.
Response: `{ "data": [User], "page": { "limit": 20, "nextCursor": null } }`.

### PATCH /api/v1/admin/users/{userId}/status
`{ "status": "SUSPENDED", "reason": "chargeback fraud" }` returns `200 { "user": User }`. Audited.

## Sessions and token lifetimes

| Thing | Lifetime | Stored as |
|---|---|---|
| Access token (JWT) | 15 min, stateless | not stored |
| Refresh token | 7 days idle, rotated on every use | SHA-256 hash in `refresh_tokens` |
| Session | 30 days absolute | `sessions` row |

**Trade-off of stateless access tokens:** revoking a session (logout, suspension, password reset)
stops refreshes immediately, but an already-issued access token stays valid until it expires
(at most 15 minutes). This is accepted to avoid a database lookup on every request in every service.

## Access token claims

```json
{ "iss": "ecommerce-auth-service", "aud": "ecommerce-api", "sub": "<userId>", "roles": ["customer"],
  "sid": "<sessionId>", "jti": "<uuid>", "iat": 1760347800, "exp": 1760348700 }
```
Header: `{ "alg": "RS256", "kid": "<key id>", "typ": "JWT" }`.

## Audit log

Every register, login (success/failure), refresh-reuse, logout, password reset, and
suspension/activation writes an `auth_audit_log` row: `userId`, `action`, `ip`, `userAgent`,
`correlationId`, `occurredAt`. It never stores passwords or tokens.
