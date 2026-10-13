# ecommerce-auth-service

Identity for the e-commerce platform: registration, login, sessions, refresh-token rotation,
email verification, password reset, roles, suspension, and auth audit logging. It is the only
service that holds JWT **signing** keys. Every other service verifies tokens using the public
keys at `/.well-known/jwks.json`.

| | |
|---|---|
| Stack | Node.js 24, Express 5, TypeScript 5.9, PostgreSQL 17, Prisma 7 (pg driver adapter), Argon2id, jose (RS256), Zod 4 |
| Port | 4001 |
| Database | `auth_db`, owned exclusively by this service |
| API docs | [docs/api.md](docs/api.md), [openapi/openapi.json](openapi/openapi.json), Swagger UI at `/docs` |
| Messages | [docs/events.md](docs/events.md), [events/schemas](events/schemas) |

## Status

| Phase | Done |
|---|---|
| 1: skeleton | ✅ app factory, config validation, structured logging with redaction, correlation IDs, RFC 9457 errors, health/readiness, graceful shutdown, Dockerfile, CI, event schemas |
| 2: features | ✅ Prisma schema & migrations, register/login/refresh (rotation + reuse detection)/logout/logout-all, email verification, password reset, `/me`, admin user list + suspension, JWKS, CSRF double-submit, rate limiting, audit log, outbox rows, OpenAPI |
| 3 | ⏳ outbox relay → SNS, `/internal/v1/auth/service-token` |

## Run locally

```bash
# 1. Postgres + Mailpit: either here (standalone, Postgres on 5441; edit DATABASE_URL in .env)…
docker compose up -d
#    …or the shared platform stack (Postgres on 5432):
#    (cd ../ecommerce-infrastructure && docker compose up -d)
cp .env.example .env
npm install            # also generates the Prisma client
npm run db:deploy      # apply migrations
npm run dev            # http://localhost:4001/docs; a signing key is created in ./keys on first run
ADMIN_PASSWORD='a long admin passphrase' npm run admin:create -- admin@example.com "Admin"
```

Emails (verification, password reset) appear in Mailpit at http://localhost:8025.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Watch mode with `.env` |
| `npm test` | Vitest: unit + integration tests against a real Postgres (`auth_test` is recreated from the migrations on every run; needs Postgres running) |
| `npm run db:migrate` | Create a new migration after editing `prisma/schema.prisma` (development) |
| `npm run db:deploy` | Apply pending migrations (CI, containers) |
| `npm run db:check-drift` | Fails if `schema.prisma` has changes without a migration (needs `SHADOW_DATABASE_URL`) |
| `npm run keys:generate` | Add a new signing key (key rotation) |
| `npm run admin:create` | Create or promote an administrator |
| `npm run openapi:export` | Regenerate `openapi/openapi.json` |
| `npm run lint` / `npm run typecheck` | ESLint / `tsc --noEmit` |
| `npm run build && npm start` | Compile to `dist/` and run |
| `docker build --target runtime .` | Production image (non-root, no Prisma CLI) |
| `docker build --target migrate .` | One-off migration job image |

## How it works

```
POST /login ──► AuthService.login
                 ├─ argon2id verify (dummy hash when the email is unknown → equal timing)
                 └─ TX: session + refresh_token(hash) + audit
                ◄── { accessToken (RS256 JWT, 15 min), csrfToken }  +  Set-Cookie refresh_token (HttpOnly)

POST /refresh ─► CSRF header == csrf_token cookie?
                 └─ TX: UPDATE refresh_tokens SET used_at=now() WHERE id=? AND used_at IS NULL
                        count = 1 → issue new pair   |   count = 0 → reuse! revoke session, 401
```

Other services never call this service to check a token. They fetch `/.well-known/jwks.json` once
(cached 10 min) and verify signatures locally.

## Layout

```
prisma/schema.prisma, prisma/migrations/   # database schema + versioned SQL migrations
src/
  app.ts                  createApp(): wires services and routes; no listen(), so tests drive it
  server.ts               entry point: keys, DB, graceful shutdown
  config/env.ts           zod-validated environment (refuses dev-only settings in production)
  db/prisma.ts            Prisma client (pg driver adapter)
  security/               key store (JWKS), token service, Argon2id, random tokens
  modules/auth/           routes, schemas, AuthService (all auth flows), cookies
  modules/admin/          user listing (keyset pagination), suspension
  middleware/             authentication, CSRF, rate limits, validation, errors, request IDs
  notifications/          secret-bearing email delivery (HTTP / Mailpit-dev / disabled)
  openapi/document.ts     OpenAPI generated from the Zod schemas
  scripts/                generate-key, create-admin, export-openapi
tests/                    Vitest + Supertest against a real Postgres
```

## Security notes

- Tokens, passwords, cookies and reset tokens never appear in logs. A test drives every flow with
  trace logging and asserts that none of the secrets appear.
- Refresh, reset and verification tokens are stored only as SHA-256 hashes.
- 5xx responses never include stack traces. The cause is logged with the `correlationId`.
- Reset and verification links never go on a queue (see [docs/events.md](docs/events.md)).
- The runtime image contains no Prisma CLI (`npm ci --omit=dev --omit=peer`). Migrations run from
  the separate `migrate` image.

## Known limitations

- Rate-limit counters are per process (Redis in Phase 7).
- The common-password list is a small sample (breached-password API in Phase 7).
- Strict refresh-token reuse detection: two browser tabs refreshing at the *same instant* can
  trip it and log the user out. That's acceptable for now; a short grace window is a possible refinement.
- Outbox rows are written but not yet published (relay in Phase 3).
