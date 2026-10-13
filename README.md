# ecommerce-auth-service

Identity for the e-commerce platform: registration, login, sessions, refresh-token rotation,
email verification, password reset, roles, suspension, and auth audit logging. It is the only
service that holds JWT **signing** keys. Every other service verifies tokens using the public
keys at `/.well-known/jwks.json`.

| | |
|---|---|
| Stack | Node.js 24, Express 5, TypeScript 5.9, PostgreSQL 17, Prisma *(Phase 2)*, Argon2id *(Phase 2)* |
| Port | 4001 |
| Database | `auth_db`, owned exclusively by this service |
| API docs | [docs/api.md](docs/api.md) |
| Messages | [docs/events.md](docs/events.md), [events/schemas](events/schemas) |

## Status

| Phase | Done |
|---|---|
| 1: skeleton | ✅ app factory, config validation, structured logging with redaction, correlation IDs, RFC 9457 errors, health/readiness, graceful shutdown, Dockerfile, CI, event schemas |
| 2: features | ⏳ Prisma schema & migrations, register/login/refresh/logout, JWKS, rate limiting, audit log |

## Run locally

```bash
cp .env.example .env
npm install
npm run dev            # http://localhost:4001/health/live
```

Database (from Phase 2): either `docker compose up -d` here (standalone, port 5441) or
`docker compose up -d` in `ecommerce-infrastructure` (shared, port 5432).

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Watch mode with `.env` |
| `npm test` | Vitest unit + HTTP tests (Supertest, in-process; no network) |
| `npm run lint` / `npm run typecheck` | ESLint / `tsc --noEmit` |
| `npm run build && npm start` | Compile to `dist/` and run |
| `docker build -t ecommerce-auth-service .` | Production image (non-root, multi-stage) |

## Layout

```
src/
  app.ts                 # createApp(): builds Express app, no listen(), so tests can use it
  server.ts              # process entry: listen, SIGTERM/SIGINT graceful shutdown
  config/env.ts          # zod-validated environment
  lib/logger.ts          # pino + secret redaction
  lib/problem.ts         # RFC 9457 problem details
  middleware/            # correlation/request IDs, error handling
  routes/health.ts       # /health/live, /health/ready
events/schemas           # JSON Schemas for events this service owns
events/examples          # one valid example per schema (validated in tests)
tests/                   # Vitest + Supertest
```

## Security notes

- Tokens, passwords, cookies and reset tokens are redacted by the logger (`src/lib/logger.ts`).
- 5xx responses never include stack traces. The cause is logged with the `correlationId`.
- Reset and verification links never go on a queue (see [docs/events.md](docs/events.md)).
