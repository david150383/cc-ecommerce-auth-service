import cookieParser from "cookie-parser";
import cors from "cors";
import express, { type Express } from "express";
import helmet from "helmet";
import { pinoHttp } from "pino-http";
import swaggerUi from "swagger-ui-express";
import type { Env } from "./config/env.js";
import type { Db } from "./db/prisma.js";
import type { Logger } from "./lib/logger.js";
import { errorHandler, notFoundHandler } from "./middleware/error-handler.js";
import { createRateLimiters } from "./middleware/rate-limit.js";
import { requestContext } from "./middleware/request-context.js";
import { adminRouter } from "./modules/admin/admin.routes.js";
import { AdminService } from "./modules/admin/admin.service.js";
import { authRouter } from "./modules/auth/auth.routes.js";
import { AuthService } from "./modules/auth/auth.service.js";
import type { TransactionalNotifier } from "./notifications/notifier.js";
import { buildOpenApiDocument } from "./openapi/document.js";
import { healthRouter, type ReadinessCheck } from "./routes/health.js";
import { jwksRouter } from "./routes/jwks.js";
import type { KeyStore } from "./security/key-store.js";
import { TokenService } from "./security/token-service.js";

export interface AppDependencies {
  env: Env;
  logger: Logger;
  db: Db;
  keys: KeyStore;
  notifier: TransactionalNotifier;
  readinessChecks?: ReadinessCheck[];
}

export interface App {
  app: Express;
  auth: AuthService;
  tokens: TokenService;
}

// Builds the Express app without starting a server, so tests can drive it
// in-process with Supertest. All collaborators are injected.
export function createApp({ env, logger, db, keys, notifier, readinessChecks = [] }: AppDependencies): App {
  const tokens = new TokenService(keys, {
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
    accessTtlSeconds: env.JWT_ACCESS_TTL_SECONDS,
  });
  const auth = new AuthService({ db, tokens, notifier, env, logger });
  const admin = new AdminService(db);
  const limits = createRateLimiters(env.RATE_LIMIT_ENABLED);

  const app = express();
  app.disable("x-powered-by");
  // Correct client IPs (rate limiting, audit) behind a known number of proxies only.
  app.set("trust proxy", env.TRUST_PROXY_HOPS);
  app.use(helmet());
  app.use(cors({ origin: env.CORS_ALLOWED_ORIGINS, credentials: true, exposedHeaders: ["X-Correlation-Id", "X-Request-Id"] }));
  app.use(requestContext);
  app.use(
    pinoHttp({
      logger,
      genReqId: (_req, res) => res.locals.requestId as string,
      customProps: (_req, res) => ({ correlationId: res.locals.correlationId as string }),
      autoLogging: { ignore: (req) => req.url?.startsWith("/health") ?? false },
      // Log only what is useful for tracing; headers can carry credentials and are noisy.
      serializers: {
        req: (req: { id: string; method: string; url: string }) => ({ id: req.id, method: req.method, url: req.url }),
        res: (res: { statusCode: number }) => ({ statusCode: res.statusCode }),
      },
    }),
  );
  app.use(express.json({ limit: "100kb" }));
  app.use(cookieParser());

  app.use(healthRouter(readinessChecks));
  app.use(jwksRouter(keys));

  const openApi = buildOpenApiDocument();
  app.get("/openapi.json", (_req, res) => {
    res.json(openApi);
  });
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(openApi));

  app.use("/api/v1/auth", authRouter({ auth, tokens, env, limits }));
  app.use("/api/v1/admin", adminRouter({ admin, tokens }));

  app.use(notFoundHandler);
  app.use(errorHandler(logger));
  return { app, auth, tokens };
}
