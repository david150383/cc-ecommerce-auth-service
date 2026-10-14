import { createApp } from "./app.js";
import { loadEnv } from "./config/env.js";
import { createPrisma } from "./db/prisma.js";
import { createLogger } from "./lib/logger.js";
import { createSns, OutboxRelay } from "./messaging/outbox-relay.js";
import { createNotifier } from "./notifications/create-notifier.js";
import { loadKeyStore } from "./security/key-store.js";
import { TokenService } from "./security/token-service.js";

const env = loadEnv();
const logger = createLogger(env.LOG_LEVEL);
const db = createPrisma(env.DATABASE_URL);
// Development convenience: create a signing key on first run. Production must provide keys.
const keys = await loadKeyStore(env.JWT_KEYS_DIR, { generateIfMissing: env.NODE_ENV !== "production" });
const notifier = createNotifier(
  env,
  logger,
  () =>
    new TokenService(keys, {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      accessTtlSeconds: env.JWT_ACCESS_TTL_SECONDS,
    }),
);

const relay = new OutboxRelay(db, createSns(env), env.EVENTS_TOPIC_ARN, env.OUTBOX_POLL_INTERVAL_MS, logger);
if (env.MESSAGING_ENABLED) relay.start();
else logger.warn("messaging disabled: outbox rows accumulate until it is enabled");

let shuttingDown = false;

const { app } = createApp({
  env,
  logger,
  db,
  keys,
  notifier,
  readinessChecks: [
    {
      // Report "not ready" as soon as shutdown starts, so the load balancer
      // stops sending new requests while in-flight ones finish.
      name: "accepting-traffic",
      check: async () => {
        if (shuttingDown) throw new Error("shutting down");
      },
    },
    { name: "database", check: async () => void (await db.$queryRaw`SELECT 1`) },
  ],
});

const server = app.listen(env.PORT, () => {
  logger.info({ port: env.PORT, signingKid: keys.signingKey.kid }, "server listening");
});

function shutdown(signal: NodeJS.Signals): void {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, "shutdown started");

  server.close((err) => {
    // Let the relay finish its current batch before closing the database it uses.
    void relay
      .stop()
      .then(() => db.$disconnect())
      .finally(() => {
        if (err) {
          logger.error({ err }, "error while closing server");
          process.exit(1);
        }
        logger.info("shutdown complete");
        process.exit(0);
      });
  });
  server.closeIdleConnections();

  setTimeout(() => {
    logger.error({ timeoutMs: env.SHUTDOWN_TIMEOUT_MS }, "forced shutdown after timeout");
    process.exit(1);
  }, env.SHUTDOWN_TIMEOUT_MS).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
