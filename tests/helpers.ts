import { Writable } from "node:stream";
import { pino } from "pino";
import type { Response } from "supertest";
import { createApp } from "../src/app.js";
import { loadEnv } from "../src/config/env.js";
import { createPrisma, type Db } from "../src/db/prisma.js";
import { Role } from "../src/generated/prisma/client.js";
import { newId } from "../src/lib/ids.js";
import type { TransactionalMessage, TransactionalNotifier } from "../src/notifications/notifier.js";
import { generatePrivateKeyPem, KeyStore } from "../src/security/key-store.js";
import { hashPassword } from "../src/security/password.js";
import type { ReadinessCheck } from "../src/routes/health.js";
import { TEST_DATABASE_URL } from "./global-setup.js";

export const STRONG_PASSWORD = "correct horse battery staple";

/** Captures outgoing emails so tests can follow verification and reset links. */
export class FakeNotifier implements TransactionalNotifier {
  readonly sent: TransactionalMessage[] = [];
  failNext = false;

  async send(message: TransactionalMessage): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("simulated delivery failure");
    }
    this.sent.push(message);
  }

  tokenFromLast(template: TransactionalMessage["templateKey"]): string {
    const msg = [...this.sent].reverse().find((m) => m.templateKey === template);
    if (!msg) throw new Error(`no ${template} message sent`);
    return new URL(msg.secretUrl).searchParams.get("token")!;
  }
}

let sharedDb: Db | undefined;
export function testDb(): Db {
  sharedDb ??= createPrisma(TEST_DATABASE_URL);
  return sharedDb;
}

let sharedKeys: Promise<KeyStore> | undefined;
export function testKeys(): Promise<KeyStore> {
  sharedKeys ??= generatePrivateKeyPem().then((pem) => KeyStore.fromPems([{ kid: "test-key", pem }]));
  return sharedKeys;
}

export async function resetDatabase(): Promise<void> {
  await testDb().$executeRawUnsafe(
    'TRUNCATE "users", "sessions", "refresh_tokens", "email_verification_tokens", "password_reset_tokens", "auth_audit_log", "outbox" CASCADE',
  );
}

export interface TestContext {
  app: ReturnType<typeof createApp>["app"];
  auth: ReturnType<typeof createApp>["auth"];
  tokens: ReturnType<typeof createApp>["tokens"];
  notifier: FakeNotifier;
  db: Db;
  logs: string[];
}

export async function buildTestContext(
  overrides: Record<string, string> = {},
  readinessChecks: ReadinessCheck[] = [],
): Promise<TestContext> {
  const env = loadEnv({
    NODE_ENV: "test",
    LOG_LEVEL: "info",
    DATABASE_URL: TEST_DATABASE_URL,
    RATE_LIMIT_ENABLED: "false",
    NOTIFICATION_DELIVERY: "disabled",
    ...overrides,
  });
  // Logs are captured (not printed) so tests can assert that no secret is ever logged.
  const logs: string[] = [];
  const logger = pino(
    { level: env.LOG_LEVEL, redact: { paths: ["*.password", "*.token"], censor: "[REDACTED]" } },
    new Writable({
      write(chunk: Buffer, _enc, cb) {
        logs.push(chunk.toString());
        cb();
      },
    }),
  );
  const notifier = new FakeNotifier();
  const db = testDb();
  const { app, auth, tokens } = createApp({ env, logger, db, keys: await testKeys(), notifier, readinessChecks });
  return { app, auth, tokens, notifier, db, logs };
}

export async function createUser(
  db: Db,
  opts: { email: string; role?: "CUSTOMER" | "ADMIN"; password?: string; verified?: boolean },
) {
  return db.user.create({
    data: {
      id: newId(),
      email: opts.email,
      fullName: "Test User",
      passwordHash: await hashPassword(opts.password ?? STRONG_PASSWORD),
      role: opts.role === "ADMIN" ? Role.ADMIN : Role.CUSTOMER,
      ...(opts.verified && { emailVerifiedAt: new Date() }),
    },
  });
}

/** Parses Set-Cookie headers into name -> { value, attributes }. */
export function cookiesOf(res: Response): Record<string, { value: string; attrs: string }> {
  const raw = res.headers["set-cookie"] as unknown as string[] | undefined;
  const out: Record<string, { value: string; attrs: string }> = {};
  for (const cookie of raw ?? []) {
    const [pair, ...attrs] = cookie.split(";");
    const [name, ...value] = pair!.split("=");
    out[name!.trim()] = { value: value.join("="), attrs: attrs.join(";").trim() };
  }
  return out;
}

/** Cookie header carrying the refresh + CSRF cookies from a login/refresh response. */
export function sessionCookies(res: Response): { cookie: string; csrf: string; refresh: string } {
  const c = cookiesOf(res);
  const refresh = c.refresh_token!.value;
  const csrf = c.csrf_token!.value;
  return { cookie: `refresh_token=${refresh}; csrf_token=${csrf}`, csrf, refresh };
}

export async function waitFor<T>(fn: () => T | undefined, timeoutMs = 3_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = fn();
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}
