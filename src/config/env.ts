import { z } from "zod";

const bool = z.enum(["true", "false"]).transform((v) => v === "true");

/**
 * Service clients for the client-credentials grant. Only the SHA-256 of each secret is
 * configured (secrets are 256-bit random values, so a fast hash is appropriate, as for
 * refresh tokens). In production this JSON comes from AWS Secrets Manager.
 * Generate an entry with `npm run service-client:create -- <clientId> <audience>...`.
 */
const ServiceClients = z
  .string()
  .default("[]")
  .transform((raw, ctx) => {
    try {
      return JSON.parse(raw) as unknown;
    } catch {
      ctx.addIssue({ code: "custom", message: "SERVICE_CLIENTS must be valid JSON" });
      return z.NEVER;
    }
  })
  .pipe(
    z.array(
      z.object({
        clientId: z.string().regex(/^ecommerce-[a-z-]+$/),
        secretSha256: z.string().regex(/^[0-9a-f]{64}$/),
        audiences: z.array(z.string().regex(/^ecommerce-[a-z-]+$/)).min(1),
      }),
    ),
  );

// All configuration comes from environment variables and is validated once at
// startup. The process refuses to boot with invalid config, rather than failing
// later on the first request that touches it.
const EnvSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().min(1).max(65535).default(4001),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
    CORS_ALLOWED_ORIGINS: z
      .string()
      .default("http://localhost:5173")
      .transform((value) =>
        value
          .split(",")
          .map((origin) => origin.trim())
          .filter(Boolean),
      ),
    SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
    /// Number of reverse-proxy hops to trust for X-Forwarded-For (1 behind an ALB, 0 locally).
    TRUST_PROXY_HOPS: z.coerce.number().int().min(0).default(0),

    DATABASE_URL: z.string().startsWith("postgresql://"),

    JWT_ISSUER: z.string().default("ecommerce-auth-service"),
    JWT_AUDIENCE: z.string().default("ecommerce-api"),
    JWT_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    /// Directory of RSA private keys (<kid>.pem). The newest file signs; all are published in JWKS.
    JWT_KEYS_DIR: z.string().default("./keys"),
    /// Alternative for containers without a persistent disk (ECS): the keys as JSON
    /// [{"kid": "...", "pem": "-----BEGIN PRIVATE KEY-----..."}], injected from a secret store. Takes
    /// precedence over JWT_KEYS_DIR. Rotate by adding a newer kid, deploying, and removing the old one
    /// only after its last tokens expired.
    JWT_SIGNING_KEYS: z
      .string()
      .optional()
      .transform((v, ctx) => {
        if (v === undefined) return undefined;
        try {
          const parsed = z.array(z.object({ kid: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/), pem: z.string().includes("PRIVATE KEY") })).min(1).parse(JSON.parse(v));
          return parsed;
        } catch {
          ctx.addIssue({ code: "custom", message: 'JWT_SIGNING_KEYS must be JSON: [{"kid": "...", "pem": "-----BEGIN PRIVATE KEY-----..."}]' });
          return z.NEVER;
        }
      }),
    SERVICE_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
    SERVICE_CLIENTS: ServiceClients,

    REFRESH_TOKEN_IDLE_DAYS: z.coerce.number().int().min(1).default(7),
    SESSION_ABSOLUTE_DAYS: z.coerce.number().int().min(1).default(30),
    COOKIE_SECURE: bool.default(true),
    /// Set in production so the CSRF cookie is readable by the storefront subdomain.
    COOKIE_DOMAIN: z.string().optional(),

    EMAIL_VERIFICATION_TTL_HOURS: z.coerce.number().int().min(1).default(48),
    PASSWORD_RESET_TTL_MINUTES: z.coerce.number().int().min(5).default(30),
    /// Base URL of the storefront, used to build links in emails.
    FRONTEND_BASE_URL: z.url().default("http://localhost:5173"),

    /// http: Notification Service (Phase 4). smtp-dev: straight to Mailpit (local only).
    NOTIFICATION_DELIVERY: z.enum(["http", "smtp-dev", "disabled"]).default("smtp-dev"),
    NOTIFICATION_SERVICE_URL: z.url().default("http://localhost:4006"),
    SMTP_HOST: z.string().default("localhost"),
    SMTP_PORT: z.coerce.number().int().default(1025),
    EMAIL_FROM: z.string().default("Shop <no-reply@shop.local>"),

    RATE_LIMIT_ENABLED: bool.default(true),

    // Messaging (SNS). Disabled: the service still works; outbox rows accumulate until enabled.
    MESSAGING_ENABLED: bool.default(false),
    AWS_REGION: z.string().default("us-east-1"),
    /// Local emulator (Floci). Unset in AWS.
    AWS_ENDPOINT_URL: z.url().optional(),
    EVENTS_TOPIC_ARN: z.string().default("arn:aws:sns:us-east-1:000000000000:local-ecommerce-auth-events"),
    OUTBOX_POLL_INTERVAL_MS: z.coerce.number().int().min(50).default(1_000),
  })
  .refine((env) => !(env.NODE_ENV === "production" && env.NOTIFICATION_DELIVERY === "smtp-dev"), {
    message: "NOTIFICATION_DELIVERY=smtp-dev is for local development only",
    path: ["NOTIFICATION_DELIVERY"],
  })
  .refine((env) => !(env.NODE_ENV === "production" && !env.COOKIE_SECURE), {
    message: "COOKIE_SECURE must be true in production",
    path: ["COOKIE_SECURE"],
  });

export type Env = z.infer<typeof EnvSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = EnvSchema.safeParse(source);
  if (!result.success) {
    throw new Error(`Invalid environment configuration:\n${z.prettifyError(result.error)}`);
  }
  return result.data;
}
