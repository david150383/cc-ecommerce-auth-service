import type { RequestHandler } from "express";
import { rateLimit } from "express-rate-limit";
import { toProblemBody, HttpProblem } from "../lib/problem.js";

// In-memory counters: correct for one instance. With several instances behind a load
// balancer each keeps its own counts, so Phase 7 moves the store to Redis/ElastiCache.

const handler: RequestHandler = (req, res) => {
  const problem = new HttpProblem(429, "RATE_LIMITED", "Too many requests", "Please wait before trying again.");
  res
    .status(429)
    .type("application/problem+json")
    .json(toProblemBody(problem, req.originalUrl, res.locals.correlationId as string | undefined));
};

export interface RateLimiters {
  /** Per client IP, on all unauthenticated auth endpoints. */
  perIp: RequestHandler;
  /** Per target account: failed logins only, to stop password guessing against one user. */
  loginPerAccount: RequestHandler;
}

const passthrough: RequestHandler = (_req, _res, next) => next();

export function createRateLimiters(enabled: boolean): RateLimiters {
  if (!enabled) return { perIp: passthrough, loginPerAccount: passthrough };
  return {
    perIp: rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: "draft-8", legacyHeaders: false, handler }),
    loginPerAccount: rateLimit({
      windowMs: 15 * 60_000,
      limit: 5,
      skipSuccessfulRequests: true,
      standardHeaders: "draft-8",
      legacyHeaders: false,
      keyGenerator: (req) => {
        const email: unknown = (req.body as { email?: unknown } | undefined)?.email;
        return `login:${typeof email === "string" ? email.trim().toLowerCase() : "(none)"}`;
      },
      handler,
    }),
  };
}
