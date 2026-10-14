import { Router } from "express";
import type { Env } from "../../config/env.js";
import type { Db } from "../../db/prisma.js";
import { HttpProblem } from "../../lib/problem.js";
import { z } from "../../lib/zod.js";
import type { RateLimiters } from "../../middleware/rate-limit.js";
import { parse } from "../../middleware/validate.js";
import { hashToken, safeEqual } from "../../security/random-token.js";
import type { TokenService } from "../../security/token-service.js";
import { requestMeta } from "../auth/auth.routes.js";
import { audit } from "../auth/auth.service.js";

export const ServiceTokenRequest = z
  .object({
    clientId: z.string().min(1).max(100),
    clientSecret: z.string().min(1).max(200),
    audience: z.string().regex(/^ecommerce-[a-z-]+$/).openapi({ example: "ecommerce-product-service" }),
  })
  .strict()
  .openapi("ServiceTokenRequest");

export const ServiceTokenResponse = z
  .object({ accessToken: z.string(), tokenType: z.literal("Bearer"), expiresIn: z.number().int() })
  .openapi("ServiceTokenResponse");

// A fixed hash compared against for unknown client ids, so timing does not reveal which ids exist.
const UNKNOWN_CLIENT_HASH = "0".repeat(64);

/**
 * OAuth 2 client-credentials grant for service-to-service calls. The token is minted for ONE
 * target service (aud), with role "service" and a short lifetime, so a leaked token is
 * narrow and short-lived. Never exposed through the public load balancer (/internal/).
 */
export function serviceTokenRouter(deps: { env: Env; tokens: TokenService; db: Db; limits: RateLimiters }): Router {
  const router = Router();

  router.post("/service-token", deps.limits.perIp, async (req, res) => {
    const body = parse(ServiceTokenRequest, req.body);
    const meta = requestMeta(req, res);
    const client = deps.env.SERVICE_CLIENTS.find((c) => c.clientId === body.clientId);
    const secretOk = safeEqual(hashToken(body.clientSecret), client?.secretSha256 ?? UNKNOWN_CLIENT_HASH);

    if (!client || !secretOk) {
      await audit(deps.db, "SERVICE_TOKEN_DENIED", meta, null, { clientId: body.clientId, reason: "INVALID_CLIENT" });
      throw new HttpProblem(401, "INVALID_CLIENT", "Invalid client credentials");
    }
    if (!client.audiences.includes(body.audience)) {
      await audit(deps.db, "SERVICE_TOKEN_DENIED", meta, null, {
        clientId: client.clientId,
        audience: body.audience,
        reason: "AUDIENCE_NOT_ALLOWED",
      });
      throw new HttpProblem(403, "AUDIENCE_NOT_ALLOWED", "This client may not call that service");
    }

    const ttl = deps.env.SERVICE_TOKEN_TTL_SECONDS;
    const accessToken = await deps.tokens.issueAccessToken({ sub: client.clientId, roles: ["service"] }, body.audience, ttl);
    await audit(deps.db, "SERVICE_TOKEN_ISSUED", meta, null, { clientId: client.clientId, audience: body.audience });
    res.setHeader("Cache-Control", "no-store");
    res.json({ accessToken, tokenType: "Bearer", expiresIn: ttl });
  });

  return router;
}
