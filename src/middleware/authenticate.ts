import type { RequestHandler } from "express";
import { HttpProblem } from "../lib/problem.js";
import type { RoleClaim, TokenService, VerifiedAccessToken } from "../security/token-service.js";

declare module "express-serve-static-core" {
  interface Locals {
    auth?: VerifiedAccessToken;
  }
}

/** Requires a valid Bearer access token; puts its claims in res.locals.auth. */
export function requireAuth(tokens: TokenService): RequestHandler {
  return async (req, res, next) => {
    const header = req.get("authorization") ?? "";
    const [scheme, token] = header.split(" ");
    if (scheme?.toLowerCase() !== "bearer" || !token) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="ecommerce"');
      throw new HttpProblem(401, "UNAUTHENTICATED", "Authentication required");
    }
    try {
      res.locals.auth = await tokens.verifyAccessToken(token);
    } catch {
      res.setHeader("WWW-Authenticate", 'Bearer realm="ecommerce", error="invalid_token"');
      throw new HttpProblem(401, "UNAUTHENTICATED", "Invalid or expired access token");
    }
    next();
  };
}

export function requireRole(role: RoleClaim): RequestHandler {
  return (_req, res, next) => {
    if (!res.locals.auth?.roles.includes(role)) {
      throw new HttpProblem(403, "FORBIDDEN", "Insufficient permissions");
    }
    next();
  };
}
