import type { RequestHandler } from "express";
import { HttpProblem } from "../lib/problem.js";
import { safeEqual } from "../security/random-token.js";

export const CSRF_COOKIE = "csrf_token";
export const CSRF_HEADER = "x-csrf-token";

/**
 * Double-submit check for endpoints authenticated by the refresh cookie. A forged
 * cross-site request carries the cookies automatically but cannot read the CSRF
 * cookie to copy it into the header. (SameSite=Strict already blocks most of this;
 * this is defense in depth.)
 */
export const requireCsrf: RequestHandler = (req, _res, next) => {
  const cookie: unknown = req.cookies?.[CSRF_COOKIE];
  const header = req.get(CSRF_HEADER);
  if (typeof cookie !== "string" || !header || !safeEqual(cookie, header)) {
    throw new HttpProblem(403, "CSRF_TOKEN_INVALID", "Missing or invalid CSRF token");
  }
  next();
};
