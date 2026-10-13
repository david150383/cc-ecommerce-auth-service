import type { CookieOptions, Response } from "express";
import type { Env } from "../../config/env.js";
import { CSRF_COOKIE } from "../../middleware/csrf.js";

export const REFRESH_COOKIE = "refresh_token";
const REFRESH_PATH = "/api/v1/auth";

function base(env: Env): CookieOptions {
  return { secure: env.COOKIE_SECURE, sameSite: "strict", ...(env.COOKIE_DOMAIN && { domain: env.COOKIE_DOMAIN }) };
}

export function setAuthCookies(res: Response, env: Env, tokens: { refreshToken: string; refreshExpiresAt: Date; csrfToken: string }): void {
  // HttpOnly: JavaScript (including injected scripts) can never read the refresh token.
  // Path-scoped: the browser sends it only to the auth endpoints, not on every API call.
  res.cookie(REFRESH_COOKIE, tokens.refreshToken, {
    ...base(env),
    httpOnly: true,
    path: REFRESH_PATH,
    expires: tokens.refreshExpiresAt,
  });
  // Readable by the frontend on purpose: it copies it into the X-CSRF-Token header.
  res.cookie(CSRF_COOKIE, tokens.csrfToken, { ...base(env), httpOnly: false, path: "/", expires: tokens.refreshExpiresAt });
}

export function clearAuthCookies(res: Response, env: Env): void {
  res.clearCookie(REFRESH_COOKIE, { ...base(env), httpOnly: true, path: REFRESH_PATH });
  res.clearCookie(CSRF_COOKIE, { ...base(env), path: "/" });
}
