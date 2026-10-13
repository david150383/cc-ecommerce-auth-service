import { type Request, type Response, Router } from "express";
import type { Env } from "../../config/env.js";
import { requireAuth } from "../../middleware/authenticate.js";
import { requireCsrf } from "../../middleware/csrf.js";
import type { RateLimiters } from "../../middleware/rate-limit.js";
import { parse } from "../../middleware/validate.js";
import type { TokenService } from "../../security/token-service.js";
import {
  ForgotPasswordRequest,
  LoginRequest,
  RegisterRequest,
  ResetPasswordRequest,
  VerifyEmailRequest,
} from "./auth.schemas.js";
import { type AuthService, type IssuedTokens, type RequestMeta, toUserDto } from "./auth.service.js";
import { clearAuthCookies, REFRESH_COOKIE, setAuthCookies } from "./cookies.js";

export function requestMeta(req: Request, res: Response): RequestMeta {
  return {
    ...(req.ip !== undefined && { ip: req.ip }),
    ...(req.get("user-agent") !== undefined && { userAgent: req.get("user-agent")! }),
    correlationId: res.locals.correlationId as string,
  };
}

export function authRouter(deps: { auth: AuthService; tokens: TokenService; env: Env; limits: RateLimiters }): Router {
  const { auth, tokens, env, limits } = deps;
  const router = Router();

  const sendTokens = (res: Response, issued: IssuedTokens) => {
    setAuthCookies(res, env, issued);
    res.setHeader("Cache-Control", "no-store");
    res.json({
      accessToken: issued.accessToken,
      tokenType: "Bearer",
      expiresIn: issued.expiresIn,
      csrfToken: issued.csrfToken,
      user: issued.user,
    });
  };

  router.post("/register", limits.perIp, async (req, res) => {
    const body = parse(RegisterRequest, req.body);
    const user = await auth.register(body, requestMeta(req, res));
    res.status(201).json({ user: toUserDto(user) });
  });

  router.post("/login", limits.perIp, limits.loginPerAccount, async (req, res) => {
    const body = parse(LoginRequest, req.body);
    sendTokens(res, await auth.login(body, requestMeta(req, res)));
  });

  router.post("/refresh", requireCsrf, async (req, res) => {
    const raw: unknown = req.cookies?.[REFRESH_COOKIE];
    try {
      sendTokens(res, await auth.refresh(typeof raw === "string" ? raw : "", requestMeta(req, res)));
    } catch (err) {
      clearAuthCookies(res, env);
      throw err;
    }
  });

  router.post("/logout", requireCsrf, async (req, res) => {
    const raw: unknown = req.cookies?.[REFRESH_COOKIE];
    await auth.logout(typeof raw === "string" ? raw : undefined, requestMeta(req, res));
    clearAuthCookies(res, env);
    res.status(204).end();
  });

  router.post("/logout-all", requireAuth(tokens), async (req, res) => {
    await auth.logoutAll(res.locals.auth!.sub, requestMeta(req, res));
    clearAuthCookies(res, env);
    res.status(204).end();
  });

  router.post("/verify-email", limits.perIp, async (req, res) => {
    const body = parse(VerifyEmailRequest, req.body);
    const { user, alreadyVerified } = await auth.verifyEmail(body.token, requestMeta(req, res));
    res.json({ user: toUserDto(user), alreadyVerified });
  });

  router.post("/verify-email/resend", requireAuth(tokens), limits.perIp, async (_req, res) => {
    await auth.resendVerification(res.locals.auth!.sub);
    res.status(202).end();
  });

  router.post("/forgot-password", limits.perIp, (req, res) => {
    const body = parse(ForgotPasswordRequest, req.body);
    auth.requestPasswordReset(body.email, requestMeta(req, res));
    res.status(202).end();
  });

  router.post("/reset-password", limits.perIp, async (req, res) => {
    const body = parse(ResetPasswordRequest, req.body);
    await auth.resetPassword(body, requestMeta(req, res));
    clearAuthCookies(res, env);
    res.status(204).end();
  });

  router.get("/me", requireAuth(tokens), async (_req, res) => {
    res.json({ user: toUserDto(await auth.getUser(res.locals.auth!.sub)) });
  });

  return router;
}
