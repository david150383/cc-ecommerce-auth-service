import { createLocalJWKSet, decodeJwt, jwtVerify, SignJWT, UnsecuredJWT } from "jose";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { generatePrivateKeyPem, KeyStore } from "../src/security/key-store.js";
import { TokenService } from "../src/security/token-service.js";
import {
  buildTestContext,
  createUser,
  resetDatabase,
  sessionCookies,
  STRONG_PASSWORD,
  type TestContext,
  testKeys,
} from "./helpers.js";

let ctx: TestContext;
beforeEach(async () => {
  await resetDatabase();
  ctx = await buildTestContext();
  await createUser(ctx.db, { email: "asha@example.com" });
});

const login = () => request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: STRONG_PASSWORD });
const refresh = (s: { cookie: string; csrf: string }) =>
  request(ctx.app).post("/api/v1/auth/refresh").set("Cookie", s.cookie).set("X-CSRF-Token", s.csrf);
const me = (token: string) => request(ctx.app).get("/api/v1/auth/me").set("Authorization", `Bearer ${token}`);

describe("access tokens", () => {
  it("can be verified by another service using only the public JWKS", async () => {
    const { body } = await login();
    const jwks = await request(ctx.app).get("/.well-known/jwks.json");
    expect(jwks.headers["cache-control"]).toMatch(/max-age=600/);
    expect(JSON.stringify(jwks.body)).not.toMatch(/"d"|"p"|"q"/); // no private key material

    const { payload, protectedHeader } = await jwtVerify(body.accessToken, createLocalJWKSet(jwks.body), {
      issuer: "ecommerce-auth-service",
      audience: "ecommerce-api",
    });
    expect(protectedHeader).toMatchObject({ alg: "RS256", kid: "test-key" });
    expect(payload).toMatchObject({ sub: body.user.id, roles: ["customer"] });
    expect(payload.exp! - payload.iat!).toBe(900);
    expect(typeof payload.sid).toBe("string");
  });

  it("GET /me works with a valid token and rejects a missing one", async () => {
    const { body } = await login();
    expect((await me(body.accessToken)).body.user.email).toBe("asha@example.com");
    const missing = await request(ctx.app).get("/api/v1/auth/me");
    expect(missing.status).toBe(401);
    expect(missing.headers["www-authenticate"]).toMatch(/Bearer/);
  });

  it("rejects a token whose payload was tampered with", async () => {
    const { body } = await login();
    const [h, p, s] = body.accessToken.split(".");
    const claims = decodeJwt(body.accessToken);
    const forged = Buffer.from(JSON.stringify({ ...claims, roles: ["admin"] })).toString("base64url");
    expect(p).not.toBe(forged);
    expect((await me(`${h}.${forged}.${s}`)).status).toBe(401);
  });

  it("rejects alg=none and tokens signed by a key not in the JWKS", async () => {
    const unsigned = new UnsecuredJWT({ roles: ["admin"] }).setSubject("x").setIssuer("ecommerce-auth-service").setAudience("ecommerce-api").setExpirationTime("5m").encode();
    expect((await me(unsigned)).status).toBe(401);

    const attackerKeys = await KeyStore.fromPems([{ kid: "test-key", pem: await generatePrivateKeyPem() }]);
    const attacker = new TokenService(attackerKeys, { issuer: "ecommerce-auth-service", audience: "ecommerce-api", accessTtlSeconds: 900 });
    expect((await me(await attacker.issueAccessToken({ sub: "x", roles: ["admin"] }))).status).toBe(401);
  });

  it("rejects expired tokens and tokens for another audience", async () => {
    const keys = await testKeys();
    const expired = await new SignJWT({ roles: ["customer"] })
      .setProtectedHeader({ alg: "RS256", kid: keys.signingKey.kid })
      .setSubject("x").setIssuer("ecommerce-auth-service").setAudience("ecommerce-api")
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600).setExpirationTime(Math.floor(Date.now() / 1000) - 120)
      .sign(keys.signingKey.privateKey);
    expect((await me(expired)).status).toBe(401);

    const otherAudience = await ctx.tokens.issueAccessToken({ sub: "x", roles: ["service"] }, "ecommerce-notification-service");
    expect((await me(otherAudience)).status).toBe(401);
  });
});

describe("refresh-token rotation", () => {
  it("requires the CSRF header to match the cookie", async () => {
    const s = sessionCookies(await login());
    const missing = await request(ctx.app).post("/api/v1/auth/refresh").set("Cookie", s.cookie);
    expect(missing.status).toBe(403);
    expect(missing.body.code).toBe("CSRF_TOKEN_INVALID");
    const wrong = await request(ctx.app).post("/api/v1/auth/refresh").set("Cookie", s.cookie).set("X-CSRF-Token", "x".repeat(43));
    expect(wrong.status).toBe(403);
  });

  it("issues a new refresh token each time, and the new one works", async () => {
    const first = sessionCookies(await login());
    const r1 = await refresh(first);
    expect(r1.status).toBe(200);
    const second = sessionCookies(r1);
    expect(second.refresh).not.toBe(first.refresh);
    expect((await refresh(second)).status).toBe(200);
  });

  it("detects reuse of a rotated token and revokes the whole session", async () => {
    const stolen = sessionCookies(await login());
    const legit = sessionCookies(await refresh(stolen)); // victim rotates

    const attacker = await refresh(stolen); // attacker replays the old token
    expect(attacker.status).toBe(401);
    expect(attacker.body.code).toBe("REFRESH_TOKEN_REUSED");

    // The victim's current token is dead too: the session family is revoked.
    const victim = await refresh(legit);
    expect(victim.status).toBe(401);
    expect(await ctx.db.authAuditLog.count({ where: { action: "REFRESH_TOKEN_REUSED" } })).toBeGreaterThanOrEqual(1);
    const session = await ctx.db.session.findFirstOrThrow();
    expect(session.revokeReason).toBe("REFRESH_TOKEN_REUSE");
  });

  it("lets exactly one of two concurrent refreshes with the same token win", async () => {
    const s = sessionCookies(await login());
    const results = await Promise.all([refresh(s), refresh(s), refresh(s)]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((x) => x === 200)).toHaveLength(1);
    expect(await ctx.db.refreshToken.count({ where: { usedAt: null } })).toBeLessThanOrEqual(1);
  });

  it("rejects expired refresh tokens and expired sessions", async () => {
    const s = sessionCookies(await login());
    await ctx.db.refreshToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    const res = await refresh(s);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("stops working once the user is suspended", async () => {
    const s = sessionCookies(await login());
    await ctx.db.user.updateMany({ data: { status: "SUSPENDED" } });
    expect((await refresh(s)).status).toBe(403);
  });
});

describe("logout", () => {
  it("revokes the session so its refresh token stops working, and clears cookies", async () => {
    const s = sessionCookies(await login());
    const res = await request(ctx.app).post("/api/v1/auth/logout").set("Cookie", s.cookie).set("X-CSRF-Token", s.csrf);
    expect(res.status).toBe(204);
    expect(String(res.headers["set-cookie"])).toMatch(/refresh_token=;/);
    expect((await refresh(s)).status).toBe(401);
  });

  it("is idempotent", async () => {
    const s = sessionCookies(await login());
    for (let i = 0; i < 2; i++) {
      const res = await request(ctx.app).post("/api/v1/auth/logout").set("Cookie", s.cookie).set("X-CSRF-Token", s.csrf);
      expect(res.status).toBe(204);
    }
  });

  it("logout-all revokes every session of the user", async () => {
    const a = sessionCookies(await login());
    const bRes = await login();
    const b = sessionCookies(bRes);
    const res = await request(ctx.app).post("/api/v1/auth/logout-all").set("Authorization", `Bearer ${bRes.body.accessToken}`);
    expect(res.status).toBe(204);
    expect((await refresh(a)).status).toBe(401);
    expect((await refresh(b)).status).toBe(401);
  });
});
