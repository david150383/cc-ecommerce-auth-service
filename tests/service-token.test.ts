import { createLocalJWKSet, jwtVerify } from "jose";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { hashToken } from "../src/security/random-token.js";
import { buildTestContext, resetDatabase, type TestContext } from "./helpers.js";

const SECRET = "order-service-test-secret-0123456789abcdefghij";
const CLIENTS = JSON.stringify([
  { clientId: "ecommerce-order-service", secretSha256: hashToken(SECRET), audiences: ["ecommerce-product-service"] },
]);

let ctx: TestContext;
beforeEach(async () => {
  await resetDatabase();
  ctx = await buildTestContext({ SERVICE_CLIENTS: CLIENTS });
});

const grant = (body: object) => request(ctx.app).post("/internal/v1/auth/service-token").send(body);

describe("POST /internal/v1/auth/service-token", () => {
  it("issues a short-lived token for exactly one target service", async () => {
    const res = await grant({ clientId: "ecommerce-order-service", clientSecret: SECRET, audience: "ecommerce-product-service" });
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.body).toMatchObject({ tokenType: "Bearer", expiresIn: 300 });

    const jwks = (await request(ctx.app).get("/.well-known/jwks.json")).body;
    const { payload } = await jwtVerify(res.body.accessToken, createLocalJWKSet(jwks), {
      issuer: "ecommerce-auth-service",
      audience: "ecommerce-product-service",
    });
    expect(payload).toMatchObject({ sub: "ecommerce-order-service", roles: ["service"] });
    expect(payload.exp! - payload.iat!).toBe(300);
    expect(payload.sid).toBeUndefined();
    expect(await ctx.db.authAuditLog.count({ where: { action: "SERVICE_TOKEN_ISSUED" } })).toBe(1);
  });

  it("the token is not accepted where user tokens are (different audience)", async () => {
    const res = await grant({ clientId: "ecommerce-order-service", clientSecret: SECRET, audience: "ecommerce-product-service" });
    const me = await request(ctx.app).get("/api/v1/auth/me").set("Authorization", `Bearer ${res.body.accessToken}`);
    expect(me.status).toBe(401);
  });

  it("rejects a wrong secret and an unknown client identically", async () => {
    const wrong = await grant({ clientId: "ecommerce-order-service", clientSecret: "nope", audience: "ecommerce-product-service" });
    const unknown = await grant({ clientId: "ecommerce-evil-service", clientSecret: SECRET, audience: "ecommerce-product-service" });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.code).toBe("INVALID_CLIENT");
    expect(unknown.body.code).toBe("INVALID_CLIENT");
  });

  it("refuses audiences the client is not allowed to call", async () => {
    const res = await grant({ clientId: "ecommerce-order-service", clientSecret: SECRET, audience: "ecommerce-payment-service" });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("AUDIENCE_NOT_ALLOWED");
    expect(await ctx.db.authAuditLog.count({ where: { action: "SERVICE_TOKEN_DENIED" } })).toBe(1);
  });

  it("validates the request and never logs the secret", async () => {
    expect((await grant({ clientId: "x" })).status).toBe(400);
    await grant({ clientId: "ecommerce-order-service", clientSecret: SECRET, audience: "ecommerce-product-service" });
    expect(ctx.logs.join("\n")).not.toContain(SECRET);
  });
});

describe("SERVICE_CLIENTS configuration", () => {
  it("rejects malformed configuration at startup", async () => {
    await expect(buildTestContext({ SERVICE_CLIENTS: "not json" })).rejects.toThrow(/SERVICE_CLIENTS/);
    await expect(
      buildTestContext({ SERVICE_CLIENTS: JSON.stringify([{ clientId: "ecommerce-x", secretSha256: "short", audiences: [] }]) }),
    ).rejects.toThrow(/Invalid environment configuration/);
  });
});
