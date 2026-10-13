import { readFileSync } from "node:fs";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { buildOpenApiDocument } from "../src/openapi/document.js";
import { buildTestContext, createUser, resetDatabase, sessionCookies, STRONG_PASSWORD, waitFor } from "./helpers.js";

beforeEach(async () => {
  await resetDatabase();
});

describe("rate limiting", () => {
  it("blocks password guessing against one account after 5 failures", async () => {
    const ctx = await buildTestContext({ RATE_LIMIT_ENABLED: "true" });
    await createUser(ctx.db, { email: "asha@example.com" });
    const attempt = (email = "asha@example.com") =>
      request(ctx.app).post("/api/v1/auth/login").send({ email, password: "guess guess guess" });

    for (let i = 0; i < 5; i++) expect((await attempt()).status).toBe(401);
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.headers["content-type"]).toMatch(/problem\+json/);
    expect(blocked.body.code).toBe("RATE_LIMITED");
    // Same casing tricks do not create a fresh bucket.
    expect((await attempt("ASHA@example.com")).status).toBe(429);
    // Other accounts are unaffected (until the per-IP limit).
    expect((await attempt("other@example.com")).status).toBe(401);
  });
});

describe("secrets never reach the logs", () => {
  it("passwords, tokens and reset links do not appear in any log line", async () => {
    const ctx = await buildTestContext({ LOG_LEVEL: "trace" });
    const reg = await request(ctx.app).post("/api/v1/auth/register").send({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "Asha" });
    expect(reg.status).toBe(201);
    const login = await request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: STRONG_PASSWORD });
    const s = sessionCookies(login);
    await request(ctx.app).post("/api/v1/auth/refresh").set("Cookie", s.cookie).set("X-CSRF-Token", s.csrf);
    await request(ctx.app).post("/api/v1/auth/forgot-password").send({ email: "asha@example.com" });
    await waitFor(() => (ctx.notifier.sent.length >= 2 ? true : undefined));

    const all = ctx.logs.join("\n");
    expect(all.length).toBeGreaterThan(0);
    for (const secret of [
      STRONG_PASSWORD,
      login.body.accessToken,
      s.refresh,
      ctx.notifier.tokenFromLast("auth.verify-email"),
      ctx.notifier.tokenFromLast("auth.password-reset"),
    ]) {
      expect(all).not.toContain(secret);
    }
  });
});

describe("OpenAPI", () => {
  it("the committed openapi/openapi.json matches the code (run `npm run openapi:export`)", () => {
    const committed = JSON.parse(readFileSync("openapi/openapi.json", "utf8"));
    expect(committed).toEqual(JSON.parse(JSON.stringify(buildOpenApiDocument())));
  });

  it("documents every route and serves Swagger UI", async () => {
    const ctx = await buildTestContext();
    const doc = (await request(ctx.app).get("/openapi.json")).body;
    expect(Object.keys(doc.paths)).toEqual(
      expect.arrayContaining(["/api/v1/auth/register", "/api/v1/auth/refresh", "/api/v1/admin/users", "/.well-known/jwks.json"]),
    );
    const ui = await request(ctx.app).get("/docs/");
    expect(ui.status).toBe(200);
    expect(ui.text).toMatch(/swagger-ui/);
  });
});
