import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { buildTestContext, createUser, resetDatabase, sessionCookies, STRONG_PASSWORD, type TestContext } from "./helpers.js";

let ctx: TestContext;
let adminToken: string;
let customerToken: string;

const loginAs = async (email: string) =>
  request(ctx.app).post("/api/v1/auth/login").send({ email, password: STRONG_PASSWORD });

beforeEach(async () => {
  await resetDatabase();
  ctx = await buildTestContext();
  await createUser(ctx.db, { email: "admin@example.com", role: "ADMIN" });
  await createUser(ctx.db, { email: "asha@example.com" });
  adminToken = (await loginAs("admin@example.com")).body.accessToken;
  customerToken = (await loginAs("asha@example.com")).body.accessToken;
});

describe("GET /api/v1/admin/users", () => {
  it("requires authentication and the admin role", async () => {
    expect((await request(ctx.app).get("/api/v1/admin/users")).status).toBe(401);
    const forbidden = await request(ctx.app).get("/api/v1/admin/users").set("Authorization", `Bearer ${customerToken}`);
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.code).toBe("FORBIDDEN");
  });

  it("pages through users with an opaque cursor, newest first", async () => {
    for (let i = 0; i < 5; i++) await createUser(ctx.db, { email: `user${i}@example.com` });
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const res: request.Response = await request(ctx.app)
        .get("/api/v1/admin/users")
        .query({ limit: 3, ...(cursor && { cursor }) })
        .set("Authorization", `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      seen.push(...res.body.data.map((u: { email: string }) => u.email));
      cursor = res.body.page.nextCursor;
    } while (cursor);
    expect(seen).toHaveLength(7);
    expect(new Set(seen).size).toBe(7);
    expect(seen[0]).toBe("user4@example.com");
  });

  it("filters by search text, role and status", async () => {
    const auth = { Authorization: `Bearer ${adminToken}` };
    const byQ = await request(ctx.app).get("/api/v1/admin/users?q=ASHA").set(auth);
    expect(byQ.body.data.map((u: { email: string }) => u.email)).toEqual(["asha@example.com"]);
    const byRole = await request(ctx.app).get("/api/v1/admin/users?role=admin").set(auth);
    expect(byRole.body.data).toHaveLength(1);
    const bad = await request(ctx.app).get("/api/v1/admin/users?limit=1000").set(auth);
    expect(bad.status).toBe(400);
  });
});

describe("PATCH /api/v1/admin/users/{userId}/status", () => {
  it("suspends a user: sessions are revoked, login is refused, and it is audited", async () => {
    const userSession = sessionCookies(await loginAs("asha@example.com"));
    const asha = await ctx.db.user.findUniqueOrThrow({ where: { email: "asha@example.com" } });

    const res = await request(ctx.app)
      .patch(`/api/v1/admin/users/${asha.id}/status`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ status: "SUSPENDED", reason: "chargeback fraud" });
    expect(res.status).toBe(200);
    expect(res.body.user.status).toBe("SUSPENDED");

    const refresh = await request(ctx.app).post("/api/v1/auth/refresh").set("Cookie", userSession.cookie).set("X-CSRF-Token", userSession.csrf);
    expect(refresh.status).toBe(401);
    expect((await loginAs("asha@example.com")).status).toBe(403);

    const entry = await ctx.db.authAuditLog.findFirstOrThrow({ where: { action: "USER_SUSPENDED" } });
    expect(entry.metadata).toMatchObject({ reason: "chargeback fraud", sessionsRevoked: 2 });
  });

  it("re-activates a user, and repeating the same change is a no-op", async () => {
    const asha = await ctx.db.user.findUniqueOrThrow({ where: { email: "asha@example.com" } });
    const patch = (status: string) =>
      request(ctx.app).patch(`/api/v1/admin/users/${asha.id}/status`).set("Authorization", `Bearer ${adminToken}`).send({ status, reason: "test" });
    await patch("SUSPENDED");
    await patch("ACTIVE");
    expect((await patch("ACTIVE")).status).toBe(200);
    expect(await ctx.db.authAuditLog.count({ where: { action: "USER_ACTIVATED" } })).toBe(1);
    expect((await loginAs("asha@example.com")).status).toBe(200);
  });

  it("prevents an admin from suspending themself, and 404s unknown users", async () => {
    const admin = await ctx.db.user.findUniqueOrThrow({ where: { email: "admin@example.com" } });
    const self = await request(ctx.app).patch(`/api/v1/admin/users/${admin.id}/status`).set("Authorization", `Bearer ${adminToken}`).send({ status: "SUSPENDED", reason: "x" });
    expect(self.status).toBe(409);
    const missing = await request(ctx.app)
      .patch("/api/v1/admin/users/0192a1b2-0000-7000-8000-000000000000/status")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ status: "SUSPENDED", reason: "x" });
    expect(missing.status).toBe(404);
  });
});
