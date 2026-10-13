import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import {
  buildTestContext,
  createUser,
  resetDatabase,
  sessionCookies,
  STRONG_PASSWORD,
  type TestContext,
  waitFor,
} from "./helpers.js";

let ctx: TestContext;
beforeEach(async () => {
  await resetDatabase();
  ctx = await buildTestContext();
});

describe("email verification", () => {
  beforeEach(async () => {
    await request(ctx.app).post("/api/v1/auth/register").send({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "Asha" });
  });

  const verify = (token: string) => request(ctx.app).post("/api/v1/auth/verify-email").send({ token });

  it("verifies with the emailed token and emits UserEmailVerified", async () => {
    const res = await verify(ctx.notifier.tokenFromLast("auth.verify-email"));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ alreadyVerified: false, user: { emailVerified: true } });
    expect((await ctx.db.outboxMessage.findMany()).map((m) => m.messageType)).toEqual(["UserRegistered", "UserEmailVerified"]);
  });

  it("is idempotent: clicking the link twice is fine", async () => {
    const token = ctx.notifier.tokenFromLast("auth.verify-email");
    await verify(token);
    const again = await verify(token);
    expect(again.status).toBe(200);
    expect(again.body.alreadyVerified).toBe(true);
    expect(await ctx.db.outboxMessage.count({ where: { messageType: "UserEmailVerified" } })).toBe(1);
  });

  it("rejects unknown and expired tokens", async () => {
    expect((await verify("x".repeat(43))).body.code).toBe("INVALID_OR_EXPIRED_TOKEN");
    await ctx.db.emailVerificationToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await verify(ctx.notifier.tokenFromLast("auth.verify-email"))).status).toBe(400);
  });

  it("stores only a hash of the token", async () => {
    const token = ctx.notifier.tokenFromLast("auth.verify-email");
    const row = await ctx.db.emailVerificationToken.findFirstOrThrow();
    expect(row.tokenHash).not.toContain(token);
    expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("can resend a link to a logged-in, unverified user", async () => {
    const login = await request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: STRONG_PASSWORD });
    const res = await request(ctx.app).post("/api/v1/auth/verify-email/resend").set("Authorization", `Bearer ${login.body.accessToken}`);
    expect(res.status).toBe(202);
    expect(ctx.notifier.sent.filter((m) => m.templateKey === "auth.verify-email")).toHaveLength(2);
  });
});

describe("password reset", () => {
  beforeEach(async () => {
    await createUser(ctx.db, { email: "asha@example.com" });
  });

  const forgot = (email: string) => request(ctx.app).post("/api/v1/auth/forgot-password").send({ email });
  const reset = (token: string, newPassword: string) =>
    request(ctx.app).post("/api/v1/auth/reset-password").send({ token, newPassword });
  const login = (password: string) =>
    request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password });
  const resetToken = () =>
    waitFor(() => (ctx.notifier.sent.some((m) => m.templateKey === "auth.password-reset") ? ctx.notifier.tokenFromLast("auth.password-reset") : undefined));

  it("answers 202 for unknown emails too, and sends nothing", async () => {
    const res = await forgot("nobody@example.com");
    expect(res.status).toBe(202);
    await new Promise((r) => setTimeout(r, 200));
    expect(ctx.notifier.sent).toHaveLength(0);
  });

  it("resets the password with the emailed token and revokes existing sessions", async () => {
    const before = sessionCookies(await login(STRONG_PASSWORD));
    expect((await forgot("asha@example.com")).status).toBe(202);
    const token = await resetToken();

    const newPassword = "a brand new long passphrase";
    expect((await reset(token, newPassword)).status).toBe(204);

    expect((await login(STRONG_PASSWORD)).status).toBe(401);
    expect((await login(newPassword)).status).toBe(200);
    const refreshed = await request(ctx.app).post("/api/v1/auth/refresh").set("Cookie", before.cookie).set("X-CSRF-Token", before.csrf);
    expect(refreshed.status).toBe(401);
  });

  it("tokens are single-use, and only the newest one works", async () => {
    await forgot("asha@example.com");
    const first = await resetToken();
    ctx.notifier.sent.length = 0;
    await forgot("asha@example.com");
    const second = await resetToken();

    expect((await reset(first, "another long passphrase")).status).toBe(400);
    expect((await reset(second, "another long passphrase")).status).toBe(204);
    expect((await reset(second, "yet another long passphrase")).status).toBe(400);
  });

  it("enforces the password policy on the new password", async () => {
    await forgot("asha@example.com");
    const res = await reset(await resetToken(), "short");
    expect(res.status).toBe(400);
    expect(res.body.errors[0].path).toBe("newPassword");
  });

  it("rejects expired tokens", async () => {
    await forgot("asha@example.com");
    const token = await resetToken();
    await ctx.db.passwordResetToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await reset(token, "another long passphrase")).body.code).toBe("INVALID_OR_EXPIRED_TOKEN");
  });
});
