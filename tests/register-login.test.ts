import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { buildTestContext, cookiesOf, createUser, resetDatabase, STRONG_PASSWORD, type TestContext } from "./helpers.js";

const schemasDir = join(import.meta.dirname, "..", "events", "schemas");
const ajv = new Ajv2020({ strict: true, strictTypes: false, allErrors: true });
addFormats.default(ajv);
ajv.addVocabulary(["x-producer", "x-consumers", "x-channel", "x-message-kind"]);
for (const f of readdirSync(schemasDir)) ajv.addSchema(JSON.parse(readFileSync(join(schemasDir, f), "utf8")));
const schemaFor = (file: string) => ajv.getSchema(`https://schemas.ecommerce.local/auth-service/${file}`)!;

let ctx: TestContext;
beforeEach(async () => {
  await resetDatabase();
  ctx = await buildTestContext();
});

const register = (body: object) => request(ctx.app).post("/api/v1/auth/register").send(body);

describe("POST /api/v1/auth/register", () => {
  it("creates a customer with a normalized email and never returns the password hash", async () => {
    const res = await register({ email: "  Asha@Example.COM ", password: STRONG_PASSWORD, fullName: "Asha Rao" });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({
      email: "asha@example.com",
      fullName: "Asha Rao",
      roles: ["customer"],
      emailVerified: false,
      status: "ACTIVE",
    });
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|argon2/);

    const stored = await ctx.db.user.findUniqueOrThrow({ where: { email: "asha@example.com" } });
    expect(stored.passwordHash).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
  });

  it("writes a schema-valid UserRegistered event to the outbox in the same transaction", async () => {
    const res = await register({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "Asha Rao" });
    const rows = await ctx.db.outboxMessage.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.messageType).toBe("UserRegistered");
    expect(rows[0]!.publishedAt).toBeNull();

    const validate = schemaFor("user-registered.v1.schema.json");
    expect(validate(rows[0]!.envelope), JSON.stringify(validate.errors)).toBe(true);
    expect(rows[0]!.envelope).toMatchObject({
      correlationId: res.headers["x-correlation-id"],
      payload: { userId: res.body.user.id, email: "asha@example.com" },
    });
  });

  it("sends a verification link and records an audit entry", async () => {
    await register({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "Asha Rao" });
    expect(ctx.notifier.sent).toHaveLength(1);
    expect(ctx.notifier.sent[0]!.secretUrl).toMatch(/^http:\/\/localhost:5173\/verify-email\?token=/);
    expect(await ctx.db.authAuditLog.count({ where: { action: "REGISTERED" } })).toBe(1);
  });

  it("still succeeds when the verification email cannot be delivered", async () => {
    ctx.notifier.failNext = true;
    const res = await register({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "Asha Rao" });
    expect(res.status).toBe(201);
  });

  it("rejects a duplicate email regardless of case", async () => {
    await register({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "Asha" });
    const res = await register({ email: "ASHA@example.com", password: STRONG_PASSWORD, fullName: "Asha" });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("EMAIL_ALREADY_REGISTERED");
    expect(await ctx.db.outboxMessage.count()).toBe(1);
  });

  it.each([
    ["too short", "short-pass1", /at least 12/],
    ["too common", "password1234", /too common/],
    ["contains the email", "ashavalidpassword", /email address/],
  ])("rejects a password that is %s", async (_label, password, message) => {
    const res = await register({ email: "asha@example.com", password, fullName: "Asha" });
    expect(res.status).toBe(400);
    expect(res.body.errors[0]).toMatchObject({ path: "password", message: expect.stringMatching(message) });
    expect(await ctx.db.user.count()).toBe(0);
  });

  it("rejects unknown fields so a client cannot sneak in role=admin", async () => {
    const res = await register({ email: "asha@example.com", password: STRONG_PASSWORD, fullName: "A", role: "ADMIN" });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("VALIDATION_FAILED");
  });

  it("is enforced by the database too: a non-normalized email cannot be stored", async () => {
    await expect(createUser(ctx.db, { email: "Mixed@Case.com" })).rejects.toThrow(/users_email_normalized/);
  });
});

describe("POST /api/v1/auth/login", () => {
  beforeEach(async () => {
    await createUser(ctx.db, { email: "asha@example.com" });
  });

  it("returns an access token and sets hardened cookies", async () => {
    const res = await request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: STRONG_PASSWORD });
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.body).toMatchObject({ tokenType: "Bearer", expiresIn: 900, user: { email: "asha@example.com" } });
    expect(res.body.refreshToken).toBeUndefined(); // only ever in the HttpOnly cookie

    const cookies = cookiesOf(res);
    expect(cookies.refresh_token!.attrs).toMatch(/HttpOnly/);
    expect(cookies.refresh_token!.attrs).toMatch(/Secure/);
    expect(cookies.refresh_token!.attrs).toMatch(/SameSite=Strict/);
    expect(cookies.refresh_token!.attrs).toMatch(/Path=\/api\/v1\/auth/);
    expect(cookies.csrf_token!.attrs).not.toMatch(/HttpOnly/);
    expect(cookies.csrf_token!.value).toBe(res.body.csrfToken);
  });

  it("gives the same answer for an unknown email and a wrong password", async () => {
    const wrong = await request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: "wrong password!!" });
    const unknown = await request(ctx.app).post("/api/v1/auth/login").send({ email: "nobody@example.com", password: "wrong password!!" });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.code).toBe("INVALID_CREDENTIALS");
    expect({ ...wrong.body, instance: null, correlationId: null }).toEqual({ ...unknown.body, instance: null, correlationId: null });
    expect(await ctx.db.authAuditLog.count({ where: { action: "LOGIN_FAILED" } })).toBe(2);
  });

  it("refuses suspended accounts, but only after the correct password", async () => {
    await ctx.db.user.update({ where: { email: "asha@example.com" }, data: { status: "SUSPENDED" } });
    const wrong = await request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: "wrong password!!" });
    expect(wrong.body.code).toBe("INVALID_CREDENTIALS");
    const right = await request(ctx.app).post("/api/v1/auth/login").send({ email: "asha@example.com", password: STRONG_PASSWORD });
    expect(right.status).toBe(403);
    expect(right.body.code).toBe("ACCOUNT_SUSPENDED");
  });
});
