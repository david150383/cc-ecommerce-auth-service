import { describe, expect, it } from "vitest";
import { loadEnv } from "../src/config/env.js";

const required = { DATABASE_URL: "postgresql://u:p@localhost:5432/db" };

describe("loadEnv", () => {
  it("applies defaults", () => {
    const env = loadEnv(required);
    expect(env.PORT).toBe(4001);
    expect(env.CORS_ALLOWED_ORIGINS).toEqual(["http://localhost:5173"]);
  });

  it("parses comma-separated CORS origins", () => {
    const env = loadEnv({ ...required, CORS_ALLOWED_ORIGINS: "https://a.example, https://b.example" });
    expect(env.CORS_ALLOWED_ORIGINS).toEqual(["https://a.example", "https://b.example"]);
  });

  it("refuses development-only settings in production", () => {
    expect(() => loadEnv({ ...required, NODE_ENV: "production", NOTIFICATION_DELIVERY: "smtp-dev" })).toThrow(/smtp-dev/);
    expect(() => loadEnv({ ...required, NODE_ENV: "production", NOTIFICATION_DELIVERY: "http", COOKIE_SECURE: "false" })).toThrow(/COOKIE_SECURE/);
  });

  it("requires DATABASE_URL", () => {
    expect(() => loadEnv({})).toThrow(/DATABASE_URL/);
  });

  it("rejects invalid configuration at startup", () => {
    expect(() => loadEnv({ ...required, PORT: "not-a-port" })).toThrow(/Invalid environment configuration/);
  });
});
