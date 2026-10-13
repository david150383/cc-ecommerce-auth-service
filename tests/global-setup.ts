import { execFileSync } from "node:child_process";
import pg from "pg";

// Recreates an empty test database and applies the real migrations, so integration
// tests run against exactly the schema production gets.
export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgresql://auth_svc:auth_local_pw@localhost:5432/auth_test";

export default async function setup(): Promise<void> {
  const url = new URL(TEST_DATABASE_URL);
  const dbName = url.pathname.slice(1);
  const maintenance = new URL(TEST_DATABASE_URL);
  maintenance.pathname = "/postgres";

  const client = new pg.Client({ connectionString: maintenance.toString() });
  try {
    await client.connect();
  } catch (err) {
    throw new Error(
      `Cannot reach PostgreSQL for integration tests (${maintenance.host}). Start it with ` +
        "`docker compose up -d` here or in ecommerce-infrastructure, or set TEST_DATABASE_URL.",
      { cause: err },
    );
  }
  await client.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  await client.query(`CREATE DATABASE "${dbName}"`);
  await client.end();

  execFileSync("npx", ["prisma", "migrate", "deploy"], {
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
    stdio: "pipe",
  });
}
