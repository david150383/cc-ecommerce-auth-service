// Prisma CLI configuration (migrate, generate). The application itself does not
// read this file; it builds its client from the validated env in src/config/env.ts.
import "dotenv/config";
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url: process.env["DATABASE_URL"],
    // Scratch database used by `npm run db:check-drift` to replay migrations. Optional.
    ...(process.env["SHADOW_DATABASE_URL"] && { shadowDatabaseUrl: process.env["SHADOW_DATABASE_URL"] }),
  },
});
