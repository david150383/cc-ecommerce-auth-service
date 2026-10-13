// Creates an administrator, or promotes an existing user. The password is read from
// the ADMIN_PASSWORD environment variable so it never appears in shell history.
//   ADMIN_PASSWORD='...' npm run admin:create -- admin@example.com "Admin Name"
import { loadEnv } from "../config/env.js";
import { createPrisma } from "../db/prisma.js";
import { Role } from "../generated/prisma/client.js";
import { newId } from "../lib/ids.js";
import { hashPassword, passwordPolicyViolation } from "../security/password.js";

const [rawEmail, fullName = "Administrator"] = process.argv.slice(2);
const password = process.env.ADMIN_PASSWORD;
if (!rawEmail || !password) {
  console.error('usage: ADMIN_PASSWORD=... npm run admin:create -- <email> ["Full Name"]');
  process.exit(2);
}
const email = rawEmail.trim().toLowerCase();
const violation = passwordPolicyViolation(password, email);
if (violation) {
  console.error(violation);
  process.exit(2);
}

const db = createPrisma(loadEnv().DATABASE_URL);
const user = await db.user.upsert({
  where: { email },
  create: { id: newId(), email, fullName, passwordHash: await hashPassword(password), role: Role.ADMIN, emailVerifiedAt: new Date() },
  update: { role: Role.ADMIN },
});
console.log(`admin ready: ${user.email} (${user.id})`);
await db.$disconnect();
