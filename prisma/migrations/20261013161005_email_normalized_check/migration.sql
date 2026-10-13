-- Prisma cannot express CHECK constraints in schema.prisma, so they live in SQL migrations.
-- The application normalizes emails before writing; this makes the database enforce it too,
-- so the UNIQUE index on email is effectively case-insensitive.
ALTER TABLE "users"
  ADD CONSTRAINT "users_email_normalized" CHECK ("email" = lower(btrim("email")));
