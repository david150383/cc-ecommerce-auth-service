import argon2 from "argon2";

// OWASP Password Storage Cheat Sheet minimum for Argon2id: m=19 MiB, t=2, p=1.
// Tune upwards while a hash still takes < ~250 ms on production hardware.
const ARGON2_OPTIONS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

// A tiny sample of the most common passwords. Phase 7 replaces this with a
// k-anonymity breached-password check (e.g. Have I Been Pwned range API).
const COMMON_PASSWORDS = new Set([
  "123456789012", "password1234", "qwertyuiop12", "iloveyou1234", "passwordpassword",
  "111111111111", "123123123123", "qwerty123456", "letmein12345", "welcome12345",
  "adminadmin12", "changeme1234", "password123!", "abc123456789", "000000000000",
]);

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Hash of a random password, verified against when the email is unknown so that
 * "no such user" takes as long as "wrong password" (no user enumeration by timing).
 */
let dummyHash: Promise<string> | undefined;
export function verifyAgainstDummy(password: string): Promise<boolean> {
  dummyHash ??= hashPassword("dummy-password-for-timing-equalization");
  return dummyHash.then((h) => verifyPassword(h, password)).then(() => false);
}

/** Returns a human-readable problem, or null when the password is acceptable. */
export function passwordPolicyViolation(password: string, email: string): string | null {
  if (password.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Password must be at most ${PASSWORD_MAX_LENGTH} characters.`;
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return "This password is too common.";
  const localPart = email.split("@")[0] ?? "";
  if (localPart.length >= 4 && password.toLowerCase().includes(localPart.toLowerCase())) {
    return "Password must not contain your email address.";
  }
  return null;
}
