import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** 256 bits of randomness, URL-safe. Used for refresh, reset and verification tokens. */
export function generateToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Tokens are stored only as SHA-256 hashes. A database leak therefore does not leak
 * usable tokens, and (unlike passwords) a fast hash is fine because the input is
 * 256 random bits, not something a human chose.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
