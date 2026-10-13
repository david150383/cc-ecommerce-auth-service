import type { Env } from "../../config/env.js";
import { isUniqueViolation, type Db } from "../../db/prisma.js";
import { type Prisma, Role, type User, UserStatus } from "../../generated/prisma/client.js";
import { buildEvent } from "../../lib/envelope.js";
import { newId } from "../../lib/ids.js";
import type { Logger } from "../../lib/logger.js";
import { HttpProblem } from "../../lib/problem.js";
import type { TransactionalNotifier } from "../../notifications/notifier.js";
import {
  hashPassword,
  passwordPolicyViolation,
  verifyAgainstDummy,
  verifyPassword,
} from "../../security/password.js";
import { generateToken, hashToken } from "../../security/random-token.js";
import type { TokenService } from "../../security/token-service.js";
import type { UserDtoT } from "./auth.schemas.js";

/** Who is making the request, for audit records and outgoing events. */
export interface RequestMeta {
  ip?: string;
  userAgent?: string;
  correlationId: string;
}

export interface IssuedTokens {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresAt: Date;
  csrfToken: string;
  user: UserDtoT;
}

type Tx = Prisma.TransactionClient;

const DAY_MS = 24 * 60 * 60 * 1000;

export type AuditAction =
  | "REGISTERED"
  | "LOGIN_SUCCEEDED"
  | "LOGIN_FAILED"
  | "TOKEN_REFRESHED"
  | "REFRESH_TOKEN_REUSED"
  | "LOGGED_OUT"
  | "LOGGED_OUT_ALL"
  | "EMAIL_VERIFIED"
  | "PASSWORD_RESET_REQUESTED"
  | "PASSWORD_RESET"
  | "USER_SUSPENDED"
  | "USER_ACTIVATED";

export function toUserDto(user: User): UserDtoT {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    roles: [user.role === Role.ADMIN ? "admin" : "customer"],
    emailVerified: user.emailVerifiedAt !== null,
    status: user.status,
    createdAt: user.createdAt.toISOString(),
  };
}

export async function audit(
  db: Tx | Db,
  action: AuditAction,
  meta: RequestMeta,
  userId: string | null,
  metadata?: Prisma.InputJsonValue,
): Promise<void> {
  await db.authAuditLog.create({
    data: {
      id: newId(),
      userId,
      action,
      ip: meta.ip ?? null,
      userAgent: meta.userAgent?.slice(0, 500) ?? null,
      correlationId: meta.correlationId,
      ...(metadata !== undefined && { metadata }),
    },
  });
}

/** Ends sessions; their refresh tokens stop working immediately. */
export async function revokeSessions(db: Tx | Db, where: Prisma.SessionWhereInput, reason: string): Promise<number> {
  const { count } = await db.session.updateMany({
    where: { ...where, revokedAt: null },
    data: { revokedAt: new Date(), revokeReason: reason },
  });
  return count;
}

export class AuthService {
  constructor(
    private readonly deps: {
      db: Db;
      tokens: TokenService;
      notifier: TransactionalNotifier;
      env: Env;
      logger: Logger;
    },
  ) {}

  // ---------------------------------------------------------------- register

  async register(input: { email: string; password: string; fullName: string }, meta: RequestMeta): Promise<User> {
    const violation = passwordPolicyViolation(input.password, input.email);
    if (violation) {
      throw new HttpProblem(400, "VALIDATION_FAILED", "Request validation failed", violation, [
        { path: "password", message: violation },
      ]);
    }

    const passwordHash = await hashPassword(input.password);
    const verificationToken = generateToken();
    const { db, env } = this.deps;

    let user: User;
    try {
      // User row, verification token, outbox event and audit record commit together or not at all.
      user = await db.$transaction(async (tx) => {
        const created = await tx.user.create({
          data: { id: newId(), email: input.email, passwordHash, fullName: input.fullName },
        });
        await tx.emailVerificationToken.create({
          data: {
            id: newId(),
            userId: created.id,
            tokenHash: hashToken(verificationToken),
            expiresAt: new Date(Date.now() + env.EMAIL_VERIFICATION_TTL_HOURS * 3_600_000),
          },
        });
        await this.writeEvent(tx, "UserRegistered", meta, {
          userId: created.id,
          email: created.email,
          fullName: created.fullName,
          roles: ["customer"],
        });
        await audit(tx, "REGISTERED", meta, created.id);
        return created;
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new HttpProblem(409, "EMAIL_ALREADY_REGISTERED", "An account with this email already exists");
      }
      throw err;
    }

    await this.sendVerificationEmail(user, verificationToken);
    return user;
  }

  // ---------------------------------------------------------------- login

  async login(input: { email: string; password: string }, meta: RequestMeta): Promise<IssuedTokens> {
    const { db } = this.deps;
    const user = await db.user.findUnique({ where: { email: input.email } });

    // Same work and same answer whether the email is unknown or the password is wrong.
    const passwordOk = user ? await verifyPassword(user.passwordHash, input.password) : await verifyAgainstDummy(input.password);
    if (!user || !passwordOk) {
      await audit(db, "LOGIN_FAILED", meta, user?.id ?? null, { reason: user ? "BAD_PASSWORD" : "UNKNOWN_EMAIL" });
      throw new HttpProblem(401, "INVALID_CREDENTIALS", "Invalid email or password");
    }
    // Only revealed after the correct password, so it does not help an attacker probe accounts.
    if (user.status === UserStatus.SUSPENDED) {
      await audit(db, "LOGIN_FAILED", meta, user.id, { reason: "SUSPENDED" });
      throw new HttpProblem(403, "ACCOUNT_SUSPENDED", "This account is suspended");
    }

    return db.$transaction(async (tx) => {
      const session = await tx.session.create({
        data: {
          id: newId(),
          userId: user.id,
          expiresAt: new Date(Date.now() + this.deps.env.SESSION_ABSOLUTE_DAYS * DAY_MS),
          userAgent: meta.userAgent?.slice(0, 500) ?? null,
          ip: meta.ip ?? null,
        },
      });
      const issued = await this.issueTokens(tx, user, session);
      await audit(tx, "LOGIN_SUCCEEDED", meta, user.id, { sessionId: session.id });
      return issued;
    });
  }

  // ---------------------------------------------------------------- refresh

  /**
   * Rotation: every refresh token works exactly once. Presenting a used token means two
   * parties hold it (one of them an attacker), so the whole session is revoked.
   */
  async refresh(rawToken: string, meta: RequestMeta): Promise<IssuedTokens> {
    const { db } = this.deps;
    const stored = await db.refreshToken.findUnique({
      where: { tokenHash: hashToken(rawToken) },
      include: { session: { include: { user: true } } },
    });
    if (!stored) throw invalidRefresh();

    const { session } = stored;
    const now = new Date();

    if (stored.usedAt !== null) {
      await this.handleReuse(session.id, session.userId, meta);
      throw new HttpProblem(401, "REFRESH_TOKEN_REUSED", "Refresh token was already used; session revoked");
    }
    if (session.revokedAt || session.expiresAt <= now || stored.expiresAt <= now) throw invalidRefresh();
    if (session.user.status === UserStatus.SUSPENDED) throw new HttpProblem(403, "ACCOUNT_SUSPENDED", "This account is suspended");

    return db.$transaction(async (tx) => {
      // Conditional update = atomic claim. If two requests race with the same token,
      // exactly one sees count === 1; the other is treated as reuse.
      const { count } = await tx.refreshToken.updateMany({
        where: { id: stored.id, usedAt: null },
        data: { usedAt: now },
      });
      if (count === 0) {
        // Deliberately NOT using tx: this transaction is about to roll back, and the
        // revocation must survive that.
        await this.handleReuse(session.id, session.userId, meta);
        throw new HttpProblem(401, "REFRESH_TOKEN_REUSED", "Refresh token was already used; session revoked");
      }
      await tx.session.update({ where: { id: session.id }, data: { lastUsedAt: now } });
      const issued = await this.issueTokens(tx, session.user, session);
      await audit(tx, "TOKEN_REFRESHED", meta, session.userId, { sessionId: session.id });
      return issued;
    });
  }

  // ---------------------------------------------------------------- logout

  /** Idempotent: an unknown or already-revoked token still results in success. */
  async logout(rawToken: string | undefined, meta: RequestMeta): Promise<void> {
    if (!rawToken) return;
    const { db } = this.deps;
    const stored = await db.refreshToken.findUnique({
      where: { tokenHash: hashToken(rawToken) },
      include: { session: true },
    });
    if (!stored) return;
    const revoked = await revokeSessions(db, { id: stored.sessionId }, "LOGOUT");
    if (revoked > 0) await audit(db, "LOGGED_OUT", meta, stored.session.userId, { sessionId: stored.sessionId });
  }

  async logoutAll(userId: string, meta: RequestMeta): Promise<number> {
    const revoked = await revokeSessions(this.deps.db, { userId }, "LOGOUT_ALL");
    await audit(this.deps.db, "LOGGED_OUT_ALL", meta, userId, { sessionsRevoked: revoked });
    return revoked;
  }

  // ---------------------------------------------------------------- email verification

  async verifyEmail(rawToken: string, meta: RequestMeta): Promise<{ user: User; alreadyVerified: boolean }> {
    const { db } = this.deps;
    const stored = await db.emailVerificationToken.findUnique({
      where: { tokenHash: hashToken(rawToken) },
      include: { user: true },
    });
    if (!stored) throw invalidLinkToken();

    // Idempotent: clicking the link twice is not an error.
    if (stored.user.emailVerifiedAt) return { user: stored.user, alreadyVerified: true };
    if (stored.usedAt || stored.expiresAt <= new Date()) throw invalidLinkToken();

    const user = await db.$transaction(async (tx) => {
      const { count } = await tx.emailVerificationToken.updateMany({
        where: { id: stored.id, usedAt: null },
        data: { usedAt: new Date() },
      });
      if (count === 0) throw invalidLinkToken();
      const updated = await tx.user.update({ where: { id: stored.userId }, data: { emailVerifiedAt: new Date() } });
      await this.writeEvent(tx, "UserEmailVerified", meta, { userId: updated.id, email: updated.email });
      await audit(tx, "EMAIL_VERIFIED", meta, updated.id);
      return updated;
    });
    return { user, alreadyVerified: false };
  }

  async resendVerification(userId: string): Promise<void> {
    const { db, env } = this.deps;
    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw new HttpProblem(404, "NOT_FOUND", "User not found");
    if (user.emailVerifiedAt) throw new HttpProblem(409, "EMAIL_ALREADY_VERIFIED", "Email is already verified");

    const token = generateToken();
    await db.emailVerificationToken.create({
      data: {
        id: newId(),
        userId,
        tokenHash: hashToken(token),
        expiresAt: new Date(Date.now() + env.EMAIL_VERIFICATION_TTL_HOURS * 3_600_000),
      },
    });
    await this.sendVerificationEmail(user, token);
  }

  // ---------------------------------------------------------------- password reset

  /**
   * Always succeeds from the caller's point of view (no account enumeration). The work
   * runs after the response is sent, so response time does not reveal whether the
   * account exists either.
   */
  requestPasswordReset(email: string, meta: RequestMeta): void {
    setImmediate(() => {
      this.doRequestPasswordReset(email, meta).catch((err: unknown) =>
        this.deps.logger.error({ err, correlationId: meta.correlationId }, "password reset request failed"),
      );
    });
  }

  /** Exposed for tests, which need to await the background work. */
  async doRequestPasswordReset(email: string, meta: RequestMeta): Promise<void> {
    const { db, env } = this.deps;
    const user = await db.user.findUnique({ where: { email } });
    if (!user || user.status !== UserStatus.ACTIVE) return;

    const token = generateToken();
    await db.$transaction(async (tx) => {
      // Only the newest link works.
      await tx.passwordResetToken.updateMany({ where: { userId: user.id, usedAt: null }, data: { usedAt: new Date() } });
      await tx.passwordResetToken.create({
        data: {
          id: newId(),
          userId: user.id,
          tokenHash: hashToken(token),
          expiresAt: new Date(Date.now() + env.PASSWORD_RESET_TTL_MINUTES * 60_000),
        },
      });
      await audit(tx, "PASSWORD_RESET_REQUESTED", meta, user.id);
    });

    await this.deps.notifier.send({
      templateKey: "auth.password-reset",
      recipient: { userId: user.id, email: user.email, fullName: user.fullName },
      secretUrl: `${env.FRONTEND_BASE_URL}/reset-password?token=${encodeURIComponent(token)}`,
      idempotencyKey: `password-reset:${hashToken(token)}`,
    });
  }

  async resetPassword(input: { token: string; newPassword: string }, meta: RequestMeta): Promise<void> {
    const { db } = this.deps;
    const stored = await db.passwordResetToken.findUnique({
      where: { tokenHash: hashToken(input.token) },
      include: { user: true },
    });
    if (!stored || stored.usedAt || stored.expiresAt <= new Date()) throw invalidLinkToken();

    const violation = passwordPolicyViolation(input.newPassword, stored.user.email);
    if (violation) {
      throw new HttpProblem(400, "VALIDATION_FAILED", "Request validation failed", violation, [
        { path: "newPassword", message: violation },
      ]);
    }
    const passwordHash = await hashPassword(input.newPassword);

    await db.$transaction(async (tx) => {
      const { count } = await tx.passwordResetToken.updateMany({
        where: { id: stored.id, usedAt: null },
        data: { usedAt: new Date() },
      });
      if (count === 0) throw invalidLinkToken();
      await tx.user.update({ where: { id: stored.userId }, data: { passwordHash } });
      // Whoever knew the old password must not stay logged in.
      const revoked = await revokeSessions(tx, { userId: stored.userId }, "PASSWORD_RESET");
      await audit(tx, "PASSWORD_RESET", meta, stored.userId, { sessionsRevoked: revoked });
    });
  }

  // ---------------------------------------------------------------- me

  async getUser(userId: string): Promise<User> {
    const user = await this.deps.db.user.findUnique({ where: { id: userId } });
    if (!user) throw new HttpProblem(404, "NOT_FOUND", "User not found");
    return user;
  }

  // ---------------------------------------------------------------- internals

  private async issueTokens(tx: Tx, user: User, session: { id: string; expiresAt: Date }): Promise<IssuedTokens> {
    const { tokens, env } = this.deps;
    const refreshToken = generateToken();
    const idleExpiry = new Date(Date.now() + env.REFRESH_TOKEN_IDLE_DAYS * DAY_MS);
    const refreshExpiresAt = idleExpiry < session.expiresAt ? idleExpiry : session.expiresAt;

    await tx.refreshToken.create({
      data: { id: newId(), sessionId: session.id, tokenHash: hashToken(refreshToken), expiresAt: refreshExpiresAt },
    });
    const dto = toUserDto(user);
    const accessToken = await tokens.issueAccessToken({ sub: user.id, roles: dto.roles, sid: session.id });
    return {
      accessToken,
      expiresIn: tokens.accessTtlSeconds,
      refreshToken,
      refreshExpiresAt,
      csrfToken: generateToken(),
      user: dto,
    };
  }

  private async handleReuse(sessionId: string, userId: string, meta: RequestMeta): Promise<void> {
    const { db, logger } = this.deps;
    await revokeSessions(db, { id: sessionId }, "REFRESH_TOKEN_REUSE");
    await audit(db, "REFRESH_TOKEN_REUSED", meta, userId, { sessionId });
    logger.warn({ sessionId, userId, correlationId: meta.correlationId }, "refresh token reuse detected");
  }

  private async writeEvent(tx: Tx, messageType: string, meta: RequestMeta, payload: Prisma.InputJsonObject): Promise<void> {
    const envelope = buildEvent({ messageType, payload, correlationId: meta.correlationId });
    await tx.outboxMessage.create({
      data: { id: envelope.messageId, messageType, envelope: envelope as unknown as Prisma.InputJsonObject },
    });
  }

  private async sendVerificationEmail(user: User, token: string): Promise<void> {
    // Delivery failure must not fail registration; the user can request a new link.
    try {
      await this.deps.notifier.send({
        templateKey: "auth.verify-email",
        recipient: { userId: user.id, email: user.email, fullName: user.fullName },
        secretUrl: `${this.deps.env.FRONTEND_BASE_URL}/verify-email?token=${encodeURIComponent(token)}`,
        idempotencyKey: `verify-email:${hashToken(token)}`,
      });
    } catch (err) {
      this.deps.logger.error({ err, userId: user.id }, "verification email delivery failed");
    }
  }
}

function invalidRefresh(): HttpProblem {
  return new HttpProblem(401, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
}

function invalidLinkToken(): HttpProblem {
  return new HttpProblem(400, "INVALID_OR_EXPIRED_TOKEN", "This link is invalid or has expired");
}
