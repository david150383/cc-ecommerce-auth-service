import type { Db } from "../../db/prisma.js";
import { type Prisma, Role, type User, UserStatus } from "../../generated/prisma/client.js";
import { HttpProblem } from "../../lib/problem.js";
import { audit, type RequestMeta, revokeSessions } from "../auth/auth.service.js";

export interface ListUsersInput {
  limit: number;
  cursor?: string | undefined;
  q?: string | undefined;
  status?: "ACTIVE" | "SUSPENDED" | undefined;
  role?: "customer" | "admin" | undefined;
}

export class AdminService {
  constructor(private readonly db: Db) {}

  /**
   * Keyset ("cursor") pagination. IDs are UUIDv7, so ordering by id is ordering by
   * creation time. Unlike OFFSET, the cost does not grow with page depth, and rows
   * inserted meanwhile do not shift pages.
   */
  async listUsers(input: ListUsersInput): Promise<{ users: User[]; nextCursor: string | null }> {
    const where: Prisma.UserWhereInput = {
      ...(input.status && { status: input.status }),
      ...(input.role && { role: input.role === "admin" ? Role.ADMIN : Role.CUSTOMER }),
      ...(input.q && {
        OR: [
          { email: { contains: input.q, mode: "insensitive" } },
          { fullName: { contains: input.q, mode: "insensitive" } },
        ],
      }),
      ...(input.cursor && { id: { lt: input.cursor } }),
    };
    const rows = await this.db.user.findMany({ where, orderBy: { id: "desc" }, take: input.limit + 1 });
    const hasMore = rows.length > input.limit;
    const users = hasMore ? rows.slice(0, input.limit) : rows;
    return { users, nextCursor: hasMore ? users[users.length - 1]!.id : null };
  }

  async setStatus(
    actorId: string,
    userId: string,
    status: "ACTIVE" | "SUSPENDED",
    reason: string,
    meta: RequestMeta,
  ): Promise<User> {
    if (actorId === userId) throw new HttpProblem(409, "CANNOT_CHANGE_OWN_STATUS", "Administrators cannot change their own status");

    return this.db.$transaction(async (tx) => {
      const existing = await tx.user.findUnique({ where: { id: userId } });
      if (!existing) throw new HttpProblem(404, "NOT_FOUND", "User not found");
      if (existing.status === status) return existing; // idempotent

      const user = await tx.user.update({ where: { id: userId }, data: { status } });
      const sessionsRevoked = status === UserStatus.SUSPENDED ? await revokeSessions(tx, { userId }, "SUSPENDED") : 0;
      await audit(tx, status === UserStatus.SUSPENDED ? "USER_SUSPENDED" : "USER_ACTIVATED", meta, userId, {
        actorId,
        reason,
        sessionsRevoked,
      });
      return user;
    });
  }
}
