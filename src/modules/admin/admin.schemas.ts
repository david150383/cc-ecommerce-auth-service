import { z } from "../../lib/zod.js";
import { UserDto } from "../auth/auth.schemas.js";

export const ListUsersQuery = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    cursor: z.uuid().optional(),
    q: z.string().trim().min(1).max(100).optional(),
    status: z.enum(["ACTIVE", "SUSPENDED"]).optional(),
    role: z.enum(["customer", "admin"]).optional(),
  })
  .strict()
  .openapi("ListUsersQuery");

export const ListUsersResponse = z
  .object({
    data: z.array(UserDto),
    page: z.object({ limit: z.number().int(), nextCursor: z.uuid().nullable() }),
  })
  .openapi("ListUsersResponse");

export const UpdateUserStatusRequest = z
  .object({ status: z.enum(["ACTIVE", "SUSPENDED"]), reason: z.string().trim().min(1).max(500) })
  .strict()
  .openapi("UpdateUserStatusRequest");

export const UserIdParam = z.object({ userId: z.uuid() });
