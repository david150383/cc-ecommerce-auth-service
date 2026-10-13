import { Router } from "express";
import { requireAuth, requireRole } from "../../middleware/authenticate.js";
import { parse } from "../../middleware/validate.js";
import type { TokenService } from "../../security/token-service.js";
import { requestMeta } from "../auth/auth.routes.js";
import { toUserDto } from "../auth/auth.service.js";
import { ListUsersQuery, UpdateUserStatusRequest, UserIdParam } from "./admin.schemas.js";
import type { AdminService } from "./admin.service.js";

export function adminRouter(deps: { admin: AdminService; tokens: TokenService }): Router {
  const router = Router();
  router.use(requireAuth(deps.tokens), requireRole("admin"));

  router.get("/users", async (req, res) => {
    const query = parse(ListUsersQuery, req.query);
    const { users, nextCursor } = await deps.admin.listUsers(query);
    res.json({ data: users.map(toUserDto), page: { limit: query.limit, nextCursor } });
  });

  router.patch("/users/:userId/status", async (req, res) => {
    const { userId } = parse(UserIdParam, req.params);
    const body = parse(UpdateUserStatusRequest, req.body);
    const user = await deps.admin.setStatus(res.locals.auth!.sub, userId, body.status, body.reason, requestMeta(req, res));
    res.json({ user: toUserDto(user) });
  });

  return router;
}
