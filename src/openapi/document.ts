import { OpenApiGeneratorV31, OpenAPIRegistry, type RouteConfig } from "@asteasolutions/zod-to-openapi";
import { z } from "../lib/zod.js";
import { ListUsersQuery, ListUsersResponse, UpdateUserStatusRequest } from "../modules/admin/admin.schemas.js";
import {
  ForgotPasswordRequest,
  LoginRequest,
  RegisterRequest,
  ResetPasswordRequest,
  TokenResponse,
  UserResponse,
  VerifyEmailRequest,
  VerifyEmailResponse,
} from "../modules/auth/auth.schemas.js";

// Built from the SAME zod schemas that validate requests, so the spec cannot drift
// from the implementation. A test compares it with the committed openapi/openapi.json.

const Problem = z
  .object({
    type: z.string(),
    title: z.string(),
    status: z.number().int(),
    code: z.string(),
    detail: z.string().optional(),
    instance: z.string(),
    correlationId: z.string().optional(),
    errors: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
  })
  .openapi("Problem");

const json = <T extends z.ZodType>(schema: T, description: string) => ({
  description,
  content: { "application/json": { schema } },
});
const problem = (description: string) => ({ description, content: { "application/problem+json": { schema: Problem } } });
const noContent = (description: string) => ({ description });

const CsrfHeader = z.object({ "x-csrf-token": z.string().openapi({ description: "Must equal the csrf_token cookie" }) });

export function buildOpenApiDocument() {
  const registry = new OpenAPIRegistry();
  const bearer = registry.registerComponent("securitySchemes", "bearerAuth", {
    type: "http",
    scheme: "bearer",
    bearerFormat: "JWT",
  });
  const refreshCookie = registry.registerComponent("securitySchemes", "refreshCookie", {
    type: "apiKey",
    in: "cookie",
    name: "refresh_token",
  });
  const secured = [{ [bearer.name]: [] }];

  const paths: RouteConfig[] = [
    {
      method: "post", path: "/api/v1/auth/register", tags: ["auth"], summary: "Register a customer account",
      request: { body: { content: { "application/json": { schema: RegisterRequest } } } },
      responses: { 201: json(UserResponse, "Created; verification email sent"), 400: problem("Validation failed"), 409: problem("EMAIL_ALREADY_REGISTERED"), 429: problem("RATE_LIMITED") },
    },
    {
      method: "post", path: "/api/v1/auth/login", tags: ["auth"], summary: "Log in; sets refresh_token and csrf_token cookies",
      request: { body: { content: { "application/json": { schema: LoginRequest } } } },
      responses: { 200: json(TokenResponse, "Logged in"), 401: problem("INVALID_CREDENTIALS"), 403: problem("ACCOUNT_SUSPENDED"), 429: problem("RATE_LIMITED") },
    },
    {
      method: "post", path: "/api/v1/auth/refresh", tags: ["auth"], summary: "Rotate the refresh token and get a new access token",
      security: [{ [refreshCookie.name]: [] }], request: { headers: CsrfHeader },
      responses: { 200: json(TokenResponse, "Rotated"), 401: problem("INVALID_REFRESH_TOKEN or REFRESH_TOKEN_REUSED (session revoked)"), 403: problem("CSRF_TOKEN_INVALID or ACCOUNT_SUSPENDED") },
    },
    {
      method: "post", path: "/api/v1/auth/logout", tags: ["auth"], summary: "Revoke the current session (idempotent)",
      security: [{ [refreshCookie.name]: [] }], request: { headers: CsrfHeader },
      responses: { 204: noContent("Logged out"), 403: problem("CSRF_TOKEN_INVALID") },
    },
    {
      method: "post", path: "/api/v1/auth/logout-all", tags: ["auth"], summary: "Revoke every session of the current user", security: secured,
      responses: { 204: noContent("All sessions revoked"), 401: problem("UNAUTHENTICATED") },
    },
    {
      method: "post", path: "/api/v1/auth/verify-email", tags: ["auth"], summary: "Consume an email verification token (idempotent)",
      request: { body: { content: { "application/json": { schema: VerifyEmailRequest } } } },
      responses: { 200: json(VerifyEmailResponse, "Verified"), 400: problem("INVALID_OR_EXPIRED_TOKEN") },
    },
    {
      method: "post", path: "/api/v1/auth/verify-email/resend", tags: ["auth"], summary: "Send a new verification email", security: secured,
      responses: { 202: noContent("Sent"), 401: problem("UNAUTHENTICATED"), 409: problem("EMAIL_ALREADY_VERIFIED") },
    },
    {
      method: "post", path: "/api/v1/auth/forgot-password", tags: ["auth"], summary: "Request a reset link (always 202: no account enumeration)",
      request: { body: { content: { "application/json": { schema: ForgotPasswordRequest } } } },
      responses: { 202: noContent("Accepted"), 429: problem("RATE_LIMITED") },
    },
    {
      method: "post", path: "/api/v1/auth/reset-password", tags: ["auth"], summary: "Set a new password; revokes all sessions",
      request: { body: { content: { "application/json": { schema: ResetPasswordRequest } } } },
      responses: { 204: noContent("Password changed"), 400: problem("INVALID_OR_EXPIRED_TOKEN or policy violation") },
    },
    {
      method: "get", path: "/api/v1/auth/me", tags: ["auth"], summary: "Current user", security: secured,
      responses: { 200: json(UserResponse, "Current user"), 401: problem("UNAUTHENTICATED") },
    },
    {
      method: "get", path: "/api/v1/admin/users", tags: ["admin"], summary: "List users (cursor pagination)", security: secured,
      request: { query: ListUsersQuery },
      responses: { 200: json(ListUsersResponse, "Users"), 401: problem("UNAUTHENTICATED"), 403: problem("FORBIDDEN") },
    },
    {
      method: "patch", path: "/api/v1/admin/users/{userId}/status", tags: ["admin"], summary: "Suspend or activate a user", security: secured,
      request: { params: z.object({ userId: z.uuid() }), body: { content: { "application/json": { schema: UpdateUserStatusRequest } } } },
      responses: { 200: json(UserResponse, "Updated"), 403: problem("FORBIDDEN"), 404: problem("NOT_FOUND"), 409: problem("CANNOT_CHANGE_OWN_STATUS") },
    },
    {
      method: "get", path: "/.well-known/jwks.json", tags: ["keys"], summary: "Public keys for verifying access tokens",
      responses: { 200: { description: "JSON Web Key Set", content: { "application/json": { schema: z.object({ keys: z.array(z.record(z.string(), z.unknown())) }) } } } },
    },
  ];
  paths.forEach((p) => registry.registerPath(p));

  return new OpenApiGeneratorV31(registry.definitions).generateDocument({
    openapi: "3.1.0",
    info: {
      title: "Auth Service",
      version: "1.0.0",
      description: "Identity, sessions and tokens. Conventions: ecommerce-infrastructure/docs/architecture/conventions.md",
    },
    servers: [{ url: "http://localhost:4001" }],
  });
}
