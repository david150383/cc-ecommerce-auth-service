import { PASSWORD_MAX_LENGTH } from "../../security/password.js";
import { z } from "../../lib/zod.js";

// Normalize first, then validate: "  Asha@Example.COM " is accepted as "asha@example.com".
const email = z
  .string()
  .trim()
  .toLowerCase()
  .pipe(z.email().max(254))
  .openapi({ example: "asha@example.com" });

// Length/complexity rules are enforced by passwordPolicyViolation() so that the
// error message can mention the email; here we only bound the size.
const password = z.string().min(1).max(PASSWORD_MAX_LENGTH).openapi({ example: "correct horse battery staple" });
const token = z.string().min(20).max(200);

export const RegisterRequest = z
  .object({ email, password, fullName: z.string().trim().min(1).max(200).openapi({ example: "Asha Rao" }) })
  .strict()
  .openapi("RegisterRequest");

export const LoginRequest = z.object({ email, password }).strict().openapi("LoginRequest");
export const VerifyEmailRequest = z.object({ token }).strict().openapi("VerifyEmailRequest");
export const ForgotPasswordRequest = z.object({ email }).strict().openapi("ForgotPasswordRequest");
export const ResetPasswordRequest = z.object({ token, newPassword: password }).strict().openapi("ResetPasswordRequest");

export const UserDto = z
  .object({
    id: z.uuid(),
    email: z.string(),
    fullName: z.string(),
    roles: z.array(z.enum(["customer", "admin"])),
    emailVerified: z.boolean(),
    status: z.enum(["ACTIVE", "SUSPENDED"]),
    createdAt: z.iso.datetime(),
  })
  .openapi("User");

export const UserResponse = z.object({ user: UserDto }).openapi("UserResponse");

export const TokenResponse = z
  .object({
    accessToken: z.string(),
    tokenType: z.literal("Bearer"),
    expiresIn: z.number().int().openapi({ description: "Access token lifetime in seconds" }),
    csrfToken: z.string().openapi({ description: "Send as X-CSRF-Token on /refresh and /logout" }),
    user: UserDto,
  })
  .openapi("TokenResponse");

export const VerifyEmailResponse = z.object({ user: UserDto, alreadyVerified: z.boolean() }).openapi("VerifyEmailResponse");

export type UserDtoT = z.infer<typeof UserDto>;
