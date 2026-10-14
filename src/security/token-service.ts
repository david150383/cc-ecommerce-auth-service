import { createLocalJWKSet, jwtVerify, SignJWT } from "jose";
import { newId } from "../lib/ids.js";
import { type KeyStore, SIGNING_ALG } from "./key-store.js";

export type RoleClaim = "customer" | "admin" | "service";

export interface AccessTokenClaims {
  sub: string;
  roles: RoleClaim[];
  sid?: string;
}

export interface VerifiedAccessToken extends AccessTokenClaims {
  jti: string;
  exp: number;
}

export class TokenService {
  private readonly verifyKeys: ReturnType<typeof createLocalJWKSet>;

  constructor(
    private readonly keys: KeyStore,
    private readonly config: { issuer: string; audience: string; accessTtlSeconds: number },
  ) {
    this.verifyKeys = createLocalJWKSet(keys.jwks());
  }

  get accessTtlSeconds(): number {
    return this.config.accessTtlSeconds;
  }

  /** Short-lived, stateless access token. Other services verify it with the JWKS. */
  issueAccessToken(
    claims: AccessTokenClaims,
    audience = this.config.audience,
    ttlSeconds = this.config.accessTtlSeconds,
  ): Promise<string> {
    const { kid, privateKey } = this.keys.signingKey;
    return new SignJWT({ roles: claims.roles, ...(claims.sid && { sid: claims.sid }) })
      .setProtectedHeader({ alg: SIGNING_ALG, kid, typ: "JWT" })
      .setIssuer(this.config.issuer)
      .setAudience(audience)
      .setSubject(claims.sub)
      .setJti(newId())
      .setIssuedAt()
      .setExpirationTime(`${ttlSeconds}s`)
      .sign(privateKey);
  }

  /** Throws on bad signature, wrong issuer/audience, expiry, or a non-RS256 algorithm. */
  async verifyAccessToken(token: string): Promise<VerifiedAccessToken> {
    const { payload } = await jwtVerify(token, this.verifyKeys, {
      issuer: this.config.issuer,
      audience: this.config.audience,
      algorithms: [SIGNING_ALG],
      clockTolerance: 30,
    });
    if (typeof payload.sub !== "string" || !Array.isArray(payload.roles)) {
      throw new Error("token is missing required claims");
    }
    return {
      sub: payload.sub,
      roles: payload.roles as RoleClaim[],
      ...(typeof payload.sid === "string" && { sid: payload.sid }),
      jti: payload.jti ?? "",
      exp: payload.exp ?? 0,
    };
  }
}
