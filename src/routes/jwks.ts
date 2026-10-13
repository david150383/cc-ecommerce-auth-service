import { Router } from "express";
import type { KeyStore } from "../security/key-store.js";

export function jwksRouter(keys: KeyStore): Router {
  const router = Router();
  router.get("/.well-known/jwks.json", (_req, res) => {
    // Verifiers cache for 10 minutes; a new key is published ≥ 24h before it signs.
    res.setHeader("Cache-Control", "public, max-age=600");
    res.json(keys.jwks());
  });
  return router;
}
