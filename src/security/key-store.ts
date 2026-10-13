import { randomBytes } from "node:crypto";
import { chmod, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type CryptoKey, exportJWK, exportPKCS8, generateKeyPair, importPKCS8, type JWK } from "jose";

export const SIGNING_ALG = "RS256";

interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

/**
 * Holds RSA signing keys. The key with the greatest kid signs new tokens; every key
 * is published in the JWKS so tokens signed by a retiring key keep verifying until
 * they expire. Rotation = add a newer key file, wait for verifier caches (10 min),
 * restart; remove the old file once its last token has expired (≥ access TTL).
 */
export class KeyStore {
  private constructor(private readonly keys: SigningKey[]) {
    if (keys.length === 0) throw new Error("KeyStore needs at least one key");
  }

  static async fromPems(entries: { kid: string; pem: string }[]): Promise<KeyStore> {
    const sorted = [...entries].sort((a, b) => a.kid.localeCompare(b.kid));
    const keys = await Promise.all(
      sorted.map(async ({ kid, pem }) => {
        const privateKey = await importPKCS8(pem, SIGNING_ALG, { extractable: true });
        const { kty, n, e } = await exportJWK(privateKey);
        return { kid, privateKey, publicJwk: { kty, n, e, kid, alg: SIGNING_ALG, use: "sig" } };
      }),
    );
    return new KeyStore(keys);
  }

  get signingKey(): { kid: string; privateKey: CryptoKey } {
    return this.keys[this.keys.length - 1]!;
  }

  /** Public keys only. Safe to serve at /.well-known/jwks.json. */
  jwks(): { keys: JWK[] } {
    return { keys: this.keys.map((k) => k.publicJwk) };
  }
}

/** Sortable key id: date of creation plus randomness, e.g. 20261013-9f2c1a7b. */
export function newKid(now = new Date()): string {
  return `${now.toISOString().slice(0, 10).replaceAll("-", "")}-${randomBytes(4).toString("hex")}`;
}

export async function generatePrivateKeyPem(): Promise<string> {
  const { privateKey } = await generateKeyPair(SIGNING_ALG, { modulusLength: 2048, extractable: true });
  return exportPKCS8(privateKey);
}

/**
 * Loads <kid>.pem files from a directory. If the directory has no keys and
 * `generateIfMissing` is set (development only), creates one so `npm run dev` just works.
 */
export async function loadKeyStore(dir: string, opts: { generateIfMissing: boolean }): Promise<KeyStore> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  let files = (await readdir(dir)).filter((f) => f.endsWith(".pem"));
  if (files.length === 0) {
    if (!opts.generateIfMissing) throw new Error(`No JWT signing keys found in ${dir}`);
    const file = join(dir, `${newKid()}.pem`);
    await writeFile(file, await generatePrivateKeyPem(), { mode: 0o600 });
    await chmod(file, 0o600);
    files = (await readdir(dir)).filter((f) => f.endsWith(".pem"));
  }
  const entries = await Promise.all(
    files.map(async (f) => ({ kid: f.replace(/\.pem$/, ""), pem: await readFile(join(dir, f), "utf8") })),
  );
  return KeyStore.fromPems(entries);
}
