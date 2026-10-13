// Creates a new RSA signing key in JWT_KEYS_DIR. Because kids sort by date, the new
// key becomes the signing key on next start; older keys stay in the JWKS.
//   npm run keys:generate
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { generatePrivateKeyPem, newKid } from "../security/key-store.js";

const dir = process.env.JWT_KEYS_DIR ?? "./keys";
await mkdir(dir, { recursive: true, mode: 0o700 });
const kid = newKid();
await writeFile(join(dir, `${kid}.pem`), await generatePrivateKeyPem(), { mode: 0o600 });
console.log(`created ${join(dir, `${kid}.pem`)}`);
