// Generates credentials for a service client.
//   npm run service-client:create -- ecommerce-order-service ecommerce-product-service
// Prints the secret ONCE (give it to the calling service) and the SERVICE_CLIENTS entry
// (give it to the Auth Service). Only the hash is ever stored by Auth.
import { generateToken, hashToken } from "../security/random-token.js";

const [clientId, ...audiences] = process.argv.slice(2);
if (!clientId || audiences.length === 0) {
  console.error("usage: npm run service-client:create -- <clientId> <audience> [<audience>...]");
  process.exit(2);
}
const secret = generateToken();
console.log(`client secret (for ${clientId} only):\n  ${secret}\n`);
console.log("SERVICE_CLIENTS entry (for the Auth Service):");
console.log(`  ${JSON.stringify({ clientId, secretSha256: hashToken(secret), audiences })}`);
