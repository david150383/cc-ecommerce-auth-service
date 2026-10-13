// Writes openapi/openapi.json. CI fails if the committed file is stale.
//   npm run openapi:export
import { mkdir, writeFile } from "node:fs/promises";
import { buildOpenApiDocument } from "../openapi/document.js";

await mkdir("openapi", { recursive: true });
await writeFile("openapi/openapi.json", `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`);
console.log("wrote openapi/openapi.json");
