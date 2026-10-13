import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

// Adds .openapi(...) to zod schemas so the same schema validates requests AND
// generates the OpenAPI document. Import `z` from here, not from "zod".
extendZodWithOpenApi(z);

export { z };
