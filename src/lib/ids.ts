import { v7 as uuidv7 } from "uuid";

/** Time-ordered UUID (v7): unique, sortable by creation time, index-friendly. */
export const newId = (): string => uuidv7();
