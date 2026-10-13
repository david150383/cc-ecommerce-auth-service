import { newId } from "./ids.js";
import { SERVICE_NAME } from "./logger.js";

// Message envelope; schema in events/schemas/envelope.v1.schema.json.
export interface Envelope<P> {
  messageId: string;
  messageKind: "event" | "command";
  messageType: string;
  messageVersion: number;
  producer: string;
  occurredAt: string;
  correlationId: string;
  causationId: string | null;
  sagaId: string | null;
  idempotencyKey: string | null;
  payload: P;
}

export function buildEvent<P>(args: {
  messageType: string;
  payload: P;
  correlationId: string;
  causationId?: string | null;
  version?: number;
}): Envelope<P> {
  return {
    messageId: newId(),
    messageKind: "event",
    messageType: args.messageType,
    messageVersion: args.version ?? 1,
    producer: SERVICE_NAME,
    occurredAt: new Date().toISOString(),
    correlationId: args.correlationId,
    causationId: args.causationId ?? null,
    sagaId: null,
    idempotencyKey: null,
    payload: args.payload,
  };
}
