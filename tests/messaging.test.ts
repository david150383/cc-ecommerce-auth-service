import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { CreateTopicCommand, SNSClient, SubscribeCommand } from "@aws-sdk/client-sns";
import { CreateQueueCommand, GetQueueAttributesCommand, ReceiveMessageCommand, SQSClient } from "@aws-sdk/client-sqs";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { pino } from "pino";
import request from "supertest";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { OutboxRelay } from "../src/messaging/outbox-relay.js";
import { buildTestContext, resetDatabase, STRONG_PASSWORD, testDb } from "./helpers.js";

// Runs against the local AWS emulator (Floci), like the DB tests run against Postgres.
const endpoint = process.env.TEST_AWS_ENDPOINT_URL ?? "http://localhost:4566";
process.env.AWS_ACCESS_KEY_ID ??= "test";
process.env.AWS_SECRET_ACCESS_KEY ??= "test";
const sns = new SNSClient({ region: "us-east-1", endpoint });
const sqs = new SQSClient({ region: "us-east-1", endpoint, useQueueUrlAsEndpoint: false });
const silent = pino({ level: "silent" });

let topicArn: string;
let probeUrl: string;

beforeAll(async () => {
  const id = Date.now().toString(36);
  topicArn = (await sns.send(new CreateTopicCommand({ Name: `test-auth-${id}-events` }))).TopicArn!;
  probeUrl = (await sqs.send(new CreateQueueCommand({ QueueName: `test-auth-${id}-probe` }))).QueueUrl!;
  const { Attributes } = await sqs.send(new GetQueueAttributesCommand({ QueueUrl: probeUrl, AttributeNames: ["QueueArn"] }));
  await sns.send(
    new SubscribeCommand({ TopicArn: topicArn, Protocol: "sqs", Endpoint: Attributes!.QueueArn!, Attributes: { RawMessageDelivery: "true" } }),
  );
});

beforeEach(async () => {
  await resetDatabase();
  await receive(0); // discard leftovers
});

async function receive(waitSeconds = 2) {
  const out: { body: { messageType: string; payload: Record<string, unknown> }; attr?: string }[] = [];
  for (let i = 0; i < 5; i++) {
    const { Messages = [] } = await sqs.send(
      new ReceiveMessageCommand({ QueueUrl: probeUrl, MaxNumberOfMessages: 10, WaitTimeSeconds: i === 0 ? waitSeconds : 1, MessageAttributeNames: ["All"] }),
    );
    if (Messages.length === 0) break;
    out.push(...Messages.map((m) => ({ body: JSON.parse(m.Body!), attr: m.MessageAttributes?.messageType?.StringValue })));
  }
  return out;
}

const register = async (app: Parameters<typeof request>[0], email: string) =>
  request(app).post("/api/v1/auth/register").send({ email, password: STRONG_PASSWORD, fullName: "Relay Test" });

describe("auth outbox relay", () => {
  it("publishes UserRegistered and UserEmailVerified to SNS, schema-valid, once", async () => {
    const ctx = await buildTestContext();
    await register(ctx.app, "relay@example.com");
    await request(ctx.app).post("/api/v1/auth/verify-email").send({ token: ctx.notifier.tokenFromLast("auth.verify-email") });

    const relay = new OutboxRelay(testDb(), sns, topicArn, 1000, silent);
    expect(await relay.publishPending()).toBe(2);
    expect(await relay.publishPending()).toBe(0);

    const received = await receive();
    expect(received.map((m) => [m.body.messageType, m.attr])).toEqual([
      ["UserRegistered", "UserRegistered"],
      ["UserEmailVerified", "UserEmailVerified"],
    ]);
    const schemasDir = join(import.meta.dirname, "..", "events", "schemas");
    const ajv = new Ajv2020({ strict: true, strictTypes: false, allErrors: true });
    addFormats.default(ajv);
    ajv.addVocabulary(["x-producer", "x-consumers", "x-channel", "x-message-kind"]);
    for (const f of readdirSync(schemasDir)) ajv.addSchema(JSON.parse(readFileSync(join(schemasDir, f), "utf8")));
    for (const m of received) {
      const id = `https://schemas.ecommerce.local/auth-service/${m.body.messageType.replace(/(?<!^)([A-Z])/g, "-$1").toLowerCase()}.v1.schema.json`;
      const validate = ajv.getSchema(id)!;
      expect(validate(m.body), JSON.stringify(validate.errors)).toBe(true);
    }
    // Secrets never travel through the queue.
    expect(JSON.stringify(received)).not.toMatch(/token|password|passwordHash/i);
  });

  it("keeps rows when SNS is unreachable and publishes them on a later tick", async () => {
    const ctx = await buildTestContext();
    await register(ctx.app, "retry@example.com");
    const broken = new OutboxRelay(testDb(), new SNSClient({ region: "us-east-1", endpoint: "http://127.0.0.1:1", maxAttempts: 1 }), topicArn, 1000, silent);
    expect(await broken.publishPending()).toBe(0);
    const row = await testDb().outboxMessage.findFirstOrThrow();
    expect(row.publishedAt).toBeNull();
    expect(row.attempts).toBe(1);

    expect(await new OutboxRelay(testDb(), sns, topicArn, 1000, silent).publishPending()).toBe(1);
    expect(await receive()).toHaveLength(1);
  });

  it("two racing relay instances publish each row exactly once (SKIP LOCKED)", async () => {
    const ctx = await buildTestContext();
    for (let i = 0; i < 6; i++) await register(ctx.app, `race${i}@example.com`);
    const a = new OutboxRelay(testDb(), sns, topicArn, 1000, silent, 2);
    const b = new OutboxRelay(testDb(), sns, topicArn, 1000, silent, 2);
    const [x, y] = await Promise.all([a.publishPending(), b.publishPending()]);
    expect(x + y).toBe(6);
    expect(await receive()).toHaveLength(6);
  });
});
