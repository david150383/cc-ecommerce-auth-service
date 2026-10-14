import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import type { Env } from "../config/env.js";
import type { Db } from "../db/prisma.js";
import type { Logger } from "../lib/logger.js";

interface OutboxRow {
  id: string;
  messageType: string;
  envelope: unknown;
}

export function createSns(env: Env): SNSClient {
  return new SNSClient({ region: env.AWS_REGION, ...(env.AWS_ENDPOINT_URL && { endpoint: env.AWS_ENDPOINT_URL }) });
}

/**
 * Publishes committed outbox rows (UserRegistered, UserEmailVerified) to SNS.
 *  - nothing committed is lost: rows stay until published
 *  - at-least-once: a crash after Publish but before marking re-publishes; consumers dedupe on messageId
 *  - several instances can run: rows are claimed with FOR UPDATE SKIP LOCKED
 * The row locks are held while publishing, so the batch is small and the transaction timeout is
 * set explicitly (Prisma's interactive-transaction default is 5 s).
 */
export class OutboxRelay {
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<void> | undefined;
  private stopped = false;

  constructor(
    private readonly db: Db,
    private readonly sns: SNSClient,
    private readonly topicArn: string,
    private readonly intervalMs: number,
    private readonly logger: Logger,
    private readonly batchSize = 20,
  ) {}

  start(): void {
    const tick = () => {
      if (this.stopped) return;
      this.running = this.publishPending()
        .then(() => undefined)
        .catch((err: unknown) => this.logger.error({ err }, "outbox relay tick failed"))
        .finally(() => {
          if (!this.stopped) this.timer = setTimeout(tick, this.intervalMs);
        });
    };
    tick();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    clearTimeout(this.timer);
    await this.running;
  }

  /** Publishes until the outbox is drained (or a publish fails). Returns how many were published. */
  async publishPending(): Promise<number> {
    let total = 0;
    for (;;) {
      const batch = await this.db.$transaction(
        async (tx) => {
          const rows = await tx.$queryRaw<OutboxRow[]>`
            SELECT id, message_type AS "messageType", envelope FROM outbox
             WHERE published_at IS NULL
             ORDER BY created_at, id
             LIMIT ${this.batchSize}
               FOR UPDATE SKIP LOCKED`;
          let ok = 0;
          for (const row of rows) {
            try {
              await this.sns.send(
                new PublishCommand({
                  TopicArn: this.topicArn,
                  Message: JSON.stringify(row.envelope),
                  MessageAttributes: { messageType: { DataType: "String", StringValue: row.messageType } },
                }),
              );
            } catch (err) {
              await tx.outboxMessage.update({ where: { id: row.id }, data: { attempts: { increment: 1 } } });
              this.logger.warn({ err, messageId: row.id, messageType: row.messageType }, "publish failed; will retry");
              return { ok, more: false };
            }
            await tx.outboxMessage.update({ where: { id: row.id }, data: { publishedAt: new Date(), attempts: { increment: 1 } } });
            ok++;
          }
          return { ok, more: rows.length === this.batchSize };
        },
        { timeout: 30_000 },
      );
      total += batch.ok;
      if (!batch.more) return total;
    }
  }
}
