import nodemailer from "nodemailer";
import type { Logger } from "../lib/logger.js";
import type { TokenService } from "../security/token-service.js";

export type TransactionalTemplate = "auth.verify-email" | "auth.password-reset";

export interface TransactionalMessage {
  templateKey: TransactionalTemplate;
  recipient: { userId: string; email: string; fullName: string };
  /** Contains a secret (the link's token). Never log, persist or enqueue it. */
  secretUrl: string;
  idempotencyKey: string;
}

/**
 * Delivery of secret-bearing messages. Deliberately synchronous REST, not a queue:
 * queues are durable and replayable, which is wrong for one-time secrets.
 */
export interface TransactionalNotifier {
  send(message: TransactionalMessage): Promise<void>;
}

/** Production path (Phase 4): the Notification Service's internal endpoint. */
export class HttpNotifier implements TransactionalNotifier {
  constructor(
    private readonly baseUrl: string,
    private readonly tokens: TokenService,
  ) {}

  async send(message: TransactionalMessage): Promise<void> {
    const serviceToken = await this.tokens.issueAccessToken(
      { sub: "ecommerce-auth-service", roles: ["service"] },
      "ecommerce-notification-service",
    );
    const res = await fetch(`${this.baseUrl}/internal/v1/notifications/transactional`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${serviceToken}`,
        "idempotency-key": message.idempotencyKey,
      },
      body: JSON.stringify({
        recipient: message.recipient,
        templateKey: message.templateKey,
        data: { fullName: message.recipient.fullName },
        secretData: { url: message.secretUrl },
      }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) throw new Error(`notification service responded ${res.status}`);
  }
}

const SUBJECTS: Record<TransactionalTemplate, string> = {
  "auth.verify-email": "Verify your email address",
  "auth.password-reset": "Reset your password",
};

/**
 * LOCAL DEVELOPMENT ONLY (refused in production by config validation): sends straight
 * to Mailpit until the Notification Service exists in Phase 4.
 */
export class SmtpDevNotifier implements TransactionalNotifier {
  private readonly transport;

  constructor(
    host: string,
    port: number,
    private readonly from: string,
  ) {
    this.transport = nodemailer.createTransport({ host, port, secure: false });
  }

  async send(message: TransactionalMessage): Promise<void> {
    const action = message.templateKey === "auth.verify-email" ? "verify your email" : "reset your password";
    await this.transport.sendMail({
      from: this.from,
      to: message.recipient.email,
      subject: SUBJECTS[message.templateKey],
      text: `Hi ${message.recipient.fullName},\n\nUse this link to ${action}:\n${message.secretUrl}\n\nIf you did not request this, ignore this email.`,
    });
  }
}

export class DisabledNotifier implements TransactionalNotifier {
  constructor(private readonly logger: Logger) {}

  async send(message: TransactionalMessage): Promise<void> {
    // Log only the template and recipient id: never the URL, which contains the secret.
    this.logger.warn({ templateKey: message.templateKey, userId: message.recipient.userId }, "notification delivery disabled");
  }
}
