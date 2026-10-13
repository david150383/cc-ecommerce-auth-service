import type { Env } from "../config/env.js";
import type { Logger } from "../lib/logger.js";
import type { TokenService } from "../security/token-service.js";
import { DisabledNotifier, HttpNotifier, SmtpDevNotifier, type TransactionalNotifier } from "./notifier.js";

export function createNotifier(env: Env, logger: Logger, tokens: () => TokenService): TransactionalNotifier {
  switch (env.NOTIFICATION_DELIVERY) {
    case "http":
      return new HttpNotifier(env.NOTIFICATION_SERVICE_URL, tokens());
    case "smtp-dev":
      return new SmtpDevNotifier(env.SMTP_HOST, env.SMTP_PORT, env.EMAIL_FROM);
    case "disabled":
      return new DisabledNotifier(logger);
  }
}
