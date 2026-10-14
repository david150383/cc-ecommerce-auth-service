# Auth Service: messages

Schemas: [`events/schemas/`](../events/schemas). Examples: [`events/examples/`](../events/examples).
The envelope is described in `ecommerce-infrastructure/docs/architecture/conventions.md`.

## Produced events (owned here)

| Event | Channel | Consumers | When | Idempotency |
|---|---|---|---|---|
| `UserRegistered` v1 | SNS `auth-events` | Notification (welcome email, recipient directory) | After the user row commits | Consumers dedupe on `messageId` |
| `UserEmailVerified` v1 | SNS `auth-events` | Notification | After the verification token is consumed | Consumers dedupe on `messageId` |

Published through a transactional outbox: the row is written in the same transaction as the user change,
and the relay (`src/messaging/outbox-relay.ts`, enabled by `MESSAGING_ENABLED`) publishes committed rows to
`EVENTS_TOPIC_ARN` with the `messageType` attribute. Rows are claimed `FOR UPDATE SKIP LOCKED`, so several
instances can relay; a failed publish leaves the row for the next tick (at-least-once). Tested against Floci:
schema-valid output, retry after an SNS outage, two racing relays publishing each row once.

## Deliberately NOT events

| Data | Why not | Instead |
|---|---|---|
| Password-reset link | Contains a secret; queues are durable, replayable and visible to operators | `POST {NOTIFICATION_SERVICE_URL}/internal/v1/notifications/transactional` with a service token |
| Email-verification link | Same | Same |
| Login events | High volume, sensitive, and no consumer needs them | `auth_audit_log` table |

## Consumed

None.
