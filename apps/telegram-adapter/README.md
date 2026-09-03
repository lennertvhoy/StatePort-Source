# StatePort Telegram adapter

> Optional channel adapter for the shared StatePort conversation service.

## Purpose

Telegram is not a separate memory or application-state store. It maps external
message identity into the same logical `ConversationThread` used by the web
messenger. Canonical application changes still require typed proposals,
approval, a governed transaction, validation, and a receipt.

## Data flow

```
Telegram fixture -> normalized MessageEnvelope -> ConversationThread -> governed action/proposal -> DeliveryReceipt
```

## Responsibilities

- Normalize provider identity, retries, replies, and attachment metadata.
- Deduplicate retries before a message can create work.
- Suppress StatePort outbound echoes.
- Preserve one conversation identity across channel bindings.
- Never treat a Telegram transcript as canonical durable state.

## Implemented status

The adapter now provides a restart-safe long-polling boundary in
`apps/telegram-adapter/src/stateport_telegram_adapter` in addition to the
credential-free fixture normalizer in `packages/conversation-service`:

- exact operator approval is required before a live transport can be built;
- credential entry uses a non-echoing prompt and keeps the value in memory;
- chat and sender identities are keyed digests bound to one authorized
  `ChannelBinding`; raw identities never enter cursor files or errors;
- provider updates are bounded and normalized before they reach an injected
  StatePort conversation sink;
- the polling cursor advances atomically and monotonically only after the sink
  acknowledges an accepted, duplicate, suppressed, or safely ignored update;
- a per-route lease prevents concurrent pollers, and transient retries have a
  finite budget with cooperative cancellation;
- the Bot API transport supports polling and separately approved sends, but is
  never constructed or started implicitly.

Long polling is the selected pilot transport. Webhook registration and a
public webhook listener are deliberately absent: Telegram must never connect
directly to an execution host, and any future webhook must terminate at the
authenticated StatePort API boundary.

## Security

- Provider credentials must never enter fixtures, logs, receipts, or browser payloads.
- The adapter cannot bypass approval gates.
- Channel binding is authorized against the selected application and instance.
- Full transcript persistence is disabled by default.

## Secure credential gate

Only after an operator has approved the exact binding and polling scope, a
launcher may invoke:

```text
python3 -m stateport_telegram_adapter \
  --approval-reference <approved-reference> \
  --binding-reference <approved-binding> \
  --chat-identity-digest <digest-from-approved-binding>
```

with `apps/telegram-adapter/src` and `packages/conversation-service/src` on
`PYTHONPATH`. The prompt does not echo. This gate validates the credential in
memory and exits; it does not start a bot or persist a secret.

## Status

All transport, binding, cursor, deduplication, retry, cancellation, ordering,
mirroring, and redaction contracts are deterministic and machine-testable.
No live Telegram authentication or external message has been attempted. A live
pilot remains explicitly approval- and credential-gated.
