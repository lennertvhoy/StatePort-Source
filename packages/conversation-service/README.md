# StatePort conversation service

This package provides one channel-neutral operational conversation shared by
web and Telegram-shaped fixture adapters. It owns StatePort message identity,
ordering, deduplication, channel bindings, delivery planning, echo prevention,
authorization, and a trusted declarative presentation model.

The transcript is explicitly `operational_noncanonical`. A conversation
message cannot mutate application state. A proposed change is represented by a
separate typed proposal digest and still requires the normal StatePort
approval, transaction, validation, and receipt boundary.

## Current boundary

- Web and Telegram are adapters to the same `ConversationThread`.
- Telegram support is deterministic fixture normalization only. There is no
  bot credential, webhook, polling loop, or live delivery client.
- The service stores operational state in memory only. Restart does not
  reconstruct a transcript and no full transcript is retained by default.
- Compression and handoff are versioned policy contracts only. Their execution
  belongs to the context-lifecycle service.
- StatePort-owned UI components render the presentation. Packages cannot inject
  browser code or grant channel access.
- Delivery receipts describe plans and fixture outcomes; they are not evidence
  that an external provider accepted a live message.
