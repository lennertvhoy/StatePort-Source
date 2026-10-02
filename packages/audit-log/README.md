# audit-log

> Structured audit logging for StatePort.

## Purpose

Records every run and tool call in a structured, redacted format:

- timestamp
- instance id
- actor
- trigger
- files read
- files changed
- tool calls
- approvals requested
- approvals granted/denied
- quota impact
- result
- errors
- validation result

## Redaction

Secrets, full payloads, and personal data are redacted by default.

## Status

Implemented as an append-only, hash-chained JSONL log. Governed API mutation
requests and outcomes record operational metadata only; canonical workflow
state and private fact values are not copied into the audit payload.
# Audit log

Append-only JSONL events with a hash chain and integrity verification. The log
records decisions and operational metadata; it is not a source of workflow
state and does not contain secrets by default.
