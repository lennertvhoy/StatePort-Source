# Data Processing

> Data processing roles, subprocessor list, and DPA checklist for StatePort.

## Roles

In a typical hosted StatePort deployment:

- **Controller:** the customer (school, trainer, company). The controller decides why and how personal data is processed.
- **Processor:** the StatePort hosted service. It processes data on the controller's instructions.
- **Subprocessors:** cloud and model providers that process data under the processor's direction.

For self-hosted deployments, the customer is both controller and processor.

## Personal data categories (example)

The exact data depends on the template. Common categories for ClassState/education use:

- Trainer/teacher identifiers
- Student names or pseudonyms
- Telegram usernames/handles
- Lesson notes and progress data
- Audit metadata (timestamps, actor)

## Subprocessor list (placeholder)

| Provider | Purpose | Region |
|----------|---------|--------|
| Microsoft Azure | Hosting, storage, logs | Belgium Central / EU |
| OpenAI / Anthropic / OpenRouter (BYOK) | Model inference | Per customer config |
| Telegram | Message transport | Global |

This list must be maintained in the signed DPA and updated when providers change.

## Data minimisation

- Templates only request data required by the workflow.
- Default templates avoid sensitive categories.
- Audit logs do not store full payloads by default.
- Pseudonymisation is encouraged where possible.

## Retention and deletion

- Retention is configurable per instance.
- Deletion removes the instance folder and associated audit logs.
- Backup retention is documented separately.
- Controller can request export before deletion.

## DPA checklist

A Data Processing Agreement should cover:

1. Subject matter and duration
2. Nature and purpose of processing
3. Types of personal data
4. Categories of data subjects
5. Controller instructions and compliance obligations
6. Subprocessor authorization and notification
7. Technical and organisational security measures
8. Confidentiality obligations
9. Data subject rights assistance
10. Personal data breach notification
11. Audit and inspection rights
12. Return/deletion of data at end of contract

## BYOK model providers

Customers may bring their own API keys for model providers. In that model:

- The customer contracts directly with the model provider.
- StatePort passes prompts/responses but does not control the model provider's terms.
- The model provider may still be a subprocessor; this must be clear in the DPA.

## No legal advice

This document is a design scaffold, not legal advice. Final data processing terms must be reviewed by legal counsel and signed by both parties.
