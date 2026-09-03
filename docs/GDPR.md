# GDPR Notes

> GDPR-conscious design notes for StatePort.

**This document is not legal advice.** It describes the intended data-protection model and the controls built into the design. Final GDPR compliance must be verified by the customer/controller with appropriate legal advice.

## Controller/processor model

The clean model for a hosted StatePort service is:

| Party | Role | Why |
|-------|------|-----|
| Customer / school / company | Controller | Decides why and how personal data is processed |
| StatePort hosted service | Processor | Processes data on the controller's behalf |
| Cloud/model providers | Subprocessors | Process data under the processor's direction |

For self-hosted deployments, the customer is both controller and processor, with model/cloud providers as subprocessors.

## Personal data categories

Potential personal data in a typical instance:

- User/teacher/trainer identifiers
- Student or client names
- Contact handles (e.g., Telegram usernames)
- Lesson notes, feedback, or progress data
- Audit log metadata (timestamps, actor identifiers)

The exact categories depend on the template and the data the controller inputs. StateSpec templates are designed to minimise required personal data.

## Data minimisation

- Templates ask only for data required by the workflow.
- Default templates avoid collecting sensitive categories unless explicitly needed.
- Input validation rejects obviously unnecessary data.
- Audit logs do not store full sensitive payloads by default.

## Retention

Retention is configurable per instance:

- `instance.yaml` may specify a retention policy.
- Default retention is the shorter of controller need and documented maximum.
- Audit logs have a separate retention setting.
- Backups follow the same retention as the instance or a documented backup policy.

## Export and deletion

StatePort instances are file-based, which simplifies export and deletion:

- **Export:** the entire instance folder can be archived or copied to the controller.
- **Deletion:** the instance folder and associated audit logs can be removed.
- **Per-record deletion:** if supported by the template schema, individual records can be removed without deleting the whole instance.

A future dashboard will provide guided export/delete workflows.

## Subprocessors

Current placeholder subprocessor list for a hosted deployment:

| Provider | Purpose | Region/notes |
|----------|---------|--------------|
| Microsoft Azure | Hosting, storage, logs | Belgium Central or EU region |
| OpenAI / Anthropic / OpenRouter (BYOK) | Model inference | Per customer configuration |
| Telegram | Message wrapper | External channel |

The actual subprocessor list must be maintained in the Data Processing Agreement and updated when providers change.

## Data Processing Agreement checklist

A DPA between StatePort (processor) and the customer (controller) should cover:

- Subject matter and duration of processing
- Nature and purpose of processing
- Types of personal data
- Categories of data subjects
- Controller's instructions and compliance obligations
- Subprocessor list and authorization mechanism
- Security measures
- Confidentiality commitments
- Data subject rights assistance
- Breach notification
- Audit rights
- Return/deletion of data at end of service

## DPIA pre-check

A Data Protection Impact Assessment may be required when templates process:

- Children's data in education contexts
- Health or life-event data (e.g., LifeState-like use cases)
- Large-scale systematic monitoring
- Sensitive data categories under GDPR Article 9

Templates in these domains should include a DPIA prompt in their contract.

## No training on customer data by default

By default, customer data is not used to train foundation models. Model provider terms and customer configuration determine whether any training occurs. This must be documented in the DPA.

## EU/Belgium region deployment

Hosted deployments prefer Azure Belgium Central or another EU region to support EU Data Boundary-conscious architecture. See [`AZURE_DEPLOYMENT.md`](AZURE_DEPLOYMENT.md).
