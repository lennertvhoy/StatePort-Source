# ADR-0004: Sensitive Data Gateway and Secret Broker

**Status:** accepted; headless first-slice foundation implemented, GUI/OS-store/runtime proof open
**Date:** 2026-07-28
**Backlog:** BL-SENSITIVE-DATA-GATEWAY-001

## Context

StatePort already treats the application plane as the owner of policy,
authorization, canonical state, audit and acceptance, while execution hosts
receive bounded context and capabilities. Its execution diagnostics also
deliberately exclude prompts, model output, environment variables,
credentials, command arguments and provider request bodies. That is a useful
data-minimisation baseline, but omission from diagnostics alone does not stop
sensitive material from entering provider context or being exposed through a
tool or process.

Scanning only composer text is not an adequate boundary. Sensitive values can
arrive through attachments, repository files, retrieval, tool results,
terminal output, environment variables, diffs, logs, screenshots, reports,
evidence, project configuration and application processes. Safe-looking user
input can also become unsafe after system context, templates and retrieved
material are assembled.

The product promise must therefore be broader and technically defensible:

> StatePort lets agents work with sanitized context and scoped capabilities
> instead of raw personal data and credentials.

## Decision

### Two related capabilities

StatePort will implement two separable capabilities behind typed adapters:

1. The **Sensitive Data Gateway** detects and controls credentials, private
   keys, connection strings, personal data and project-defined sensitive
   material before it enters agent/model context and when it leaves tools or
   execution.
2. The **Secret Broker** stores secret material outside repositories and
   ordinary application state, then grants narrowly scoped use without placing
   the value in prompts, agent memory, logs or evidence whenever a brokered
   operation is available.

The gateway is part of the complete context and execution boundary, not a
composer utility. It covers ingress, assembled provider context, tool and
process results, evidence and outbound side effects. A separate final scan
runs after context assembly and immediately before the provider adapter
serializes the request. Strict policy fails closed when that scan crashes or
cannot classify the payload safely.

### Capabilities, not credentials

The governing invariant is:

> Agents use brokered capabilities without receiving credentials whenever the
> operation supports it.

A repository may declare a `SecretRequirement`: identifier, display name,
purpose, expected interface, requested capability, scope, optionality,
acquisition guidance, approval policy and preferred delivery. It may never
contain the value, encrypted value material, recovery keys, vault credentials
or reusable capability tokens.

The application plane resolves an approved opaque `SecretReference` inside a
trusted broker operation. The execution plane receives the reference,
capability and scope needed to request the operation, not the secret. The
broker returns a sanitized typed result and metadata-only receipt. A grant is
bound to one run and one operation, short-lived, non-transferable, revocable,
and consumed after use. Failure does not authorize retry; an externally
effectful or non-idempotent operation needs a new explicit authorization.

### Honest delivery modes

Every use declares one of three modes. Product language and evidence must not
collapse their security properties.

| Delivery mode | Exposure | Default |
| --- | --- | --- |
| `brokered_capability` | StatePort performs the authorized operation; the agent does not receive the credential | Yes |
| `restricted_process_injection` | The approved isolated process can access the secret even when the agent does not receive it directly | Conditional |
| `development_environment_injection` | A generic agent-controlled shell or environment can effectively access the value | No; explicit compatibility mode only |

Restricted process injection requires an exact executable or command
template, one-run lifetime, no interactive agent shell, bounded network,
output scanning, no command-line secret and no persistent `.env`. Its UI must
state that code in the process may access and disclose the value.

Development-environment injection is never called agent-blind, invisible or
safe by default. It is a compatibility escape hatch whose effective authority
includes credential access.

### Local detection and redaction

Detection is local and layered:

- deterministic structures and known credential formats;
- entropy combined with credential-related context;
- replaceable, locale-aware local PII recognizers;
- exact matching of values already stored in the local secret store;
- project-declared fields, paths and identifier rules;
- rule-, project-, location- and expiry-scoped user allowlists.

No remote model decides whether candidate text is sensitive. Findings use
`confirmed_sensitive`, `high_confidence`, `possible_sensitive` and
`user_allowlisted`; possible personal information is never represented as
confirmed. Private keys, known credentials, password-bearing URLs and stored
secret matches block by default. Lower-confidence personal information uses
review and redaction according to policy.

Redaction uses stable typed placeholders such as `[PERSON_1]`, `[EMAIL_1]` and
`[SECRET_GITHUB_TOKEN]` so the model can preserve relationships without seeing
the value. The placeholder map remains local, outside model context, and is
kept in trusted memory for short workflows or encrypted and scoped to the
conversation/run when durable continuity is required.

### Secret storage boundary

Secret material and metadata are separate. The initial `SecretStore` uses the
operating-system credential/keyring service; StatePort metadata contains
identity, purpose, scope, capability, lifecycle and access history but no
secret value. The abstraction remains replaceable by an ephemeral-memory
backend and later external-vault adapters. StatePort does not invent custom
cryptography.

Saved values are never returned through the standard API or normally revealed
again. Rotation and replacement are preferred to reveal. Normal backups,
exports, screenshots, diagnostics, bug reports and evidence exclude secret
material. Removing a project does not silently delete a secret shared by other
bindings, while revocation immediately prevents new grants.

### Egress and evidence

The same gateway scans tool responses before model return, terminal and test
output, generated diffs and commits, problem reports, screenshots and evidence
metadata, outbound HTTP-tool payloads and final response text. When a known
secret is detected, the result is withheld or the process is terminated
according to policy before the value crosses the boundary.

Exact-value scanning catches accidental echoes, not deliberate transformation
through encoding, splitting, encryption or inference. Those risks require
network restrictions, approved tools, bounded commands, sandboxing and
capability-level access. The product never claims complete exfiltration
prevention from output scanning alone.

Findings and audit events record identifiers, actor, project, application,
run, detector, category, confidence, source location or offsets, policy and
scanner versions, action, timestamp and outcome. They never record the matched
substring or surrounding sensitive text.

### Typed contracts

The initial contract family is:

- `SensitiveFinding`
- `SensitiveDataPolicy`
- `RedactionDecision`
- `SanitizedContextReceipt`
- `SecretMetadata`
- `SecretRequirement`
- `SecretReference`
- `CapabilityRequest`
- `SecretUseGrant`
- `SecretUseReceipt`

Audit vocabulary includes `sensitive_scan_completed`,
`sensitive_send_blocked`, `finding_redacted`, `finding_allowed_once`,
`secret_created`, `secret_rotated`, `secret_revoked`,
`capability_requested`, `capability_approved`, `capability_denied`,
`secret_resolved_by_broker`, `capability_completed` and
`output_withheld_sensitive`.

### Product sequencing

This decision does not interrupt the current StudyState product journey or the
owner-test convergence checkpoint. `BL-SENSITIVE-DATA-GATEWAY-001` is the next
flagship P1 platform capability after that journey is completed and
agent-validated. The first implementation is a fictional, public-safe GUI
journey with a mock provider and local mock broker, followed by negative scans
for the synthetic values. It uses no real credentials, real connectors or real
Codex execution.

The CTO verdict referred to the StudyState trajectory as
`BL-STUDYSTATE-JOURNEY-001`; the current repository queue names the controlling
work `BL-LOCAL-OWNER-TEST-001`. This ADR preserves the authoritative one-item
queue and records the sequencing relationship without inventing a concurrent
active slice.

## Required first-slice proof

Before this architecture may be described as implemented:

1. The actual GUI blocks a synthetic private key without persisting its value
   in evidence.
2. Prompt, attachment, selected context and final serialized provider payload
   scans are exercised, including fail-closed scanner failure.
3. An email can be reviewed and redacted; a possible personal name is not
   presented as confirmed PII.
4. A synthetic secret is stored through the OS-backed abstraction and the
   ordinary API cannot return it.
5. One exact fictional brokered capability requires human approval and the
   agent/provider sees only an opaque reference.
6. The one-use grant cannot retry silently, and revocation produces a typed
   refusal.
7. Tool output containing the known synthetic value is withheld before model
   return.
8. Browser console and network behavior are inspected through the identified
   runtime, and logs, state, repository, evidence, screenshots, frontend
   storage and test artifacts are negatively searched for the values.
9. Evidence binds exact source, runtime, instance, expected and observed
   results, errors and uncertainty without recording sensitive content.
10. `agent_validated`, human validation and human acceptance remain separate.

## Non-goals

- perfect PII recognition or a legal/compliance certification claim;
- secrecy inside arbitrary agent-controlled shells;
- enterprise DLP, cloud-vault synchronization or multi-user sharing;
- production credential migration, deployment secrets or automatic rotation;
- every provider or connector;
- real credentials in development, tests or evidence;
- real Codex execution in the first proof.

## Consequences

- StatePort owns policy, authorization, sanitized context, capability grants,
  secret metadata, receipts and audit; execution hosts receive only the
  minimum context and authority their declared mode permits.
- The distinctive implementation work is boundary enforcement, typed policy,
  understandable approval/redaction UX and brokered operations. Detection
  rule sets, local recognizers and OS credential storage should be borrowed
  behind replaceable adapters where mature options exist.
- A composer indicator is useful but never represents the whole enforcement
  boundary. The final provider scan and egress controls are mandatory.
- The headless foundation is implemented with focused automated validation. It
  does not complete the required GUI proof, OS credential-store adapter,
  identified-runtime browser inspection, agent validation, release, production
  qualification or human acceptance.
