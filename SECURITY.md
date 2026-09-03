# Security policy

## Reporting status

**No private vulnerability-reporting route is active yet.** StatePort is not
publicly released, and no supported version or response-time commitment has
been published. Activating a verified private route is a release blocker.

Until that route exists:

- do not disclose a suspected vulnerability or exploit details in a public
  issue, pull request, discussion, commit, chat log, or screenshot;
- do not send credentials, browser profiles, conversations, learner content,
  real instances, private paths, or other sensitive evidence through an
  improvised channel; and
- if a local installation may be affected, stop the service, keep it on an
  isolated machine, revoke any exposed credentials through their provider,
  and preserve only redacted diagnostic information.

This is an acknowledged reporting gap, not a request to stay silent after a
route is activated. The root README and this file will name the route directly
when the project owner verifies and activates one.

## What a future report should contain

Once the private route is active, provide only what is needed to reproduce and
assess the issue:

- the affected public version or commit;
- a minimal, redacted reproduction;
- the observed impact and affected component;
- relevant operating-system and deployment details; and
- a suggested mitigation, if known.

Do not include live secrets or real user data as proof. The project will
acknowledge, triage, contain, and coordinate disclosure through the activated
private route. No response-time or remediation-time promise exists unless it
is explicitly published there.

## Supported versions

No public version is supported yet. A supported-version table will be added
with the first public release; source availability or a passing local check
does not create a support commitment.

## Current engineering posture

This policy governs disclosure and public handling. The current controls,
assumptions, and known gaps are documented in the
[engineering security posture](docs/SECURITY.md),
[threat model](docs/THREAT_MODEL.md), and
[local-alpha limitations](docs/LOCAL_ALPHA_LIMITATIONS.md).

The local alpha is Linux-first, loopback-only, and single-user. It has not
received a formal security audit or penetration test and is not qualified for
production, hosted, multi-user, or public-network use. These documents are not
a security certification, legal opinion, or compliance claim.
