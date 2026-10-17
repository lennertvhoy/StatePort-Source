# Security policy

## How to report a vulnerability

**Use GitHub private vulnerability reporting on the public source repository:
<https://github.com/lennertvhoy/StatePort-Source/security/advisories/new>.**
The setting was verified as enabled through the GitHub API on 2026-10-17. Reports
submitted there are visible only to the repository maintainers. A GitHub account
is required. No response-time or remediation-time commitment is offered, and no
bug bounty exists; this is an early-alpha project.

Signed alpha artifacts are public. Please:

- do not disclose a suspected vulnerability or exploit details in a public
  issue, pull request, discussion, commit, chat log, or screenshot;
- do not send credentials, browser profiles, conversations, learner content,
  real instances, private paths, or other sensitive evidence, even through the
  private route; send a minimal, redacted reproduction instead; and
- if a local installation may be affected, stop the service, keep it on an
  isolated machine, revoke any exposed credentials through their provider,
  and preserve only redacted diagnostic information.

If the private route is unavailable to you, open a public issue that asks for a
private contact **without** describing the vulnerability, and wait for a reply.

## What a report should contain

Provide only what is needed to reproduce and assess the issue:

- the affected public version or commit;
- a minimal, redacted reproduction;
- the observed impact and affected component;
- relevant operating-system and deployment details; and
- a suggested mitigation, if known.

Do not include live secrets or real user data as proof. The project will
acknowledge, triage, contain, and coordinate disclosure through the private
route when it can. No response-time or remediation-time promise exists unless it
is explicitly published there.

## Supported versions

The current public alpha is **Alpha.24** (`0.1.0-alpha.24`). Every published
alpha (Alpha.15 to Alpha.17 and Alpha.20 to Alpha.24; Alpha.18 and Alpha.19 were
never published) is an evaluation artifact, not a production-qualified version:
the Alpha.24 signed release index marks it a qualification *candidate* and
declares rollback unsupported. Alpha.16 is a superseded predecessor and has a
reproduced fresh-install signature-preflight defect, so the Alpha.16 route is
not usable for a fresh installation. The public Alpha.13 route is defective: its
signed payload identifies Alpha.12 while site pages disagree about the current
version. Its bytes are preserved as evidence; do not use it. Earlier alphas are
kept for history only. Published signed artifacts are immutable.

What was measured on Alpha.24 is a single public one-line install (exit 0 in
474 s) on a local KVM-hosted Windows 11 guest, not bare metal, with the bundled
study sample passing and its data surviving a service restart and a full
`wsl --terminate`. Not measured: Windows reboot survival, uninstall or an
identical reinstall on Windows, ProjectState or a third template on the
installed product, AI provider, chat and coding-agent paths, and resource use.
The qualification target is Windows 11 WSL2 Ubuntu 24.04 AMD64; complete native
evidence remains pending. Publication does not create a support commitment.
The public site is the authoritative statement of what is currently published.

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
