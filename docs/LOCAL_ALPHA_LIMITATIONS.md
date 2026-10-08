# Local-alpha limitations

This page records the user-visible boundary of the StatePort alpha in this
repository. It is **candidate documentation**, not evidence that a public
alpha, package, tag, image, or hosted service has been released.

## Supported evaluation shape

- Linux-first local development and evaluation
- one local user
- loopback network binding
- Python 3.10 or newer for the checkout-based CLI path
- a fresh clone or isolated worktree for write-capable runs
- synthetic or public-safe invented data

The local StudyState quickstart and component checks have been run in project
development environments. Slice A passed its exact-head private remote CI;
that evidence does not transfer to the expanded alpha candidate. Clean-host
installation, a published release artifact, and stranger-run reproduction are
separate gates and are not established by those local results.

## Known product limits

- The canonical StudyState production release remains unresolved. The
  `builtin:studydd-local-alpha` source profile is an exact local-alpha input,
  not a production-eligible canonical release.
- `synthetic-run` is deterministic test execution, not tutor quality, a live
  model, or autonomous production work.
- A narrow opt-in local Codex conversation path exists, but its authentication
  and host behaviour are provider-specific. Pi, OpenCode, direct API, and
  other hosts are not claimed equivalent or generally available.
- The normal local service is single-user and loopback-only. Hosted,
  public-network, multi-user, SSO, billing, and managed-service operation are
  not qualified.
- Terminal, editor, CTO orchestration, runtime controls, and StateBench are
  optional capabilities, not universal application features.
- Linux x86-64 is the current release-program target. macOS, Windows, ARM64,
  and other distributions or architectures have no acceptance claim.
- Backup and governed restore-as-new-instance commands exist. Restore leaves
  the source instance unchanged and cannot undo external side effects. Never
  automatically retry unknown or non-idempotent external work.
- The public alpha user interface and documentation are English-only. There is
  no localization framework or translated support commitment yet.

## Security and privacy limits

- No formal security audit or penetration test has been performed.
- Do not expose a StatePort execution-host server directly to Telegram, a
  browser, or the public internet. Keep managed hosts loopback-only or behind
  the authenticated StatePort API.
- Do not use real secrets, learner data, private instances, or production data
  for alpha evaluation. Durable data and model context are separate concerns;
  context policy must remain explicit and bounded.
- StatePort makes no GDPR, NIS2, CyberFundamentals, legal, or compliance
  certification claim.

## Reporting and support limits

There is no active public bug/support route and no active private
vulnerability-reporting route. Public issue templates present in the source do
not activate intake by themselves.

- For an ordinary failure, use [troubleshooting](TROUBLESHOOTING.md) and keep a
  minimal redacted reproduction for the future support route. Do not publish
  private data.
- For a suspected vulnerability, follow [the security policy](../SECURITY.md).
  Do not disclose sensitive details publicly while no private route exists.
- No supported-version matrix, SLA, paid support, or response-time commitment
  exists. See [SUPPORT.md](../SUPPORT.md).

## Evidence vocabulary

- **Implemented** means code or documentation exists in a named source state.
- **Locally validated** means a named check passed in a recorded local
  environment.
- **Clean-host validated** requires a fresh supported host and the documented
  install journey.
- **Remote-CI accepted**, **released**, **production-qualified**, and
  **human-accepted** are distinct states requiring their own evidence and
  authority.

Do not promote one state into another based on a screenshot, a handoff, a
branch-local pass, or an agent's completion statement.
