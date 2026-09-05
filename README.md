# StatePort

> Run durable, user-owned AI applications while keeping their state
> inspectable and under your control.

StatePort is the local platform behind applications built with StateSpec. The
first application path is **StudyState**: a study workspace whose goals,
progress, evidence, and history live in a durable local repository instead of
only in a chat session. The application is the product people use; lifecycle,
policy, validation, execution-host adapters, and receipts stay behind it.

StatePort has published signed alpha artifacts for **Windows 11, WSL2, Ubuntu
24.04 AMD64**. Publication is not complete-product or native qualification.
The current public Alpha.16 installer has a reproduced predecessor-signature
preflight failure; do not use it for a fresh installation until a corrected
additive successor is qualified. Earlier published artifacts are immutable.
See the [public installation guidance](https://lennertvhoy.github.io/StatePort-Site/)
and [current release status](https://lennertvhoy.github.io/StatePort-Site/releases/).

The source workflow below is a local development/evaluation lane. It is not the
anonymous installed-user journey or evidence of support for native Linux.

- **Public product name:** StatePort
- **Product category:** Stateware
- **Engineering method:** State-Centric Engineering
- **Portable specification:** StateSpec (formerly StateDD) — `StateDD` remains a compatibility identifier
- **First application:** StudyState (canonical release acceptance remains open)

## Try the local StudyState path

Use a fresh clone or an isolated worktree on Linux. The local path needs
Python 3.10 or newer; it does not need root, Compose, cloud resources, a model
provider, or provider credentials.

```bash
# Check first so that two write-capable runs do not share a worktree.
git worktree list

./stateport setup --source-mirror /path/to/StudyState_Template init
./stateport instance create \
  --source-profile builtin:studydd-local-alpha \
  --allow-development-candidate \
  --instance-id studydd-ai103 \
  --name "AI-103 Study" \
  --owner-name "Local Owner" \
  --target-id ai-103
./stateport service start --open
./stateport instance synthetic-run studydd-ai103
./stateport instance backup studydd-ai103
./stateport service stop
./stateport service start --open
```

The compatibility CLI and persisted IDs remain lowercase `studydd` pending a
separately versioned migration. The public application name is StudyState.
`synthetic-run` is deterministic test execution, not tutor quality or
production AI execution.
`--allow-development-candidate` records explicit consent bound to the exact
plan, approval, immutable source, and created directory identity. StatePort
rechecks that receipt before execution and apply; it never promotes the source
to a production release.

The instance repository is canonical. Catalog entries, source caches,
application summaries, runtime files, and run history are disposable
management metadata. For a local Git mirror, run
`./stateport setup --source-mirror /path/to/StudyDD init` or set
`STATEPORT_STUDYDD_MIRROR`; the installed identity records the exact source
commit and digests.

See the [complete local quickstart](docs/LOCAL_ALPHA_QUICKSTART.md),
[service lifecycle](docs/LOCAL_SERVICE.md), and
[troubleshooting guide](docs/TROUBLESHOOTING.md).

## What the alpha proves—and what it does not

Implemented and locally validated foundations include durable StateSpec
instances, source locking and lifecycle checks, a loopback application shell,
the local CLI, deterministic synthetic execution, backups, and governed
control-plane contracts. A narrow opt-in local Codex conversation path also
exists with separate setup and limitations; it is not required for the
quickstart above.

Those results do **not** establish any of the following:

- clean-host installation on a stranger's machine;
- exact-head remote CI acceptance for this expanded alpha candidate (Slice A's
  exact-head private CI passed; that result does not transfer to later slices);
- complete-product or native qualification of the published alpha artifacts;
- production, hosted, multi-user, macOS, ARM64, or Windows outside the stated
  WSL2 qualification target;
- independent security review, penetration testing, or compliance
  certification;
- product-owner, external-user, or stranger acceptance; or
- a canonical, production-eligible StudyState release.

Read [all current alpha limitations](docs/LOCAL_ALPHA_LIMITATIONS.md) before
running the alpha, and do not use real or sensitive data for evaluation. The
service binds to loopback by default; do not expose an execution-host server
directly to a browser, Telegram, or the public internet.

## How it fits together

Each installed application is defined by a trusted declarative StateSpec
template and materialised as a durable, user-owned StateSpec instance.
StatePort checks instance grants, operator policy, runtime support, and actor
permissions before an action reaches an execution host. Candidate results only
become durable state through StatePort-owned validation and receipt paths.

See the [one-page architecture diagram](docs/ARCHITECTURE_OVERVIEW.md) for the
maintainable component map and [the full architecture](docs/ARCHITECTURE.md)
for ownership and trust boundaries. StatePort supports opinionated execution
providers through capability-declaring adapters; it does not claim that Pi,
Codex, OpenCode, direct API, or future hosts behave equivalently.

## Bugs, security, and contributions

There is not yet an activated public bug/support route or a private
vulnerability-reporting route. That absence is a release blocker, not an
invitation to improvise a channel.

- For an ordinary defect, first consult [troubleshooting](docs/TROUBLESHOOTING.md)
  and [support status](SUPPORT.md). Do not place private data in an issue,
  patch, log, or screenshot. Public issue intake is not active yet.
- For a suspected vulnerability, follow [SECURITY.md](SECURITY.md). Do not
  disclose exploit details, credentials, learner data, or private instances in
  a public issue, pull request, discussion, or commit.
- External contribution intake is also closed until the documented agreement
  and verification route exists. [CONTRIBUTING.md](CONTRIBUTING.md) describes
  the bounded starter work and validation expected when intake opens.

## Product and trust documentation

- [Positioning and oversight model](docs/POSITIONING.md)
- [Architecture overview](docs/ARCHITECTURE_OVERVIEW.md)
- [Local-alpha limitations](docs/LOCAL_ALPHA_LIMITATIONS.md)
- [Security policy](SECURITY.md) and [engineering security posture](docs/SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md), [governance](GOVERNANCE.md), and
  [code of conduct](CODE_OF_CONDUCT.md)
- [Licensing scope](LICENSES.md) — AGPL-3.0-or-later for code and StateSpec
  artifacts; CC BY 4.0 for human-readable documentation, subject to the
  stated exclusions
- [Documentation map](docs/DOCUMENTATION_MAP.md)

## Safety and release boundary

StatePort is not a claim of GDPR or NIS2 compliance,
CyberFundamentals certification, legal approval, security assurance, or
production readiness. Design documents describe intended boundaries and
implemented controls only at the evidence level they name. Passing a local
test is not remote validation, release acceptance, or human acceptance.

ClassState (legacy identifier `ClassDD`) remains a historical local
development/demo skeleton, not a released canonical source. Public naming and
compatibility identifiers follow
[`config/terminology-policy.yaml`](config/terminology-policy.yaml).
