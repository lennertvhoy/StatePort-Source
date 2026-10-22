# StatePort governance

## Current model

StatePort uses a benevolent-dictator-for-now model. **Lennert Van Hoyweghen**
is the project owner and final decision maker for product direction, release
authority, contributor intake, security embargoes, and changes to this
governance model.

The model is deliberately explicit while the project is small and not yet
publicly released. It does not claim a foundation, board, or community
governance structure that does not yet exist.

## Maintainers and review

The owner may delegate review or maintenance responsibilities in writing.
Delegation does not transfer final release, security-embargo, trademark, or
licensing authority unless an explicit public record says otherwise.

Reviewers evaluate scope, tests, privacy, security, provenance, and release
claims. A passing automated check is evidence, not unilateral authority to
merge or publish.

## Decisions and RFCs

Material architecture, policy, compatibility, or lifecycle decisions should
be recorded in the repository through an ADR, issue, or RFC once public
intake is available. The record should name the decision, alternatives,
evidence, and implementation boundary.

While publication remains gated, no community decision channel is open. The
current truth documents and release plan remain the authoritative record of
what is implemented, validated, pending, or blocked.

## Releases and security

No person may merge a release branch, change repository visibility, publish
artifacts, deploy production infrastructure, or announce a release merely
because code or tests exist. Those actions require the owner’s explicit
approval after the applicable machine and human acceptance gates.

Security reports and embargo handling follow [SECURITY.md](SECURITY.md).

## Succession and changes

If the owner becomes unavailable, a successor or interim maintainer must be
named in a public repository record before exercising release or licensing
authority. Changes to this document require a dated rationale and must not
retroactively weaken existing contributor, security, or licence commitments.
