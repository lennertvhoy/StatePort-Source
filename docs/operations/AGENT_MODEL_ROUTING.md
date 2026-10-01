# Agent model routing policy

`config/agent-routing-policy.yaml` is StatePort's versioned, declarative
guidance for human-directed model and subagent assignment. It is not an
automatic router and does not grant permissions, create agents, or change an
instance lease. Routing identity, cost, and review provenance are backstage
operator controls; they are not part of an application's normal user journey.

Use the cheapest reliable role for the bounded task. Put higher-cost reasoning
in planning and use the implementing roles for bounded execution. Scouts are
read-only. Architects and reviewers are independently assigned and read-only.
Sol Max is reserved for exceptional adjudication, never a default escalation.

The policy limits a work group to four threads and one nesting depth. A write
run still requires its own instance lease and base Git SHA; this policy does
not relax StatePort's one-writer rules.

Escalate after two failed repair loops. Also escalate when tests pass but
ownership, migration, recovery, or compatibility remains unclear. Review this
policy after a model, pricing, or Codex-configuration change.

## Routing deviations

A difference between the intended and actual model profile is provenance and
cost information. It is not evidence that otherwise correct implementation is
invalid. Handle a deviation in this order:

```text
record intended and actual profile
→ inspect the produced commit or diff
→ run focused tests where useful
→ retain valid work
→ repair only reproduced defects
→ obtain independent review before an acceptance claim
```

Record every deviation in
`docs/operations/routing-deviation-ledger.yaml`. The entry includes the
assignment, intended and actual profiles, reason, incremental cost when known,
produced commits/files, test result, review disposition, retained and discarded
work, and corrective configuration action. Unknown historical attribution or
cost remains explicitly unknown.

Do not rerun a complete assignment because of model identity alone. A complete
rerun is allowed only for a controlled benchmark, a material reproduced
defect, unsafe execution, irrecoverable provenance, or an explicit human
request. Preserve the first output and its cost even when one of those reasons
applies.

Independent acceptance requires a separately assigned read-only reviewer in a
clean detached or isolated read-only worktree. That reviewer must not own the
original implementation and must inspect the actual commit or diff. A second
implementer in the same modified worktree is neither an independent review nor
an acceptance rerun.

Validate a proposed change before it is used:

```bash
python3 scripts/validate_agent_routing_policy.py
python3 scripts/validate_routing_deviation_ledger.py
```

Keep assigned context narrow, follow the nearest applicable nested repository
instructions, and disable MCP servers that are irrelevant to the task. Do not
place credentials, provider tokens, or customer context in the policy.
