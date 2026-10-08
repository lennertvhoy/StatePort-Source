# Codex subagent configuration

Use `config/agent-routing-policy.yaml` as assignment guidance only. Codex
subagents are manually selected; StatePort does not implement automatic model
routing.

For a bounded task, select one policy role, give it only the local task context
and nearest instructions, and set its access exactly as the role declares.
Scouts, architects, reviewers, and exceptional adjudicators remain read-only.
Write-capable implementers must use an isolated worktree and StatePort's
existing lease/base-SHA controls.

Keep at most four concurrent threads and no more than one subagent nesting
level. Do not use nested delegation to bypass the thread limit. Disable MCP
servers that the task does not need.

After two failed repair loops, or when passing tests leave ownership,
migration, recovery, or compatibility uncertain, stop local repair cycling and
escalate for an appropriate independent review or adjudication. Reserve
`sol-max` for exceptional adjudication.

If Codex exposes a different profile from the assignment, stop assigning new
work long enough to record the routing deviation, then inspect and test the
actual output. Do not discard it or repeat the whole assignment solely to
obtain the intended profile label. Only a controlled benchmark, material
defect, unsafe execution, irrecoverable provenance, or explicit human request
permits a complete rerun. A rerun in the same modified worktree cannot serve as
independent acceptance.

Acceptance review uses a separate read-only reviewer in a clean detached or
isolated read-only worktree. Record the assignment and review outcome in
`docs/operations/routing-deviation-ledger.yaml`; never infer independence from
the reviewer's model name.

Revalidate the policy after changes to available models, pricing, or Codex
configuration:

```bash
python3 scripts/validate_agent_routing_policy.py
python3 scripts/validate_routing_deviation_ledger.py
```

This document does not configure provider authentication, credentials, or
automatic execution.
