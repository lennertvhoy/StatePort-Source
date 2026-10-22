# Template contract

A StatePort template is a Git repository that declares what it is, what it
evaluates, and what it can do. StatePort imports it as an isolated instance and
never runs repository code on the host: every action runs on a disposable copy
inside a sandbox, and every change becomes one reviewable proposal.

This document is the contract a template author writes against. It is short on
purpose; the machine-checked rules live in
[`stateport_portable_execution.contracts`](../packages/portable-execution/src/stateport_portable_execution/contracts.py)
and in the import review
([`template_adapters.native_capability_review`](../packages/persistent-app/src/stateport_persistent_app/template_adapters.py)).

## Two files

An application template ships two YAML files at its repository root.

### `application.yaml` — the application

```yaml
formatVersion: stateport.application/v1
applicationId: acme.notes              # reverse-DNS-ish, unique per template
displayName: Acme Notes
description: A note-taking application for Acme.
actionsPath: actions.yaml              # where the actions live
executorCommand: scripts/notes.py      # default script executor for the actions
evaluatorAction: acme.notes.check/v1   # optional: the deterministic evaluator
validationCommand: python3 scripts/notes.py --root . --validate
stateLayout:
  ownership:
    notes/: instance                   # a trailing "/" is a PREFIX entry
    vault/: template                   # template-owned: never writable
  protectedPaths:
    scripts/notes.py                   # never writable, by any action
```

| Member | Meaning |
|---|---|
| `evaluatorAction` | Optional. The action id of the template's deterministic check. It runs on the staged base **and** on the candidate, and both verdicts travel with the proposal. |
| `stateLayout.ownership` | Maps a path to its owner: `instance`, `template` or `generated`. A key ending in `/` is a **prefix** entry (`state/: instance` covers everything under `state/`). The **longest** matching entry wins. Only `instance` paths may be written. |
| `stateLayout.protectedPaths` | Paths no action may write, even when the ownership map says `instance`. |
| `validationCommand` | Run after a change is applied, on the staged copy, before the commit is made. Exit `0` means the template is still valid. |

### `actions.yaml` — the actions

```yaml
formatVersion: acme.notes.actions/v1
actions:
  - id: acme.notes.check/v1
    displayName: Check the notes
    purpose: Judge whether the notes are consistent.
    executorKind: script
    mutationPolicy: none
    networkPolicy: disabled
    inputSchema: {type: object, additionalProperties: false}
    outputSchema: {type: object, required: [actionId, verdict, summary, findings]}
    contextPolicy: {id: acme.notes.context/v1, includeCategories: [], excludeCategories: [credentials]}
    requiredCapabilities: [structuredEvents, nonInteractiveExecution]
    timeoutSeconds: 30
    budgetDefaults: {token: 400, costMinor: 0, timeSeconds: 30, steps: 1}

  - id: acme.notes.summarize/v1
    displayName: Summarize the notes
    purpose: Ask a model to summarize the notes and return its work as one proposal.
    executorKind: agent
    actionClass: agent.edit-state
    instructions: |-
      Summarize the open notes in notes/ into notes/SUMMARY.md.
      Do not change anything else.
    mutationPolicy: propose_only
    networkPolicy: model_provider_only
    writablePaths: [notes/]
    inputSchema: {type: object, additionalProperties: false}
    outputSchema: {type: object}
    contextPolicy: {id: acme.notes.agent-context/v1, includeCategories: [], excludeCategories: [credentials]}
    requiredCapabilities: [structuredEvents, nonInteractiveExecution]
    timeoutSeconds: 300
    budgetDefaults: {token: 6000, costMinor: 0, timeSeconds: 300, steps: 1}
```

An action id is `<applicationId>.<name>/v1`.

## The two kinds of action

### `script` — a deterministic check

- `executorKind: script` (the default), `mutationPolicy: none`, `networkPolicy: disabled`.
- The executor is run as `--root <instance> --action <name> --inputs <json>` and
  prints one JSON object on stdout.
- A **check** action prints a closed verdict:

  ```json
  {"verdict": "passed", "summary": "The notes are consistent.", "findings": []}
  ```

  `verdict` is `passed`, `not_yet` or `invalid`. `summary` is one sentence.
  `findings` is a list of short strings. A check action never changes the
  instance; if it does, the run is refused.
- A script action that may change the instance uses `mutationPolicy: propose_only`
  and is still only allowed to *propose*: StatePort computes the change itself
  from the staged copy.

### `agent` — a model works on a copy

- `executorKind: agent`, `mutationPolicy: propose_only`,
  `networkPolicy: model_provider_only`, `actionClass: agent.edit-state`.
- `instructions` is required, at most 4000 characters, and becomes the bound
  objective of the run: it is part of the run specification the owner approves.
- The model runs in StatePort's agent sandbox on a disposable copy of the
  instance. It has read/edit tools and model-provider egress only.
- `writablePaths` is optional and **only narrows**: a path must be
  instance-owned *and* inside `writablePaths`. It can never widen the writable
  set. A trailing `/` is a prefix entry.
- Everything the model changes is turned by StatePort into **one**
  file-change proposal. The model never writes canonical state, and it never
  decides whether its own work is good.

## What the owner sees

1. The owner prepares the action and approves the run specification (the
   objective, the inputs, the model route).
2. The action runs on a copy. The evaluator runs on the base and on the result.
3. StatePort emits **one** proposal: the changed files with their patch, the
   statistics, and both evaluator verdicts.
4. The owner approves the proposal separately. Only then does StatePort write
   the files and make **one** Git commit in the instance, with author
   `StatePort` and a message naming the action, the run and the proposal.
5. If the instance moved on since the proposal was made, the proposal is void
   and nothing is applied.

## Rules that are not negotiable

- The policy vocabularies are closed: an unknown `executorKind`,
  `mutationPolicy`, `networkPolicy`, `toolPolicy` or `actionClass` is refused at
  import, never carried as an opaque string.
- `.git/`, `.stateport/` and `.statedd/` are never writable, whatever the
  template declares. A nested `.git` anywhere is refused outright.
- Owner-owned files (for example the `PROJECT.md` of a ProjectState instance)
  stay owner-owned: a template action may not edit them.
- A template's own executor, its action file and its evaluator are protected
  from every action: no loop may change its own measure.
- The inputs of an action are part of the approved run specification
  (`inputsDigest`), so an approved run cannot be re-pointed at other inputs.
- A template's script executors run in a no-network sandbox on a staged copy.
  When no sandbox is available, they are refused with `sandbox_required`; they
  are never run as host processes.
- Importing an application template shows the operator a **capability review**
  that lists every action with its executor kind, its policies, its timeout,
  its writable paths and the validator. The approval binds that review's
  digest; editing the template afterwards withdraws every reviewed action.

## A minimal example

A template with one check and one agent action needs three files:

```text
application.yaml      # as above
actions.yaml          # as above
scripts/notes.py      # the executor: reads --root/--action/--inputs, prints JSON
```

The executor of a check action is a plain program:

```python
import argparse, json, pathlib

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=pathlib.Path)
parser.add_argument("--action")
parser.add_argument("--inputs", default="{}")
args = parser.parse_args()

notes = sorted((args.root / "notes").glob("*.md"))
print(json.dumps({
    "actionId": "acme.notes.check/v1",
    "verdict": "passed" if notes else "not_yet",
    "summary": f"{len(notes)} notes.",
    "findings": [],
}))
```

## See also

- [ADR-0007](adr/0007-evaluator-loops-and-the-curve.md) — why an application is
  (state, outcome, evaluator, actions, grants).
- [`docs/design/agent-sandbox.md`](design/agent-sandbox.md) — the sandbox an
  agent action runs in.
- [`docs/API_CONTRACT_WEB.md`](API_CONTRACT_WEB.md) — the HTTP shapes of a run
  record and its proposal.
- [`docs/TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md`](TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md) —
  where template sources come from and what may be vendored.
