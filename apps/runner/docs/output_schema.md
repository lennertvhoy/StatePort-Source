# Runner Output Schema

The `./stateport run-instance <path>` command prints a JSON object with three
top-level keys.

## Fields

- `status` (string): the value of `instance.spec.status`. The runner echoes this
  value; it does not compute its own execution status. When `instance.yaml`
  cannot be loaded, the value is the empty string `""` to indicate the status is
  unknown.
- `logs` (list of strings): ordered, human-readable trace of what the runner did.
- `errors` (list of strings): human-readable failure descriptions. When empty,
  the command exits `0`; otherwise it exits `1`.

## Example — successful run

```json
{
  "status": "active",
  "logs": [
    "runner started",
    "instance loaded: demo-classdd",
    "template loaded: classdd",
    "state files present: state/class.yaml, state/topics.yaml, state/students.yaml"
  ],
  "errors": []
}
```

## Example — missing state file

```json
{
  "status": "active",
  "logs": [
    "runner started",
    "instance loaded: demo-classdd",
    "template loaded: classdd"
  ],
  "errors": [
    "missing required state file: state/topics.yaml"
  ]
}
```

## Future compatibility

SP-002 (Telegram adapter) may require a more structured events array in
addition to or instead of the human `logs` strings. SP-001b keeps the output
minimal and stable.
