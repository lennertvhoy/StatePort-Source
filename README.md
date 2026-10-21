# Decision Log

A StatePort template for keeping a small, honest decision log. Every question the team has to settle gets an entry with a
`decideBy` date. When it is settled, the entry gets a one-line `rationale` and a written record in `decisions/`. A
deterministic check tells you whether the log is up to date, and a model can draft the next record for you to review.

It is a public-safe example of an independent StatePort application: nothing in it depends on ProjectState or StudyState.

## Files

| Path | Purpose |
|---|---|
| `application.yaml` | StatePort application descriptor (`stateport.application/v1`). Names the evaluator, `decision-log.check/v1`. |
| `actions.yaml` | The four actions below. |
| `scripts/decision_actions.py` | Executor for the two check actions. Read-only, Python standard library plus PyYAML, prints one JSON object, always exits 0. |
| `state/DECISIONS.yaml` | The log. Owned by the instance. Seeded with a small example (database backups, meeting cadence, status page). |
| `decisions/<id>.md` | One record per decided entry: context, options considered, decision, rationale, consequences. Owned by the instance. |
| `tests/test_check.py` | pytest suite for the check actions and the descriptors. |

### Entry fields

Required: `id` (also the record file name, so letters, digits, `.`, `_`, `-`), `title`, `status` (`open`, `decided` or
`superseded`) and `created` (`YYYY-MM-DD`). Optional: `decideBy`, `decidedOn`, `reviewOn` (dates), `rationale`, `owner`,
`context`, `needs`, `supersededBy`.

## Actions

1. **`decision-log.check/v1`** (script, changes nothing, no network). The evaluator. It prints
   `{formatVersion, actionId, verdict, summary, findings}` with one of three verdicts:
   - `invalid`: `state/DECISIONS.yaml` is missing or does not parse, or an entry lacks `id`, `title`, a valid `status` or `created`.
   - `not_yet`: an `open` question is older than its `decideBy` date, or a `decided` entry has no `rationale` or no `decisions/<id>.md` record.
   - `passed`: neither of the above.
2. **`decision-log.list-due/v1`** (script, changes nothing, no network). Same output shape. Lists open questions past
   `decideBy` and decided entries whose `reviewOn` date has passed, oldest first. A date is overdue the day after it.
3. **`decision-log.draft-decision/v1`** (agent, propose only, model provider network only). A model takes the oldest open
   question, writes `decisions/<id>.md` with context, at least two options, a recommendation, rationale and consequences, and
   marks the entry `decided` with a `rationale` and `decidedOn`. It may only write `state/DECISIONS.yaml` and `decisions/`.
   If information is missing it keeps the entry `open` and lists what it needs under `needs`. The result is a proposal for
   you to review, and the evaluator is the judge of the outcome.
4. **`decision-log.add-question/v1`** (agent, propose only, model provider network only). You give a question, and
   optionally context, an owner and a decide-by date; a model adds it as one well-formed `open` entry (default decide-by:
   14 days from today) and changes nothing else. It may only write `state/DECISIONS.yaml`.

On the seeded state the check says `not_yet`, because question `0002-meeting-cadence` is past its `decideBy` date. Draft it,
approve it, and the verdict becomes `passed`.

## Run it by hand

```
python3 scripts/decision_actions.py --root . --action check
python3 scripts/decision_actions.py --root . --action list-due
python3 -m pytest tests
```

`--today YYYY-MM-DD` fixes the date (used by the tests). `--fail-on-invalid` makes an `invalid` verdict exit 1; it is what
`validationCommand` uses.

## Importing into StatePort

Import this template by its public HTTPS repository URL and a full 40-character commit, never a branch name. StatePort
reads `application.yaml` and `actions.yaml`, runs the check actions inside its sandbox, and records the commit in the
instance.

## License

MIT. Copyright (c) 2026 StatePort contributors.
