# ClassState Template

> StateSpec template for trainers and education teams.

## Purpose

ClassState helps a trainer manage a class lifecycle from lesson notes to student follow-up.

## Workflow

1. Trainer drops lesson notes into the instance inbox (via Telegram, CLI, or file drop).
2. Runner parses notes and updates class state.
3. Runner produces:
   - student follow-up list
   - weak topics summary
   - reminders for next lesson
   - next-lesson preparation notes
   - weekly review

## State files

- `state/class.yaml` — class metadata, schedule, students
- `state/topics.yaml` — topics covered and mastery levels
- `state/students.yaml` — student list and follow-up status
- `actions/pending/` — proposed actions awaiting approval
- `decisions/` — recorded decisions
- `reminders/` — scheduled reminders
- `evidence/` — lesson notes and supporting evidence

## Allowed actions

- Read/write state files within the instance
- Propose follow-up actions
- Create reminders
- Send summary messages (L3 approval required)

## Demo instance

A skeleton compatibility instance using this template exists in the
engineering repository's private-internal `instances/` area; it is not part
of the public export.

## Status

The lifecycle template and local runner contract are implemented and covered
by repository validation. This template is still a compatibility fixture, not
a separately released canonical ClassState package.
