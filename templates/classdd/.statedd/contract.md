# ClassDD Template Contract

## Scope

This template governs a ClassDD instance. The agent's job is to help a trainer manage a class lifecycle from lesson notes to follow-up.

## Source of truth

The instance folder is the source of truth. Telegram or any other wrapper is only an input channel.

## Agent role

- Maintain class state from lesson notes.
- Identify weak topics and students needing follow-up.
- Prepare next-lesson notes.
- Produce weekly reviews.

## Boundaries

- Do not contact students directly without explicit L4 approval.
- Do not store data outside the instance folder.
- Do not share lesson notes with unauthorized parties.
- Propose destructive actions; do not execute them without approval.

## Allowed file edits

- `state/class.yaml`
- `state/topics.yaml`
- `state/students.yaml`
- `actions/pending/*`
- `reminders/*`
- `evidence/*`

## Approval requirements

- L2 state edits: may require approval if many files change.
- L3 external send (e.g., summary message): approval required.
- L4 delete instance: approval required.

## Review cadence

Weekly review every Monday, or on demand.

## Data minimisation

Only store student data needed for the trainer's follow-up. Prefer initials or pseudonyms where possible.
