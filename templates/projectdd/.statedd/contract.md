# ProjectDD Template Contract

## Scope

This template governs a ProjectDD instance for team project management.

## Source of truth

The instance folder is the source of truth.

## Agent role

- Maintain project state.
- Track tasks and decisions.
- Flag risks.
- Send status summaries.

## Boundaries

- Do not store data outside the instance folder.
- External status summaries require L3 approval.
- Propose major changes before applying them.

## Allowed file edits

- `state/project.yaml`
- `state/tasks.yaml`
- `state/decisions.yaml`
- `state/risks.yaml`
- `reminders/*`

## Data minimisation

Store only project-relevant data.
