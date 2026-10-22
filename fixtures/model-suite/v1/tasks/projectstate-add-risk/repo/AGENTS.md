# Lantern Library agent contract

This is a ProjectState repository (fictional, public-safe practice fixture).

- `PROJECT.md` is owned by the project owner. Agents never edit it.
- `STATE.yaml` is the durable project state. Agents may edit it when a task
  asks for it, and must keep it valid YAML with every existing entry intact.
- Change only what the task needs.
