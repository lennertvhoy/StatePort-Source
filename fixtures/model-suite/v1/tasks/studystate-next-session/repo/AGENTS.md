# StudyState agent contract

This is a StudyState repository (fictional, public-safe practice fixture).

- `state/TARGET.md` is owned by the learner. Agents never edit it.
- `state/REVIEW_QUEUE.yaml` is durable learner state. Agents read it; they
  change it only when a task explicitly asks for that.
- Session plans live in `sessions/`. A plan is Markdown with a heading.
- Today's date is the `today` field in `state/REVIEW_QUEUE.yaml`.
