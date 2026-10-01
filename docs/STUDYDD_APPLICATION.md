# StudyState application

StatePort creates an empty or public-safe synthetic StudyState instance through
the typed legacy-compatible `studydd.bootstrap/v1` contract supplied by the
StudyState package. Domain field semantics and valid initial document shapes remain in StudyState; StatePort owns
source identity, approval, staging, publication, catalog, and audit boundaries.

An existing private learning state is never adopted in place. It is read-only
input to the typed import plan and transaction.
