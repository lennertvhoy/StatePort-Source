/**
 * The declarations a governed qualification run selects, recovered from the
 * retained artifacts themselves rather than from a launch script that no longer
 * exists. `at-run-artifacts-batch5/results.json` and `-batch6/results.json` both
 * end `config.argv` with a `--grep`/`-g` alternation of exactly these 13 titles,
 * and the verifier confirmed the two artifacts carry the same titles in the same
 * order.
 *
 * WHY THIS IS A FILE AND NOT A COMMENT. The collection guard used to describe the
 * governed filter as `-g "Actual pinned ProjectState"`, verified "against the 13
 * retained run artifacts". Measured, no retained artifact used that filter: the
 * recent governed runs pass a 13-title alternation, and the guard was checking a
 * filter nobody ran, which is false confidence rather than a check. The comment
 * also called the 13 "artifacts" when 13 is the number of DECLARATIONS; there are
 * six artifact roots. Naming the selection here makes it version-controlled, so a
 * rename that silently drops a declaration from the governed set fails loudly
 * instead of quietly reducing what a run measures.
 *
 * Additions are deliberately allowed: this is a subset check, not an equality, so
 * adding a declaration to the suite cannot break the guard. Only a RENAME or a
 * REMOVAL of one of these is a failure, and that is the point.
 *
 * ITS OWN LIMIT, measured rather than assumed: editing THIS LIST also silences
 * the guard, because the list is the source of truth it is checked against. A
 * rename in the spec fails loudly; the same rename plus a matching deletion from
 * this file passes cleanly. That is deliberate -- the alternative is an equality
 * that breaks every time a declaration is added -- and the exposure is that this
 * file's diff is the review surface for a narrowed governed run, so a removal
 * here must be argued in the commit rather than slipped.
 */
export const GOVERNED_SELECTION = [
  "Platform is reachable by keyboard and retains denied provider authority on a narrow screen",
  "Approvals inbox routes a prepared run decision to its owning exact-revision endpoint",
  "Orchestration completes one exact provider-free slice, refuses stale authority, and stops after close",
  "Orchestration shows terminal base drift and requires fresh approval after restart",
  "Infrastructure hides every operation when the deterministic target is unavailable",
  "Infrastructure preserves dirty and stopped truth through read-only, exact-approved, grant-covered, and destructive gates",
  "Application-owned real workspaces use independent capsule authority",
  "Actual pinned ProjectState, StudyState, and generic StateSpec imports seed independent workspaces",
  "Connected capsule overflow Reconnect opens a fresh session on the same target",
  "Operation center cancels an awaiting approval run durably without executing it",
  "Status bar scopes active operations to the current instance and clears after durable cancellation and restart",
  "Provider selection persists an enabled OpenCode provider across an isolated service restart",
  "Reviewed source authority download reaches a real capsule after explicit fixture operator issuance"
]
