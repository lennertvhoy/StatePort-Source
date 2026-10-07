/**
 * A surface claim must not be able to exceed what the run actually observed.
 *
 * The defect this makes structurally impossible: `live-core.spec.ts` wrote a
 * whole-surface `matrix.surfaces.approvals` entry at the END of one PASSING test,
 * so `status: 'live-tested'` appeared whenever that single test passed, whether
 * or not the rest of the surface had ever loaded. In batch5 the approvals entry
 * read `live-tested` / `approved; execution remains separate` while a second leg
 * that exercises the same surface through the `infrastructure_plan` deep link
 * FAILED, and `test-results/.last-run.json` said `status: failed`. The run knew
 * it had failed (`journeyFailed`) and never used that knowledge for a claim. A
 * release evidence file that overstates coverage is a truthfulness defect in a
 * release prerequisite, not polish.
 *
 * The shape here is deliberately STRUCTURAL rather than a memorised literal:
 * a surface is fully tested only if every observation path declared for it
 * contributed a valid observation. Renaming a surface key, renaming a path, or
 * renaming the field that carries the evidence can therefore never restore an
 * unjustified `live-tested` -- each of those changes removes a contribution
 * rather than editing a constant. tests/live-core-surface-claim.test.mjs is the
 * falsifiability guard for exactly that, and it runs in routine validation.
 *
 * Pure and side-effect free apart from the in-memory store below, so it can be
 * exercised by a cheap `node --test` without Playwright, a service, or a
 * container. Erasable syntax only (no enums, namespaces or parameter
 * properties) so it can be imported directly under type stripping.
 */

/** An observation a contributing test recorded for one path of one surface. */
export type SurfaceObservation = {
  /** Required. The evidence the leg actually gathered. */
  detail: string
  [key: string]: unknown
}

export type SurfaceEntry = {
  status: string
  index: string
  detail: string
  requiredPaths: string[]
  coveredPaths: string[]
  /** Exactly the required paths that did NOT contribute. Never a memorised list. */
  uncoveredPaths: string[]
  /**
   * Why each path needs explaining, paired by path: the required paths that did
   * NOT contribute, plus any whose declared reason is blank. A reader must never
   * be handed a bare name to interpret. The reason is declared alongside the
   * path, so it is present for every kind by construction and cannot be
   * forgotten when a new kind is added. This list is a SUPERSET of
   * `uncoveredPaths`, never a subset.
   */
  uncoveredPathReasons: Array<{ path: string; reason: string }>
  observations: Record<string, SurfaceObservation>
  rejectedObservationPaths: string[]
  /** Declared paths whose stated reason is blank or missing. Never earns coverage. */
  invalidDeclarationPaths: string[]
  downgradeReason?: string
}

export type RunOutcome = {
  status: string
  failedTestTitles: string[]
  claim: string
}

export const SURFACE_STATUS_FULLY_TESTED = 'live-tested'
export const SURFACE_STATUS_NOT_FULLY_TESTED = 'not-fully-live-tested'

/**
 * The one required path a surface with no declared coverage criterion reports as
 * uncovered. See the fail-closed note in `deriveSurfaces`.
 */
export const UNDECLARED_SCOPE = '<surface scope undeclared: no required observation paths>'

/** Why a surface with no declared coverage criterion reports `UNDECLARED_SCOPE`. */
export const UNDECLARED_SCOPE_REASON =
  'this surface declares no required observation paths, so no coverage criterion exists for it and recording something is not the same as covering everything; declaring the paths is the only way to earn a fully tested status'

/**
 * Substituted for a declared path whose reason is blank. Reported so the
 * invalidity is visible, never so the path can quietly read as explained.
 */
export const INVALID_DECLARATION_REASON =
  'this path is declared as required but carries no reason, so it is an invalid declaration: it cannot earn full coverage and it is not reported as a bare name'

const RUN_FAILED_DOWNGRADE =
  'the run failed, so no surface can be certified as fully live-tested by it'

/**
 * Observation paths every surface must cover before it may claim
 * `live-tested`, each with the reason it is required. Adding a path here makes
 * coverage STRICTER, never looser: a surface that gains a required path
 * immediately reports the new path in `uncoveredPaths` until some leg records
 * it.
 *
 * The value is a path -> reason map rather than a bare path list ON PURPOSE. A
 * list invites a path with no stated reason, and an uncovered path reported as a
 * bare name is unactionable to whoever reads the evidence: it does not say
 * whether the leg failed, was skipped, is owner-reserved, or simply has not been
 * written yet. A declared path with an empty or whitespace-only reason is
 * treated as an INVALID declaration and fails closed, so the reason cannot be
 * laundered away by deleting its text.
 *
 * Only `approvals` is declared, because only the approvals surface has been
 * given a coverage criterion. THE OTHER 20 SURFACE RECORDS ARE STILL WRITTEN
 * DIRECTLY BY THEIR OWN LEGS, and 16 of them still carry an unconditioned
 * `status: 'live-tested'`; converting them is separate work that needs a
 * per-surface judgement about what "covered" means, and guessing that here
 * would be inventing evidence rather than deriving it. This change is
 * therefore SCOPED TO THE APPROVALS SURFACE plus the run-level refusal in
 * `stampRunOutcomeCaveat`, and it does NOT make every surface claim in the
 * matrix derived. Measured by an independent verifier, not assumed.
 */
export const REQUIRED_SURFACE_OBSERVATION_PATHS: Readonly<
  Record<string, Readonly<Record<string, string>>>
> = {
  approvals: {
    'run-decision':
      'the run-decision approvals leg: prepare, deep link to the owning exact-revision run approval, approve, and read the resulting state back',
    'infrastructure-plan':
      'the infrastructure_plan approvals leg, reached by deep link and approved through the exact planDigest. NOT yet exercisable under STATEPORT_UI_REAL_WORKSPACES=1, where the fixture forces the platform_operator actor and service_process.py projects an infrastructure_plan approval only for local-user. That boundary is owner-reserved and is recorded in evidence/one-line-release-001/journal/20260928-owner-decision-infrastructure-plan-approval-visibility.md; the path stays declared so the surface cannot read fully tested while a leg that owns half its gates never reported.',
  },
}

const observations: Record<string, Record<string, SurfaceObservation>> = {}
const rejected: Record<string, string[]> = {}

function noteRejection(surface: string, path: string): void {
  const list = rejected[surface] ?? (rejected[surface] = [])
  if (!list.includes(path)) list.push(path)
}

function isUsableObservation(value: unknown): value is SurfaceObservation {
  if (typeof value !== 'object' || value === null) return false
  const detail = (value as { detail?: unknown }).detail
  // The evidence field is what makes an observation an observation. Requiring
  // it is the teeth against renaming it: a renamed or dropped `detail` makes
  // the observation unusable, so the path stays uncovered instead of quietly
  // counting toward `live-tested`.
  return typeof detail === 'string' && detail.trim().length > 0
}

/**
 * Record what ONE leg observed about ONE path of ONE surface.
 *
 * Deliberately not a whole-surface write: a surface entry is derived from the
 * set of contributions, so a leg can only speak for the path it actually
 * exercised.
 */
export function recordSurfaceObservation(
  surface: string,
  path: string,
  observation: SurfaceObservation,
): void {
  if (typeof surface !== 'string' || surface.trim().length === 0) {
    throw new Error('recordSurfaceObservation: surface must be a non-empty string')
  }
  if (typeof path !== 'string' || path.trim().length === 0) {
    throw new Error(`recordSurfaceObservation: path must be a non-empty string for ${surface}`)
  }
  if (!isUsableObservation(observation)) {
    // Not thrown: a broken observation is evidence about the harness too, and
    // it must be visible in the artifact rather than aborting the run.
    noteRejection(surface, path)
    return
  }
  const forSurface = observations[surface] ?? (observations[surface] = {})
  forSurface[path] = observation
}

export type DeriveOptions = {
  /**
   * The run's real outcome. When the run failed, no entry may read
   * `live-tested`: a leg that never executed, or that failed after its own
   * contribution, cannot be distinguished from one that passed, so a failed run
   * must not be able to read as a clean surface set.
   */
  runFailed?: boolean
}

/**
 * Derive every declared or touched surface from the recorded contributions.
 *
 * FAIL-CLOSED DEFAULT for an undeclared surface: a surface with no declared
 * required paths has no defined coverage criterion, so this reports
 * `not-fully-live-tested` with `uncoveredPaths: [UNDECLARED_SCOPE]`. It does not
 * assume that recording anything is the same as covering everything, and it
 * does not report an empty `uncoveredPaths` either -- an empty list would skim
 * like full coverage. Declaring the paths is therefore the only way to earn
 * `live-tested`, which is the safe direction to be wrong in.
 */
export function deriveSurfaces(options: DeriveOptions = {}): Record<string, SurfaceEntry> {
  const runFailed = options.runFailed === true
  const names = new Set<string>([
    ...Object.keys(REQUIRED_SURFACE_OBSERVATION_PATHS),
    ...Object.keys(observations),
    ...Object.keys(rejected),
  ])
  const derived: Record<string, SurfaceEntry> = {}

  for (const name of [...names].sort()) {
    const recorded = observations[name] ?? {}
    const declaration = REQUIRED_SURFACE_OBSERVATION_PATHS[name]
    const reasons = declaration ?? {}
    const required = Object.keys(reasons).sort()
    const declared = required.length > 0
    // A declared path whose reason is blank or missing is an INVALID
    // declaration. It must not be able to buy full coverage, and it must not be
    // handed on as a bare name either, so it is reported on its own rather than
    // folded into the ordinary uncovered set where its invalidity would hide.
    const invalidDeclarationPaths = declared
      ? required.filter(
          (path) =>
            typeof reasons[path] !== 'string' || reasons[path].trim().length === 0,
        )
      : []

    const coveredPaths = declared
      ? required.filter((path) => recorded[path] !== undefined)
      : Object.keys(recorded).sort()
    const uncoveredPaths = declared
      ? required.filter((path) => recorded[path] === undefined)
      : [UNDECLARED_SCOPE]

    // Every path a reader needs EXPLAINED: the ones that did not contribute,
    // plus the ones whose declaration is invalid. An invalid declaration is
    // reported even when its path DID contribute, because contributing does not
    // excuse a required path from carrying a stated reason.
    const unexplainedPaths = declared
      ? [...new Set([...uncoveredPaths, ...invalidDeclarationPaths])].sort()
      : [UNDECLARED_SCOPE]
    const uncoveredPathReasons = declared
      ? unexplainedPaths.map((path) => ({
          path,
          reason: invalidDeclarationPaths.includes(path)
            ? INVALID_DECLARATION_REASON
            : reasons[path],
        }))
      : [{ path: UNDECLARED_SCOPE, reason: UNDECLARED_SCOPE_REASON }]

    const complete = declared && uncoveredPaths.length === 0 && invalidDeclarationPaths.length === 0
    let status = complete ? SURFACE_STATUS_FULLY_TESTED : SURFACE_STATUS_NOT_FULLY_TESTED
    const entry: SurfaceEntry = {
      status,
      // `index` mirrored the status in the record this replaces; it is derived
      // from the same value so no reader can pick up a stale `live-tested` from
      // it while `status` says otherwise.
      index: status,
      detail: coveredPaths.length
        ? coveredPaths
            .map((path) => `${path}: ${recorded[path].detail}`)
            .join('; ')
        : 'no observation was contributed for this surface',
      requiredPaths: declared ? required : [],
      coveredPaths,
      uncoveredPaths,
      uncoveredPathReasons,
      invalidDeclarationPaths,
      observations: { ...recorded },
      rejectedObservationPaths: (rejected[name] ?? []).slice().sort(),
    }
    if (runFailed) {
      status = SURFACE_STATUS_NOT_FULLY_TESTED
      entry.status = status
      entry.index = status
      entry.downgradeReason = RUN_FAILED_DOWNGRADE
    }
    derived[name] = entry
  }
  return derived
}

/**
 * Stamp the run's REAL outcome at the top level of the matrix.
 *
 * `journeyFailed` was already declared, already set in `beforeAll` and
 * `afterEach`, and consumed only to decide whether to retain the disposable
 * durable root. This carries the same fact into the evidence file itself, so a
 * failed run cannot be read as a clean surface set from the matrix alone.
 */
export function stampRunOutcome(input: {
  failed: boolean
  failedTestTitles: readonly string[]
}): RunOutcome {
  const failed = input.failed === true
  const failedTestTitles = [...input.failedTestTitles]
  return {
    status: failed ? 'failed' : 'passed',
    failedTestTitles,
    claim: failed
      ? 'this run FAILED; surfaces below record only the paths whose legs reached their own success point, and no surface is certified as fully live-tested'
      : 'this run passed; a surface is certified fully live-tested only when every declared required observation path contributed',
  }
}

/**
 * Refuse to certify ANY surface by a run that failed.
 *
 * `deriveSurfaces` downgrades only the surfaces it derives. The other 20 surface
 * records are still written directly by their own legs, each with an
 * unconditioned `status: 'live-tested'`, so a failed run would otherwise leave
 * 16 of them reading `live-tested` while `runOutcome` says the run failed. An
 * independent verifier measured exactly that.
 *
 * This is a deliberately narrow remedy: it does NOT claim those surfaces cover
 * less than they do, and it does not invent a coverage criterion for them --
 * both would be per-surface judgements nobody has made. It only removes the
 * certification, so a reader cannot take a failed run's word for their coverage.
 * Every entry is stamped, converted or not, so a reader never has to know which
 * surfaces are derived.
 */
export function stampRunOutcomeCaveat(
  surfaces: Record<string, unknown>,
  input: { failed: boolean },
): Record<string, unknown> {
  if (input.failed !== true) return surfaces
  const stamped: Record<string, unknown> = {}
  for (const [name, entry] of Object.entries(surfaces)) {
    if (entry === null || typeof entry !== 'object') {
      stamped[name] = entry
      continue
    }
    stamped[name] = {
      ...entry,
      runCertified: false,
      runOutcomeCaveat:
        'this run FAILED, so no surface in this file is certified by it; this entry reports what its own leg reached, not a passing run',
    }
  }
  return stamped
}

/** Clear the in-memory store. Exists so a test file can isolate its cases. */
export function resetSurfaceObservations(): void {
  for (const key of Object.keys(observations)) delete observations[key]
  for (const key of Object.keys(rejected)) delete rejected[key]
}

/**
 * Replace the required-path declaration. TEST SEAM ONLY.
 *
 * It exists so a guard can prove the declaration is load-bearing rather than
 * decorative: a test tampers with a declared reason and shows the derived status
 * changes. There is deliberately no production caller, and the spec under test
 * never invokes it, so a run cannot quietly redeclare its own coverage
 * criterion mid-suite and call the result earned.
 */
export function setRequiredSurfaceObservationPaths(
  declaration: Readonly<Record<string, Readonly<Record<string, string>>>>,
): void {
  for (const key of Object.keys(REQUIRED_SURFACE_OBSERVATION_PATHS)) {
    delete (REQUIRED_SURFACE_OBSERVATION_PATHS as Record<string, unknown>)[key]
  }
  for (const [surface, paths] of Object.entries(declaration)) {
    ;(REQUIRED_SURFACE_OBSERVATION_PATHS as Record<string, unknown>)[surface] = paths
  }
}
