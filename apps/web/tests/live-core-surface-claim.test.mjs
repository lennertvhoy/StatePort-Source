/**
 * A surface claim must not be able to exceed what the run observed.
 *
 * The defect, in one sentence: the release evidence matrix wrote the whole
 * `approvals` surface as a static literal at the end of one PASSING test, so
 * `status: 'live-tested'` appeared whenever that single test passed — while a
 * second leg exercising the same surface through the `infrastructure_plan` deep
 * link FAILED. `test-results/.last-run.json` said `failed`; the matrix said the
 * surface was live-tested and approved, and the failure appeared nowhere in it.
 *
 * The teeth of the fix are the falsifiability cases at the end. A guard that
 * only proves the happy path would still pass against the original static
 * literal, which is the whole point of the defect: the literal read
 * "live-tested" no matter what happened. So these tests RENAME things — the
 * surface key, a required path, the field carrying the evidence — and require
 * that none of those renames can produce an unjustified `live-tested`.
 *
 * Cheap by construction: the module under test is pure and needs no service, no
 * container and no browser, so this runs in routine validation.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import {
  deriveSurfaces,
  recordSurfaceObservation,
  resetSurfaceObservations,
  setRequiredSurfaceObservationPaths,
  stampRunOutcomeCaveat,
  stampRunOutcome,
  REQUIRED_SURFACE_OBSERVATION_PATHS,
  SURFACE_STATUS_FULLY_TESTED,
  SURFACE_STATUS_NOT_FULLY_TESTED,
  UNDECLARED_SCOPE,
} from './live-core-surface-claim.ts'

const RUN_DECISION = { detail: 'exact run, instance, revision and digest reviewed' }
const INFRA_PLAN = { detail: 'infrastructure_plan approved through its owning endpoint' }

test('a surface missing one required path does NOT report live-tested and names it', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)

  const entry = deriveSurfaces().approvals

  assert.notEqual(
    entry.status,
    SURFACE_STATUS_FULLY_TESTED,
    'one contributed path out of two must not certify the whole surface',
  )
  assert.equal(entry.status, SURFACE_STATUS_NOT_FULLY_TESTED)
  assert.deepEqual(entry.uncoveredPaths, ['infrastructure-plan'])
  assert.deepEqual(entry.coveredPaths, ['run-decision'])
  // The mirrored `index` must not keep the old value alive for a reader that
  // skims the wrong field.
  assert.equal(entry.index, SURFACE_STATUS_NOT_FULLY_TESTED)
})

test('it reaches live-tested only once EVERY required path contributed', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)
  assert.notEqual(deriveSurfaces().approvals.status, SURFACE_STATUS_FULLY_TESTED)

  recordSurfaceObservation('approvals', 'infrastructure-plan', INFRA_PLAN)
  const entry = deriveSurfaces().approvals

  assert.equal(entry.status, SURFACE_STATUS_FULLY_TESTED)
  assert.deepEqual(entry.uncoveredPaths, [])
  assert.deepEqual(entry.coveredPaths, ['infrastructure-plan', 'run-decision'])
  // The evidence itself is carried, not just a status.
  assert.equal(entry.observations['infrastructure-plan'].detail, INFRA_PLAN.detail)
})

test('a failed run stamps a failed runOutcome naming the failing legs', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)
  recordSurfaceObservation('approvals', 'infrastructure-plan', INFRA_PLAN)

  const passed = stampRunOutcome({ failed: false, failedTestTitles: [] })
  assert.equal(passed.status, 'passed')
  assert.deepEqual(passed.failedTestTitles, [])

  const failed = stampRunOutcome({
    failed: true,
    failedTestTitles: [
      'Infrastructure preserves dirty and stopped truth through read-only, exact-approved, grant-covered, and destructive gates',
    ],
  })
  assert.equal(failed.status, 'failed')
  assert.equal(failed.failedTestTitles.length, 1)
  assert.match(failed.failedTestTitles[0], /^Infrastructure preserves dirty/)
  // A failed run must not be able to read as clean even when every path did
  // contribute: a leg that failed after contributing is indistinguishable from
  // one that passed.
  const derived = deriveSurfaces({ runFailed: true })
  assert.notEqual(derived.approvals.status, SURFACE_STATUS_FULLY_TESTED)
  assert.match(derived.approvals.downgradeReason ?? '', /run failed/)
})

test('a declared surface that contributed nothing is visible as uncovered', () => {
  resetSurfaceObservations()
  // No observations at all. The surface is still declared, so it must appear
  // and must not read as covered.
  const derived = deriveSurfaces()
  assert.ok('approvals' in derived)
  assert.equal(derived.approvals.status, SURFACE_STATUS_NOT_FULLY_TESTED)
  assert.deepEqual(derived.approvals.uncoveredPaths, ['infrastructure-plan', 'run-decision'])
})

test('an undeclared surface fails closed and does not report an empty gap', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('receipts', 'whatever-this-leg-did', { detail: 'observed' })

  const entry = deriveSurfaces().receipts

  assert.equal(entry.status, SURFACE_STATUS_NOT_FULLY_TESTED)
  // An empty uncoveredPaths would skim like full coverage, so the missing
  // declaration is named instead.
  assert.deepEqual(entry.uncoveredPaths, [UNDECLARED_SCOPE])
  assert.deepEqual(entry.requiredPaths, [])
})

test('an observation whose evidence field is missing or renamed is rejected, not counted', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)
  // `detial`: the evidence field, misspelled. This is what a rename looks like.
  recordSurfaceObservation('approvals', 'infrastructure-plan', { detial: 'renamed away' })

  const entry = deriveSurfaces().approvals

  assert.notEqual(entry.status, SURFACE_STATUS_FULLY_TESTED)
  assert.deepEqual(entry.uncoveredPaths, ['infrastructure-plan'])
  // The rejection is itself evidence, so it is recorded rather than swallowed.
  assert.deepEqual(entry.rejectedObservationPaths, ['infrastructure-plan'])
})

test('FALSIFIABILITY: renaming a required path cannot restore an unjustified live-tested', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)
  // A contributor "renames" the path it satisfied, so it no longer matches the
  // declared requirement.
  recordSurfaceObservation('approvals', 'infrastructure-plan-v2', INFRA_PLAN)

  const entry = deriveSurfaces().approvals

  assert.notEqual(
    entry.status,
    SURFACE_STATUS_FULLY_TESTED,
    'a renamed path must not satisfy the declared requirement it no longer spells',
  )
  assert.deepEqual(entry.uncoveredPaths, ['infrastructure-plan'])
})

test('FALSIFIABILITY: renaming the surface key cannot restore an unjustified live-tested', () => {
  resetSurfaceObservations()
  // A contributor renames the surface it writes to, so its work lands under a
  // key that is not the declared one.
  recordSurfaceObservation('Approvals', 'run-decision', RUN_DECISION)
  recordSurfaceObservation('Approvals', 'infrastructure-plan', INFRA_PLAN)

  const derived = deriveSurfaces()

  // The declared surface got no contributions, so it cannot be live-tested.
  assert.notEqual(derived.approvals.status, SURFACE_STATUS_FULLY_TESTED)
  assert.deepEqual(derived.approvals.uncoveredPaths, ['infrastructure-plan', 'run-decision'])
  // And the renamed key is reported as its own undeclared surface rather than
  // quietly standing in for the declared one.
  assert.equal(derived.Approvals.status, SURFACE_STATUS_NOT_FULLY_TESTED)
  assert.deepEqual(derived.Approvals.uncoveredPaths, [UNDECLARED_SCOPE])
})

test('FALSIFIABILITY: the batch5 shape — one passing leg, one failing leg — cannot read clean', () => {
  resetSurfaceObservations()
  // Exactly the batch5 situation: the run-decision leg passed and recorded, the
  // infrastructure leg failed before recording anything.
  recordSurfaceObservation('approvals', 'run-decision', {
    detail: 'exact run, instance, revision, and digest reviewed',
    resultingState: 'approved; execution remains separate',
  })
  const titles = [
    'Infrastructure preserves dirty and stopped truth through read-only, exact-approved, grant-covered, and destructive gates',
  ]

  // Coverage is asserted INDEPENDENTLY of the run-failure downgrade, so the
  // downgrade cannot carry this test on its own. A mutant that certifies a
  // surface from one path would still be caught if the downgrade were removed.
  const coverageOnly = deriveSurfaces()
  assert.notEqual(coverageOnly.approvals.status, SURFACE_STATUS_FULLY_TESTED)
  assert.deepEqual(coverageOnly.approvals.uncoveredPaths, ['infrastructure-plan'])

  const matrix = {
    surfaces: deriveSurfaces({ runFailed: true }),
    runOutcome: stampRunOutcome({ failed: true, failedTestTitles: titles }),
  }

  assert.notEqual(matrix.surfaces.approvals.status, SURFACE_STATUS_FULLY_TESTED)
  assert.deepEqual(matrix.surfaces.approvals.uncoveredPaths, ['infrastructure-plan'])
  assert.equal(matrix.runOutcome.status, 'failed')
  assert.deepEqual(matrix.runOutcome.failedTestTitles, titles)
  // The failed leg must be readable straight out of the matrix.
  assert.equal(JSON.stringify(matrix).includes('Infrastructure preserves dirty'), true)
})

/*
 * PORTED PROPERTIES. The prior guard scripts/test_matrix_evidence_truthfulness.py
 * (added 4f7ec3f0) enforced four properties by grepping the spec source for a
 * literal `approvals: {` block. Structural derivation removes that block, so the
 * guard's LOCATOR failed while its INTENT was still live. These tests carry the
 * intent forward against the derived shape, so retiring that guard drops no
 * guarantee:
 *
 *   1. the record names the kinds it does not cover   -> `uncoveredPaths`
 *   2. an uncovered kind carries a REASON, not just a name -> `uncoveredPathReasons`
 *   3. `resultingState` is derived, not a literal    -> PORTED 3 pins the pure
 *      pass-through, and the WIRING test below reads the spec to prove the
 *      interpolation is actually there (an earlier draft of this comment claimed
 *      the collection test covered it. IT DOES NOT: it only counts specs, and
 *      asserting otherwise would be an unverified claim about the truthfulness
 *      of a release field, which is the exact defect class being fixed.)
 *   4. the record is not written before the decision is observed
 *      -> the WIRING test below pins the source order of the call site against
 *      the assertion it reports. It cannot EXECUTE the leg, so this is a
 *      tripwire on ordering, not a proof of runtime order.
 */

test('PORTED 1: an uncovered path is named explicitly', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)

  const { uncoveredPaths } = deriveSurfaces().approvals

  assert.ok(
    uncoveredPaths.includes('infrastructure-plan'),
    'the kind that did not contribute must be named',
  )
})

test('PORTED 2: an uncovered path carries a reason, not just a name', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)

  const entry = deriveSurfaces().approvals

  // A superset, never a subset: an invalid declaration is explained even when
  // its path did contribute.
  assert.ok(
    entry.uncoveredPathReasons.length >= entry.uncoveredPaths.length,
    'every uncovered path must have a reason row',
  )
  assert.deepEqual(
    entry.uncoveredPathReasons.map((row) => row.path).sort(),
    entry.uncoveredPaths.slice().sort(),
  )
  for (const { path, reason } of entry.uncoveredPathReasons) {
    assert.equal(typeof reason, 'string')
    assert.ok(reason.trim().length > 0, `${path} is uncovered with no reason`)
  }
  const infra = entry.uncoveredPathReasons.find(
    (row) => row.path === 'infrastructure-plan',
  )
  assert.ok(infra, 'infrastructure-plan must carry its own reason')
  // A bare name is unactionable. Assert the reason is SUBSTANTIVE, not that it
  // contains any particular word: an earlier draft required the literal
  // `owner-reserved`, which would have kept failing after the owner decides, and
  // turning an honest status into a permanently red test is its own kind of lie.
  assert.ok(
    infra.reason.trim().length >= 40,
    'an uncovered path needs a substantive reason, not a token phrase',
  )
  assert.notEqual(infra.reason.trim(), infra.path, 'a bare name is not a reason')
})

test('PORTED 3: the recorded resultingState is the observed one, not a literal', () => {
  resetSurfaceObservations()
  recordSurfaceObservation('approvals', 'run-decision', {
    detail: 'observed',
    resultingState: 'approved; execution remains separate',
  })

  const entry = deriveSurfaces().approvals

  // The derivation carries the leg's own value through unchanged; it does not
  // substitute a status of its own, so a leg that observed something else
  // cannot be recorded as `approved`.
  assert.equal(
    entry.observations['run-decision'].resultingState,
    'approved; execution remains separate',
  )
})

test('PORTED 2b: a declared path with a blank reason is an invalid declaration', () => {
  // Fail-closed on the reason itself: laundering the text away must not buy
  // coverage, and must not be reported as a bare name either.
  const original = REQUIRED_SURFACE_OBSERVATION_PATHS.approvals
  const tampered = { ...original, 'infrastructure-plan': '   ' }
  try {
    setRequiredSurfaceObservationPaths({ approvals: tampered })
    resetSurfaceObservations()
    recordSurfaceObservation('approvals', 'run-decision', RUN_DECISION)
    recordSurfaceObservation('approvals', 'infrastructure-plan', INFRA_PLAN)

    const entry = deriveSurfaces().approvals

    assert.notEqual(
      entry.status,
      SURFACE_STATUS_FULLY_TESTED,
      'a blank reason must not buy full coverage even with every path covered',
    )
    assert.deepEqual(entry.invalidDeclarationPaths, ['infrastructure-plan'])
    const row = entry.uncoveredPathReasons.find(
      (candidate) => candidate.path === 'infrastructure-plan',
    )
    assert.ok(row, 'an invalid declaration is still reported by path')
    assert.match(row.reason, /invalid declaration/)
  } finally {
    setRequiredSurfaceObservationPaths({ approvals: original })
    resetSurfaceObservations()
  }
})

/*
 * WIRING GUARD. The unit tests above prove the DERIVATION cannot overstate, but
 * they exercise an isolated module: an independent verifier showed that
 * reinstating the batch5 literal `approvals: { status: 'live-tested', ... }`,
 * deleting the `deriveSurfaces` merge in `afterAll` and dropping the imports
 * left every wired check GREEN, because nothing tied the module to the spec.
 * These tests close that gap by reading the spec source.
 *
 * HONEST LIMITS, stated because they are the same defect class this change
 * exists to fix, and a check that overstates itself is what this work removed.
 *
 * A source-text check is a TRIPWIRE, not a proof. It catches deletion, a literal
 * reintroduction, a reordering out of afterAll, a hardcoded status, and a call
 * site moved ahead of the evidence it reports -- all of which were measured. It
 * does NOT catch semantic dead-coding: an independent verifier wrapped the
 * `afterAll` merge in `if (false)` and every wired check stayed green, because
 * the calls are still textually present. Closing that needs execution of the
 * legs, not a better grep.
 *
 * So the three layers are stated separately and not merged into one claim: the
 * DERIVATION cannot overstate (proven structurally, by mutation), the WIRING
 * pins the module to the spec (proven as text, with the dead-code gap named
 * above), and the RUN-TIME product claim still needs a governed live-core run.
 */
/**
 * The text of the call that starts at `at`, from just after its opening paren to
 * its matching close. Brace/paren nesting is respected, so the extracted text is
 * this call's own arguments and cannot include a sibling call that follows.
 */
function balancedCallArgs(source, at) {
  const open = source.indexOf('(', at)
  assert.ok(open > 0, 'the call at the given offset must have an opening paren')
  let depth = 0
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i]
    if (ch === '(') depth += 1
    else if (ch === ')') {
      depth -= 1
      if (depth === 0) return source.slice(open + 1, i)
    }
  }
  throw new Error('unbalanced call: no matching close paren')
}

const SPEC_SOURCE = readFileSync(
  new URL('./live-core.spec.ts', import.meta.url),
  'utf8',
)

test('WIRING: the spec no longer writes a whole-surface approvals literal', () => {
  // The value is deliberately NOT required to be `{`. Independent verification
  // reinstated the batch5 overstatement as `approvals: BATCH5_APPROVALS_LITERAL`
  // -- the literal one identifier away -- and every check stayed green, because
  // this pattern demanded a brace. A leg-written approvals ENTRY is the defect
  // however its value is spelled.
  assert.equal(
    /matrix\.surfaces\s*=\s*\{[^}]*\bapprovals\s*:/s.test(SPEC_SOURCE),
    false,
    'a leg-written matrix.surfaces.approvals entry is the batch5 overstatement, whatever its value is spelled',
  )
  assert.equal(
    /status:\s*'live-tested'[\s\S]{0,400}?notExercisedApprovalKinds/.test(SPEC_SOURCE),
    false,
    'the hand-maintained not-exercised list must not come back',
  )
})

test('WIRING: afterAll merges the derived surfaces and stamps the run outcome', () => {
  // The stamp must be built from the real run outcome, not a literal.
  assert.match(SPEC_SOURCE, /failed:\s*journeyFailed/)
  // The single serialisation of the matrix must come after both, or the outcome
  // never reaches the artifact.
  const serialize = SPEC_SOURCE.indexOf("'matrix.json'")
  assert.ok(serialize > 0, 'the matrix must still be serialised')
  assert.ok(
    SPEC_SOURCE.lastIndexOf('stampRunOutcome(') < serialize,
    'runOutcome must be stamped before the matrix is written',
  )
  // NOTE: the existence check must come first. `lastIndexOf` returns -1 when the
  // call is absent, and -1 is also < serialize, so a deleted merge would have
  // satisfied a bare ordering assertion. That is precisely the mutation this
  // test exists to catch, so it is asserted present explicitly.
  // Anchored INSIDE afterAll, not merely somewhere before the write: a merge left
  // in another scope would still satisfy a bare ordering assertion while the
  // artifact never received it.
  const afterAll = SPEC_SOURCE.indexOf('test.afterAll(')
  assert.ok(afterAll > 0, 'afterAll must exist')
  const deriveAt = SPEC_SOURCE.indexOf('deriveSurfaces(')
  const stampAt = SPEC_SOURCE.indexOf('stampRunOutcome(')
  assert.ok(deriveAt > 0, 'the derived surfaces must actually be merged')
  assert.ok(stampAt > 0, 'the run outcome must actually be stamped')
  assert.ok(
    deriveAt > afterAll && deriveAt < serialize,
    'derived surfaces must be merged inside afterAll, before the write',
  )
  assert.ok(
    stampAt > afterAll && stampAt < serialize,
    'runOutcome must be stamped inside afterAll, before the write',
  )
})

test('WIRING: every surface is run-certified through stampRunOutcomeCaveat in afterAll', () => {
  // Without this the verifier's finding (a) is unprotected: deriveSurfaces
  // downgrades only the approvals surface, and the 20 directly-written surfaces
  // -- 16 of them carrying an unconditioned `status: 'live-tested'` -- would keep
  // reading as certified by a run that failed. A deleted or dead-coded caveat
  // wrapper would leave every other wired check green, which is the exact
  // mutation that made the first version of this guard cosmetic.
  const afterAll = SPEC_SOURCE.indexOf('test.afterAll(')
  const caveatAt = SPEC_SOURCE.indexOf('stampRunOutcomeCaveat(', afterAll)
  const serialize = SPEC_SOURCE.indexOf("'matrix.json'")
  assert.ok(
    caveatAt > afterAll,
    'the run-certification caveat must be applied inside afterAll',
  )
  assert.ok(caveatAt < serialize, 'it must be applied before the matrix is written')
  // It must be given the real run outcome, and it must wrap the MERGED surfaces
  // (derived and directly-written alike), not just the derived entry.
  //
  // The argument text is extracted by BALANCED PARENS, not by a fixed window: a
  // 400-char slice also contains the following stampRunOutcome call, so a
  // hardcoded `{ failed: false }` here still matched a `journeyFailed` further
  // down. That was measured, and it is the same defect class in reverse -- a
  // check that cannot tell which call it is inspecting.
  const caveatArgs = balancedCallArgs(SPEC_SOURCE, caveatAt)
  assert.match(caveatArgs, /failed:\s*journeyFailed/)
  assert.match(caveatArgs, /deriveSurfaces\(/)
  assert.match(caveatArgs, /matrix\.surfaces as Record<string, unknown>/)
  // And the result must be what lands in the artifact.
  assert.match(
    SPEC_SOURCE,
    /matrix\.surfaces = stampRunOutcomeCaveat\(/,
    'matrix.surfaces must be the caveated set, not the raw merge',
  )
  // NEITHER THE CAVEAT NOR THE STAMP MAY BE CONDITIONAL. Independent
  // verification rewrote the caveat as `if (!journeyFailed) matrix.surfaces =
  // stampRunOutcomeCaveat(...)` -- so it would run on a PASSING run and be
  // skipped on a failing one, exactly inverting its contract -- and every check
  // stayed green, because the text of the call is unchanged. A conditional
  // prefix is invisible to any pattern that only looks for the call itself.
  for (const [label, needle] of [
    ['the run-certification caveat', 'matrix.surfaces = stampRunOutcomeCaveat('],
    ['the run outcome stamp', 'matrix.runOutcome = stampRunOutcome('],
  ]) {
    const at = SPEC_SOURCE.indexOf(needle)
    assert.ok(at > 0, `${label} must be present`)
    const lineStart = SPEC_SOURCE.lastIndexOf('\n', at) + 1
    const line = SPEC_SOURCE.slice(lineStart, SPEC_SOURCE.indexOf('\n', at))
    assert.equal(
      /\bif\s*\(|\bfor\s*\(|\bwhile\s*\(|\?/.test(line),
      false,
      `${label} must not be conditional or inlined into a loop -- a prefix like \`if (!journeyFailed) \` inverts its contract invisibly`,
    )
  }
  // SPREAD ORDER IS LOAD-BEARING AND WAS UNGUARDED. Independent verification
  // swapped the two spreads so a leg-written entry landed last, which displaces
  // the derived approval entirely: uncoveredPaths, coveredPaths and
  // invalidDeclarationPaths all vanish and the surface reads `live-tested` with
  // no coverage data at all. That was green across all 22 checks. The claim in
  // the correction journal that "its spread is last so it wins over any
  // leg-written entry" was true of the tree and checked by nothing.
  const caveatArgs2 = balancedCallArgs(SPEC_SOURCE, SPEC_SOURCE.indexOf('stampRunOutcomeCaveat('))
  const existingAt = caveatArgs2.indexOf('...(matrix.surfaces as Record<string, unknown>)')
  const derivedAt = caveatArgs2.indexOf('...deriveSurfaces(')
  assert.ok(existingAt > 0 && derivedAt > 0, 'both spreads must be present in the merge')
  assert.ok(
    derivedAt > existingAt,
    'the DERIVED entry must spread LAST, or a leg-written entry displaces it and the surface reads live-tested with no coverage data',
  )
})

test('WIRING: resultingState is interpolated from the observed decision, not a literal', () => {
  // Restores retired-guard property 3, which the pure unit test could not carry.
  assert.match(SPEC_SOURCE, /resultingState:\s*`\$\{[^}]*result\.status\}/)
  assert.equal(
    /resultingState:\s*'approved; execution remains separate'/.test(SPEC_SOURCE),
    false,
    'the hardcoded literal is the batch5 claim and must not return',
  )
})

test('WIRING: each approvals observation is recorded after its leg observed the decision', () => {
  // Restores retired-guard property 4: the call site must not precede the
  // evidence it reports.
  const approveAssertion = SPEC_SOURCE.indexOf(
    "expect(approvePayload.result).toMatchObject(",
  )
  const runDecision = SPEC_SOURCE.indexOf(
    "recordSurfaceObservation('approvals', 'run-decision'",
  )
  assert.ok(approveAssertion > 0, 'the observed approval assertion must exist')
  assert.ok(runDecision > 0, "the run-decision observation must be recorded")
  assert.ok(
    runDecision > approveAssertion,
    "run-decision must be recorded after the decision is observed, not before",
  )
  // ANCHORED TO THE LEG, NOT TO THE FILE. This used to compare against the
  // FIRST `toContainText(` anywhere in an 8,000-line spec -- an accessibility
  // helper some 3,700 lines above the infrastructure leg. Independent
  // verification moved the infrastructure-plan call site to the top of an
  // unrelated early test and all 22 checks stayed green: the assertion's own
  // message said "after its own evidence is asserted" while it was checking
  // against a helper it never looked at. The same defect I had already fixed
  // once with balanced-paren extraction, left in place here.
  const infraPlan = SPEC_SOURCE.indexOf(
    "recordSurfaceObservation('approvals', 'infrastructure-plan'",
  )
  assert.ok(infraPlan > 0, 'the infrastructure-plan observation must be recorded')
  const infraLegStart = SPEC_SOURCE.lastIndexOf("\ntest('", infraPlan)
  assert.ok(infraLegStart > 0, 'the call site must sit inside a named test')
  const infraLeg = SPEC_SOURCE.slice(infraLegStart, SPEC_SOURCE.indexOf('\n})', infraLegStart))
  assert.ok(
    /Infrastructure preserves dirty and stopped truth/.test(infraLeg),
    'the infrastructure-plan observation must be recorded by the infrastructure leg, not some other test',
  )
  assert.ok(
    infraPlan > infraLeg.indexOf('toContainText('),
    'infrastructure-plan must be recorded after ITS OWN leg asserts its evidence',
  )
})

test('WIRING: the two approvals paths are recorded by two DIFFERENT legs', () => {
  // A single leg that recorded both paths would let one observation generalise
  // into a whole-surface claim, which is the batch5 shape. Close the practical
  // case by pinning each call site to its own enclosing test title.
  const legs = [...SPEC_SOURCE.matchAll(/^test\('([^']+)'/gm)].map((m) => [
    m.index,
    m[1],
  ])
  const legAt = (index) => {
    let owner = null
    for (const [at, title] of legs) {
      if (at > index) break
      owner = title
    }
    return owner
  }
  const runDecision = SPEC_SOURCE.indexOf(
    "recordSurfaceObservation('approvals', 'run-decision'",
  )
  const infraPlan = SPEC_SOURCE.indexOf(
    "recordSurfaceObservation('approvals', 'infrastructure-plan'",
  )
  const a = legAt(runDecision)
  const b = legAt(infraPlan)
  assert.ok(a, 'the run-decision call must sit inside a named leg')
  assert.ok(b, 'the infrastructure-plan call must sit inside a named leg')
  assert.notEqual(
    a,
    b,
    'both approvals paths recorded by one leg would generalise a single observation',
  )
  // Exactly once each: a duplicated call site would hide a second writer.
  for (const path of ['run-decision', 'infrastructure-plan']) {
    const count = SPEC_SOURCE.split(
      `recordSurfaceObservation('approvals', '${path}'`,
    ).length - 1
    assert.equal(count, 1, `the ${path} observation must be recorded exactly once`)
  }
})

test('a failed run refuses to certify ANY surface, including the unconverted ones', () => {
  resetSurfaceObservations()
  // The shape an independent verifier measured: one derived surface plus the
  // directly-written surfaces that still carry an unconditioned live-tested.
  const surfaces = {
    approvals: { status: SURFACE_STATUS_FULLY_TESTED },
    orchestration: { status: SURFACE_STATUS_FULLY_TESTED, detail: 'real HTTP' },
    infrastructure: { status: SURFACE_STATUS_FULLY_TESTED, detail: 'fixture' },
  }

  const failedRun = stampRunOutcomeCaveat(surfaces, { failed: true })

  for (const [name, entry] of Object.entries(failedRun)) {
    assert.equal(
      entry.runCertified,
      false,
      `${name} must not be certified by a run that failed`,
    )
    assert.match(String(entry.runOutcomeCaveat), /FAILED/)
    // The remedy removes the certification; it must not silently invent a
    // coverage verdict for a surface nobody has judged.
    assert.equal(entry.status, SURFACE_STATUS_FULLY_TESTED)
  }
  // A passing run changes nothing.
  const passing = stampRunOutcomeCaveat(surfaces, { failed: false })
  assert.equal(passing.orchestration.runCertified, undefined)
})

/*
 * DRIFT GUARD: the spec's `effectiveActorRole` MIRRORS the fixture's decision
 * about which actor the service is launched as. A mirror is a second copy of a
 * fact, and this one has already drifted once: the pinned version of the repair
 * stated in its comment that `reviewed_issuance` is "a fixture CLI flag, not an
 * environment variable" and that a run without `--authority-proof` is
 * "unaffected by it". Measured, it is `os.environ.get(
 * "STATEPORT_UI_REVIEWED_ISSUANCE")` and it FEEDS `source_authority`. The
 * comment was wrong in both directions while the code it described was right,
 * which is exactly how a mirror rots: the copy is what fails first.
 *
 * So the invariant is pinned against the FIXTURE, not restated. If someone
 * changes which conditions the fixture keys its override on, this fails instead
 * of the assertion quietly checking a configuration that can no longer occur.
 */
const FIXTURE_SOURCE = readFileSync(
  new URL('./live-core-fixture.py', import.meta.url),
  'utf8',
)

test('DRIFT: the spec helper mirrors the conditions the fixture actually keys on', () => {
  // Each of these is a fact about the fixture, asserted against its source, and
  // the spec helper is then required to name the same environment variables.
  assert.match(
    FIXTURE_SOURCE,
    /reviewed_issuance\s*=\s*os\.environ\.get\("STATEPORT_UI_REVIEWED_ISSUANCE"\)/,
    'reviewed_issuance is an ENVIRONMENT variable; a claim that it is a CLI flag is the drift this guard exists to catch',
  )
  assert.match(
    FIXTURE_SOURCE,
    /source_authority\s*=.*STATEPORT_UI_SOURCE_AUTHORITY.*or reviewed_issuance/,
    'reviewed_issuance must reach source_authority',
  )
  // ANCHORED TO THE END OF THE ASSIGNMENT, not merely "contains". Independent
  // verification added a THIRD route -- `or os.environ.get("STATEPORT_UI_REVIEWED_OPERATOR") == "1"`
  // -- and the guard stayed green with the spec helper now wrong, because
  // `.*` is intra-line and the pattern matched the original text as a prefix.
  // The guard's own comment claims it fails when "someone changes which
  // conditions the fixture keys its override on"; that is true for removals and
  // reorderings and was FALSE for additions. This falsified the guard's stated
  // invariant, so the invariant is now the one actually enforced.
  const assignmentLine = (name) => {
    const line = FIXTURE_SOURCE.split('\n').find((l) => l.trimStart().startsWith(name))
    assert.ok(line, `${name} must be assigned in the fixture`)
    return line.trim()
  }
  assert.match(
    assignmentLine('workspace_operator ='),
    /^workspace_operator = os\.environ\.get\("STATEPORT_UI_REAL_WORKSPACES"\) == "1" or source_authority$/,
    'workspace_operator must be reachable through EXACTLY these two routes; a third route leaves the spec helper wrong',
  )
  assert.match(
    assignmentLine('source_authority ='),
    /^source_authority = os\.environ\.get\("STATEPORT_UI_SOURCE_AUTHORITY"\) == "1" or reviewed_issuance$/,
    'source_authority must be reachable through EXACTLY these two routes',
  )
  // The precondition that makes mirroring only two conditions sufficient. If
  // this is ever removed, the two-condition helper becomes wrong for a
  // reachable state and the sufficiency argument in the spec comment dies.
  assert.match(
    FIXTURE_SOURCE,
    /if reviewed_issuance and os\.environ\.get\("STATEPORT_UI_REAL_WORKSPACES"\) != "1":\s*\n\s*raise RuntimeError/,
    'the fixture must refuse reviewed issuance without governed real workspace mode',
  )

  // The helper must name the two mirrored variables, or it is checking a
  // different configuration from the one the fixture launches.
  const start = SPEC_SOURCE.indexOf('function effectiveActorRole(')
  assert.ok(start > 0, 'effectiveActorRole must exist in the spec')
  const body = SPEC_SOURCE.slice(start, SPEC_SOURCE.indexOf('\n}', start))
  for (const name of ['STATEPORT_UI_REAL_WORKSPACES', 'STATEPORT_UI_SOURCE_AUTHORITY']) {
    assert.ok(body.includes(name), `the helper must mirror ${name}`)
  }
  // And it must NOT claim to consult reviewed_issuance, because doing so would
  // be a second, differently-derived route to the same answer.
  assert.equal(
    body.includes('STATEPORT_UI_REVIEWED_ISSUANCE'),
    false,
    'the helper reaches platform_operator through REAL_WORKSPACES/SOURCE_AUTHORITY only; the reviewed_issuance route is covered by the fixture precondition above',
  )
})

test('WIRING: the retention record states what the named evidence actually holds', () => {
  // `retained-durable-root.json` classifies a failed run's durable root as "the
  // evidence" and names a workload ledger. It used to name the path and stop, so
  // a reader had to assume the ledger held something. Measured on the retained
  // roots of two runs (batch5 and batch6) that ledger had ZERO entries in both,
  // so a bare path invited exactly the wrong reading. The record now carries the
  // observed entry count and says so when the ledger is empty.
  // Anchored by the two assignments themselves rather than by a window around
  // the filename: the record is BUILT before it is written, so a search for
  // `workloadLedgerNote` from the filename onwards finds nothing and a slice
  // built on that silently inspected the wrong region.
  assert.match(
    SPEC_SOURCE,
    /workloadLedgerEntries\s*=\s*readdirSync\(/,
    'the record must count what the named ledger holds, not assert that it does',
  )
  assert.match(
    SPEC_SOURCE,
    /the named ledger is EMPTY in this run/,
    'an empty ledger must be stated, because that is the case a reader would otherwise assume away',
  )
  // The count and the write must be in the same record, with the count set
  // first: a record that writes a path and only then measures it is the defect.
  const countAt = SPEC_SOURCE.indexOf('workloadLedgerEntries = readdirSync(')
  const writeAt = SPEC_SOURCE.indexOf("'retained-durable-root.json'")
  assert.ok(countAt > 0 && writeAt > countAt, 'the count must be recorded before the record is written')
  // And the classification must not be left implying workload state was captured.
  assert.match(
    SPEC_SOURCE,
    /a retention decision, not a statement that workload state was captured/,
    'the classification must be qualified so it cannot read as a capture claim',
  )
})
