/**
 * The live-core suite must actually COLLECT tests.
 *
 * A committed lint fix once renamed the first parameter of this suite's
 * afterEach hook from `{}` to `_fixtures` to silence `no-empty-pattern`.
 * Playwright parses that first hook argument as a fixture list, so the rename
 * was not cosmetic: it made the file collect ZERO specs. The governed run then
 * recorded stats {"expected":0,"unexpected":0,"flaky":0,"skipped":0} — a
 * vacuously clean sheet that skims exactly like a pass — while the real
 * signature sat unused in the `errors` field. 44 tests had stopped existing
 * and nothing said so.
 *
 * The lint error itself is now fixed by a targeted disable comment above the
 * hook, so `{}` is correct again. The silence is the part that stayed
 * unguarded, and this file is that guard. It uses Playwright's own listing
 * mode so it measures real collection; a textual `test(` count would not, and
 * would be fooled by exactly the rename that caused this.
 *
 * It runs in ordinary routine validation, not only inside a governed
 * admission, so CI and local runs both execute it.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { GOVERNED_SELECTION } from './live-core-governed-selection.mjs'
import { fileURLToPath } from 'node:url'

const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const CONFIG_NAME = 'playwright.live-core.config.ts'
const SPEC_NAME = 'live-core.spec.ts'
const PLAYWRIGHT_CLI = path.join(WEB_ROOT, 'node_modules', '@playwright', 'test', 'cli.js')

/**
 * A FLOOR, not an equality. Measured 44 collected specs at the 2026-09-27 pin
 * (origin/main bb86e87b, spec last touched 1115). A hardcoded exact count
 * would turn every legitimate test addition into a failure and teach
 * reviewers to bump a number instead of reading the suite, so this is
 * deliberately set below the measured count.
 *
 * Its whole job is the partial collapse that a bare "count > 0" cannot see:
 * most of the suite quietly failing to collect while a few stragglers keep
 * the number positive. Raise it when the suite grows. Lower it only with an
 * explained test removal recorded in this comment.
 */
const MINIMUM_COLLECTED_SPECS = 40

/** What `--list` actually returned at the pin the floor was measured at. */
const MEASURED_AT_PIN = 44

/**
 * The grep filter every governed qualification run ACTUALLY passes.
 *
 * CORRECTED. This used to read `-g "Actual pinned ProjectState"`, "verified
 * against the 13 retained run artifacts". Measured, that was wrong twice over:
 * no retained artifact used that filter (batch5 passes `-g` and batch6 passes
 * `--grep`, both with a 13-title alternation), and 13 is the number of
 * DECLARATIONS, not of artifacts, and the root count it was paired with was a
 * point-in-time figure that has already moved twice, so neither number is
 * restated here: "13 artifacts" matched neither the declarations nor the roots.
 * What is enforced is mechanical -- `retainedRoots()` enumerates whatever is on
 * disk at run time, and the batch planner refuses against that -- not a count
 * written into a comment. The guard was
 * therefore checking a filter nobody ran, which is false confidence rather than
 * a check, while the filter that governs every admitted run was unvalidated.
 *
 * The real selection now lives in `live-core-governed-selection.mjs`, recovered
 * from the artifacts' own `config.argv`, and the guard below checks that every
 * one of those declarations is still collectable. The floor above deliberately
 * does not apply to a filtered listing, and this is a SUBSET check rather than an
 * equality so that adding a declaration to the suite cannot break the guard; only
 * a rename or removal of a selected declaration is a failure.
 */
const GOVERNED_FILTER = 'Actual pinned ProjectState'
const GOVERNED_FILTER_ARGS = ['-g', GOVERNED_FILTER]

const LIKELY_CAUSE = [
  `Likely cause: an afterEach/beforeEach hook in ${SPEC_NAME} whose FIRST parameter`,
  'was renamed away from the empty object pattern `{}` — Playwright parses that first',
  'hook argument as a fixture list, and any other binding (a bare name, `_fixtures`,',
  'a rest property, a type annotation) makes the whole file collect ZERO tests.',
  'The fix is `test.afterEach(({}, testInfo) => {` with the eslint-disable comment',
  'above it, never a renamed parameter.',
  'Second likely cause: a throw while the module is being collected, which also',
  'drops every spec in the file.',
].join('\n')

/**
 * Why a FILTERED listing can be empty while the unfiltered one is full. This is
 * the case the unfiltered-only guard could not see: the file can still collect
 * 40+ specs, the floor still passes, and the one spec the governed runs
 * actually execute silently stops existing.
 */
const FILTERED_LIKELY_CAUSE = [
  `Likely cause: the spec matching -g "${GOVERNED_FILTER}" no longer collects, so the`,
  'governed run emits the same vacuous sheet — expected 0 / unexpected 0 /',
  'flaky 0 / skipped 0 — while the UNFILTERED count stays above its floor of',
  `${MINIMUM_COLLECTED_SPECS}. That is exactly the case the unfiltered-only guard`,
  'could not see.',
  'Either the hook/collect-time cause below applies to that spec, or its title no',
  'longer matches the filter the governed runs still pass.',
  LIKELY_CAUSE,
].join('\n')

/** Count specs across the nested suite tree the JSON reporter emits. */
function countSpecs(suites, acc = { specs: 0, files: new Set() }) {
  for (const suite of suites ?? []) {
    for (const spec of suite.specs ?? []) {
      acc.specs += 1
      if (spec.file) acc.files.add(path.basename(spec.file))
    }
    countSpecs(suite.suites, acc)
  }
  return acc
}

/**
 * Collect the live-core suite with Playwright's own listing mode. This never
 * launches a browser, never starts a service and never needs a build: `--list`
 * loads the spec and reports what it collected.
 *
 * `extraArgs` is appended verbatim so a caller can reproduce a governed run's own
 * invocation. Omitted means the plain unfiltered listing, which is exactly what
 * the pre-existing assertions have always measured.
 */
function collectLiveCore(extraArgs = []) {
  assert.ok(
    existsSync(PLAYWRIGHT_CLI),
    `Playwright CLI is absent at ${PLAYWRIGHT_CLI}; the collection guard cannot measure anything.`,
  )
  const result = spawnSync(
    process.execPath,
    [
      PLAYWRIGHT_CLI,
      'test',
      `--config=${CONFIG_NAME}`,
      '--list',
      '--reporter=json',
      ...extraArgs,
    ],
    {
      cwd: WEB_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      timeout: 120_000,
    },
  )
  if (result.error) {
    throw new Error(
      `Could not run Playwright listing for ${SPEC_NAME}: ${result.error.message}\n${LIKELY_CAUSE}`,
    )
  }
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
  let report
  try {
    report = JSON.parse(result.stdout)
  } catch {
    throw new Error(
      `Playwright listing for ${SPEC_NAME} did not emit parseable JSON ` +
        `(exit status ${result.status}). Raw output:\n${output.trim()}\n${LIKELY_CAUSE}`,
    )
  }
  return { report, status: result.status, output }
}

test('the live-core suite collects a non-zero number of specs', () => {
  const { report, status, output } = collectLiveCore()
  const { specs, files } = countSpecs(report.suites)

  assert.ok(
    specs > 0,
    [
      `COLLECTION COLLAPSE: ${SPEC_NAME} collected 0 specs.`,
      `That means this suite is not testing anything, and a run reports`,
      `expected 0 / unexpected 0 / flaky 0 / skipped 0 — which reads like a clean pass.`,
      `Playwright exit status: ${status}`,
      `Playwright errors: ${(report.errors ?? []).length}`,
      (report.errors ?? []).map((e) => (e?.message ?? e?.stack ?? String(e))).join('\n'),
      LIKELY_CAUSE,
    ].join('\n'),
  )

  assert.equal(status, 0, `${SPEC_NAME} must list cleanly.\n${output.trim()}`)
  assert.deepEqual(
    [...files],
    [SPEC_NAME],
    `${SPEC_NAME} listing reported unexpected files: ${[...files].join(', ')}`,
  )
  console.log(`[live-core collection guard] ${SPEC_NAME} collected ${specs} specs`)
})

/**
 * The governed runs are grep-filtered to a single spec, so the unfiltered floor
 * never observes them. A filtered run that collected nothing would still emit
 * the vacuous all-zeros sheet, so it gets its own non-zero check.
 */
test('the governed grep filter still collects a non-zero number of specs', () => {
  const { report, status, output } = collectLiveCore(GOVERNED_FILTER_ARGS)
  const { specs, files } = countSpecs(report.suites)

  assert.ok(
    specs > 0,
    [
      `FILTERED COLLECTION COLLAPSE: -g "${GOVERNED_FILTER}" collected 0 specs from`,
      `${SPEC_NAME}.`,
      'Every governed qualification run passes exactly this filter, so each one',
      'would now report expected 0 / unexpected 0 / flaky 0 / skipped 0 and read',
      'as a clean pass while executing nothing.',
      'The unfiltered count is unaffected and still above its floor, which is why',
      'the unfiltered-only guard could not see this.',
      `Playwright exit status: ${status}`,
      `Playwright errors: ${(report.errors ?? []).length}`,
      (report.errors ?? []).map((e) => (e?.message ?? e?.stack ?? String(e))).join('\n'),
      FILTERED_LIKELY_CAUSE,
    ].join('\n'),
  )

  assert.equal(
    status,
    0,
    `The filtered listing -g "${GOVERNED_FILTER}" must list cleanly.\n${output.trim()}`,
  )
  assert.deepEqual(
    [...files],
    [SPEC_NAME],
    `-g "${GOVERNED_FILTER}" reported unexpected files: ${[...files].join(', ')}`,
  )
  console.log(
    `[live-core collection guard] ${SPEC_NAME} collected ${specs} spec(s) under -g "${GOVERNED_FILTER}"`,
  )
})

test('the live-core suite does not partially collapse below its measured floor', () => {
  const { report } = collectLiveCore()
  const { specs } = countSpecs(report.suites)

  assert.ok(
    specs >= MINIMUM_COLLECTED_SPECS,
    [
      `PARTIAL COLLECTION COLLAPSE: ${SPEC_NAME} collected only ${specs} specs,`,
      `below the floor of ${MINIMUM_COLLECTED_SPECS}.`,
      `This is a floor, not an exact count: ${MEASURED_AT_PIN} were collected at the`,
      `2026-09-27 pin (origin/main bb86e87b), and legitimate additions are expected`,
      `to raise it.`,
      `Specs missing against that measured pin: ${Math.max(0, MEASURED_AT_PIN - specs)}.`,
      LIKELY_CAUSE,
    ].join('\n'),
  )
})

/**
 * Every declaration a governed run selects must still be collectable BY NAME.
 *
 * The floor catches a suite that stops collecting. It cannot catch a single
 * declaration being renamed, and that is the case that matters here: the governed
 * selection is a grep alternation of 13 titles, so a rename drops that
 * declaration out of the alternation, the run collects 12 instead of 13, and
 * nothing fails. The comparison is by full title, and a rename is a failure,
 * which is the only warning that arrives before the evidence quietly narrows.
 */
test('every declaration the governed runs select is still collectable by name', () => {
  const alternation = GOVERNED_SELECTION.join('|')
  const { report, status, output } = collectLiveCore(['-g', alternation])
  const { specs } = countSpecs(report.suites)

  assert.equal(status, 0, `the governed selection must list cleanly.\n${output.trim()}`)

  const collected = new Set()
  const walk = (node) => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child)
      return
    }
    if (!node || typeof node !== 'object') return
    if (typeof node.title === 'string') collected.add(node.title)
    for (const child of node.suites ?? []) walk(child)
    for (const spec of node.specs ?? []) walk(spec)
  }
  for (const suite of report.suites ?? []) walk(suite)

  const missing = GOVERNED_SELECTION.filter((title) => !collected.has(title))
  assert.deepEqual(
    missing,
    [],
    [
      `${missing.length} of the ${GOVERNED_SELECTION.length} declarations a governed run selects no longer collect under that name.`,
      'A rename drops the declaration out of the grep alternation, so the run',
      'measures less than the record claims and nothing else notices.',
      ...missing.map((title) => `  missing: ${title}`),
    ].join('\n'),
  )
  console.log(
    `[live-core collection guard] governed selection collected ${specs} of ${GOVERNED_SELECTION.length}`,
  )
})
