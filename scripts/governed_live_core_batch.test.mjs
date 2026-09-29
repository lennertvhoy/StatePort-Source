/**
 * The refusals, tested without a heavy slot and without running the suite.
 *
 * These are the checks that must hold BEFORE an admission is spent. A run that
 * re-admits a retained root does not fail loudly; it writes over evidence that
 * is the only record of what a previous run actually did, which is how batch3
 * nearly lost a third attempt to a fourth. So the refusals are pinned here, and
 * pinned with teeth measured by mutation rather than asserted.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { Refusal, buildPlan, governedSelection, retainedRoots } from './governed_live_core_batch.mjs'

function scratchBase() {
  const base = mkdtempSync(path.join(tmpdir(), 'governed-batch-plan-'))
  mkdirSync(path.join(base, 'at-run-artifacts-batch1'))
  mkdirSync(path.join(base, 'at-run-artifacts-restart-r7'))
  return base
}

const refuses = async (options, expected) => {
  await assert.rejects(
    () => buildPlan(options),
    (error) => {
      assert.ok(error instanceof Refusal, `expected a Refusal, got ${error}`)
      assert.match(error.message, expected)
      return true
    },
  )
}

test('the selection comes from the version-controlled module, not a literal here', async () => {
  const selection = await governedSelection()
  assert.ok(Array.isArray(selection) && selection.length > 0)
  // Every entry is a full declaration title, which is what makes a rename
  // detectable rather than a silent drop out of the alternation.
  for (const title of selection) {
    assert.equal(typeof title, 'string')
    assert.ok(title.length > 20, 'a selection entry must be a full title, not a fragment')
  }
})

test('it refuses to re-admit a retained root, by pattern', async () => {
  await refuses(
    { rootName: 'at-run-artifacts-batch1', base: scratchBase() },
    /re-admit a retained root/,
  )
  // The refusal is not keyed to a hand-maintained list of known batches: a
  // restart root refuses for the same reason, which is what stops the next batch
  // from being added to a list somebody has to remember to update.
  await refuses(
    { rootName: 'at-run-artifacts-restart-r7', base: scratchBase() },
    /re-admit a retained root/,
  )
})

test('it refuses a HALF-USED root, which is the case the old freshness gate missed', async () => {
  // The recorded freshness gate checks only three outcome filenames and is
  // structurally blind to a half-used root: a spent admission, a trace, and no
  // results.json is exactly the shape batch3 was left in. This is refused by the
  // re-admission rule, because the root matches the prefix -- which is why the
  // separate "pre-existing root" branch was removed as unreachable.
  const base = scratchBase()
  const spent = path.join(base, 'at-run-artifacts-batch9')
  mkdirSync(spent)
  writeFileSync(path.join(spent, 'guard-qualification.json'), '{}')
  writeFileSync(path.join(spent, 'trace.zip'), 'PK')
  await refuses({ rootName: 'at-run-artifacts-batch9', base }, /re-admit a retained root/)
})

test('it refuses a root name that is not a batch root', async () => {
  await refuses({ rootName: '../../etc', base: scratchBase() }, /not a batch root/)
  await refuses({ rootName: 'batch7', base: scratchBase() }, /not a batch root/)
})

test('a fresh root plans, and the argv carries the full selection', async () => {
  const base = scratchBase()
  const plan = await buildPlan({ rootName: 'at-run-artifacts-batch7', base })

  assert.equal(plan.target, path.join(base, 'at-run-artifacts-batch7'))
  const grepIndex = plan.argv.indexOf('--grep')
  assert.ok(grepIndex > 0, 'the plan must carry an explicit grep filter')
  assert.equal(
    plan.argv[grepIndex + 1],
    plan.selection.join('|'),
    'the argv filter must be the version-controlled selection, not a copy of it',
  )
  assert.deepEqual(retainedRoots(base).length, 2, 'refusing a plan must not alter the roots')
})
