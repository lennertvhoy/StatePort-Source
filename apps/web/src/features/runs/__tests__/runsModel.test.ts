import { describe, expect, it } from 'vitest'

import type { ExecutionEngine, GovernedAction, RunRecord, RunStatus } from '@/client'

import {
  canRequestRunEvidence,
  defaultEngineFor,
  parseSchemaInputs,
  runControls,
  safeEvidenceValue,
} from '../runsModel'

function run(status: RunStatus): RunRecord {
  return {
    id: 'run_1',
    instanceId: 'ins_1',
    actionId: 'act_1',
    engineId: 'engine_1',
    state: status === 'state_change_approved' ? 'approved' : 'awaiting_approval',
    status,
    revision: 2,
    inputs: {},
    createdAt: '2026-07-18T10:00:00Z',
    updatedAt: '2026-07-18T10:00:00Z',
  }
}

describe('exact run controls', () => {
  it('distinguishes run approval from proposal approval despite the same coarse state', () => {
    expect(runControls(run('approved'))).toMatchObject({ execute: true, apply: false })
    expect(runControls(run('state_change_approved'))).toMatchObject({ execute: false, apply: true })
  })

  it('does not authorize any transition when exact status is absent', () => {
    const legacy = { ...run('approved'), status: undefined }
    expect(runControls(legacy)).toEqual({
      approve: false,
      execute: false,
      proposalReview: false,
      apply: false,
      cancel: false,
    })
  })

  it('offers evidence only after an evidence-bearing execution status', () => {
    expect(canRequestRunEvidence(run('awaiting_approval'))).toBe(false)
    expect(canRequestRunEvidence(run('approved'))).toBe(false)
    expect(canRequestRunEvidence(run('result_validating'))).toBe(false)
    expect(canRequestRunEvidence({ ...run('result_validating'), lifecycleState: 'RUNNING' })).toBe(false)
    expect(canRequestRunEvidence({ ...run('result_validating'), lifecycleState: 'CLOSED' })).toBe(true)
    expect(canRequestRunEvidence(run('state_change_proposed'))).toBe(true)
    expect(canRequestRunEvidence(run('applied'))).toBe(true)
  })
})

describe('declared inputs and engines', () => {
  it('parses declared primitive and structured fields without accepting missing required input', () => {
    const schema = {
      type: 'object',
      properties: {
        label: { type: 'string', title: 'Label' },
        count: { type: 'integer' },
        enabled: { type: 'boolean' },
        detail: { type: 'object' },
      },
      required: ['label', 'count'],
    }
    expect(parseSchemaInputs(schema, { label: '', count: '2', enabled: true, detail: '{}' })).toEqual({
      ok: false,
      field: 'label',
      error: 'Label is required.',
    })
    expect(parseSchemaInputs(schema, { label: 'sample', count: '2', enabled: true, detail: '{"safe":true}' })).toEqual({
      ok: true,
      value: { label: 'sample', count: 2, enabled: true, detail: { safe: true } },
    })
  })

  it('never falls back outside an action engine allow-list', () => {
    const action: GovernedAction = {
      id: 'act_1',
      instanceId: 'ins_1',
      title: 'Action',
      engineIds: ['missing'],
    }
    const engines: ExecutionEngine[] = [
      {
        id: 'synthetic',
        label: 'Synthetic',
        kind: 'fixture',
        availability: 'available',
        available: true,
      },
    ]
    expect(defaultEngineFor(action, engines)).toBeUndefined()
  })
})

describe('safe evidence projection', () => {
  it('withholds absolute host paths while retaining application-relative proposal paths', () => {
    expect(
      safeEvidenceValue({
        bundlePath: '/var/lib/stateport/runs/run_1',
        windowsPath: 'C:\\stateport\\run_1',
        proposalPath: 'state/SAMPLE.yaml',
      }),
    ).toEqual({
      bundlePath: '[local path withheld]',
      windowsPath: '[local path withheld]',
      proposalPath: 'state/SAMPLE.yaml',
    })
  })
})
