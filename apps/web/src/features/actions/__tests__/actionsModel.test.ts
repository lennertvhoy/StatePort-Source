import { describe, expect, it } from 'vitest'

import type { ExecutionEngine, GovernedAction, RunRecord } from '@/client'

import {
  actionInputFields,
  cardActions,
  engineForAction,
  initialInputValues,
  inputSummary,
  parseActionInputs,
  type KindedAction,
} from '../actionsModel'

const engine = (id: string, availability: ExecutionEngine['availability'] = 'available'): ExecutionEngine => ({
  id, label: id, kind: id, availability, available: availability === 'available', limitations: [],
})

const action = (overrides: Partial<GovernedAction>): GovernedAction => ({
  id: 'act', instanceId: 'ins_1', title: 'Act', engineIds: [], ...overrides,
})

const run = (actionId: string, status: RunRecord['status']): RunRecord => ({
  id: `run_${actionId}`, instanceId: 'ins_1', actionId, engineId: 'opencode', state: 'applied', status,
  revision: 1, inputs: {}, createdAt: '2026-10-21T08:00:00Z', updatedAt: '2026-10-21T08:00:00Z',
})

const SETUP_SCHEMA = {
  type: 'object',
  required: ['project', 'user', 'outcome'],
  properties: {
    project: { type: 'string', title: 'Project name', maxLength: 80 },
    user: { type: 'string', maxLength: 80 },
    outcome: { type: 'string', maxLength: 600, description: 'What the work is for.' },
    firstSlice: { type: 'string', maxLength: 200 },
    deadline: { type: 'string', format: 'date' },
    hoursPerWeek: { type: 'integer', minimum: 1, maximum: 80 },
  },
}

describe('actions model', () => {
  it('offers only check and agent actions, setup first until a setup run succeeded', () => {
    const actions = [
      action({ id: 'projectstate.gate/v1', kind: 'check' }),
      action({ id: 'legacy/v1' }),
      action({ id: 'projectstate.setup-project/v1', kind: 'agent' }),
    ]
    expect(cardActions(actions, []).actions.map((item) => item.id)).toEqual(['projectstate.setup-project/v1', 'projectstate.gate/v1'])
    expect(cardActions(actions, []).setupFirst).toBe(true)
    expect(cardActions(actions, [run('projectstate.setup-project/v1', 'failed')]).setupFirst).toBe(true)
    const done = cardActions(actions, [run('projectstate.setup-project/v1', 'applied')])
    expect(done.setupFirst).toBe(false)
    expect(done.actions.map((item) => item.id)).toEqual(['projectstate.gate/v1', 'projectstate.setup-project/v1'])
  })

  it('never picks an engine outside the declared allow-list; agents default to OpenCode', () => {
    const engines = [engine('synthetic'), engine('opencode'), engine('codex', 'environment_gated')]
    const agent = action({ kind: 'agent' }) as KindedAction
    const check = action({ kind: 'check' }) as KindedAction
    expect(engineForAction(agent, engines)?.id).toBe('opencode')
    expect(engineForAction(check, engines)?.id).toBe('synthetic')
    expect(engineForAction({ ...agent, engineIds: ['codex'] }, engines)).toBeUndefined()
    expect(engineForAction(agent, [engine('synthetic')])).toBeUndefined()
  })

  it('generates fields from the schema: titles, required, maxLength, dates and integers', () => {
    const fields = actionInputFields(action({ inputSchema: SETUP_SCHEMA }))
    expect(fields.map((field) => [field.name, field.label, field.type, field.required, field.maxLength])).toEqual([
      ['project', 'Project name', 'string', true, 80],
      ['user', 'User', 'string', true, 80],
      ['outcome', 'Outcome', 'text', true, 600],
      ['firstSlice', 'First slice', 'string', false, 200],
      ['deadline', 'Deadline', 'date', false, undefined],
      ['hoursPerWeek', 'Hours per week', 'integer', false, undefined],
    ])
    const values = initialInputValues(fields)
    expect(parseActionInputs(fields, values)).toEqual({
      ok: false,
      errors: { project: 'Project name is required.', user: 'User is required.', outcome: 'Outcome is required.' },
    })
    const tooLong = parseActionInputs(fields, { ...values, project: 'x'.repeat(81), user: 'Ann', outcome: 'Ship', deadline: '21/10/2026', hoursPerWeek: '2.5' })
    expect(tooLong).toEqual({
      ok: false,
      errors: {
        project: 'Project name can be at most 80 characters.',
        deadline: 'Deadline must be a date (YYYY-MM-DD).',
        hoursPerWeek: 'Hours per week must be a whole number.',
      },
    })
    const parsed = parseActionInputs(fields, { ...values, project: ' StatePort ', user: 'Ann', outcome: 'Ship Alpha.26', deadline: '2026-10-30', hoursPerWeek: '6' })
    expect(parsed).toEqual({ ok: true, value: { project: 'StatePort', user: 'Ann', outcome: 'Ship Alpha.26', deadline: '2026-10-30', hoursPerWeek: 6 } })
    if (parsed.ok) {
      expect(inputSummary(fields, parsed.value).map((item) => `${item.label}: ${item.value}`)).toEqual([
        'Project name: StatePort', 'User: Ann', 'Outcome: Ship Alpha.26', 'Deadline: 2026-10-30', 'Hours per week: 6',
      ])
    }
  })
})

describe('input field order', () => {
  it('puts required fields first in the template order, whatever order the service sent the keys in', () => {
    // The service serialises with sorted keys: firstSlice, outcome, project, user.
    const fields = actionInputFields({
      inputSchema: {
        type: 'object',
        required: ['project', 'user', 'outcome'],
        properties: {
          firstSlice: { type: 'string', maxLength: 300, title: 'First piece of work' },
          outcome: { type: 'string', maxLength: 600, title: 'Outcome' },
          project: { type: 'string', maxLength: 120, title: 'Project name' },
          user: { type: 'string', maxLength: 300, title: 'Who it is for' },
        },
      },
    } as never)
    expect(fields.map((field) => field.label)).toEqual(['Project name', 'Who it is for', 'Outcome', 'First piece of work'])
  })
})
