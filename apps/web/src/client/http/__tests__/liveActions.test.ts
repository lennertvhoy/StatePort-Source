import { describe, expect, it } from 'vitest'

import live from './fixtures/live-actions-20261022.json'
import { mapActions } from '../mappers'
import { cardActions } from '@/features/actions/actionsModel'

// Captured from the running service on 2026-10-22 (dev loop, one instance per template). The Actions card showed
// "This application declares no check or agent actions" because the web client read `kind` and the service sends
// `executorKind`. These are the service's real bytes, so a mismatch on either side fails here.
type Live = Record<string, { instanceId: string; payload: unknown }>

const expected: Record<string, { check: string[]; agent: string[] }> = {
  projectstate: {
    check: ['stateport.template.projectstate.check/v1'],
    agent: ['stateport.template.projectstate.setup-project/v1', 'stateport.template.projectstate.next-action/v1'],
  },
  studystate: {
    check: ['stateport.template.studystate.check/v1'],
    agent: ['stateport.template.studystate.setup-study/v1', 'stateport.template.studystate.plan-next-session/v1'],
  },
  decisionlog: {
    check: ['decision-log.check/v1', 'decision-log.list-due/v1'],
    agent: ['decision-log.draft-decision/v1', 'decision-log.add-question/v1'],
  },
}

describe('the Actions card on the real service projection', () => {
  for (const [template, { instanceId, payload }] of Object.entries(live as Live)) {
    it(`${template}: offers its checks and agent actions, setup first`, () => {
      const actions = mapActions((payload as { result: unknown }).result, instanceId)
      const { actions: card } = cardActions(actions, [])
      const want = expected[template]
      expect(card.filter((action) => action.kind === 'check').map((action) => action.id).sort()).toEqual([...want.check].sort())
      expect(card.filter((action) => action.kind === 'agent').map((action) => action.id).sort()).toEqual([...want.agent].sort())
      expect(card.some((action) => action.id.endsWith('.inspect/v1'))).toBe(false)
      if (template !== 'decisionlog') expect(card[0].id).toMatch(/setup-/)
    })
  }
})
