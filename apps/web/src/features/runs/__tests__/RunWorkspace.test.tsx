import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import type { RunRecord } from '@/client'

import { RunWorkspace } from '../RunWorkspace'

function closedNoMutationRun(result: Record<string, unknown>): RunRecord {
  return {
    id: 'run_1',
    instanceId: 'ins_1',
    actionId: 'act_1',
    engineId: 'engine_1',
    state: 'completed_without_change',
    status: 'result_validating',
    lifecycleState: 'CLOSED',
    revision: 3,
    inputs: {},
    result,
    createdAt: '2026-07-18T10:00:00Z',
    updatedAt: '2026-07-18T10:05:00Z',
  }
}

function renderWorkspace(run: RunRecord) {
  return render(
    <RunWorkspace
      run={run}
      busy={false}
      transitionError={null}
      onTransition={() => Promise.resolve()}
      onRefresh={() => undefined}
      onNewRun={() => undefined}
      onOpenEvidence={() => undefined}
    />,
  )
}

afterEach(cleanup)

describe('closed no-mutation run workspace', () => {
  it('renders the persisted typed result and the canonical-unchanged truth', () => {
    renderWorkspace(
      closedNoMutationRun({
        item: { label: 'Reviewed 3 flashcards', status: 'completed' },
        actionId: 'act_1',
        canonicalStateUnchanged: true,
      }),
    )
    expect(screen.getByText(/Result recorded; no project change applied/)).toBeTruthy()
    expect(screen.getByText('Reviewed 3 flashcards')).toBeTruthy()
    expect(screen.getByText('Unchanged')).toBeTruthy()
    expect(screen.getByTestId('run-open-evidence')).toBeTruthy()
  })

  it('reports the canonical-state flag as not recorded when the field is absent', () => {
    renderWorkspace(closedNoMutationRun({ item: { label: 'Reviewed 3 flashcards' } }))
    expect(screen.getByText('Not recorded')).toBeTruthy()
    expect(screen.queryByText('Unchanged')).toBeNull()
    expect(screen.queryByText('Change proposed or applied')).toBeNull()
  })

  it('states an explicit change only when the result records one', () => {
    renderWorkspace(closedNoMutationRun({ canonicalStateUnchanged: false }))
    expect(screen.getByText('Change proposed or applied')).toBeTruthy()
  })
})
