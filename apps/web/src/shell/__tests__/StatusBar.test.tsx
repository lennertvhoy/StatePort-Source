import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it } from 'vitest'

import { resetClientForTests, resetMockState, type OperationExecutionRecord } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useSessionStore } from '@/state'

import { StatusBar } from '../StatusBar'
import { useShellUiStore } from '../shellUi'
import { WorkbenchStatusContext } from '../workbenchStatus'

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  useSessionStore.setState({ operations: [], operationsError: null })
  useShellUiStore.setState({ operationCenterOpen: false })
})

afterEach(() => {
  cleanup()
  resetClientForTests()
})

it('follows the current application through operation completion and navigation', () => {
  const [first, second] = buildSeed().instances
  const foreign: OperationExecutionRecord = {
    id: 'foreign', instanceId: second.id, kind: 'backup', title: 'Other application backup',
    state: 'running', stageLabel: 'Saving', startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(), canPause: false, canCancel: true, log: [],
  }
  const local: OperationExecutionRecord = {
    ...foreign, id: 'local', instanceId: first.id, title: 'Current application backup',
  }
  useSessionStore.getState().setOperations([foreign, local])
  const view = (instance: typeof first) => (
    <MemoryRouter>
      <WorkbenchStatusContext.Provider value={{
        instance, instanceId: instance.id, tool: 'files', terminalState: null,
        terminalAvailable: false, targetName: null, deploymentsAvailable: false,
      }}>
        <StatusBar />
      </WorkbenchStatusContext.Provider>
    </MemoryRouter>
  )
  const rendered = render(view(first))
  expect(screen.getByTestId('status-operation').textContent).toContain(local.title)
  expect(screen.getByTestId('status-operation').textContent).not.toContain(foreign.title)

  act(() => useSessionStore.getState().upsertOperation({ ...local, state: 'completed' }))
  expect(screen.getByTestId('status-operation').textContent).toContain('No active operation')

  rendered.rerender(view(second))
  expect(screen.getByTestId('status-operation').textContent).toContain(foreign.title)
  fireEvent.click(screen.getByTestId('status-operation'))
  expect(useShellUiStore.getState().operationCenterOpen).toBe(true)
  expect(useSessionStore.getState().operations).toHaveLength(2)
})
