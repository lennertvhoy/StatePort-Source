/**
 * Bounded synthetic validation is classified, not executed.
 *
 * The backend exposes a production-ineligible `synthetic_run` capability
 * (POST /v1/instances/:instanceId/synthetic-run). The product contract
 * (CURRENT_BACKEND_CONTRACT.md) says the frontend must never call it:
 * infrastructure configuration validation uses the `validate` plan/run
 * contract, and synthetic verification never implies production readiness.
 *
 * So the app overview resolves the `run-button` preservation surface on the
 * EXPLAIN branch: the capability appears in the ordinary capabilities list as
 * an explicitly non-executable classified entry. These tests fail if that
 * entry disappears, stops being visibly non-executable, or ever grows a
 * control that starts the endpoint.
 */
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { resetClientForTests, useScenarioStore } from '@/client'
import { invalidateInstanceCache } from '@/shell/data'
import { AppContextShell } from '@/shell/AppContextShell'
import { useSessionStore, useWorkspaceStore } from '@/state'

import AppOverviewPage from '../AppOverviewPage'

const LONG = 15_000

beforeEach(() => {
  resetClientForTests()
  useScenarioStore.getState().setActive(null)
  invalidateInstanceCache()
  useWorkspaceStore.setState({
    lastInstanceId: null,
    lastView: null,
    lastWorkbenchTool: null,
    density: 'compact',
    layouts: {},
    openFiles: {},
    activeFile: {},
  })
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: 'http://127.0.0.1:8734' } })
  useSessionStore.getState().setActiveScenario(null)
})

afterEach(() => {
  cleanup()
  useScenarioStore.getState().setActive(null)
  vi.restoreAllMocks()
})

function renderOverview(instanceId: string) {
  return render(
    <MemoryRouter initialEntries={[`/app/${instanceId}`]}>
      <Routes>
        <Route path="/app/:instanceId" element={<AppContextShell />}>
          <Route index element={<AppOverviewPage />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

async function openCapabilities(user: ReturnType<typeof userEvent.setup>) {
  const toggle = await screen.findByRole('button', { name: /available/i }, { timeout: LONG })
  expect(toggle.getAttribute('aria-expanded')).toBe('false')
  await user.click(toggle)
  return toggle
}

describe('synthetic validation classification', () => {
  it(
    'classifies bounded synthetic validation inside the capabilities list as non-executable',
    async () => {
      const user = userEvent.setup()
      renderOverview('ins_cto_pilot')
      await openCapabilities(user)

      const entry = screen.getByTestId('capability-synthetic-run')
      expect(entry.getAttribute('data-executable')).toBe('false')

      // The classification is user-visible copy, not just an attribute.
      expect(entry.textContent).toContain('Synthetic validation')
      expect(entry.textContent).toContain('Bounded synthetic contract inspection')
      expect(entry.textContent).toContain('not executable from this UI')
      expect(entry.textContent).toContain('It does not imply production readiness.')
      expect(entry.textContent).toContain(
        'Infrastructure configuration validation is performed by the validate plan/run operation.',
      )
    },
    LONG,
  )

  it(
    'offers no control that could start synthetic validation',
    async () => {
      const user = userEvent.setup()
      renderOverview('ins_cto_pilot')
      await openCapabilities(user)

      // A classification is text. Anything interactive inside it would be a
      // production-ineligible run control the contract forbids.
      const entry = screen.getByTestId('capability-synthetic-run')
      expect(within(entry).queryAllByRole('button')).toHaveLength(0)
      expect(within(entry).queryAllByRole('link')).toHaveLength(0)
      expect(entry.querySelector('button, a')).toBeNull()
    },
    LONG,
  )

  it(
    'renders the classification for an instance whose capabilities are gated',
    async () => {
      const user = userEvent.setup()
      // StudyState has no workbench/backup capabilities, so its summary reads
      // differently. The classification must not depend on capability state.
      renderOverview('ins_study_alpha')
      const toggle = await screen.findByRole('button', { name: /available|unavailable/i }, { timeout: LONG })
      await user.click(toggle)

      const entry = screen.getByTestId('capability-synthetic-run')
      expect(entry.getAttribute('data-executable')).toBe('false')
      expect(entry.textContent).toContain('It does not imply production readiness.')
    },
    LONG,
  )
})
