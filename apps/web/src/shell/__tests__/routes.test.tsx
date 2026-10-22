/**
 * Route smoke — every route from design.md §12 renders its current surface
 * through the real App, and a missing instance renders the honest error
 * state. Guards redirect instances without the requested application view to
 * the app overview.
 */
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { getClient, resetClientForTests } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { invalidateInstanceCache } from '@/shell/data'
import { useWorkspaceStore } from '@/state'

afterEach(() => {
  cleanup()
  window.location.hash = ''
  resetClientForTests()
})

/** Render <App/> at a hash route. */
async function renderAt(route: string) {
  window.location.hash = route
  return render(<App />)
}

const STUB_ROUTES: { route: string; testId: string; name: string }[] = [
  { route: '#/platform', testId: 'platform-page', name: 'Platform' },
  { route: '#/applications', testId: 'applications-stub', name: 'Applications' },
  { route: '#/catalog', testId: 'catalog-stub', name: 'Catalog' },
  { route: '#/execution-host', testId: 'execution-host-page', name: 'Execution host' },
  { route: '#/authority', testId: 'authority-page', name: 'Standing authority' },
  { route: '#/updater', testId: 'updater-page', name: 'Installed updater' },
  { route: '#/approvals', testId: 'approvals-stub', name: 'Approvals' },
  { route: '#/approvals/apr_demo', testId: 'approvals-stub', name: 'Approval detail' },
  { route: '#/settings', testId: 'settings-stub', name: 'Settings' },
  { route: '#/settings/appearance', testId: 'settings-stub', name: 'Settings group' },
  { route: '#/app/ins_cto_pilot', testId: 'app-overview-stub', name: 'App overview' },
  { route: '#/app/ins_cto_pilot/conversation', testId: 'conversation-stub', name: 'Conversation' },
  // Runs is application-level and capability-gated.
  { route: '#/app/ins_study_alpha/runs', testId: 'runs-stub', name: 'Governed Runs' },
  { route: '#/app/ins_cto_pilot/settings', testId: 'settings-stub', name: 'App settings' },
  {
    route: '#/app/ins_study_alpha/receipts',
    testId: 'application-receipts-page',
    name: 'Application-native receipt index',
  },
  {
    route: '#/app/ins_study_alpha/receipts/rcpt_0004',
    testId: 'application-receipt-page',
    name: 'Application-native receipt detail',
  },
]

describe('route smoke', () => {
  for (const { route, testId, name } of STUB_ROUTES) {
    it(
      `${name} (${route}) renders`,
      async () => {
        await renderAt(route)
        expect(await screen.findByTestId(testId, undefined, { timeout: 10_000 })).toBeTruthy()
        // Shell chrome is present on every route.
        expect(screen.getByTestId('topbar')).toBeTruthy()
      },
      20_000,
    )
  }

  it('root without a previously opened application redirects to Applications', async () => {
    useWorkspaceStore.setState({ lastInstanceId: null, lastView: null })
    await renderAt('#/')
    expect(await screen.findByTestId('applications-stub', undefined, { timeout: 10_000 })).toBeTruthy()
  })

  it('unknown route renders the not-found surface', async () => {
    await renderAt('#/no/such/route')
    expect(await screen.findByTestId('not-found', undefined, { timeout: 10_000 })).toBeTruthy()
  })

  it('serves the Models page at #/settings/models and the own-account provider page at #/settings/provider', async () => {
    await renderAt('#/settings/models')
    expect(await screen.findByRole('heading', { name: 'Models', level: 1 }, { timeout: 10_000 })).toBeTruthy()
    cleanup()
    await renderAt('#/settings/provider')
    expect(
      await screen.findByRole('heading', { name: 'Coding provider' }, { timeout: 10_000 }),
    ).toBeTruthy()
  })

  it.each([
    '#/sources',
    '#/sources/studystate.sample',
    '#/statebench',
    '#/deployments',
    '#/preview-routes',
    '#/execution-host/workspaces/ins_cto_pilot/terminal',
    '#/app/ins_cto_pilot/workbench',
    '#/app/ins_cto_pilot/workbench/files',
    '#/app/ins_cto_pilot/workbench/terminal',
    '#/app/ins_nixos_infra/workbench/deployments',
    '#/app/ins_cto_pilot/workbench/orchestration',
    '#/app/ins_cto_pilot/workbench/receipts',
  ])('%s is not a route in this release and renders the not-found surface', async (route) => {
    await renderAt(route)
    expect(await screen.findByTestId('not-found', undefined, { timeout: 10_000 })).toBeTruthy()
  }, 20_000)

  it('opens an exact application receipt', async () => {
    await renderAt('#/app/ins_study_alpha/receipts/rcpt_0004')
    expect(
      await screen.findByTestId('application-receipt-page', undefined, {
        timeout: 10_000,
      }),
    ).toBeTruthy()
    expect(
      await screen.findByTestId('receipt-detail', undefined, {
        timeout: 10_000,
      }),
    ).toBeTruthy()
    expect(screen.queryByTestId('workbench-shell')).toBeNull()
    expect(document.querySelectorAll('a[href*="/workbench"]').length).toBe(0)
    expect(window.location.hash).toBe(
      '#/app/ins_study_alpha/receipts/rcpt_0004',
    )
    await waitFor(() => expect(document.title).toBe('Receipts · StudyState Alpha · StatePort'))
    expect(document.querySelector('nav[aria-label="Breadcrumb"]')?.textContent).toContain('Receipts')
  })

  it('direct links to a capability-gated application view fail closed', async () => {
    // ChecklistState has no goal_execution capability in the mock projection.
    await renderAt('#/app/ins_checklist_sample/runs')
    expect(await screen.findByTestId('app-overview-stub', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(window.location.hash).toBe('#/app/ins_checklist_sample')
    expect(await screen.findByText(/Runs is not part of this application/i)).toBeTruthy()
  })

  it('guards direct native receipt links when the application lacks receipts', async () => {
    const client = getClient()
    const instance = buildSeed().instances.find(({ id }) => id === 'ins_checklist_sample')
    if (!instance) throw new Error('Checklist fixture is missing from the mock seed.')
    invalidateInstanceCache(instance.id)
    vi.spyOn(client.applications, 'get').mockResolvedValue({
      ...instance,
      capabilities: instance.capabilities.filter((capability) => capability.id !== 'receipts'),
    })
    await renderAt('#/app/ins_checklist_sample/receipts')
    expect(await screen.findByTestId('app-overview-stub', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(window.location.hash).toBe('#/app/ins_checklist_sample')
    expect(await screen.findByText(/Receipts is not part of this application/i)).toBeTruthy()
  })

  it('missing instance renders the error state', async () => {
    // Per contract: render <App/> directly and wait for the error state —
    // do NOT route through a stub-waiting helper.
    window.location.hash = '#/app/ins_missing'
    render(<App />)
    expect(await screen.findByTestId('error-state', undefined, { timeout: 20_000 })).toBeTruthy()
  }, 25_000)
})
