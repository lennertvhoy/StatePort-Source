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
  { route: '#/applications', testId: 'applications-stub', name: 'Applications' },
  { route: '#/catalog', testId: 'catalog-stub', name: 'Catalog' },
  { route: '#/sources', testId: 'source-registry-page', name: 'Application sources' },
  { route: '#/statebench', testId: 'platform-statebench-page', name: 'StateBench evidence' },
  { route: '#/deployments', testId: 'platform-deployments-page', name: 'Platform deployments' },
  { route: '#/authority', testId: 'authority-page', name: 'Standing authority' },
  { route: '#/updater', testId: 'updater-page', name: 'Installed updater' },
  { route: '#/preview-routes', testId: 'preview-routes-page', name: 'Preview routes' },
  { route: '#/approvals', testId: 'approvals-stub', name: 'Approvals' },
  { route: '#/approvals/apr_demo', testId: 'approvals-stub', name: 'Approval detail' },
  { route: '#/settings', testId: 'settings-stub', name: 'Settings' },
  { route: '#/settings/appearance', testId: 'settings-stub', name: 'Settings group' },
  { route: '#/app/ins_cto_pilot', testId: 'app-overview-stub', name: 'App overview' },
  { route: '#/app/ins_cto_pilot/conversation', testId: 'conversation-stub', name: 'Conversation' },
  // Runs is application-level and capability-gated; StudyState intentionally
  // has goal_execution without Workbench.
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
  { route: '#/app/ins_cto_pilot/workbench', testId: 'workbench-overview-stub', name: 'Workbench overview' },
  { route: '#/app/ins_cto_pilot/workbench/files', testId: 'files-stub', name: 'Files tool' },
  { route: '#/app/ins_cto_pilot/workbench/terminal', testId: 'terminal-stub', name: 'Terminal tool' },
  // Deployments requires the infrastructure capability — environment_gated on
  // ins_cto_pilot by seed, so this route is asserted on ins_nixos_infra.
  { route: '#/app/ins_nixos_infra/workbench/deployments', testId: 'deployments-stub', name: 'Deployments tool' },
  { route: '#/app/ins_cto_pilot/workbench/orchestration', testId: 'orchestration-stub', name: 'Orchestration tool' },
  { route: '#/app/ins_cto_pilot/workbench/receipts', testId: 'receipts-stub', name: 'Receipts tool' },
  { route: '#/app/ins_cto_pilot/workbench/receipts/rct_demo', testId: 'receipts-stub', name: 'Receipt detail' },
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

  it('root redirects to Applications', async () => {
    await renderAt('#/')
    expect(await screen.findByTestId('applications-stub', undefined, { timeout: 10_000 })).toBeTruthy()
  })

  it('unknown route renders the not-found surface', async () => {
    await renderAt('#/no/such/route')
    expect(await screen.findByTestId('not-found', undefined, { timeout: 10_000 })).toBeTruthy()
  })

  it('gives the global StateBench route its exact document title', async () => {
    await renderAt('#/statebench')
    expect(await screen.findByTestId('platform-statebench-page')).toBeTruthy()
    await waitFor(() => expect(document.title).toBe('StateBench Evidence · StatePort'))
  })

  it('workbench routes render inside the workbench shell with a status bar', async () => {
    await renderAt('#/app/ins_cto_pilot/workbench/files')
    expect(await screen.findByTestId('workbench-shell', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(await screen.findByTestId('files-stub', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(screen.getByTestId('status-bar')).toBeTruthy()
  })

  it('opens an exact application receipt without granting the Workbench', async () => {
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

  it('no-workbench instances are redirected to the overview with a note', async () => {
    // ins_study_alpha has no workbench capability (seed).
    await renderAt('#/app/ins_study_alpha/workbench')
    expect(await screen.findByTestId('app-overview-stub', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(window.location.hash).not.toContain('/workbench')
    expect(await screen.findByTestId('inline-notice', undefined, { timeout: 10_000 })).toBeTruthy()
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
