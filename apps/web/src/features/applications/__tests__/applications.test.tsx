/**
 * Applications home — resume dashboard behavior:
 * - the four seeded instances render with distinct, honest statuses
 *   (never a repeated "Ready" wall),
 * - attention counts and the de-duplicated Needs-attention feed are correct,
 * - pinning flows through the client and the pinned order persists in the
 *   feature prefs store (zustand + persist, the workspace-store seam for this
 *   surface),
 * - attention acknowledge flows through the client,
 * - palette commands for switching applications register,
 * - the no-applications empty state matches the design.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'
import type { ApplicationInstance, OperationExecutionRecord, OperationRecord } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useCommandStore } from '@/shell/commands'
import { invalidateInstanceCache } from '@/shell/data'
import { useSessionStore, useWorkspaceStore } from '@/state'

import ApplicationsPage from '../ApplicationsPage'
import { resetDashboardSnapshotForTests } from '../lib/dashboardData'
import { dominantInstanceStatus, isLiveOperationState } from '../lib/dominantStatus'
import { APPLICATIONS_PREFS_STORAGE_KEY, useApplicationsPrefs } from '../lib/prefsStore'

const LONG = 15_000

beforeEach(() => {
  resetClientForTests()
  invalidateInstanceCache()
  resetDashboardSnapshotForTests()
  useApplicationsPrefs.setState({
    pinnedOrder: [],
    unpinnedOrder: [],
    sort: 'recent',
    onboardingDismissed: false,
    checklistDoneOverrides: {},
    studyGoalOverrides: {},
  })
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
  useCommandStore.setState({ commands: {}, paletteOpen: false, shortcutsOpen: false })
})

afterEach(() => {
  cleanup()
})

function renderPage() {
  return render(
    <MemoryRouter>
      <ApplicationsPage />
    </MemoryRouter>,
  )
}

const statusOf = (id: string) => screen.getByTestId(`instance-status-${id}`)

describe('Applications home', () => {
  const summaryInstance = buildSeed().instances.find((instance) => instance.id === 'ins_study_alpha') as ApplicationInstance
  const operation = (state: OperationExecutionRecord['state'], instanceId = summaryInstance.id) => ({
    id: `op_${state}`,
    instanceId,
    kind: 'orchestration_run' as const,
    title: `${state} operation`,
    state,
    stageLabel: state,
    startedAt: '2026-09-08T00:00:00Z',
    updatedAt: '2026-09-08T00:00:00Z',
    canPause: false,
    canCancel: state === 'cancelling',
    log: [],
  } satisfies OperationRecord)

  it.each(['prepared', 'approved', 'cancelling', 'interrupted'] as const)(
    'surfaces %s as an active operation in the dominant status',
    (state) => {
      const status = dominantInstanceStatus({ instance: summaryInstance, operations: [operation(state)] })
      expect(status.presentation.label).toBe('Active operation')
    },
  )

  it('excludes terminal and foreign operations from the dominant active status', () => {
    const status = dominantInstanceStatus({
      instance: summaryInstance,
      operations: [operation('completed'), operation('running', 'ins_other')],
    })
    expect(status.presentation.label).toBe('Idle')
  })

  it('does not treat unknown or terminal states as active work', () => {
    expect(isLiveOperationState('unknown')).toBe(false)
    expect(isLiveOperationState('completed')).toBe(false)
    expect(isLiveOperationState(undefined)).toBe(false)
  })

  it(
    'renders the four seeded instances with distinct honest statuses (no repeated "Ready")',
    async () => {
      renderPage()
      expect(await screen.findByTestId('instance-row-ins_cto_pilot', undefined, { timeout: LONG })).toBeTruthy()
      for (const id of ['ins_study_alpha', 'ins_checklist_sample', 'ins_nixos_infra']) {
        expect(screen.getByTestId(`instance-row-${id}`)).toBeTruthy()
      }

      expect(statusOf('ins_cto_pilot').textContent).toBe('Backup due')
      expect(statusOf('ins_cto_pilot').getAttribute('data-state')).toBe('attention')
      expect(statusOf('ins_nixos_infra').textContent).toBe('Awaiting approval')
      expect(statusOf('ins_nixos_infra').getAttribute('data-state')).toBe('waiting')
      expect(statusOf('ins_study_alpha').textContent).toBe('Idle')
      expect(statusOf('ins_checklist_sample').textContent).toBe('Idle')

      const labels = ['ins_cto_pilot', 'ins_nixos_infra', 'ins_study_alpha', 'ins_checklist_sample'].map(
        (id) => statusOf(id).textContent,
      )
      expect(new Set(labels).size).toBeGreaterThanOrEqual(3)
      expect(labels).not.toContain('Ready')
    },
    LONG,
  )

  it(
    'shows correct attention counts and a de-duplicated needs-attention feed',
    async () => {
      renderPage()
      await screen.findByTestId('needs-attention-section', undefined, { timeout: LONG })

      // Per-instance attention counts (CTO Pilot backup due, NixOS approval waiting).
      expect(screen.getByTestId('attention-count-ins_cto_pilot').textContent).toContain('1')
      expect(screen.getByTestId('attention-count-ins_nixos_infra').textContent).toContain('1')
      expect(screen.queryByTestId('attention-count-ins_study_alpha')).toBeNull()
      expect(screen.queryByTestId('attention-count-ins_checklist_sample')).toBeNull()

      // Feed: the pending approval row + the CTO Pilot backup attention item.
      expect(screen.getByTestId('attention-approval-appr_0001')).toBeTruthy()
      expect(screen.getByTestId('attention-item-attn_0001')).toBeTruthy()
      // The NixOS attention item merely points at the approval — de-duplicated away.
      expect(screen.queryByTestId('attention-item-attn_0002')).toBeNull()

      // Pending approvals summary links to the inbox.
      expect(screen.getByRole('link', { name: /view all in approvals|approvals inbox/i })).toBeTruthy()
    },
    LONG,
  )

  it(
    'pins via the client and persists pinned order in the prefs store',
    async () => {
      const user = userEvent.setup()
      renderPage()
      const row = await screen.findByTestId('instance-row-ins_checklist_sample', undefined, { timeout: LONG })

      // Keyboard pin: P on the focused row (design keyboard map).
      row.focus()
      await user.keyboard('p')

      await waitFor(
        () => expect(useSessionStore.getState().toasts.some((t) => t.title === 'Pinned ChecklistState Sample')).toBe(true),
        { timeout: LONG },
      )

      // The pin flag persisted through the client boundary. Mock writes are
      // debounced (120 ms), so first wait for the storage envelope, then prove
      // a freshly constructed client reads the pin back.
      await waitFor(
        () => {
          const raw = window.localStorage.getItem('stateport.mock.v1')
          expect(raw).toBeTruthy()
          const data = (JSON.parse(raw!) as { data: { instances: { id: string; pinned: boolean }[] } }).data
          expect(data.instances.find((i) => i.id === 'ins_checklist_sample')?.pinned).toBe(true)
        },
        { timeout: LONG },
      )
      resetClientForTests()
      const list = await getClient().applications.list()
      expect(list.find((i) => i.id === 'ins_checklist_sample')?.pinned).toBe(true)

      // The pinned order persisted through the feature store's storage key.
      await waitFor(
        () => {
          const raw = window.localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)
          expect(raw).toBeTruthy()
          const persisted = JSON.parse(raw!) as { state: { pinnedOrder: string[] } }
          expect(persisted.state.pinnedOrder).toContain('ins_checklist_sample')
        },
        { timeout: LONG },
      )
    },
    LONG,
  )

  it(
    'acknowledging an attention item removes it through the client',
    async () => {
      const user = userEvent.setup()
      renderPage()
      const row = await screen.findByTestId('attention-item-attn_0001', undefined, { timeout: LONG })
      await user.click(within(row).getByRole('button', { name: /acknowledge/i }))

      await waitFor(() => expect(screen.queryByTestId('attention-item-attn_0001')).toBeNull(), { timeout: LONG })

      resetClientForTests()
      const instance = await getClient().applications.get('ins_cto_pilot')
      expect(instance.attention).toHaveLength(0)
      expect(instance.health).toBe('ready')
    },
    LONG,
  )

  it(
    'registers switch-to-recent and reopen-last-workspace commands; hero resumes context',
    async () => {
      useWorkspaceStore.setState({ lastInstanceId: 'ins_cto_pilot', lastView: 'workbench', lastWorkbenchTool: 'files' })
      renderPage()
      const hero = await screen.findByTestId('continue-hero', undefined, { timeout: LONG })
      expect(hero.textContent).toContain('StatePort CTO Pilot')
      expect(hero.textContent).toContain('Files')
      expect(hero.textContent?.match(/Files/g)).toHaveLength(1)
      expect(within(hero).getByRole('button', { name: /continue in stateport cto pilot/i })).toBeTruthy()

      const ids = Object.keys(useCommandStore.getState().commands)
      expect(ids).toContain('applications.reopen_last_workspace')
      expect(ids).toContain('applications.switch.ins_cto_pilot')
      expect(ids).toContain('applications.switch.ins_nixos_infra')
    },
    LONG,
  )

  it(
    'renders the honest empty state with install CTA and onboarding strip when no applications exist',
    async () => {
      useSessionStore.getState().setActiveScenario('no_applications')
      renderPage()
      expect(await screen.findByTestId('empty-state', undefined, { timeout: LONG })).toBeTruthy()
      expect(screen.getByText('No applications yet')).toBeTruthy()
      expect(screen.getByRole('button', { name: /browse catalog/i })).toBeTruthy()
      expect(screen.getByRole('button', { name: /import a repository/i })).toBeTruthy()
      expect(screen.getByTestId('onboarding-strip')).toBeTruthy()
    },
    LONG,
  )

  it(
    'service offline renders read-only notice and hides mutating actions',
    async () => {
      useSessionStore.setState({ serviceStatus: { state: 'offline', endpoint: '', detail: 'No answer.' } })
      renderPage()
      await screen.findByTestId('instance-row-ins_cto_pilot', undefined, { timeout: LONG })
      expect(screen.getByText(/local service is offline/i)).toBeTruthy()
      expect(screen.getByText(/read-only snapshots/i)).toBeTruthy()
      expect(screen.queryByRole('button', { name: /new instance/i })).toBeNull()
      expect(screen.queryByRole('button', { name: /acknowledge/i })).toBeNull()
    },
    LONG,
  )

  it(
    'hides Rename when the connected adapter has no durable rename contract',
    async () => {
      const user = userEvent.setup()
      const applications = getClient().applications as { canRename: boolean }
      applications.canRename = false

      renderPage()
      const row = await screen.findByTestId('instance-row-ins_cto_pilot', undefined, {
        timeout: LONG,
      })
      await user.click(within(row).getByRole('button', { name: 'Actions for StatePort CTO Pilot' }))
      expect(screen.queryByRole('menuitem', { name: /Rename/ })).toBeNull()
    },
    LONG,
  )
})

function installedOrder() {
  return within(screen.getByRole('list', { name: 'Installed applications' }))
    .getAllByTestId(/^instance-row-/).map((row) => row.getAttribute('data-testid'))
}

async function unpinExamples() {
  for (const id of ['ins_cto_pilot', 'ins_study_alpha', 'ins_nixos_infra']) {
    await getClient().applications.setPinned(id, false)
  }
}

it('uses saved name/recent defaults after route reload without turning them into view overrides', async () => {
  await unpinExamples()
  useApplicationsPrefs.getState().setSort(null)
  await getClient().globalSettings.update({ general: { defaultApplicationSorting: 'name' } })
  const first = renderPage()
  await screen.findByText('Sort: Name', undefined, { timeout: LONG })
  await screen.findByTestId('instance-row-ins_cto_pilot', undefined, { timeout: LONG })
  expect(installedOrder()).toEqual(['instance-row-ins_checklist_sample', 'instance-row-ins_nixos_infra', 'instance-row-ins_cto_pilot', 'instance-row-ins_study_alpha'])
  expect(useApplicationsPrefs.getState().sort).toBeNull()
  first.unmount()
  await getClient().globalSettings.update({ general: { defaultApplicationSorting: 'recent' } })
  renderPage()
  await screen.findByText('Sort: Recent', undefined, { timeout: LONG })
  await waitFor(() => expect(installedOrder()).toEqual(['instance-row-ins_nixos_infra', 'instance-row-ins_cto_pilot', 'instance-row-ins_study_alpha', 'instance-row-ins_checklist_sample']))
}, LONG)

it('preserves an explicit view sort through persistence reload and can return to the settings default', async () => {
  await unpinExamples()
  await getClient().globalSettings.update({ general: { defaultApplicationSorting: 'name' } })
  useApplicationsPrefs.getState().setSort(null)
  const user = userEvent.setup()
  const first = renderPage()
  await screen.findByText('Sort: Name', undefined, { timeout: LONG })
  await user.click(screen.getByRole('button', { name: 'Sort: Name' }))
  await user.click(screen.getByRole('menuitemradio', { name: 'Recent' }))
  expect(useApplicationsPrefs.getState().sort).toBe('recent')
  const persisted = localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)!
  first.unmount()
  useApplicationsPrefs.setState({ sort: null })
  localStorage.setItem(APPLICATIONS_PREFS_STORAGE_KEY, persisted)
  await useApplicationsPrefs.persist.rehydrate()
  renderPage()
  await screen.findByText('Sort: Recent', undefined, { timeout: LONG })
  await waitFor(() => expect(installedOrder()[0]).toBe('instance-row-ins_nixos_infra'))
  await user.click(screen.getByRole('button', { name: 'Sort: Recent' }))
  await user.click(await screen.findByRole('menuitemradio', { name: 'Use settings default (Name)' }))
  await waitFor(() => expect(installedOrder()[0]).toBe('instance-row-ins_checklist_sample'))
  expect(useApplicationsPrefs.getState().sort).toBeNull()
  expect(JSON.parse(localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)!).state.sort).toBeNull()
}, LONG)

it('manually reorders unpinned rows with menu and keyboard, preserving order after reload and identity changes', async () => {
  await unpinExamples()
  useApplicationsPrefs.getState().setSort('manual')
  const user = userEvent.setup()
  const first = renderPage()
  await screen.findByTestId('instance-row-ins_study_alpha', undefined, { timeout: LONG })
  await user.click(within(screen.getByTestId('instance-row-ins_study_alpha')).getByRole('button', { name: 'Actions for StudyState Alpha' }))
  await user.click(screen.getByRole('menuitem', { name: 'Move up' }))
  expect(installedOrder()[0]).toBe('instance-row-ins_study_alpha')
  fireEvent.keyDown(screen.getByTestId('instance-row-ins_nixos_infra'), { key: 'ArrowUp', altKey: true })
  expect(installedOrder()).toEqual(['instance-row-ins_study_alpha', 'instance-row-ins_cto_pilot', 'instance-row-ins_nixos_infra', 'instance-row-ins_checklist_sample'])
  const persisted = localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)!
  first.unmount()
  useApplicationsPrefs.setState({ unpinnedOrder: [] })
  localStorage.setItem(APPLICATIONS_PREFS_STORAGE_KEY, persisted)
  await useApplicationsPrefs.persist.rehydrate()
  resetDashboardSnapshotForTests()
  const second = renderPage()
  await screen.findByTestId('instance-row-ins_study_alpha', undefined, { timeout: LONG })
  expect(installedOrder()[0]).toBe('instance-row-ins_study_alpha')
  second.unmount()
  const current = await getClient().applications.list()
  const added = { ...current[0], id: 'ins_new_ordered', name: 'New application' }
  vi.spyOn(getClient().applications, 'list').mockResolvedValue([...current.filter((item) => item.id !== 'ins_cto_pilot').map((item) => item.id === 'ins_study_alpha' ? { ...item, name: 'Renamed StudyState' } : item), added])
  resetDashboardSnapshotForTests()
  renderPage()
  await screen.findByTestId('instance-row-ins_new_ordered', undefined, { timeout: LONG })
  expect(installedOrder()).toEqual(['instance-row-ins_study_alpha', 'instance-row-ins_nixos_infra', 'instance-row-ins_checklist_sample', 'instance-row-ins_new_ordered'])
  await waitFor(() => expect(useApplicationsPrefs.getState().unpinnedOrder).toEqual(['ins_study_alpha', 'ins_nixos_infra', 'ins_checklist_sample', 'ins_new_ordered']))
}, LONG)

it('does not move hidden applications while filtered and resumes ordering after clearing the filter', async () => {
  await unpinExamples()
  useApplicationsPrefs.getState().setSort('manual')
  const user = userEvent.setup()
  renderPage()
  await screen.findByTestId('instance-row-ins_study_alpha', undefined, { timeout: LONG })
  const before = installedOrder()
  const input = screen.getByRole('searchbox')
  await user.type(input, 'StudyState')
  expect(screen.getByText('Clear the filter to reorder applications. Hidden applications keep their positions.')).toBeTruthy()
  fireEvent.keyDown(screen.getByTestId('instance-row-ins_study_alpha'), { key: 'ArrowUp', altKey: true })
  await user.click(within(screen.getByTestId('instance-row-ins_study_alpha')).getByRole('button', { name: 'Actions for StudyState Alpha' }))
  expect(screen.queryByRole('menuitem', { name: 'Move up' })).toBeNull()
  await user.keyboard('{Escape}')
  await user.clear(input)
  expect(installedOrder()).toEqual(before)
  fireEvent.keyDown(screen.getByTestId('instance-row-ins_study_alpha'), { key: 'ArrowUp', altKey: true })
  expect(installedOrder()[0]).toBe('instance-row-ins_study_alpha')
}, LONG)

it('reports a session-only order after storage denial and retries its durable save', async () => {
  await unpinExamples()
  useApplicationsPrefs.getState().setSort('manual')
  const user = userEvent.setup()
  renderPage()
  await screen.findByTestId('instance-row-ins_study_alpha', undefined, { timeout: LONG })
  const persisted = localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)
  const original = localStorage.setItem.bind(localStorage)
  const write = vi.spyOn(localStorage, 'setItem').mockImplementation((key, value) => {
    if (key === APPLICATIONS_PREFS_STORAGE_KEY) throw new Error('Storage denied')
    original(key, value)
  })
  fireEvent.keyDown(screen.getByTestId('instance-row-ins_study_alpha'), { key: 'ArrowUp', altKey: true })
  expect(installedOrder()[0]).toBe('instance-row-ins_study_alpha')
  expect(screen.getByRole('alert').textContent).toContain('could not be saved')
  expect(localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)).toBe(persisted)
  write.mockRestore()
  await user.click(screen.getByRole('button', { name: 'Retry saving order' }))
  expect(screen.queryByRole('alert')).toBeNull()
  expect(JSON.parse(localStorage.getItem(APPLICATIONS_PREFS_STORAGE_KEY)!).state.unpinnedOrder[0]).toBe('ins_study_alpha')
}, LONG)

it('keeps the pinned group ahead of manually ordered cards', async () => {
  await getClient().applications.setPinned('ins_study_alpha', false)
  await getClient().applications.setPinned('ins_nixos_infra', false)
  useApplicationsPrefs.getState().setSort('manual')
  useWorkspaceStore.setState({ density: 'comfortable' })
  const user = userEvent.setup()
  renderPage()
  const card = await screen.findByTestId('instance-card-ins_study_alpha', undefined, { timeout: LONG })
  await user.click(within(card).getByRole('button', { name: 'Actions for StudyState Alpha' }))
  await user.click(screen.getByRole('menuitem', { name: 'Move down' }))
  expect(within(screen.getByRole('list', { name: 'Installed applications' })).getAllByTestId(/^instance-card-/).map((item) => item.getAttribute('data-testid')))
    .toEqual(['instance-card-ins_cto_pilot', 'instance-card-ins_checklist_sample', 'instance-card-ins_study_alpha', 'instance-card-ins_nixos_infra'])
  expect(useApplicationsPrefs.getState().pinnedOrder).toEqual(['ins_cto_pilot'])
}, LONG)


it('reloads recent-application visibility without hiding resume or the full list', async () => {
  await getClient().globalSettings.update({ general: { showRecentApplications: false } })
  const view = renderPage()
  await screen.findByTestId('continue-hero')
  expect(screen.queryByTestId('recently-used-section')).toBeNull()
  expect(screen.getByTestId('instance-row-ins_study_alpha')).toBeTruthy()
  view.unmount()
  await getClient().globalSettings.update({ general: { showRecentApplications: true } })
  renderPage()
  expect(await screen.findByTestId('recently-used-section')).toBeTruthy()
  expect(screen.getByTestId('continue-hero')).toBeTruthy()
  expect(screen.getByTestId('instance-row-ins_study_alpha')).toBeTruthy()
}, LONG)
