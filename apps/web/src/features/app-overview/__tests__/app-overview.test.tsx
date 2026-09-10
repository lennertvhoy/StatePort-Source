/**
 * App overview — the front door to an application:
 * - CTO Pilot surfaces backup-due as the ONE dominant attention state (badge +
 *   fact, not restated), and Back up now flows through the client,
 * - StudyState Alpha shows the learning goal + evidence progress and renders
 *   NO workbench actions (capability-gated),
 * - NixOS Infrastructure shows the stopped VM as neutral (a fact, not an
 *   alarm) and the pending approval as the dominant state,
 * - contextual palette commands register (pin, approvals, backup).
 */
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ApplicationInstance } from '@/client'
import { getClient, resetClientForTests, useScenarioStore } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useCommandStore } from '@/shell/commands'
import { invalidateInstanceCache } from '@/shell/data'
import { AppContextShell } from '@/shell/AppContextShell'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useSessionStore, useWorkspaceStore } from '@/state'

import AppOverviewPage from '../AppOverviewPage'
import { useOverviewData } from '../lib/overviewData'
import { resetDashboardSnapshotForTests } from '@/features/applications/lib/dashboardData'
import { useApplicationsPrefs } from '@/features/applications/lib/prefsStore'

const LONG = 15_000

beforeEach(() => {
  resetClientForTests()
  useScenarioStore.getState().setActive(null)
  invalidateInstanceCache()
  resetDashboardSnapshotForTests()
  useApplicationsPrefs.setState({
    pinnedOrder: [],
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
  useScenarioStore.getState().setActive(null)
})

function renderOverview(instanceId: string) {
  return render(
    <MemoryRouter initialEntries={[`/app/${instanceId}`]}>
      <LocationProbe />
      <Routes>
        <Route path="/app/:instanceId" element={<AppContextShell />}>
          <Route index element={<AppOverviewPage />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="current-path">{location.pathname}</output>
}

function SameInstanceRefreshProbe() {
  const { instance, refresh } = useCurrentInstance()
  const [applied, setApplied] = useState(false)

  return (
    <div>
      <button
        type="button"
        onClick={async () => {
          if (!instance) return
          invalidateInstanceCache(instance.id)
          await Promise.resolve(refresh())
          setApplied(true)
        }}
      >
        Apply and refresh
      </button>
      {applied ? <div data-testid="study-applied">Applied</div> : null}
    </div>
  )
}

function OverviewDataProbe({ instance }: { instance: ApplicationInstance }) {
  const data = useOverviewData(instance)
  return (
    <div>
      <output data-testid="overview-activity-state">{data.sourceStates.activity}</output>
      <output data-testid="overview-activity-count">{data.activity.length}</output>
      <output data-testid="overview-activity-first">{data.activity[0]?.title ?? 'none'}</output>
      <output data-testid="overview-infrastructure-state">{data.sourceStates.infrastructure}</output>
      <output data-testid="overview-loading">{String(data.loading)}</output>
      <button type="button" onClick={data.refresh}>Refresh overview</button>
    </div>
  )
}

describe('App overview', () => {
  it(
    'does not present Ready while overview reads are pending',
    async () => {
      useScenarioStore.getState().setActive('service_slow')
      renderOverview('ins_study_alpha')
      const header = await screen.findByTestId('overview-header', undefined, { timeout: LONG })
      expect(header.querySelector('[data-state]')?.getAttribute('data-state')).toBe('blocked')
    },
    LONG,
  )

  it('retains each source last-good value when a later overview refresh partially fails', async () => {
    const user = userEvent.setup()
    const instance = buildSeed().instances.find(({ id }) => id === 'ins_cto_pilot')
    if (!instance) throw new Error('CTO Pilot fixture is missing from the mock seed.')
    const activity = vi.spyOn(getClient().activity, 'listActivity')
    render(<OverviewDataProbe instance={instance} />)

    await waitFor(() => expect(screen.getByTestId('overview-activity-state').textContent).toBe('fresh'), {
      timeout: LONG,
    })
    const initialCount = Number(screen.getByTestId('overview-activity-count').textContent)
    expect(initialCount).toBeGreaterThan(0)

    activity.mockRejectedValueOnce(new Error('activity projection unavailable'))
    await user.click(screen.getByRole('button', { name: 'Refresh overview' }))

    await waitFor(() => expect(screen.getByTestId('overview-activity-state').textContent).toBe('stale'), {
      timeout: LONG,
    })
    expect(screen.getByTestId('overview-activity-count').textContent).toBe(String(initialCount))
  }, LONG)

  it('binds recent activity rows to their exact receipt identities', async () => {
    renderOverview('ins_cto_pilot')

    const section = await screen.findByTestId('recent-activity-section', undefined, { timeout: LONG })
    const row = section.querySelector('[data-receipt-id="rcpt_0001"]')
    expect(row?.getAttribute('data-activity-id')).toBe('act_0002')
    expect(row?.textContent).toContain('File change saved')
  }, LONG)

  it('does not render the previous application overview while switching application keys', async () => {
    const cto = buildSeed().instances.find(({ id }) => id === 'ins_cto_pilot')
    const study = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')
    if (!cto || !study) throw new Error('Overview fixtures are missing from the mock seed.')
    const view = render(<OverviewDataProbe instance={cto} />)
    await waitFor(() => expect(screen.getByTestId('overview-activity-first').textContent).toBe('File change saved'), {
      timeout: LONG,
    })

    view.rerender(<OverviewDataProbe instance={study} />)
    expect(screen.getByTestId('overview-loading').textContent).toBe('true')
    expect(screen.getByTestId('overview-activity-first').textContent).toBe('none')
    await waitFor(() => expect(screen.getByTestId('overview-activity-first').textContent).toBe('Activity in progress'), {
      timeout: LONG,
    })
  }, LONG)

  it('requests goal-execution receipts only from CTO orchestration', async () => {
    const instance = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')
    if (!instance) throw new Error('StudyState fixture is missing from the mock seed.')
    const receipts = vi.spyOn(getClient().receipts, 'list')
    render(<OverviewDataProbe instance={instance} />)

    await waitFor(() => expect(screen.getByTestId('overview-activity-state').textContent).toBe('fresh'), {
      timeout: LONG,
    })
    expect(receipts.mock.calls.some(([filter]) => filter?.goalExecution === true)).toBe(false)

    receipts.mockClear()
    const cto = buildSeed().instances.find(({ id }) => id === 'ins_cto_pilot')
    if (!cto) throw new Error('CTO Pilot fixture is missing from the mock seed.')
    const view = render(<OverviewDataProbe instance={cto} />)
    await waitFor(() => expect(receipts.mock.calls.length).toBeGreaterThan(0), { timeout: LONG })
    expect(receipts.mock.calls.some(([filter]) => filter?.goalExecution === true)).toBe(true)
    view.unmount()
  }, LONG)

  it('does not expose native receipt links when resolved experience omits Receipts', async () => {
    const seeded = buildSeed().instances.find(({ id }) => id === 'ins_cto_pilot')
    if (!seeded) throw new Error('CTO Pilot fixture is missing from the mock seed.')
    const resolvedInstance: ApplicationInstance = {
      ...seeded,
      experienceResolution: 'resolved',
      experience: {
        formatVersion: 'stateport.application-experience-resolution/v1',
        applicationId: 'stateport.development-reference',
        views: [],
        navigation: [],
        advancedControls: [],
      },
    }
    vi.spyOn(getClient().applications, 'get').mockResolvedValue(resolvedInstance)
    renderOverview(resolvedInstance.id)

    await screen.findByTestId('app-overview-page', undefined, { timeout: LONG })
    expect(Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href*="/receipts"]')).map((link) => link.href)).toEqual([])
  }, LONG)

  it('keeps a valid null source value stale after a later read fails', async () => {
    const instance = buildSeed().instances.find(({ id }) => id === 'ins_nixos_infra')
    if (!instance) throw new Error('NixOS fixture is missing from the mock seed.')
    const target = vi.spyOn(getClient().infrastructure, 'getTarget').mockResolvedValue(null as never)
    const user = userEvent.setup()
    render(<OverviewDataProbe instance={instance} />)

    await waitFor(() => expect(screen.getByTestId('overview-infrastructure-state').textContent).toBe('fresh'), {
      timeout: LONG,
    })
    target.mockRejectedValueOnce(new Error('target projection unavailable'))
    await user.click(screen.getByRole('button', { name: 'Refresh overview' }))

    await waitFor(() => expect(screen.getByTestId('overview-infrastructure-state').textContent).toBe('stale'), {
      timeout: LONG,
    })
  }, LONG)

  it(
    'CTO Pilot: backup due is the dominant attention state (badge + fact), not restated',
    async () => {
      renderOverview('ins_cto_pilot')
      const header = await screen.findByTestId('overview-header', undefined, { timeout: LONG })
      expect(header.textContent).toContain('StatePort CTO Pilot')
      expect(header.textContent).toContain('ProjectState')
      // One dominant badge, honest attention state.
      expect(header.textContent).toContain('Backup due')

      // Facts strip carries the same state once, mapped as attention.
      const fact = await screen.findByTestId('fact-backup', undefined, { timeout: LONG })
      expect(fact.textContent).toContain('Backup due')
      expect(fact.querySelector('[data-state]')?.getAttribute('data-state')).toBe('attention')

      // Needs attention section lists the backup item with an acknowledge affordance.
      const section = await screen.findByTestId('overview-attention-section', undefined, { timeout: LONG })
      expect(section.textContent).toContain('Backup is due')

      // Recovery section offers the governed action.
      expect(screen.getByRole('button', { name: /back up now/i })).toBeTruthy()
    },
    LONG,
  )

  it.each(['delayed', 'error'] as const)(
    'does not open the saved tool when settings are %s during an early Continue click',
    async (mode) => {
      useWorkspaceStore.setState({ lastInstanceId: 'ins_cto_pilot', lastView: 'workbench', lastWorkbenchTool: 'files' })
      const client = getClient()
      const saved = await client.globalSettings.get()
      saved.navigation.restoreLastTool = false
      let resolve!: (value: typeof saved) => void
      let reject!: (reason?: unknown) => void
      const pending = new Promise<typeof saved>((done, fail) => { resolve = done; reject = fail })
      vi.spyOn(client.globalSettings, 'get').mockReturnValue(pending)
      const user = userEvent.setup()
      renderOverview('ins_cto_pilot')
      const header = await screen.findByTestId('overview-header', undefined, { timeout: LONG })
      await user.click(within(header).getByRole('button', { name: /continue in workbench/i }))
      await waitFor(() => expect(screen.getByTestId('current-path').textContent).toBe('/app/ins_cto_pilot/workbench'), { timeout: LONG })
      if (mode === 'delayed') resolve(saved)
      else reject(new Error('settings unavailable'))
    },
  )

  it(
    'CTO Pilot: Back up now runs through the client and recovery becomes current',
    async () => {
      const user = userEvent.setup()
      renderOverview('ins_cto_pilot')
      const button = await screen.findByRole('button', { name: /back up now/i }, { timeout: LONG })
      await user.click(button)

      await waitFor(
        () => expect(useSessionStore.getState().toasts.some((t) => t.title === 'Backup completed')).toBe(true),
        { timeout: LONG },
      )

      // Fresh client read proves the domain change persisted (after debounce).
      await waitFor(
        async () => {
          resetClientForTests()
          const instance = await getClient().applications.get('ins_cto_pilot')
          expect(instance.recovery.state).toBe('current')
        },
        { timeout: LONG },
      )
    },
    LONG * 2,
  )

  it(
    'CTO Pilot: provenance is human-first and exact identity stays behind disclosure',
    async () => {
      const user = userEvent.setup()
      renderOverview('ins_cto_pilot')
      const section = await screen.findByTestId('provenance-ownership-section', undefined, {
        timeout: LONG,
      })

      expect(section.textContent).toContain('Canonical release source')
      expect(section.textContent).toContain('Version 1.4.0')
      expect(within(section).getByTestId('ownership-count-template').textContent).toBe('3')
      expect(within(section).getByTestId('ownership-count-instance').textContent).toBe('2')
      expect(
        within(section).queryByText('https://github.com/example/project-state.git'),
      ).toBeNull()

      const disclosure = within(section).getByRole('button', {
        name: /exact identity and bounded paths/i,
      })
      expect(disclosure.getAttribute('aria-expanded')).toBe('false')
      await user.click(disclosure)
      expect(disclosure.getAttribute('aria-expanded')).toBe('true')

      const exact = within(section).getByTestId('provenance-exact-detail')
      expect(exact.textContent).toContain('https://github.com/example/project-state.git')
      expect(exact.textContent).toContain('Git commit')
      expect(exact.textContent).toContain('README.md')
      expect(exact.textContent).toContain('.statedd/lock.yaml')
    },
    LONG,
  )

  it(
    'StudyState Alpha: shows learning goal and evidence progress, and NO workbench actions',
    async () => {
      renderOverview('ins_study_alpha')
      const section = await screen.findByTestId('study-section', undefined, { timeout: LONG })
      expect(section.textContent).toContain('Pass the NixOS fundamentals assessment')
      expect(section.textContent).toContain('62% toward goal')
      expect(section.textContent).toContain('1 of 3 evidence items verified')
      expect(section.textContent).toContain('Read: modules and options')

      // Header: wait for the overview reads before asserting the quiet Ready
      // state; generic Conversation is secondary so the
      // state-derived learning action owns the page's primary hierarchy.
      const header = await screen.findByTestId('overview-header', undefined, { timeout: LONG })
      await waitFor(() => expect(header.querySelector('[data-state]')?.getAttribute('data-state')).toBe('success'), {
        timeout: LONG,
      })
      expect(screen.queryByRole('button', { name: /open conversation — studystate alpha/i })).toBeNull()
      expect(screen.getByRole('button', { name: 'Conversation' }).getAttribute('data-variant')).toBe('outline')

      // The workbench capability is unavailable → no workbench action anywhere.
      expect(screen.queryByRole('button', { name: /workbench/i })).toBeNull()
      expect(screen.queryByRole('link', { name: /workbench/i })).toBeNull()
      const quickLinks = screen.getByTestId('quick-links')
      expect(within(quickLinks).getByRole('link', { name: 'Receipts' }).getAttribute('href')).toBe(
        '/app/ins_study_alpha/receipts',
      )
      expect(document.querySelectorAll('a[href*="/workbench"]').length).toBe(0)

      // StudyState has no backup capability → no backup action/command either.
      expect(screen.queryByRole('button', { name: /back up now/i })).toBeNull()
      const ids = Object.keys(useCommandStore.getState().commands)
      expect(ids).toContain('app.toggle_pin')
      expect(ids).not.toContain('app.run_backup')
      expect(ids).not.toContain('app.open_approvals')
    },
    LONG,
  )

  it(
    'keeps the same-instance success state mounted while refreshing durable state',
    async () => {
      const user = userEvent.setup()
      const instance = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')
      if (!instance) throw new Error('StudyState fixture is missing from the mock seed.')
      vi.spyOn(getClient().applications, 'get')
        .mockResolvedValueOnce(instance)
        .mockImplementationOnce(() => new Promise<ApplicationInstance>(() => undefined))

      render(
        <MemoryRouter initialEntries={[`/app/${instance.id}`]}>
          <Routes>
            <Route path="/app/:instanceId" element={<AppContextShell />}>
              <Route index element={<SameInstanceRefreshProbe />} />
            </Route>
          </Routes>
        </MemoryRouter>,
      )
      await user.click(await screen.findByRole('button', { name: 'Apply and refresh' }, { timeout: LONG }))

      expect(await screen.findByTestId('study-applied', undefined, { timeout: LONG })).toBeTruthy()
      expect(screen.queryByTestId('app-loading')).toBeNull()
    },
    LONG,
  )

  it(
    'ChecklistState Sample: checklist renders with honest progress and item toggling persists',
    async () => {
      const user = userEvent.setup()
      renderOverview('ins_checklist_sample')
      const section = await screen.findByTestId('checklist-section', undefined, { timeout: LONG })
      expect(section.textContent).toContain('2 of 5 complete')
      expect(section.textContent).toContain('Next up:')
      expect(section.textContent).toContain('Open the receipt for the change')

      // Toggle the next unchecked item — optimistic, persisted in the feature store.
      const checkbox = await screen.findByRole('checkbox', { name: 'Open the receipt for the change' }, { timeout: LONG })
      await user.click(checkbox)
      await waitFor(() => {
        expect(useApplicationsPrefs.getState().checklistDoneOverrides['ins_checklist_sample:chk_3']).toBe(true)
      })
      expect((await screen.findByTestId('checklist-section')).textContent).toContain('3 of 5 complete')

      // The local override is explicitly labelled — never presented as
      // recorded application state — and can be reset.
      const draftNote = await screen.findByTestId('checklist-local-draft')
      expect(draftNote.textContent).toContain('stored in this browser only')
      await user.click(within(draftNote).getByRole('button', { name: /reset to application state/i }))
      await waitFor(() => {
        expect(useApplicationsPrefs.getState().checklistDoneOverrides['ins_checklist_sample:chk_3']).toBeUndefined()
      })
      expect(screen.queryByTestId('checklist-local-draft')).toBeNull()

      // Recovery honestly says not configured; no backup button.
      expect(screen.getByTestId('recovery-section').textContent).toContain('Not configured')
      expect(screen.queryByRole('button', { name: /back up now/i })).toBeNull()
    },
    LONG,
  )

  it(
    'NixOS Infrastructure: stopped VM is neutral, pending approval is dominant, commands register',
    async () => {
      renderOverview('ins_nixos_infra')
      // Wait for overview data (approvals drive the dominant badge).
      const vm = await screen.findByTestId('target-vm', undefined, { timeout: LONG })
      const header = await screen.findByTestId('overview-header', undefined, { timeout: LONG })
      await waitFor(() => expect(header.textContent).toContain('Awaiting approval'), { timeout: LONG })
      expect(header.textContent).toContain('NixOS Infrastructure')
      expect(vm.textContent).toContain('Stopped')
      expect(vm.querySelector('[data-state]')?.getAttribute('data-state')).toBe('neutral')
      const ssh = screen.getByTestId('target-ssh')
      expect(ssh.textContent).toContain('SSH unavailable — VM stopped')
      expect(ssh.querySelector('[data-state]')?.getAttribute('data-state')).toBe('neutral')

      // Repository line is present and clean.
      const project = screen.getByTestId('project-section')
      expect(project.textContent).toContain('nixos-homelab')
      expect(project.textContent).toContain('Clean')

      // The pending approval surfaces in Needs attention.
      const section = await screen.findByTestId('overview-attention-section', undefined, { timeout: LONG })
      expect(section.textContent).toContain('Start virtual machine')
      // De-duplicated: the raw "approval waiting" attention item is not doubled.
      expect(section.textContent).not.toContain('One approval is waiting')

      // Contextual commands: pin, approvals for this app, run backup.
      const ids = Object.keys(useCommandStore.getState().commands)
      expect(ids).toContain('app.toggle_pin')
      expect(ids).toContain('app.open_approvals')
      expect(ids).toContain('app.run_backup')
    },
    LONG,
  )

  it(
    'keeps the legacy app-overview-stub alias for the shell route-smoke test',
    async () => {
      renderOverview('ins_cto_pilot')
      expect(await screen.findByTestId('app-overview-stub', undefined, { timeout: LONG })).toBeTruthy()
      expect(screen.getByTestId('app-overview-page')).toBeTruthy()
    },
    LONG,
  )
})
