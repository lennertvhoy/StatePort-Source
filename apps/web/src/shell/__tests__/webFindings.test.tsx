/**
 * Web findings proven by the e2e matrix (stale same-session views, axe
 * aria-required-children on the empty sidebar list, keyboard bypass, honest
 * settings storage). Each test fails on the pre-fix code.
 */
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { getClient, resetClientForTests } from '@/client'
import type { ApplicationInstance } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useWorkspaceStore } from '@/state'
import SettingsPage from '@/features/settings/SettingsPage'

import { AppContextShell } from '../AppContextShell'
import { AppShell } from '../AppShell'
import { invalidateInstanceCache, notifyApplicationsChanged } from '../data'
import { Sidebar } from '../Sidebar'
import { useCurrentInstance } from '../currentInstance'

const seeded = buildSeed().instances.find((row) => row.id === 'ins_cto_pilot')!

function setDesktop() {
  Object.defineProperty(window, 'innerWidth', { configurable: true, writable: true, value: 1440 })
  window.matchMedia = (query: string): MediaQueryList => {
    const max = /^\(max-width: (\d+)px\)$/.exec(query)
    const min = /^\(min-width: (\d+)px\)$/.exec(query)
    const matches = max ? 1440 <= Number(max[1]) : min ? 1440 >= Number(min[1]) : false
    return {
      matches, media: query, onchange: null,
      addEventListener: () => undefined, removeEventListener: () => undefined,
      addListener: () => undefined, removeListener: () => undefined, dispatchEvent: () => false,
    }
  }
}

beforeEach(() => {
  resetClientForTests()
  invalidateInstanceCache()
  setDesktop()
  useWorkspaceStore.setState({ sidebar: 'expanded', sidebarUserChosen: true, sidebarAutoCollapseBelowPx: 1200 })
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  invalidateInstanceCache()
  resetClientForTests()
})

describe('sidebar catalog freshness', () => {
  it('lists an application installed after first render without a reload', async () => {
    let installed = false
    vi.spyOn(getClient().applications, 'list').mockImplementation(async () => (installed ? [seeded] : []))
    render(<MemoryRouter><Sidebar /></MemoryRouter>)
    expect(await screen.findByText(/No applications yet/)).toBeTruthy()

    installed = true
    act(() => notifyApplicationsChanged())

    expect(await screen.findByRole('link', { name: new RegExp(seeded.name) })).toBeTruthy()
    expect(screen.queryByText(/No applications yet/)).toBeNull()
  })

  it('keeps the empty hint out of the list role and passes axe aria-required-children', async () => {
    vi.spyOn(getClient().applications, 'list').mockResolvedValue([])
    const { container } = render(<MemoryRouter><Sidebar /></MemoryRouter>)
    const hint = await screen.findByText(/No applications yet/)
    expect(hint.closest('[role="list"]')).toBeNull()
    expect(screen.queryByRole('list', { name: 'Pinned and recent applications' })).toBeNull()
    const result = await axe.run(container, { runOnly: ['aria-required-children'] })
    expect(result.violations).toEqual([])
    // Secondary text, not tertiary: tertiary is 4.16:1 on the light sidebar.
    expect(hint.className).toContain('text-foreground-secondary')
    expect(hint.className).not.toContain('text-foreground-tertiary')
  })

  it('renders each application as a real link inside a listitem', async () => {
    vi.spyOn(getClient().applications, 'list').mockResolvedValue([seeded])
    const { container } = render(<MemoryRouter><Sidebar /></MemoryRouter>)
    const link = await screen.findByRole('link', { name: new RegExp(seeded.name) })
    expect(link.parentElement?.getAttribute('role')).toBe('listitem')
    const result = await axe.run(container, { runOnly: ['aria-required-children', 'aria-required-parent'] })
    expect(result.violations).toEqual([])
  })
})

describe('application context refresh', () => {
  function Probe() {
    const { instance, refresh } = useCurrentInstance()
    return (
      <div>
        <span data-testid="state">{instance?.recovery.state ?? 'none'}</span>
        <button onClick={refresh}>refresh</button>
      </div>
    )
  }

  it('re-reads the service after refresh() instead of returning the cached instance', async () => {
    const due: ApplicationInstance = { ...seeded, recovery: { ...seeded.recovery, state: 'due', lastBackupAt: undefined } }
    const current_: ApplicationInstance = { ...seeded, recovery: { ...seeded.recovery, state: 'current' } }
    let current = due
    const get = vi.spyOn(getClient().applications, 'get').mockImplementation(async () => current)
    vi.spyOn(getClient().applications, 'touchOpened').mockResolvedValue(undefined)
    render(
      <MemoryRouter initialEntries={[`/app/${seeded.id}/settings`]}>
        <Routes>
          <Route path="/app/:instanceId/*" element={<AppContextShell><Probe /></AppContextShell>} />
        </Routes>
      </MemoryRouter>,
    )
    await waitFor(() => expect(screen.getByTestId('state').textContent).toBe('due'))

    current = current_ // the backup landed on the service
    fireEvent.click(screen.getByRole('button', { name: 'refresh' }))

    await waitFor(() => expect(screen.getByTestId('state').textContent).toBe('current'))
    expect(get.mock.calls.length).toBeGreaterThanOrEqual(2)
  })
})

describe('keyboard bypass', () => {
  it('makes the skip link the first Tab stop and moves focus into main without changing the route', async () => {
    render(
      <MemoryRouter initialEntries={['/applications']}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/applications" element={<button>Open the study sample</button>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )
    const skip = await screen.findByTestId('skip-to-content')
    const shell = screen.getByTestId('app-shell')
    const firstFocusable = shell.querySelector<HTMLElement>('a[href], button:not([disabled]), input, [tabindex="0"]')
    expect(firstFocusable).toBe(skip)

    const clicked = fireEvent.click(skip)
    expect(clicked).toBe(false) // default prevented: no hash navigation under the hash router
    expect(document.activeElement).toBe(document.getElementById('main-content'))
    expect(window.location.hash).not.toContain('main-content')
    // The next focusable inside main is the page's primary action.
    const main = document.getElementById('main-content')!
    expect(main.querySelector('button')?.textContent).toBe('Open the study sample')
  })
})

describe('settings storage honesty', () => {
  it('says where settings are stored', async () => {
    render(
      <MemoryRouter initialEntries={['/settings/appearance']}>
        <Routes>
          <Route path="/settings/:group?" element={<SettingsPage />} />
        </Routes>
      </MemoryRouter>,
    )
    const note = await screen.findByTestId('settings-storage-note')
    expect(note.textContent).toMatch(/stored in this browser/i)
  })
})
