/**
 * Sidebar acceptance follow-up:
 * - the collapsed rail pins Expand as its first visible control, with no
 *   bottom duplicate;
 * - the auto-collapse threshold comes from the saved navigation setting, not
 *   a hardcoded breakpoint;
 * - the saved sidebar default applies as a default, never as a permanent
 *   explicit user override;
 * - startup reconciliation respects an explicit user sidebar choice.
 */
import { act, cleanup, render, renderHook, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import { getClient, resetClientForTests, resetMockState } from '@/client'
import type { GlobalSettings } from '@/client'
import { useWorkspaceStore } from '@/state'
import { applySavedSettingsToWorkspace } from '@/features/settings/model'

import { useSavedNavigationSettings } from '../data'
import { useIsBelowSidebarThreshold } from '../platform'
import { Sidebar } from '../Sidebar'

function setViewportWidth(px: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, writable: true, value: px })
  window.matchMedia = (query: string): MediaQueryList => {
    const max = /^\(max-width: (\d+)px\)$/.exec(query)
    const min = /^\(min-width: (\d+)px\)$/.exec(query)
    const matches = max ? px <= Number(max[1]) : min ? px >= Number(min[1]) : false
    return {
      matches,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }
  }
}

async function baseSettings(): Promise<GlobalSettings> {
  return getClient().globalSettings.get()
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  setViewportWidth(1440)
  useWorkspaceStore.setState({
    sidebar: 'expanded',
    sidebarUserChosen: false,
    sidebarAutoCollapseBelowPx: 1200,
  })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('collapsed rail', () => {
  it('pins Expand sidebar as the first rail control with no bottom duplicate', () => {
    useWorkspaceStore.setState({ sidebar: 'collapsed', sidebarUserChosen: true })
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    )
    const rail = screen.getByTestId('sidebar-rail')
    const expandButtons = screen.getAllByLabelText('Expand sidebar')
    expect(expandButtons).toHaveLength(1)
    const firstFocusable = rail.querySelector('button, a')
    expect(firstFocusable).toBe(expandButtons[0])
    // The home/brand control follows immediately after.
    const secondFocusable = rail.querySelectorAll('button, a')[1]
    expect(secondFocusable?.getAttribute('aria-label')).toBe('StatePort — Applications')
  })
})

describe('useIsBelowSidebarThreshold', () => {
  it('uses the saved auto-collapse width, not a hardcoded breakpoint', () => {
    setViewportWidth(1000)
    useWorkspaceStore.setState({ sidebarAutoCollapseBelowPx: 1200 })
    const wide = renderHook(() => useIsBelowSidebarThreshold())
    expect(wide.result.current).toBe(true)
    wide.unmount()

    // A narrower configured threshold keeps the same window expanded.
    act(() => {
      useWorkspaceStore.getState().setSidebarAutoCollapseBelowPx(800)
    })
    const narrow = renderHook(() => useIsBelowSidebarThreshold())
    expect(narrow.result.current).toBe(false)
  })
})

describe('applySavedSettingsToWorkspace', () => {
  it('applies the sidebar default and threshold without pinning an explicit user choice', async () => {
    const settings = await baseSettings()
    settings.navigation.sidebarDefault = 'collapsed'
    settings.navigation.autoCollapseBelowPx = 1000
    applySavedSettingsToWorkspace(settings)
    const workspace = useWorkspaceStore.getState()
    expect(workspace.sidebar).toBe('collapsed')
    expect(workspace.sidebarUserChosen).toBe(false)
    expect(workspace.sidebarAutoCollapseBelowPx).toBe(1000)
  })
})

describe('useSavedNavigationSettings', () => {
  it('applies the saved default only when the user made no explicit choice', async () => {
    const settings = await baseSettings()
    settings.navigation.sidebarDefault = 'collapsed'
    settings.navigation.autoCollapseBelowPx = 900
    vi.spyOn(getClient().globalSettings, 'get').mockResolvedValue(settings)

    useWorkspaceStore.setState({ sidebar: 'expanded', sidebarUserChosen: false })
    renderHook(() => useSavedNavigationSettings())
    await act(async () => {})
    expect(useWorkspaceStore.getState().sidebar).toBe('collapsed')
    expect(useWorkspaceStore.getState().sidebarUserChosen).toBe(false)
    expect(useWorkspaceStore.getState().sidebarAutoCollapseBelowPx).toBe(900)
  })

  it('keeps an explicit user choice but still applies the threshold', async () => {
    const settings = await baseSettings()
    settings.navigation.sidebarDefault = 'collapsed'
    settings.navigation.autoCollapseBelowPx = 900
    vi.spyOn(getClient().globalSettings, 'get').mockResolvedValue(settings)

    useWorkspaceStore.setState({ sidebar: 'expanded', sidebarUserChosen: true })
    renderHook(() => useSavedNavigationSettings())
    await act(async () => {})
    expect(useWorkspaceStore.getState().sidebar).toBe('expanded')
    expect(useWorkspaceStore.getState().sidebarAutoCollapseBelowPx).toBe(900)
  })

  it('keeps local values when settings cannot be loaded', async () => {
    vi.spyOn(getClient().globalSettings, 'get').mockRejectedValue(new Error('offline'))
    useWorkspaceStore.setState({ sidebar: 'expanded', sidebarUserChosen: false, sidebarAutoCollapseBelowPx: 1100 })
    renderHook(() => useSavedNavigationSettings())
    await act(async () => {})
    expect(useWorkspaceStore.getState().sidebar).toBe('expanded')
    expect(useWorkspaceStore.getState().sidebarAutoCollapseBelowPx).toBe(1100)
  })
})
