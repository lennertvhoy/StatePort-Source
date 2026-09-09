/**
 * Settings surface tests (settings.md binding rules):
 * - human labels instead of raw enum values (no `environment_gated` on screen)
 * - read-only effective values render as text, never disabled inputs
 * - the save bar appears only while dirty (save + discard paths)
 * - shortcut conflict detection is surfaced, and “Reassign anyway” resolves it
 * - appearance edits live-preview into the workspace store
 * - settings search finds “font size” and jumps to the group
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { format } from 'date-fns'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { ClientError, getClient, resetClientForTests } from '@/client'
import { useSessionStore, useShortcutsStore, useWorkspaceStore } from '@/state'
import { AppContextShell } from '@/shell/AppContextShell'
import { useCommandStore } from '@/shell/commands'
import { invalidateInstanceCache } from '@/shell/data'

import SettingsPage from '../SettingsPage'

function renderGlobal(initial: string) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/settings/:group" element={<SettingsPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

function renderAppSettings(instanceId: string, group?: string) {
  const search = group ? `?group=${group}` : ''
  return render(
    <MemoryRouter initialEntries={[`/app/${instanceId}/settings${search}`]}>
      <Routes>
        <Route path="/app/:instanceId" element={<AppContextShell />}>
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
  invalidateInstanceCache()
  useWorkspaceStore.setState({
    sidebar: 'expanded',
    sidebarUserChosen: false,
    theme: 'system',
    density: 'compact',
    fontScale: 100,
    highContrast: false,
    highContrastBase: 'dark',
    reducedMotion: false,
    disableNonessentialAnimation: false,
    strongFocus: false,
    notificationQuietMode: false,
    notificationImportantOnly: false,
  })
  useShortcutsStore.setState({ overrides: {} })
})

afterEach(() => {
  cleanup()
})

describe('settings: human labels (settings.md — no raw enums)', () => {
  it('capabilities show “Unavailable in this environment”, never the raw enum', async () => {
    // ins_cto_pilot seeds infrastructure as environment_gated.
    renderAppSettings('ins_cto_pilot', 'capabilities')
    expect(await screen.findByText('Unavailable in this environment', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(screen.queryByText(/environment_gated/)).toBeNull()
    // Human capability names, not ids.
    expect(screen.getByText('Infrastructure')).toBeTruthy()
  }, 15_000)

  it('appearance renders human theme labels, not raw values', async () => {
    renderGlobal('/settings/appearance')
    expect(await screen.findByText('Follow system', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(screen.getByText('High contrast')).toBeTruthy()
    expect(screen.queryByText('high_contrast')).toBeNull()
    expect(screen.queryByText('match_interface')).toBeNull()
  }, 15_000)
})

describe('settings: read-only effective values', () => {
  it('reports an application pin failure without changing the displayed preference', async () => {
    vi.spyOn(getClient().applications, 'setPinned').mockRejectedValue(new Error('Browser storage is full'))
    const toast = vi.spyOn(useSessionStore.getState(), 'pushToast')
    renderAppSettings('ins_cto_pilot', 'general')
    const toggle = await screen.findByRole('switch', { name: 'Pinned' })
    const before = toggle.getAttribute('aria-checked')
    fireEvent.click(toggle)
    await waitFor(() => expect(toast).toHaveBeenCalledWith({
      kind: 'error', title: 'Pin preference could not be saved', body: 'Browser storage is full',
    }))
    expect(toggle.getAttribute('aria-checked')).toBe(before)
  })

  it('adapter mode renders as wrapping text with no disabled input', async () => {
    renderGlobal('/settings/advanced')
    await screen.findByText(/Mock \(built-in simulation\)/, undefined, { timeout: 10_000 })
    // The adapter row contains no form control at all — text + copy button only.
    const adapterRow = document.getElementById('setting-adapter-mode')
    expect(adapterRow).toBeTruthy()
    expect(adapterRow!.textContent).toContain('Mock (built-in simulation)')
    expect(adapterRow!.querySelector('input, select, textarea')).toBeNull()
    expect(within(adapterRow as HTMLElement).queryByRole('textbox')).toBeNull()

    const endpointRow = document.getElementById('setting-endpoint')
    expect(endpointRow).toBeTruthy()
    expect(endpointRow!.textContent).toContain('Built-in simulation')
    expect(endpointRow!.querySelector('input, select, textarea')).toBeNull()
  }, 15_000)

  it('presents file and terminal context selection as enforced boundaries, not unsupported toggles', async () => {
    renderGlobal('/settings/privacy')
    await screen.findByTestId('settings-group-privacy', undefined, { timeout: 10_000 })

    expect(screen.getByText(/Default context chips are configured under Conversation/)).toBeTruthy()
    const fileBoundary = document.getElementById('setting-selected-files-only')
    const terminalBoundary = document.getElementById('setting-selected-terminal-only')
    expect(fileBoundary?.textContent).toContain('Selected files only — enforced')
    expect(terminalBoundary?.textContent).toContain('Selected terminal output only — enforced')
    expect(fileBoundary?.querySelector('input, button, select, textarea')).toBeNull()
    expect(terminalBoundary?.querySelector('input, button, select, textarea')).toBeNull()
    expect(screen.queryByRole('switch', { name: /Include selected files only/i })).toBeNull()
    expect(screen.queryByRole('switch', { name: /Include selected terminal output only/i })).toBeNull()
    expect(screen.queryByText('Default model context')).toBeNull()
  }, 15_000)

})

describe('settings: browser-storage privacy boundary', () => {
  it('inventories and clears all StatePort-prefixed browser keys without a backend mutation', async () => {
    window.localStorage.setItem('stateport.future-feature.v9', 'future local state')
    window.localStorage.setItem('another.product.v1', 'preserve')
    window.sessionStorage.setItem('stateport.future-session.v1', 'future tab state')
    window.sessionStorage.setItem('another.session.v1', 'preserve')

    renderGlobal('/settings/privacy')
    const inventory = await screen.findByTestId(
      'browser-storage-inventory',
      undefined,
      { timeout: 10_000 },
    )
    expect(screen.getAllByText('Browser storage inventory').length).toBeGreaterThan(0)
    expect(inventory.textContent).toContain('stateport.workspace.v1')
    expect(inventory.textContent).toContain('stateport.terminal.tabs.v1')
    expect(inventory.textContent).toContain('stateport.future-feature.v9')
    expect(inventory.textContent).toContain('stored now · unclassified')
    expect(inventory.textContent).toContain(
      'Scenario Lab uses no production service credential',
    )
    expect(inventory.textContent).toContain(
      'Live terminal output, unsaved file contents, credentials, and provider tokens are not persisted',
    )
    expect(screen.getByText('Export settings, drafts & search history')).toBeTruthy()
    expect(screen.queryByText('Export local data')).toBeNull()

    const client = getClient()
    const update = vi.spyOn(client.globalSettings, 'update')
    const reset = vi.spyOn(client.globalSettings, 'reset')
    const resetMockState = vi.spyOn(client.scenario, 'resetMockState')

    fireEvent.click(screen.getByTestId('clear-browser-data'))
    const dialog = await screen.findByTestId('confirm-dialog')
    expect(dialog.textContent).toContain('No service request is made')
    expect(dialog.textContent).toContain(
      'Backend-owned application state, conversations, attachments, approvals, receipts, and settings are unchanged',
    )
    const confirm = screen.getByTestId('confirm-action') as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    fireEvent.change(screen.getByTestId('confirm-typed-input'), {
      target: { value: 'clear' },
    })
    expect(confirm.disabled).toBe(false)
    fireEvent.click(confirm)

    await waitFor(() => {
      expect(
        Array.from({ length: window.localStorage.length }, (_, index) =>
          window.localStorage.key(index),
        ).filter((key) => key?.startsWith('stateport.')),
      ).toEqual([])
      expect(
        Array.from({ length: window.sessionStorage.length }, (_, index) =>
          window.sessionStorage.key(index),
        ).filter((key) => key?.startsWith('stateport.')),
      ).toEqual([])
    })
    expect(window.localStorage.getItem('another.product.v1')).toBe('preserve')
    expect(window.sessionStorage.getItem('another.session.v1')).toBe('preserve')
    expect(update).not.toHaveBeenCalled()
    expect(reset).not.toHaveBeenCalled()
    expect(resetMockState).not.toHaveBeenCalled()
    expect(window.location.hash).toBe('')
    expect(screen.getByTestId('browser-storage-inventory').textContent).toContain(
      '0 StatePort browser keys currently stored',
    )
  }, 20_000)

  it('states exactly what turning draft persistence off retains', async () => {
    useWorkspaceStore.setState({
      drafts: { 'conversation-one': 'an existing saved draft' },
    })
    await getClient().globalSettings.update({
      conversation: { draftPersistence: false },
    })

    renderGlobal('/settings/privacy')
    const notice = await screen.findByTestId(
      'draft-persistence-off',
      undefined,
      { timeout: 10_000 },
    )
    expect(notice.textContent).toContain(
      'Draft persistence is off. New composer text stays in memory only.',
    )
    expect(notice.textContent).toContain(
      '1 previously saved draft remains until you clear it below.',
    )

    cleanup()
    renderGlobal('/settings/conversation')
    await screen.findByTestId('settings-group-conversation', undefined, {
      timeout: 10_000,
    })
    expect(
      document.getElementById('setting-drafts')?.textContent,
    ).toContain(
      'Turning this off stops future persistence but does not delete drafts already saved',
    )
  }, 20_000)
})

describe('settings: backend-owned global history', () => {
  it('confirms an exact receipt and rolls back only backend-owned values', async () => {
    const client = getClient()
    await client.globalSettings.update({
      appearance: { theme: 'dark' },
      editor: { fontSize: 19 },
    })

    renderGlobal('/settings/advanced')
    await screen.findByText(/Current backend revision/, undefined, { timeout: 10_000 })
    const history = screen.getByTestId('global-settings-history')
    expect(history.textContent).toContain('Current backend revision 1')
    expect(history.textContent).toContain('Backend settings change')
    expect(history.textContent).toContain('Appearance')
    expect(history.textContent).not.toContain('Font size')
    expect(screen.getByText(/Browser-only presentation preferences/)).toBeTruthy()

    const rollback = await screen.findByTestId(/^settings-rollback-/)
    const receiptId = rollback.getAttribute('data-testid')!.replace('settings-rollback-', '')
    fireEvent.click(rollback)

    const dialog = await screen.findByTestId('confirm-dialog')
    expect(dialog.textContent).toContain(`Global settings receipt ${receiptId} (revision 1)`)
    expect(dialog.textContent).toContain('current backend revision 1')
    expect(dialog.textContent).toContain('Appearance (general.appearance): dark → system')
    expect(dialog.textContent).toContain('Browser-only preferences and application settings are not affected')

    fireEvent.click(screen.getByTestId('confirm-action'))
    await waitFor(
      () => expect(screen.getByTestId('global-settings-history').textContent).toContain('Current backend revision 2'),
      { timeout: 10_000 },
    )

    const restored = await client.globalSettings.get()
    expect(restored.appearance.theme).toBe('system')
    // Browser-only editor preferences are outside the rollback receipt.
    expect(restored.editor.fontSize).toBe(19)
  }, 25_000)

  it('surfaces a stale revision refusal instead of retrying or hiding it', async () => {
    const client = getClient()
    await client.globalSettings.update({ appearance: { theme: 'dark' } })
    renderGlobal('/settings/advanced')

    const rollback = await screen.findByTestId(/^settings-rollback-/, undefined, { timeout: 10_000 })
    // The service rejects this exact-revision request because another process
    // changed backend-owned settings after the projection was loaded.
    vi.spyOn(client.globalSettings, 'rollback').mockRejectedValueOnce(
      new ClientError(
        'http',
        'Settings changed since you loaded them — reload and try again',
        { status: 409, code: 'settings_revision_stale' },
      ),
    )
    fireEvent.click(rollback)
    fireEvent.click(await screen.findByTestId('confirm-action'))

    const refusal = await screen.findByText('Rollback refused', undefined, { timeout: 10_000 })
    expect(refusal.parentElement?.textContent).toContain('Settings changed since you loaded them')
    expect(screen.getByRole('button', { name: 'Reload current history' })).toBeTruthy()
  }, 25_000)
})

describe('settings: application context lifecycle', () => {
  it('shows backend-owned identities without presenting context as canonical state', async () => {
    renderAppSettings('ins_cto_pilot', 'context')

    const surface = await screen.findByTestId('app-settings-context-lifecycle', undefined, { timeout: 10_000 })
    expect(surface.textContent).toContain('Operational context, not application truth')
    expect(surface.textContent).toContain('Not accepted by this contract')
    expect(surface.textContent).toContain('Effective policy digest')
    expect(surface.textContent).toContain('Maximum input budget')
    expect(surface.textContent).toContain('Included categories')
    expect(surface.textContent).toContain('provider credentials')
    expect(surface.textContent).toContain('Repository identity')
    expect(surface.textContent).toContain('Candidate default — not benchmarked')
    expect(surface.textContent).toContain('Expected base commit')
    expect(surface.textContent).toContain('Continuity digest')
    expect(surface.textContent).toContain('Scenario context composition')
    expect(screen.getByTestId('context-compact')).toBeTruthy()
    expect(screen.getByTestId('context-handoff')).toBeTruthy()
  }, 15_000)

  it('updates preference and records an exact-identity handoff receipt', async () => {
    renderAppSettings('ins_cto_pilot', 'context')

    const preference = (await screen.findByRole('combobox', { name: 'Context depth' }, { timeout: 10_000 })) as HTMLSelectElement
    expect(preference.value).toBe('balanced')
    fireEvent.change(preference, { target: { value: 'faster' } })
    await waitFor(() => expect(preference.value).toBe('faster'))

    fireEvent.click(screen.getByTestId('context-handoff'))
    expect(await screen.findByText('Create context handoff?')).toBeTruthy()
    fireEvent.click(screen.getByTestId('confirm-action'))

    const receipt = await screen.findByTestId('context-transition-receipt')
    expect(receipt.textContent).toMatch(/^Receipt: \S+$/)
    expect(screen.getAllByText(/canonical state/i).length).toBeGreaterThan(0)
  }, 20_000)
})

describe('settings: dirty save bar', () => {
  it('appears only after an edit; save persists through the client', async () => {
    renderGlobal('/settings/general')
    const toggle = await screen.findByRole('switch', { name: 'Show recent applications' }, { timeout: 10_000 })
    expect(screen.queryByTestId('settings-save-bar')).toBeNull()

    fireEvent.click(toggle)
    expect(await screen.findByTestId('settings-save-bar')).toBeTruthy()

    fireEvent.click(screen.getByTestId('settings-save'))
    await waitFor(() => expect(screen.queryByTestId('settings-save-bar')).toBeNull(), { timeout: 10_000 })

    const saved = await getClient().globalSettings.get()
    expect(saved.general.showRecentApplications).toBe(false)
    // The switch reflects the saved value.
    expect(screen.getByRole('switch', { name: 'Show recent applications' }).getAttribute('data-state')).toBe('unchecked')
  }, 20_000)

  it('discard rolls the draft back and hides the bar', async () => {
    renderGlobal('/settings/general')
    const toggle = await screen.findByRole('switch', { name: 'Show recent applications' }, { timeout: 10_000 })
    expect(toggle.getAttribute('data-state')).toBe('checked')

    fireEvent.click(toggle)
    expect(await screen.findByTestId('settings-save-bar')).toBeTruthy()
    fireEvent.click(screen.getByTestId('settings-discard'))

    await waitFor(() => expect(screen.queryByTestId('settings-save-bar')).toBeNull())
    expect(screen.getByRole('switch', { name: 'Show recent applications' }).getAttribute('data-state')).toBe('checked')
    const saved = await getClient().globalSettings.get()
    expect(saved.general.showRecentApplications).toBe(true)
  }, 20_000)
})

describe('settings: shortcuts', () => {
  it('detects a conflict, names it, and “Reassign anyway” resolves it', async () => {
    renderGlobal('/settings/shortcuts')
    const rebind = await screen.findByTestId('shortcut-rebind-global.command_palette', undefined, { timeout: 10_000 })
    fireEvent.click(rebind)

    const capture = await screen.findByTestId('shortcut-capture-global.command_palette')
    // mod+p is “Quick open” in the same (global) scope.
    fireEvent.keyDown(capture, { key: 'p', ctrlKey: true })

    // Inline conflict error naming the other command + the escape hatch.
    expect(await screen.findByText(/Conflicts with “Quick open”/)).toBeTruthy()
    const reassign = await screen.findByTestId('shortcut-reassign-anyway')
    fireEvent.click(reassign)

    await waitFor(() => {
      expect(useShortcutsStore.getState().keysFor('global.command_palette')).toBe('mod+p')
    })
    // The displaced default was moved to a free chord, not left conflicting.
    expect(useShortcutsStore.getState().keysFor('global.quick_open')).not.toBe('mod+p')
    const views = useShortcutsStore.getState().list()
    expect(views.every((v) => v.conflictWith === null)).toBe(true)
  }, 15_000)

  it('shows platform-aware labels and lists every command', async () => {
    renderGlobal('/settings/shortcuts')
    expect(await screen.findByTestId('shortcut-search', undefined, { timeout: 10_000 })).toBeTruthy()
    // jsdom is non-mac → Ctrl style labels.
    expect(screen.getAllByText('Ctrl+K').length).toBeGreaterThan(0)
    const rows = screen.getAllByTestId(/^shortcut-rebind-/)
    expect(rows.length).toBe(useShortcutsStore.getState().list().length)
  }, 15_000)
})

describe('settings: appearance live preview', () => {
  it('previews and discards decorative-animation removal independently of reduced motion', async () => {
    renderGlobal('/settings/accessibility')
    const row = await screen.findByText('Disable nonessential animation')
    const toggle = within(row.closest('[data-setting-anchor]') as HTMLElement).getByRole('switch')
    fireEvent.click(toggle)
    await waitFor(() => expect(useWorkspaceStore.getState().disableNonessentialAnimation).toBe(true))
    expect(useWorkspaceStore.getState().reducedMotion).toBe(false)
    fireEvent.click(screen.getByTestId('settings-discard'))
    await waitFor(() => expect(useWorkspaceStore.getState().disableNonessentialAnimation).toBe(false))
  })

  it('previews, discards and saves the high-contrast fallback base', async () => {
    await getClient().globalSettings.update({ appearance: { theme: 'high_contrast', highContrastBase: 'dark' } })
    renderGlobal('/settings/appearance')
    fireEvent.click(await screen.findByRole('radio', { name: 'Light base' }))
    await waitFor(() => expect(useWorkspaceStore.getState().highContrastBase).toBe('light'))
    fireEvent.click(screen.getByTestId('settings-discard'))
    await waitFor(() => expect(useWorkspaceStore.getState().highContrastBase).toBe('dark'))
    fireEvent.click(screen.getByRole('radio', { name: 'Light base' }))
    fireEvent.click(screen.getByTestId('settings-save'))
    await waitFor(() => expect(screen.queryByTestId('settings-save-bar')).toBeNull())
    expect((await getClient().globalSettings.get()).appearance.highContrastBase).toBe('light')
    cleanup()
    useWorkspaceStore.setState({ highContrastBase: 'dark' })
    renderGlobal('/settings/appearance')
    await waitFor(() => expect(useWorkspaceStore.getState().highContrastBase).toBe('light'))
  })

  it('theme change persists to the workspace store immediately', async () => {
    renderGlobal('/settings/appearance')
    const dark = await screen.findByRole('radio', { name: 'Dark' }, { timeout: 10_000 })
    fireEvent.click(dark)
    await waitFor(() => expect(useWorkspaceStore.getState().theme).toBe('dark'))
    // Density mirrors General ↔ Appearance into the workspace store too.
    fireEvent.click(screen.getAllByRole('radio', { name: 'Comfortable' })[0])
    await waitFor(() => expect(useWorkspaceStore.getState().density).toBe('comfortable'))
  }, 15_000)
})

describe('settings: search', () => {
  it('finds “font size” and jumps to the Editor group', async () => {
    renderGlobal('/settings/general')
    const search = await screen.findByTestId('settings-search', undefined, { timeout: 10_000 })
    fireEvent.change(search, { target: { value: 'font size' } })

    const results = await screen.findByTestId('settings-search-results')
    expect(within(results).getAllByText('Font size').length).toBeGreaterThan(0)
    expect(within(results).getByText('Settings › Editor')).toBeTruthy()
    expect(within(results).queryByText(/font_size/)).toBeNull()

    // Clicking the Editor result jumps to the editor group.
    const editorResult = within(results)
      .getAllByRole('button')
      .find((b) => b.textContent?.includes('Settings › Editor'))
    expect(editorResult).toBeTruthy()
    fireEvent.click(editorResult!)
    expect(await screen.findByTestId('settings-group-editor')).toBeTruthy()
    expect(document.getElementById('setting-editor-font-size')).toBeTruthy()
  }, 15_000)

  it('shows the empty state with reset for unknown terms', async () => {
    renderGlobal('/settings/general')
    const search = await screen.findByTestId('settings-search', undefined, { timeout: 10_000 })
    fireEvent.change(search, { target: { value: 'xyzzy nothing' } })
    expect(await screen.findByText(/No settings match/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Reset search' }))
    expect((screen.getByTestId('settings-search') as HTMLInputElement).value).toBe('')
  }, 15_000)
})

describe('advanced settings: asynchronous failures preserve reviewed input', () => {
  it('keeps pasted JSON when an older file read completes', async () => {
    renderGlobal('/settings/advanced')
    const input = await screen.findByLabelText('Choose settings file')
    let finish!: (value: string) => void
    const text = new Promise<string>((resolve) => { finish = resolve })
    fireEvent.change(input, { target: { files: [{ size: 12, text: () => text }] } })
    expect(screen.getByTestId('import-settings-apply')).toHaveProperty('disabled', true)
    fireEvent.change(screen.getByTestId('import-settings-text'), { target: { value: '{"newer":"draft"}' } })
    finish('{"older":"file"}')
    await waitFor(() => expect(screen.getByTestId('import-settings-apply')).toHaveProperty('disabled', false))
    expect(screen.getByTestId('import-settings-text')).toHaveProperty('value', '{"newer":"draft"}')
  })

  it('reports file read failure and permits deliberate retry', async () => {
    renderGlobal('/settings/advanced')
    const input = await screen.findByLabelText('Choose settings file')
    fireEvent.change(input, { target: { files: [{ size: 12, text: () => Promise.reject(new Error('File unavailable')) }] } })
    expect(await screen.findByText(/Settings file could not be read: File unavailable/)).toBeTruthy()
    fireEvent.change(input, { target: { files: [{ size: 12, text: () => Promise.resolve('{"retry":true}') }] } })
    await waitFor(() => expect(screen.getByTestId('import-settings-text')).toHaveProperty('value', '{"retry":true}'))
    expect(screen.queryByTestId('import-issues')).toBeNull()
  })

  it('reports export, policy and descriptor failures', async () => {
    const client = getClient()
    const spies = [
      vi.spyOn(client.globalSettings, 'exportJson').mockRejectedValue(new Error('Export unavailable')),
      vi.spyOn(client.catalog, 'list').mockRejectedValue(new Error('Policy unavailable')),
      vi.spyOn(client.applications, 'list').mockRejectedValue(new Error('Descriptor unavailable')),
    ]
    try {
      renderGlobal('/settings/advanced')
      fireEvent.click(await screen.findByRole('button', { name: 'Export settings' }))
      expect(await screen.findByText(/Settings export failed: Export unavailable/)).toBeTruthy()
      fireEvent.click(screen.getByText('Inspect effective policy'))
      fireEvent.click(screen.getByRole('button', { name: 'Load policy summary' }))
      expect(await screen.findByText(/Policy summary could not be loaded: Policy unavailable/)).toBeTruthy()
      fireEvent.click(screen.getByText('View raw capability descriptor'))
      fireEvent.click(screen.getByRole('button', { name: 'Load descriptor' }))
      expect(await screen.findByText(/Capability descriptor could not be loaded: Descriptor unavailable/)).toBeTruthy()
    } finally { spies.forEach((spy) => spy.mockRestore()) }
  })

  it('preserves cached bytes on storage refusal and clears only the exact key on retry', async () => {
    window.localStorage.setItem('unrelated.cache', 'preserve')
    renderGlobal('/settings/advanced')
    const button = await screen.findByRole('button', { name: 'Clear caches' })
    useCommandStore.setState({ recents: ['keep'] })
    const before = window.localStorage.getItem('stateport.commands.v1')
    const original = window.localStorage.removeItem
    const denied = vi.spyOn(window.localStorage, 'removeItem').mockImplementation(function (this: Storage, key: string) {
      if (key === 'stateport.commands.v1') throw new Error('Storage denied')
      return original.call(this, key)
    })
    try {
      fireEvent.click(button)
      expect(await screen.findByText(/Caches could not be cleared: Storage denied/)).toBeTruthy()
      expect(window.localStorage.getItem('stateport.commands.v1')).toBe(before)
      expect(useCommandStore.getState().recents).toEqual(['keep'])
    } finally { denied.mockRestore() }
    fireEvent.click(button)
    expect(window.localStorage.getItem('stateport.commands.v1')).toBeNull()
    expect(window.localStorage.getItem('unrelated.cache')).toBe('preserve')
    expect(useCommandStore.getState().recents).toEqual([])
    expect(screen.queryByText(/Caches could not be cleared/)).toBeNull()
    window.localStorage.removeItem('unrelated.cache')
  })
})


describe('privacy clearance verification', () => {
  it('refuses a success claim when storage becomes unreadable during confirmation', async () => {
    renderGlobal('/settings/privacy')
    fireEvent.click(await screen.findByTestId('clear-browser-data'))
    const dialog = await screen.findByTestId('confirm-dialog')
    const text = within(dialog).getByRole('textbox')
    fireEvent.change(text, { target: { value: 'clear' } })
    const previous = Object.getOwnPropertyDescriptor(window, 'localStorage')!
    const toast = vi.spyOn(useSessionStore.getState(), 'pushToast')
    toast.mockClear()
    try {
      Object.defineProperty(window, 'localStorage', { configurable: true, get: () => { throw new Error('Storage unavailable') } })
      fireEvent.click(screen.getByTestId('confirm-action'))
      await waitFor(() => expect(toast).toHaveBeenCalledWith({
        kind: 'error', title: 'Browser data clearance could not be verified',
        body: 'Browser storage is unavailable. Some data may remain; restore storage access and retry.',
      }))
      expect(toast).not.toHaveBeenCalledWith(expect.objectContaining({ title: 'StatePort browser data cleared' }))
    } finally {
      Object.defineProperty(window, 'localStorage', previous)
      toast.mockRestore()
    }
  })
})


it('application recovery and installed timestamps follow saved display mode without mutating facts', async () => {
  const client = getClient()
  const before = await client.applications.get('ins_cto_pilot')
  const view = renderAppSettings(before.id, 'backup')
  await screen.findByText('Last backup')
  const last = view.container.querySelector('#setting-backup-last time')!
  const next = view.container.querySelector('#setting-backup-next time')!
  expect(last.getAttribute('datetime')).toBe(new Date(before.recovery.lastBackupAt!).toISOString())
  expect(next.getAttribute('datetime')).toBe(new Date(before.recovery.nextDueAt!).toISOString())
  act(() => useWorkspaceStore.getState().setDateTimeFormat('absolute'))
  expect(last.textContent).toBe(format(new Date(before.recovery.lastBackupAt!), 'PPpp'))
  expect(next.textContent).toBe(format(new Date(before.recovery.nextDueAt!), 'PPpp'))
  act(() => useWorkspaceStore.getState().setDateTimeFormat('both'))
  expect(last.textContent).toContain(' · ')
  expect(last.classList.contains('whitespace-normal')).toBe(true)
  expect(last.closest('[data-testid="read-only-value"]')).toBeTruthy()
  view.unmount()
  const advanced = renderAppSettings(before.id, 'advanced')
  await screen.findByText('Installed')
  const created = advanced.container.querySelector('#setting-app-created time')!
  expect(created.getAttribute('datetime')).toBe(new Date(before.createdAt).toISOString())
  expect(created.textContent).toContain(format(new Date(before.createdAt), 'PPpp'))
  expect(created.textContent).toContain(' · ')
  expect((await client.applications.get(before.id)).recovery).toEqual(before.recovery)
  expect((await client.applications.get(before.id)).createdAt).toBe(before.createdAt)
}, 20_000)

it('keeps Never as a read-only value and omits absent next due dates', async () => {
  const client = getClient()
  const instance = await client.applications.get('ins_checklist_sample')
  // Exact absent recovery facts exercise rendering only; no write API is called.
  vi.spyOn(client.applications, 'get').mockResolvedValue({ ...instance, recovery: { state: 'not_configured' } })
  const view = renderAppSettings(instance.id, 'backup')
  await screen.findByText('Last backup')
  const last = view.container.querySelector('#setting-backup-last')!
  expect(within(last as HTMLElement).getByTestId('read-only-value').textContent).toBe('Never')
  expect(last.querySelector('time,input')).toBeNull()
  expect(view.container.querySelector('#setting-backup-next')).toBeNull()
  vi.restoreAllMocks()
}, 20_000)


it('previews, discards, saves and rehydrates panel contrast without changing high-contrast or motion choices', async () => {
  await getClient().globalSettings.update({ appearance: { panelContrast: 'default', highContrastBase: 'light' }, accessibility: { disableNonessentialAnimation: true } })
  const view = renderGlobal('/settings/appearance')
  fireEvent.click(await screen.findByRole('radio', { name: 'Increased' }))
  await waitFor(() => expect(useWorkspaceStore.getState().panelContrast).toBe('increased'))
  fireEvent.click(screen.getByTestId('settings-discard'))
  await waitFor(() => expect(useWorkspaceStore.getState().panelContrast).toBe('default'))
  fireEvent.click(screen.getByRole('radio', { name: 'Increased' }))
  fireEvent.click(screen.getByTestId('settings-save'))
  await waitFor(() => expect(screen.queryByTestId('settings-save-bar')).toBeNull())
  expect((await getClient().globalSettings.get()).appearance.panelContrast).toBe('increased')
  const stored = localStorage.getItem('stateport.workspace.v1')!
  expect(JSON.parse(stored).state.panelContrast).toBe('increased')
  view.unmount()
  useWorkspaceStore.setState({ panelContrast: 'default' })
  localStorage.setItem('stateport.workspace.v1', stored)
  await useWorkspaceStore.persist.rehydrate()
  expect(useWorkspaceStore.getState().panelContrast).toBe('increased')
  renderGlobal('/settings/appearance')
  await screen.findByRole('radio', { name: 'Increased' })
  expect(useWorkspaceStore.getState().highContrastBase).toBe('light')
  expect(useWorkspaceStore.getState().disableNonessentialAnimation).toBe(true)
}, 20_000)
