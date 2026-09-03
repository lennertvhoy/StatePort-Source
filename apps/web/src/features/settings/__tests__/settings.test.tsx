/**
 * Settings surface tests (settings.md binding rules):
 * - human labels instead of raw enum values (no `environment_gated` on screen)
 * - read-only effective values render as text, never disabled inputs
 * - the save bar appears only while dirty (save + discard paths)
 * - shortcut conflict detection is surfaced, and “Reassign anyway” resolves it
 * - appearance edits live-preview into the workspace store
 * - settings search finds “font size” and jumps to the group
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { ClientError, getClient, resetClientForTests } from '@/client'
import { useShortcutsStore, useWorkspaceStore } from '@/state'
import { AppContextShell } from '@/shell/AppContextShell'

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
  useWorkspaceStore.setState({
    sidebar: 'expanded',
    sidebarUserChosen: false,
    theme: 'system',
    density: 'compact',
    fontScale: 100,
    highContrast: false,
    reducedMotion: false,
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
