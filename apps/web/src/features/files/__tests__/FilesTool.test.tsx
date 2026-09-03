/**
 * FilesTool integration tests — the governed write flow through the real App:
 * controls hidden before selection, dirty on edit, Ctrl/Cmd+S opens the
 * preview (never a silent save), confirm writes with expectedRevision and
 * surfaces the receipt link, conflict/path-policy/read-only outcomes, and
 * bridge patch-drafts staged into the governed preview.
 * CodeMirror is mocked (textarea double; diff view stub) per the task brief.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import { sendToBridge, useBridgeStore } from '@/features/bridge/bridgeStore'
import { useFilesStore } from '@/features/files/filesStore'
import { useSessionStore, useWorkspaceStore } from '@/state'

interface MockEditorProps {
  path: string
  value: string
  readOnly?: boolean
  'aria-label'?: string
  onChangeValue: (value: string) => void
}

vi.mock('@/features/files/CodeEditor', () => ({
  CodeEditor: ({ path, value, readOnly, onChangeValue, 'aria-label': ariaLabel }: MockEditorProps) => (
    <textarea
      data-testid={`cm-${path}`}
      aria-label={ariaLabel}
      readOnly={readOnly}
      value={value}
      onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => onChangeValue(e.target.value)}
    />
  ),
}))

vi.mock('@/features/files/DiffView', () => ({
  DiffView: ({ path }: { path: string }) => <div data-testid={`diff-${path}`} />,
}))

vi.mock('@/features/files/editorCommands', () => ({ openFindInView: () => true }))

const ID = 'ins_nixos_infra'
const FILE = 'flake.nix'
const READONLY_FILE = 'hosts/homelab/hardware-configuration.nix'

beforeEach(() => {
  localStorage.clear()
  resetMockState()
  resetClientForTests()
  useFilesStore.getState().resetForTests()
  useBridgeStore.setState({ pending: [] })
  useSessionStore.getState().clearToasts()
  useWorkspaceStore.setState(useWorkspaceStore.getInitialState(), true)
  window.location.hash = ''
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  window.location.hash = ''
})

async function renderFiles() {
  window.location.hash = `#/app/${ID}/workbench/files`
  render(<App />)
  await screen.findByTestId('files-stub', undefined, { timeout: 15_000 })
}

async function openFile(path: string) {
  // Expand ancestor directories first — the tree starts collapsed, so nested
  // rows only render after their parents are expanded. Each ancestor row is
  // awaited, not queried synchronously: the tree arrives asynchronously after
  // the stub, and a sync query would race the first tree render.
  const segments = path.split('/')
  for (let i = 1; i < segments.length; i += 1) {
    const dirPath = segments.slice(0, i).join('/')
    const dirRow = await screen.findByTestId(`tree-row-${dirPath}`, undefined, { timeout: 15_000 })
    if (dirRow.getAttribute('aria-expanded') === 'false') {
      fireEvent.click(dirRow)
    }
  }
  const row = await screen.findByTestId(`tree-row-${path}`, undefined, { timeout: 15_000 })
  fireEvent.click(row)
  await screen.findByTestId(`cm-${path}`, undefined, { timeout: 15_000 })
}

function editFile(path: string, value: string) {
  fireEvent.change(screen.getByTestId(`cm-${path}`), { target: { value } })
}

describe('FilesTool — empty state & controls', () => {
  it('hides editor controls before any file is selected', async () => {
    await renderFiles()
    expect(await screen.findByTestId('editor-placeholder')).toBeTruthy()
    expect(screen.queryByTestId('editor-status-strip')).toBeNull()
    expect(screen.queryByTestId('review-save')).toBeNull()
    expect(screen.queryByTestId('dirty-count')).toBeNull()
  }, 20_000)

  it('shows dirty state on edit (header, tab dot, status strip)', async () => {
    await renderFiles()
    await openFile(FILE)
    editFile(FILE, '# edited\n')
    expect((await screen.findByTestId('dirty-count')).textContent).toContain('1 unsaved')
    expect(await screen.findByTestId('review-save')).toBeTruthy()
    const tab = screen.getByTestId(`editor-tab-primary-${FILE}`)
    expect(within(tab).getByLabelText('Unsaved changes')).toBeTruthy()
    expect(await screen.findByTestId('editor-status-strip')).toBeTruthy()
  }, 20_000)
})

describe('FilesTool — governed write flow', () => {
  it('Ctrl/Cmd+S opens the diff preview and never writes silently', async () => {
    const writeSpy = vi.spyOn(getClient().files, 'write')
    await renderFiles()
    await openFile(FILE)
    editFile(FILE, '# edited\n')
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    expect(await screen.findByTestId('save-preview')).toBeTruthy()
    expect(screen.getByTestId(`preview-file-${FILE}`)).toBeTruthy()
    expect(screen.getByTestId('affected-paths').textContent).toContain(FILE)
    expect(writeSpy).not.toHaveBeenCalled()
  }, 20_000)

  it('confirm writes with expectedRevision and surfaces the receipt link', async () => {
    const entry = await getClient().files.read(ID, FILE)
    const writeSpy = vi.spyOn(getClient().files, 'write')
    await renderFiles()
    await openFile(FILE)
    editFile(FILE, '# edited via governed flow\n')
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    fireEvent.click(await screen.findByTestId('confirm-save'))
    await waitFor(() => expect(writeSpy).toHaveBeenCalledTimes(1), { timeout: 10_000 })
    expect(writeSpy).toHaveBeenCalledWith(ID, FILE, {
      content: '# edited via governed flow\n',
      expectedRevision: entry.revision,
    })
    const toast = await screen.findByTestId('toast', undefined, { timeout: 10_000 })
    expect(toast.textContent).toContain('File change saved')
    expect(toast.textContent).toContain('View receipt')
    fireEvent.click(screen.getByText(/View receipt/))
    await waitFor(() => expect(window.location.hash).toContain(`/app/${ID}/workbench/receipts/rcpt_`), {
      timeout: 10_000,
    })
    expect(useFilesStore.getState().docs[ID]?.[FILE]?.lastReceiptId).toMatch(/^rcpt_/)
  }, 25_000)

  it('renders an honest conflict UI when the revision went stale', async () => {
    const entry = await getClient().files.read(ID, FILE)
    await renderFiles()
    await openFile(FILE)
    editFile(FILE, '# my version\n')
    const external = await getClient().files.write(ID, FILE, {
      content: '# external version\n',
      expectedRevision: entry.revision,
    })
    expect(external.ok).toBe(true)
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    fireEvent.click(await screen.findByTestId('confirm-save'))
    const conflict = await screen.findByTestId(`conflict-${FILE}`, undefined, { timeout: 10_000 })
    expect(conflict.textContent).toContain('changed on disk')
    expect(screen.getByTestId(`conflict-save-anyway-${FILE}`)).toBeTruthy()
    fireEvent.click(screen.getByTestId(`conflict-save-anyway-${FILE}`))
    const toast = await screen.findByTestId('toast', undefined, { timeout: 10_000 })
    expect(toast.textContent).toContain('File change saved')
    const doc = useFilesStore.getState().docs[ID]?.[FILE]
    expect(doc?.draft).toBe('# my version\n')
    expect(doc?.savedContent).toBe('# my version\n')
  }, 25_000)

  it('surfaces a path-policy rejection with a permissions link and no retry', async () => {
    vi.spyOn(getClient().files, 'write').mockResolvedValue({
      ok: false,
      reason: 'path_policy',
      detail: `"${FILE}" is outside the permitted project root for this application.`,
    })
    await renderFiles()
    await openFile(FILE)
    editFile(FILE, '# blocked write\n')
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    fireEvent.click(await screen.findByTestId('confirm-save'))
    const notice = await screen.findByTestId(`path-policy-${FILE}`, undefined, { timeout: 10_000 })
    expect(notice.textContent).toContain('permitted project root')
    expect(within(notice.parentElement as HTMLElement).getByText('Review permissions')).toBeTruthy()
    expect(useFilesStore.getState().docs[ID]?.[FILE]?.draft).toBe('# blocked write\n')
  }, 20_000)
})

describe('FilesTool — read-only & bridge intake', () => {
  it('blocks editing a read-only file and shows the reason', async () => {
    await renderFiles()
    await openFile(READONLY_FILE)
    expect(await screen.findByTestId(`readonly-banner-${READONLY_FILE}`)).toBeTruthy()
    const editor = screen.getByTestId(`cm-${READONLY_FILE}`)
    expect(editor.hasAttribute('readonly')).toBe(true)
    const strip = await screen.findByTestId('editor-status-strip')
    expect(strip.textContent).toContain('Read-only')
    expect(useFilesStore.getState().docs[ID]?.[READONLY_FILE]?.readOnly).toBe(true)
  }, 20_000)

  it('stages a bridge patch-draft into the governed preview (never auto-applies)', async () => {
    const writeSpy = vi.spyOn(getClient().files, 'write')
    sendToBridge({ kind: 'patch-draft', instanceId: ID, path: FILE, proposed: '# proposed by conversation\n' })
    await renderFiles()
    expect(await screen.findByTestId('save-preview', undefined, { timeout: 15_000 })).toBeTruthy()
    expect(screen.getByText(/proposed in Conversation/i)).toBeTruthy()
    expect(screen.getByTestId(`preview-file-${FILE}`)).toBeTruthy()
    expect(writeSpy).not.toHaveBeenCalled()
    expect(useFilesStore.getState().docs[ID]?.[FILE]?.draft).toBe('# proposed by conversation\n')
    expect((await screen.findByTestId('dirty-count')).textContent).toContain('1 unsaved')
  }, 25_000)
})

describe('FilesTool — governed regular-file path mutations', () => {
  it('reviews a new path and content before creating, then opens the receipted file', async () => {
    const createSpy = vi.spyOn(getClient().files, 'create')
    await renderFiles()

    fireEvent.click(await screen.findByTestId('file-create-root'))
    expect(await screen.findByTestId('file-create-dialog')).toBeTruthy()
    fireEvent.change(screen.getByTestId('file-create-path'), {
      target: { value: 'notes/reviewed.md' },
    })
    fireEvent.change(screen.getByTestId('file-create-content'), {
      target: { value: '# Reviewed\n' },
    })
    expect(createSpy).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('file-create-confirm'))

    await waitFor(() => expect(createSpy).toHaveBeenCalledWith(ID, 'notes/reviewed.md', {
      content: '# Reviewed\n',
    }), { timeout: 10_000 })
    expect(await screen.findByTestId('cm-notes/reviewed.md', undefined, { timeout: 10_000 })).toBeTruthy()
    await waitFor(() => {
      expect(screen.queryByTestId('file-create-dialog')).toBeNull()
      expect(screen.queryByTestId('file-mutation-error')).toBeNull()
    }, { timeout: 10_000 })
    fireEvent.click(await screen.findByTestId('tree-row-notes', undefined, { timeout: 10_000 }))
    expect(await screen.findByTestId('tree-row-notes/reviewed.md', undefined, { timeout: 10_000 })).toBeTruthy()
    const toast = await screen.findByTestId('toast')
    expect(toast.textContent).toContain('File created')
    expect(toast.textContent).toContain('View receipt')
  }, 30_000)

  it('reads an exact basis before rename and reconciles open document state', async () => {
    const renameSpy = vi.spyOn(getClient().files, 'rename')
    await renderFiles()
    await openFile(FILE)

    fireEvent.contextMenu(screen.getByTestId(`tree-row-${FILE}`))
    fireEvent.click(await screen.findByText('Rename reviewed file'))
    expect(await screen.findByTestId('file-rename-dialog')).toBeTruthy()
    fireEvent.change(screen.getByTestId('file-rename-path'), {
      target: { value: 'flake-renamed.nix' },
    })
    fireEvent.click(screen.getByTestId('file-rename-confirm'))

    await waitFor(() => expect(renameSpy).toHaveBeenCalledTimes(1), { timeout: 10_000 })
    await waitFor(() => expect(screen.queryByTestId(`tree-row-${FILE}`)).toBeNull(), { timeout: 10_000 })
    expect(await screen.findByTestId('tree-row-flake-renamed.nix', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(await screen.findByTestId('cm-flake-renamed.nix', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(useFilesStore.getState().docs[ID]?.[FILE]).toBeUndefined()
    expect((await screen.findByTestId('toast')).textContent).toContain('File renamed')
  }, 30_000)

  it('requires a separate destructive confirmation and removes the exact reviewed file', async () => {
    const deleteSpy = vi.spyOn(getClient().files, 'delete')
    await renderFiles()
    await openFile(FILE)

    fireEvent.contextMenu(screen.getByTestId(`tree-row-${FILE}`))
    fireEvent.click(await screen.findByText('Delete reviewed file'))
    const dialog = await screen.findByTestId('file-delete-dialog')
    expect(dialog.textContent).toContain('No automatic restore is promised')
    expect(deleteSpy).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('file-delete-confirm'))

    await waitFor(() => expect(deleteSpy).toHaveBeenCalledTimes(1), { timeout: 10_000 })
    await waitFor(() => expect(screen.queryByTestId(`tree-row-${FILE}`)).toBeNull(), { timeout: 10_000 })
    expect(screen.queryByTestId(`cm-${FILE}`)).toBeNull()
    expect(useFilesStore.getState().docs[ID]?.[FILE]).toBeUndefined()
    expect((await screen.findByTestId('toast')).textContent).toContain('File deleted')
  }, 30_000)

  it('cannot dismiss a mutation dialog while the broker result is still being validated', async () => {
    const client = getClient()
    const realDelete = client.files.delete.bind(client.files)
    let release!: () => void
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const deleteSpy = vi.spyOn(client.files, 'delete').mockImplementation(async (...args) => {
      await gate
      return realDelete(...args)
    })
    await renderFiles()
    await openFile(FILE)

    fireEvent.contextMenu(screen.getByTestId(`tree-row-${FILE}`))
    fireEvent.click(await screen.findByText('Delete reviewed file'))
    fireEvent.click(await screen.findByTestId('file-delete-confirm'))
    await waitFor(() => expect(deleteSpy).toHaveBeenCalledTimes(1))
    fireEvent.keyDown(screen.getByTestId('file-delete-dialog'), { key: 'Escape' })
    expect(screen.getByTestId('file-delete-dialog')).toBeTruthy()

    release()
    await waitFor(() => expect(screen.queryByTestId('file-delete-dialog')).toBeNull(), { timeout: 10_000 })
  }, 30_000)

  it('keeps the review open and truthfully reports a stale rename refusal', async () => {
    vi.spyOn(getClient().files, 'rename').mockResolvedValue({
      ok: false,
      reason: 'conflict',
      detail: `${FILE} changed since it was reviewed.`,
    })
    await renderFiles()
    await openFile(FILE)

    fireEvent.contextMenu(screen.getByTestId(`tree-row-${FILE}`))
    fireEvent.click(await screen.findByText('Rename reviewed file'))
    fireEvent.change(await screen.findByTestId('file-rename-path'), {
      target: { value: 'stale.nix' },
    })
    fireEvent.click(screen.getByTestId('file-rename-confirm'))

    const refusal = await screen.findByTestId('file-mutation-error')
    expect(refusal.textContent).toContain('changed since it was reviewed')
    expect(screen.getByTestId('file-rename-dialog')).toBeTruthy()
    expect(screen.getByTestId(`tree-row-${FILE}`)).toBeTruthy()
  }, 25_000)
})
