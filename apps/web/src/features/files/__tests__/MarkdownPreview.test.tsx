import {
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { EditorSettings } from '@/client'
import {
  getClient,
  resetClientForTests,
  resetMockState,
} from '@/client'
import { Markdown } from '@/features/conversation/Markdown'
import { useFilesStore } from '@/features/files/filesStore'

import { EditorPane } from '../EditorPane'
import { MarkdownPreview } from '../MarkdownPreview'
import { isMarkdownPath } from '../markdownPreviewModel'

interface MockEditorProps {
  path: string
  value: string
  readOnly?: boolean
  'aria-label'?: string
  onChangeValue: (value: string) => void
}

vi.mock('@/features/files/CodeEditor', () => ({
  CodeEditor: ({
    path,
    value,
    readOnly,
    onChangeValue,
    'aria-label': ariaLabel,
  }: MockEditorProps) => (
    <textarea
      data-testid={`cm-${path}`}
      aria-label={ariaLabel}
      readOnly={readOnly}
      value={value}
      onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) =>
        onChangeValue(event.target.value)
      }
    />
  ),
}))

const ID = 'ins_nixos_infra'
const MARKDOWN = 'README.md'
const OTHER = 'flake.nix'

const SETTINGS: EditorSettings = {
  fontFamily: 'JetBrains Mono',
  fontSize: 13,
  lineHeight: 1.5,
  tabSize: 2,
  indentWith: 'spaces',
  wordWrap: true,
  minimap: false,
  ligatures: false,
  formatOnSave: false,
  autoCloseBrackets: true,
  showWhitespace: false,
  previewDiffBeforeSave: true,
  restoreOpenFiles: true,
  restoreCursorPositions: true,
  autosave: false,
}

beforeEach(() => {
  localStorage.clear()
  resetMockState()
  resetClientForTests()
  useFilesStore.getState().resetForTests()
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function pane(
  options: {
    pane?: 'primary' | 'secondary'
    paths?: string[]
    active?: string
    showTabs?: boolean
  } = {},
) {
  const selectedPane = options.pane ?? 'primary'
  const paths = options.paths ?? [MARKDOWN]
  const active = options.active ?? MARKDOWN
  return (
    <EditorPane
      instanceId={ID}
      pane={selectedPane}
      paths={paths}
      active={active}
      settings={SETTINGS}
      wordWrap
      showTabs={options.showTabs}
      cursor={null}
      selection={null}
      onFocusPane={vi.fn()}
      onSelect={vi.fn()}
      onClose={vi.fn()}
      onCloseOthers={vi.fn()}
      onReorder={vi.fn()}
      onReveal={vi.fn()}
      onCompare={vi.fn()}
      onReviewSave={vi.fn()}
      onSendSelection={vi.fn()}
      onOpenReceipt={vi.fn()}
      onCursor={vi.fn()}
      onSelection={vi.fn()}
      registerView={vi.fn()}
    />
  )
}

describe('MarkdownPreview safety', () => {
  it('renders raw HTML as inert text and refuses active link schemes', () => {
    render(
      <MarkdownPreview
        path="HOSTILE.markdown"
        content={[
          '# Draft',
          '<script>window.evil = true</script>',
          '<img src=x onerror="window.evil = true">',
          '<iframe src="https://example.test"></iframe>',
          '[javascript](javascript:alert(1))',
          '[data](data:text/html,boom)',
          '[file](file:///etc/passwd)',
          '[custom](stateport:run)',
          '[safe](https://example.test/docs)',
        ].join('\n\n')}
      />,
    )

    const preview = screen.getByTestId('markdown-preview-HOSTILE.markdown')
    expect(preview.textContent).toContain('Noncanonical draft preview')
    expect(screen.getByRole('heading', { level: 1, name: 'Draft' })).toBeTruthy()
    expect(preview.querySelector('script')).toBeNull()
    expect(preview.querySelector('img')).toBeNull()
    expect(preview.querySelector('iframe')).toBeNull()
    expect(screen.queryByRole('link', { name: 'javascript' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'data' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'file' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'custom' })).toBeNull()
    const safe = screen.getByRole('link', { name: 'safe' })
    expect(safe.getAttribute('href')).toBe('https://example.test/docs')
    expect(safe.getAttribute('rel')).toContain('noopener')
  })

  it('keeps Conversation heading containment as the default variant', () => {
    render(<Markdown content="# Conversation heading" />)
    expect(
      screen.getByRole('heading', {
        level: 3,
        name: 'Conversation heading',
      }),
    ).toBeTruthy()
    expect(
      screen.queryByRole('heading', {
        level: 1,
        name: 'Conversation heading',
      }),
    ).toBeNull()
  })

  it('renders an honest accessible empty-draft state', () => {
    render(<MarkdownPreview path="empty.md" content={'  \n'} />)
    const empty = screen.getByTestId('markdown-preview-empty-empty.md')
    expect(empty.getAttribute('role')).toBe('status')
    expect(empty.textContent).toContain('Empty draft')
    expect(empty.textContent).toContain('Nothing was saved or changed')
  })

  it('is offered only for .md and .markdown paths, case-insensitively', () => {
    expect(isMarkdownPath('README.md')).toBe(true)
    expect(isMarkdownPath('notes/PLAN.markdown')).toBe(true)
    expect(isMarkdownPath('README.md.txt')).toBe(false)
    expect(isMarkdownPath('package.json')).toBe(false)
    expect(isMarkdownPath('.markdownrc')).toBe(false)
  })
})

describe('EditorPane Markdown projection', () => {
  it('previews the dirty in-memory draft without saving or remounting the mobile editor', async () => {
    const write = vi.spyOn(getClient().files, 'write')
    await useFilesStore.getState().openDocument(ID, MARKDOWN)
    render(pane({ showTabs: false }))

    const editor = screen.getByTestId(`cm-${MARKDOWN}`) as HTMLTextAreaElement
    const hostileDraft = [
      '# Unsaved live draft',
      '[unsafe](javascript:alert(1))',
      '[safe](https://example.test/current)',
    ].join('\n\n')
    fireEvent.change(editor, { target: { value: hostileDraft } })
    editor.setSelectionRange(2, 9)

    fireEvent.click(screen.getByTestId(`markdown-preview-toggle-${MARKDOWN}`))

    expect(screen.getByTestId(`cm-${MARKDOWN}`)).toBe(editor)
    expect(
      screen
        .getByTestId(`markdown-editor-layer-primary-${MARKDOWN}`)
        .hasAttribute('inert'),
    ).toBe(true)
    expect(
      screen.getByTestId(`markdown-preview-${MARKDOWN}`).textContent,
    ).toContain('Unsaved live draft')
    expect(screen.queryByRole('link', { name: 'unsafe' })).toBeNull()
    expect(screen.getByRole('link', { name: 'safe' })).toBeTruthy()
    expect(useFilesStore.getState().docs[ID]?.[MARKDOWN]?.draft).toBe(
      hostileDraft,
    )
    expect(
      useFilesStore.getState().docs[ID]?.[MARKDOWN]?.savedContent,
    ).not.toBe(hostileDraft)
    expect(write).not.toHaveBeenCalled()

    fireEvent.click(screen.getByTestId(`markdown-edit-${MARKDOWN}`))
    const restored = screen.getByTestId(`cm-${MARKDOWN}`) as HTMLTextAreaElement
    expect(restored).toBe(editor)
    expect(restored.value).toBe(hostileDraft)
    expect(restored.selectionStart).toBe(2)
    expect(restored.selectionEnd).toBe(9)
  })

  it('keeps each Markdown mode and mounted editor across tabs in a split pane', async () => {
    await Promise.all([
      useFilesStore.getState().openDocument(ID, MARKDOWN),
      useFilesStore.getState().openDocument(ID, OTHER),
    ])
    const view = render(
      pane({
        pane: 'secondary',
        paths: [MARKDOWN, OTHER],
        active: MARKDOWN,
      }),
    )

    const editor = screen.getByTestId(`cm-${MARKDOWN}`)
    fireEvent.click(screen.getByTestId(`markdown-preview-toggle-${MARKDOWN}`))
    expect(
      screen.getByTestId(`markdown-preview-toggle-${MARKDOWN}`).getAttribute(
        'aria-pressed',
      ),
    ).toBe('true')

    view.rerender(
      pane({
        pane: 'secondary',
        paths: [MARKDOWN, OTHER],
        active: OTHER,
      }),
    )
    expect(screen.getByTestId(`cm-${MARKDOWN}`)).toBe(editor)
    expect(
      screen.getByTestId(`editor-host-secondary-${MARKDOWN}`).getAttribute(
        'aria-hidden',
      ),
    ).toBe('true')
    expect(screen.queryByTestId(`markdown-mode-${OTHER}`)).toBeNull()

    view.rerender(
      pane({
        pane: 'secondary',
        paths: [MARKDOWN, OTHER],
        active: MARKDOWN,
      }),
    )
    expect(screen.getByTestId(`cm-${MARKDOWN}`)).toBe(editor)
    expect(
      screen.getByTestId(`markdown-preview-toggle-${MARKDOWN}`).getAttribute(
        'aria-pressed',
      ),
    ).toBe('true')
  })
})
