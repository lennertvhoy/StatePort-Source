import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { PatchView, COLLAPSE_ROWS } from '../PatchView'
import { mergeFileList, parseUnifiedDiff } from '../unifiedDiff'
import { SAMPLE_PATCH } from './fixtures'

afterEach(cleanup)

describe('parseUnifiedDiff', () => {
  it('reads change types, counts and line numbers from a git patch', () => {
    const files = parseUnifiedDiff(SAMPLE_PATCH)
    expect(files.map((file) => [file.path, file.change, file.additions, file.deletions, file.binary])).toEqual([
      ['STATE.yaml', 'modified', 3, 3, false],
      ['notes/today.md', 'added', 2, 0, false],
      ['old.txt', 'deleted', 0, 1, false],
      ['docs/b.md', 'renamed', 0, 0, false],
      ['logo.png', 'modified', 0, 0, true],
    ])
    const [state] = files
    expect(state.hunks).toHaveLength(2)
    // A removed line whose text starts with "--" stays a removed line.
    expect(state.hunks[0].lines.map((line) => line.kind)).toEqual(['context', 'del', 'add', 'add', 'context', 'del'])
    expect(state.hunks[0].lines[5].text).toBe('-- not a header, a removed line starting with two dashes')
    expect(state.hunks[0].lines[2]).toMatchObject({ newNumber: 2, oldNumber: null })
    expect(state.hunks[1].lines[0]).toMatchObject({ kind: 'context', oldNumber: 10, newNumber: 11 })
    expect(files[1].hunks[0].lines.at(-1)).toMatchObject({ kind: 'meta', text: '\\ No newline at end of file' })
    expect(files[3].oldPath).toBe('docs/a.md')
  })

  it('parses a plain unified diff without git headers', () => {
    const [file] = parseUnifiedDiff('--- a/x.txt\n+++ b/x.txt\n@@ -1 +1 @@\n-a\n+b\n')
    expect(file).toMatchObject({ path: 'x.txt', change: 'modified', additions: 1, deletions: 1 })
  })

  it('prefers declared files and fills missing counts from the patch', () => {
    const merged = mergeFileList(
      [{ path: 'STATE.yaml', oldPath: null, change: 'modified', additions: null, deletions: null, binary: false }],
      parseUnifiedDiff(SAMPLE_PATCH),
    )
    expect(merged).toEqual([{ path: 'STATE.yaml', oldPath: null, change: 'modified', additions: 3, deletions: 3, binary: false }])
  })
})

describe('PatchView', () => {
  it('renders each file with its change badge, counts and coloured +/− rows', () => {
    render(<PatchView patch={SAMPLE_PATCH} />)
    const sections = screen.getAllByTestId('patch-file')
    expect(sections.map((section) => section.getAttribute('data-path'))).toEqual(['STATE.yaml', 'notes/today.md', 'old.txt', 'docs/b.md', 'logo.png'])
    const state = within(sections[0])
    expect(state.getByText('Modified')).toBeTruthy()
    expect(state.getByText('+3 −3')).toBeTruthy()
    const added = sections[0].querySelector('[data-kind="add"]')!
    expect(added.textContent).toContain('next_action: "Run the gate on the clean machine"')
    expect(added.className).toContain('bg-status-success-bg')
    expect(sections[0].querySelector('[data-kind="del"]')!.className).toContain('bg-status-danger-bg')
    expect(within(sections[1]).getByText('Added')).toBeTruthy()
    expect(within(sections[2]).getByText('Deleted')).toBeTruthy()
    expect(within(sections[3]).getByText('docs/a.md → docs/b.md')).toBeTruthy()
    expect(within(sections[4]).getByText(/Binary file/)).toBeTruthy()
  })

  it('collapses a long file diff until asked, and shows unparseable text verbatim', async () => {
    const lines = Array.from({ length: COLLAPSE_ROWS + 5 }, (_, index) => `+line ${index}`)
    const patch = `--- /dev/null\n+++ b/big.txt\n@@ -0,0 +1,${lines.length} @@\n${lines.join('\n')}\n`
    render(<PatchView patch={patch} />)
    expect(screen.getByTestId('patch-file-collapsed')).toBeTruthy()
    expect(screen.queryByTestId('patch-rows')).toBeNull()
    await userEvent.click(screen.getByTestId('patch-file-toggle'))
    expect(screen.getByTestId('patch-rows').querySelectorAll('[data-kind="add"]')).toHaveLength(lines.length)
    cleanup()
    render(<PatchView patch="something that is not a diff" />)
    expect(screen.getByTestId('patch-raw').textContent).toBe('something that is not a diff')
    cleanup()
    render(<PatchView patch="" />)
    expect(screen.getByTestId('patch-empty')).toBeTruthy()
  })
})
