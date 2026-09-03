/**
 * Governed Files Markdown preview against the real CodeMirror integration.
 * Preview renders the dirty in-memory draft, never saves, and never remounts
 * the editor (undo + selection survive toggles and tab switches).
 */
import { expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'

import {
  DESKTOP,
  INSTANCES,
  MOBILE,
  expectNoHorizontalOverflow,
  gotoApp,
  onProjects,
} from './helpers'

const FILES = `#/app/${INSTANCES.ctoPilot}/workbench/files`
const MARKDOWN = 'README.md'
const OTHER = 'package.json'
const CAPTURE = process.env.STATEPORT_CAPTURE_MARKDOWN_PREVIEW === '1'
const OUT_DIR = path.resolve(
  process.cwd(),
  '../../output/playwright/markdown-preview',
)
const INSERTION = [
  '',
  '## Unsaved preview state',
  '[unsafe-preview-link](javascript:alert(1))',
  '[safe-preview-link](https://example.test/preview)',
].join('\n')

async function openDesktopFile(page: Page, path: string): Promise<void> {
  await page.getByTestId(`tree-row-${path}`).click()
  await expect(
    page.getByTestId(`editor-host-primary-${path}`).locator('.cm-content'),
  ).toBeVisible()
}

async function markEditor(page: Page, value: string): Promise<void> {
  await page
    .getByTestId(`editor-host-primary-${MARKDOWN}`)
    .locator('.cm-content')
    .evaluate((element, marker) => {
      const editor = element as HTMLElement
      editor.dataset.mountProof = marker
    }, value)
}

async function expectSameEditor(page: Page, value: string): Promise<void> {
  await expect(
    page
      .getByTestId(`editor-host-primary-${MARKDOWN}`)
      .locator('.cm-content'),
  ).toHaveAttribute('data-mount-proof', value)
}

test.describe('Markdown preview state preservation', () => {
  onProjects(DESKTOP)

  test('keeps CodeMirror undo and selection across preview and tab switches', async ({
    page,
  }) => {
    await gotoApp(page, FILES)
    await openDesktopFile(page, MARKDOWN)
    await openDesktopFile(page, OTHER)
    await page.getByTestId(`editor-tab-primary-${MARKDOWN}`).click()

    const editor = page
      .getByTestId(`editor-host-primary-${MARKDOWN}`)
      .locator('.cm-content')
    const mountProof = 'desktop-markdown-editor'
    await markEditor(page, mountProof)
    await editor.click()
    await page.keyboard.press('Control+End')
    await page.keyboard.insertText(INSERTION)
    await expect(editor).toContainText('Unsaved preview state')
    await expect(
      page.getByTestId(`editor-tab-primary-${MARKDOWN}`).getByLabel(
        'Unsaved changes',
      ),
    ).toBeVisible()

    for (let index = 0; index < 6; index += 1) {
      await page.keyboard.press('Shift+ArrowLeft')
    }
    await expect(page.getByTestId('status-send-selection')).toBeVisible()

    const mutations: string[] = []
    page.on('request', (request) => {
      if (!['GET', 'HEAD'].includes(request.method())) {
        mutations.push(`${request.method()} ${request.url()}`)
      }
    })

    await page
      .getByTestId(`markdown-preview-toggle-${MARKDOWN}`)
      .click()
    const preview = page.getByTestId(`markdown-preview-${MARKDOWN}`)
    await expect(preview).toBeVisible()
    await expect(preview).toContainText('Noncanonical draft preview')
    await expect(preview).toContainText('Unsaved preview state')
    await expect(
      preview.getByRole('link', { name: 'safe-preview-link' }),
    ).toHaveAttribute('rel', /noopener/)
    await expect(
      preview.getByRole('link', { name: 'unsafe-preview-link' }),
    ).toHaveCount(0)
    await expect(editor).not.toBeVisible()
    await expectSameEditor(page, mountProof)
    expect(mutations).toEqual([])
    if (CAPTURE) {
      fs.mkdirSync(OUT_DIR, { recursive: true })
      await page.screenshot({
        path: path.join(OUT_DIR, 'desktop-dirty-draft-preview.png'),
        animations: 'disabled',
      })
    }

    await page.getByTestId(`editor-tab-primary-${OTHER}`).click()
    await page.getByTestId(`editor-tab-primary-${MARKDOWN}`).click()
    await expect(preview).toBeVisible()
    await expectSameEditor(page, mountProof)

    await page.getByTestId(`markdown-edit-${MARKDOWN}`).click()
    await expect(editor).toBeVisible()
    await expect(page.getByTestId('status-send-selection')).toBeVisible()
    await expectSameEditor(page, mountProof)
    await editor.press('Control+z')
    await expect(editor).not.toContainText('Unsaved preview state')
  })
})

test.describe('Markdown preview on mobile', () => {
  onProjects(MOBILE)

  test('uses the same mounted editor and bounded noncanonical projection', async ({
    page,
  }) => {
    await gotoApp(page, FILES)
    await page.getByTestId('mobile-file-picker').click()
    await page.getByTestId(`tree-row-${MARKDOWN}`).click()

    const editor = page
      .getByTestId(`editor-host-primary-${MARKDOWN}`)
      .locator('.cm-content')
    await expect(editor).toBeVisible()
    const mountProof = 'mobile-markdown-editor'
    await markEditor(page, mountProof)
    await editor.click()
    await page.keyboard.press('Control+End')
    await page.keyboard.insertText('\n## Mobile draft preview')

    await page
      .getByTestId(`markdown-preview-toggle-${MARKDOWN}`)
      .click()
    await expect(
      page.getByTestId(`markdown-preview-${MARKDOWN}`),
    ).toContainText('Mobile draft preview')
    await expect(editor).not.toBeVisible()
    await expectSameEditor(page, mountProof)
    await expectNoHorizontalOverflow(page)
    if (CAPTURE) {
      fs.mkdirSync(OUT_DIR, { recursive: true })
      await page.screenshot({
        path: path.join(OUT_DIR, 'mobile-dirty-draft-preview.png'),
        animations: 'disabled',
      })
    }

    await page.getByTestId(`markdown-edit-${MARKDOWN}`).click()
    await expect(editor).toBeVisible()
    await expectSameEditor(page, mountProof)
    await editor.press('Control+z')
    await expect(editor).not.toContainText('Mobile draft preview')
  })
})
