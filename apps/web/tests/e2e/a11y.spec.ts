/**
 * Accessibility: axe on the 10 major routes × light/dark (zero serious or
 * critical violations beyond the two reported app bugs tracked in
 * KNOWN_AXE_ISSUES), focus traps in the command palette and dialogs, and no
 * document horizontal overflow at 320×568 on any major route (design §16).
 */
import { AxeBuilder } from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

import { DESKTOP, INSTANCES, expectNoHorizontalOverflow, gotoApp, onProjects } from './helpers'

const CTO = INSTANCES.ctoPilot

/** The 10 major routes + readiness selectors (desktop / 320 px mobile). */
const MAJOR_ROUTES: Array<{ name: string; hash: string; ready: string; readyMobile?: string }> = [
  { name: 'applications', hash: '#/applications', ready: 'applications-page' },
  { name: 'catalog', hash: '#/catalog', ready: 'catalog-stub' },
  { name: 'approvals', hash: '#/approvals', ready: 'approvals-stub' },
  // At <768 px settings shows the group list first; the detail pane is hidden.
  { name: 'settings', hash: '#/settings', ready: 'settings-page', readyMobile: 'settings-group-list' },
  { name: 'app overview', hash: `#/app/${CTO}`, ready: 'app-overview-page' },
  { name: 'conversation', hash: `#/app/${CTO}/conversation`, ready: 'conversation-surface' },
  { name: 'workbench overview', hash: `#/app/${CTO}/workbench`, ready: 'workbench-overview-stub' },
  { name: 'files', hash: `#/app/${CTO}/workbench/files`, ready: 'files-stub' },
  { name: 'terminal', hash: `#/app/${CTO}/workbench/terminal`, ready: 'terminal-tool' },
  { name: 'deployments', hash: `#/app/${INSTANCES.nixosInfra}/workbench/deployments`, ready: 'deployments-tool' },
]

/**
 * Known-issues allowlist. Currently empty: the fix cycle resolved the two
 * previously reported app bugs (aria-allowed-attr on PanelGroup divs,
 * link-in-text-block on the conversation privacy link). The scans below fail
 * on any serious/critical violation NOT listed here, so regressions are
 * caught immediately; add an entry only with a tracked bug reference.
 */
const KNOWN_AXE_ISSUES: Array<{ ruleId: string; routes: string[]; note: string }> = []

function formatViolations(violations: Awaited<ReturnType<AxeBuilder['analyze']>>['violations']): string {
  return violations
    .map(
      (v) =>
        `${v.id} (${v.impact}): ${v.help}\n` +
        v.nodes.map((n) => `  ${n.target.join(' ')} — ${n.html.slice(0, 120)}`).join('\n'),
    )
    .join('\n')
}

test.describe('axe scans (10 routes × light/dark)', () => {
  onProjects(DESKTOP)

  for (const theme of ['light', 'dark'] as const) {
    for (const route of MAJOR_ROUTES) {
      test(`${route.name} has no new serious/critical violations (${theme})`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: theme })
        await gotoApp(page, route.hash)
        await expect(page.getByTestId(route.ready)).toBeVisible()
        const results = await new AxeBuilder({ page }).analyze()
        const serious = results.violations.filter(
          (v) => v.impact === 'serious' || v.impact === 'critical',
        )
        const known = KNOWN_AXE_ISSUES.filter((k) => k.routes.includes(route.name)).map(
          (k) => k.ruleId,
        )
        const unexpected = serious.filter((v) => !known.includes(v.id))
        expect(
          unexpected,
          `new serious/critical axe violations on ${route.name} (${theme}):\n${formatViolations(unexpected)}`,
        ).toEqual([])
      })
    }
  }
})

test.describe('focus traps', () => {
  onProjects(DESKTOP)

  async function expectFocusInside(page: Page, testid: string): Promise<void> {
    const inside = await page.evaluate((tid) => {
      const container = document.querySelector(`[data-testid="${tid}"]`)
      return !!container && container.contains(document.activeElement)
    }, testid)
    expect(inside, `focus escaped ${testid} (activeElement outside)`).toBe(true)
  }

  test('command palette traps Tab and Escape closes', async ({ page }) => {
    await gotoApp(page, '#/applications')
    await page.getByTestId('command-trigger').click()
    const palette = page.getByTestId('command-palette')
    await expect(palette).toBeVisible()
    await expect(page.getByRole('combobox', { name: 'Search commands' })).toBeFocused()

    // Tab cycles inside the trap, never out of the palette.
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press('Tab')
      await expectFocusInside(page, 'command-palette')
    }

    await page.keyboard.press('Escape')
    await expect(palette).not.toBeVisible()
  })

  // design.md §16: Escape closes the palette and focus returns to the
  // element that was focused before it opened (here: the trigger button).
  test('command palette restores focus to the trigger after Escape', async ({ page }) => {
    await gotoApp(page, '#/applications')
    const trigger = page.getByTestId('command-trigger')
    await trigger.click()
    await expect(page.getByTestId('command-palette')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('command-palette')).not.toBeVisible()
    await expect(trigger).toBeFocused()
  })

  test('save preview dialog traps Tab and Escape closes', async ({ page }) => {
    await gotoApp(page, `#/app/${CTO}/workbench/files`)
    await page.getByTestId('tree-row-package.json').click()
    const editor = page.getByTestId('editor-host-primary-package.json').locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+End')
    await page.keyboard.type('\n// a11y focus trap check')
    await page.keyboard.press('Control+s')

    const dialog = page.getByTestId('save-preview')
    await expect(dialog).toBeVisible()
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press('Tab')
      await expectFocusInside(page, 'save-preview')
    }

    await page.keyboard.press('Escape')
    await expect(dialog).not.toBeVisible()
  })

  // design.md §16: Escape closes the save preview and focus returns to the
  // editor that was focused before it opened.
  test('save preview dialog restores focus to the editor after Escape', async ({ page }) => {
    await gotoApp(page, `#/app/${CTO}/workbench/files`)
    await page.getByTestId('tree-row-package.json').click()
    const editor = page.getByTestId('editor-host-primary-package.json').locator('.cm-content')
    await editor.click()
    await page.keyboard.press('Control+End')
    await page.keyboard.type('\n// a11y focus restore check')
    await page.keyboard.press('Control+s')
    const dialog = page.getByTestId('save-preview')
    await expect(dialog).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(dialog).not.toBeVisible()
    const focusBack = await page.evaluate(() => {
      const el = document.activeElement
      return !!el && !!el.closest('[data-testid^="editor-host-primary"]')
    })
    expect(focusBack, 'focus was not restored to the editor after Escape').toBe(true)
  })
})

test.describe('no horizontal overflow at 320×568', () => {
  onProjects(DESKTOP)

  for (const route of MAJOR_ROUTES) {
    test(`${route.name} does not overflow horizontally`, async ({ page }) => {
      await page.setViewportSize({ width: 320, height: 568 })
      await gotoApp(page, route.hash)
      await expect(page.getByTestId(route.readyMobile ?? route.ready)).toBeVisible()
      await expectNoHorizontalOverflow(page)
    })
  }
})
