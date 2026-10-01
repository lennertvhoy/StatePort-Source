/**
 * Navigation: global routes, sidebar persistence, mobile drawer, legacy hash
 * forms, workbench deep links, document titles (design.md §12, §16).
 */
import { expect, test } from '@playwright/test'

import {
  DESKTOP,
  INSTANCES,
  MOBILE,
  expectNoHorizontalOverflow,
  gotoApp,
  onProjects,
} from './helpers'

const CTO = INSTANCES.ctoPilot

test.describe('global routes @smoke', () => {
  onProjects(DESKTOP)

  const globalRoutes: Array<{ hash: string; testid: string; title: string }> = [
    { hash: '#/applications', testid: 'applications-page', title: 'Applications · StatePort' },
    { hash: '#/catalog', testid: 'catalog-stub', title: 'Catalog · StatePort' },
    { hash: '#/sources', testid: 'source-registry-page', title: 'Application Sources · StatePort' },
    { hash: '#/approvals', testid: 'approvals-stub', title: 'Approvals · StatePort' },
    { hash: '#/settings', testid: 'settings-page', title: 'Settings · StatePort' },
  ]

  for (const route of globalRoutes) {
    test(`loads ${route.hash} with a meaningful title`, async ({ page }) => {
      await gotoApp(page, route.hash)
      await expect(page.getByTestId(route.testid)).toBeVisible()
      await expect(page).toHaveTitle(route.title)
    })
  }

  const appRoutes: Array<{ hash: string; title: string | RegExp }> = [
    { hash: `#/app/${CTO}`, title: 'Overview · StatePort CTO Pilot · StatePort' },
    { hash: `#/app/${CTO}/conversation`, title: 'Conversation · StatePort CTO Pilot · StatePort' },
    { hash: `#/app/${CTO}/settings`, title: 'Settings · StatePort CTO Pilot · StatePort' },
    { hash: `#/app/${CTO}/workbench`, title: 'Workbench · StatePort CTO Pilot · StatePort' },
  ]

  for (const route of appRoutes) {
    test(`loads ${route.hash}`, async ({ page }) => {
      await gotoApp(page, route.hash)
      await expect(page).toHaveTitle(route.title)
      await expect(page.getByTestId('app-context-shell')).toBeVisible()
    })
  }

  test('index hash redirects to applications', async ({ page }) => {
    await gotoApp(page, '#/')
    await expect(page).toHaveURL(/#\/applications$/)
    await expect(page.getByTestId('applications-page')).toBeVisible()
  })

  test('unknown route renders the not-found empty state', async ({ page }) => {
    await gotoApp(page, '#/definitely/not/a/route')
    await expect(page.getByTestId('not-found')).toBeVisible()
    await expect(page.getByText('Page not found')).toBeVisible()
  })
})

test.describe('workbench deep links', () => {
  onProjects(DESKTOP)

  const tools: Array<{ tool: string; testid: string; title: string }> = [
    { tool: 'files', testid: 'files-stub', title: 'Files · Workbench · StatePort CTO Pilot · StatePort' },
    { tool: 'terminal', testid: 'terminal-tool', title: 'Terminal · Workbench · StatePort CTO Pilot · StatePort' },
    { tool: 'orchestration', testid: 'orchestration-tool', title: 'Orchestration · Workbench · StatePort CTO Pilot · StatePort' },
    { tool: 'receipts', testid: 'receipts-stub', title: 'Receipts · Workbench · StatePort CTO Pilot · StatePort' },
  ]

  for (const { tool, testid, title } of tools) {
    test(`#/workbench/${tool} lands on the ${tool} tool`, async ({ page }) => {
      await gotoApp(page, `#/app/${CTO}/workbench/${tool}`)
      await expect(page).toHaveTitle(title)
      await expect(page.getByTestId(testid)).toBeVisible()
    })
  }

  test('deployments deep link lands for the nixos instance', async ({ page }) => {
    await gotoApp(page, `#/app/${INSTANCES.nixosInfra}/workbench/deployments`)
    await expect(page).toHaveTitle('Deployments · Workbench · NixOS Infrastructure · StatePort')
    await expect(page.getByTestId('deployments-tool')).toBeVisible()
  })
})

test.describe('sidebar persistence', () => {
  onProjects(DESKTOP)

  test('collapse persists across reload', async ({ page }) => {
    await gotoApp(page, '#/applications')
    await expect(page.getByTestId('sidebar-expanded')).toBeVisible()

    await page.getByRole('button', { name: 'Collapse sidebar' }).click()
    await expect(page.getByTestId('sidebar-rail')).toBeVisible()

    await page.reload()
    await expect(page.getByTestId('sidebar-rail')).toBeVisible()
    await expect(page.getByTestId('sidebar-expanded')).not.toBeVisible()

    // Restore for cleanliness, then verify it sticks too.
    await page.getByRole('button', { name: 'Expand sidebar' }).click()
    await expect(page.getByTestId('sidebar-expanded')).toBeVisible()
    await page.reload()
    await expect(page.getByTestId('sidebar-expanded')).toBeVisible()
  })
})

test.describe('collapsed rail expand control', () => {
  onProjects(DESKTOP)

  test('expand is pinned first in the rail, keyboard-reachable, with no duplicate', async ({ page }) => {
    await gotoApp(page, '#/applications')
    await page.getByRole('button', { name: 'Collapse sidebar' }).click()
    const rail = page.getByTestId('sidebar-rail')
    await expect(rail).toBeVisible()

    // Exactly one expand control, and it is the rail's first focusable control.
    const expand = page.getByRole('button', { name: 'Expand sidebar' })
    await expect(expand).toHaveCount(1)
    await expect(rail.locator('button, a').first()).toHaveAttribute('aria-label', 'Expand sidebar')

    // Keyboard: focus the first rail control, Enter expands.
    await expand.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('sidebar-expanded')).toBeVisible()
  })
})

test.describe('auto-collapse threshold', () => {
  onProjects('desktop-1024x768')

  test('below the default threshold the sidebar starts as a rail', async ({ page }) => {
    await gotoApp(page, '#/applications')
    await expect(page.getByTestId('sidebar-rail')).toBeVisible()
  })

  test('a narrower configured threshold keeps the sidebar expanded', async ({ page }) => {
    await gotoApp(page, '#/applications')
    await expect(page.getByTestId('sidebar-rail')).toBeVisible()

    // Drive the real settings workflow: save a narrower threshold.
    await gotoApp(page, '#/settings/navigation')
    const input = page.getByLabel('Auto-collapse below width')
    await input.fill('800')
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('Settings saved')).toBeVisible()

    await gotoApp(page, '#/applications')
    await expect(page.getByTestId('sidebar-expanded')).toBeVisible()

    // Restore the default so later tests are unaffected.
    await gotoApp(page, '#/settings/navigation')
    await page.getByLabel('Auto-collapse below width').fill('1200')
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('Settings saved')).toBeVisible()
  })
})

test.describe('mobile drawer', () => {
  onProjects(MOBILE)

  test('opens and closes at 390×844', async ({ page }) => {
    await gotoApp(page, '#/applications')
    const openButton = page.getByRole('button', { name: 'Open navigation' })
    await expect(openButton).toBeVisible()

    await openButton.click()
    const drawer = page.getByTestId('mobile-nav-drawer')
    await expect(drawer).toBeVisible()
    await expect(drawer).toHaveAttribute('data-state', 'open')

    // NOTE: the drawer panel itself is currently positioned off-viewport
    // (reported app bug — DialogContent centering translate is not reset),
    // so in-drawer navigation links are not clickable; Escape is the working
    // close path. When the positioning bug is fixed this test should also
    // exercise close-on-nav from inside the drawer.
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('mobile-nav-drawer')).not.toBeVisible()

    // Reopens cleanly after the Escape close.
    await page.getByRole('button', { name: 'Open navigation' }).click()
    await expect(page.getByTestId('mobile-nav-drawer')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('mobile-nav-drawer')).not.toBeVisible()
  })
})

test.describe('mobile topbar', () => {
  onProjects(MOBILE, 'mobile-320x568')

  test('keeps the application identity separate from actions at the narrowest widths', async ({
    page,
  }) => {
    await gotoApp(page, `#/app/${CTO}/conversation`)
    const topbar = page.getByTestId('topbar')
    await expect(topbar).toBeVisible()
    await expectNoHorizontalOverflow(page)

    const collisions = await topbar.evaluate((header) => {
      const visible = Array.from(header.children)
        .map((element) => {
          const node = element as HTMLElement
          const box = node.getBoundingClientRect()
          return {
            label:
              node.getAttribute('aria-label') ??
              node.getAttribute('data-testid') ??
              node.tagName.toLowerCase(),
            left: box.left,
            right: box.right,
            width: box.width,
            height: box.height,
          }
        })
        .filter((box) => box.width > 0 && box.height > 0)

      return visible.flatMap((box, index) => {
        const next = visible[index + 1]
        return next && box.right > next.left + 0.5
          ? [`${box.label} ends at ${box.right}; ${next.label} starts at ${next.left}`]
          : []
      })
    })
    expect(collisions).toEqual([])

    const appSwitcher = page.getByTestId('app-switcher')
    await expect(appSwitcher).toBeVisible()
    await expect(appSwitcher).toHaveAttribute('aria-label', 'Switch application')

    const moreActions = topbar.getByRole('button', { name: 'More actions' })
    await moreActions.click()
    await expect(page.getByRole('menuitem', { name: 'Search or command' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /Operation center/ })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /Approvals/ })).toBeVisible()

    await page.getByRole('menuitem', { name: 'Search or command' }).click()
    await expect(page.getByTestId('command-palette')).toBeVisible()
    await page.keyboard.press('Escape')

    await moreActions.click()
    await page.getByRole('menuitem', { name: /Operation center/ }).click()
    await expect(page.getByRole('heading', { name: 'Operation center' })).toBeVisible()
    await page.getByRole('button', { name: 'Close' }).click()

    await moreActions.click()
    await page.getByRole('menuitem', { name: /Approvals/ }).click()
    await expect(page).toHaveURL(/#\/approvals$/)
    await expect(page.getByTestId('approvals-stub')).toBeVisible()
  })
})

test.describe('legacy hash forms', () => {
  onProjects(DESKTOP)

  // Legacy hashes are normalized by src/legacyRoutes.ts before the router renders.
  test('#home redirects to #/applications', async ({ page }) => {
    await gotoApp(page, '#home')
    await expect(page.getByTestId('applications-page')).toBeVisible()
    await expect(page).toHaveURL(/#\/applications$/)
  })

  test('#app/ins_cto_pilot (missing slash) resolves to the app overview', async ({ page }) => {
    await gotoApp(page, `#app/${CTO}`)
    await expect(page).toHaveTitle('Overview · StatePort CTO Pilot · StatePort')
    await expect(page.getByTestId('app-overview-page')).toBeVisible()
  })
})
