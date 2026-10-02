/**
 * Responsive screenshot matrix (design.md §16 validation matrix).
 *
 * Route matrix — every configured viewport project × light/dark:
 *   applications, conversation, workbench-files, terminal, deployments,
 *   approvals, settings
 * Scenario states (desktop light unless noted): empty, error, waiting,
 *   blocked, danger, loading, sidebar collapsed, mobile drawer open (390),
 *   font scale 125 %, reduced motion.
 *
 * Files land in docs/screenshots/ as <route>_<viewport>_<theme>[_<state>].png.
 * Document routes are captured full-page (scroll chain expanded); workbench
 * routes are captured at viewport size (fixed-height regions by design).
 */
import { expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'

import {
  DESKTOP,
  INSTANCES,
  MOBILE,
  gotoApp,
  onProjects,
  seedWorkspacePrefs,
  viewportTag,
} from './helpers'

const OUT_DIR = process.env.STATEPORT_BROWSER_ARTIFACT_ROOT
  ? path.join(process.env.STATEPORT_BROWSER_ARTIFACT_ROOT, 'screenshots')
  : path.join(process.cwd(), 'docs', 'screenshots')

const CTO = INSTANCES.ctoPilot
const NIXOS = INSTANCES.nixosInfra

const ROUTES: Array<{ name: string; hash: string; ready: string; fullPage: boolean }> = [
  { name: 'applications', hash: '#/applications', ready: 'applications-page', fullPage: true },
  { name: 'conversation', hash: `#/app/${CTO}/conversation`, ready: 'conversation-surface', fullPage: false },
  { name: 'workbench-files', hash: `#/app/${CTO}/workbench/files`, ready: 'files-stub', fullPage: false },
  { name: 'terminal', hash: `#/app/${CTO}/workbench/terminal`, ready: 'terminal-tool', fullPage: false },
  { name: 'deployments', hash: `#/app/${NIXOS}/workbench/deployments`, ready: 'deployments-tool', fullPage: false },
  { name: 'approvals', hash: '#/approvals', ready: 'approvals-stub', fullPage: true },
  { name: 'settings', hash: '#/settings', ready: 'settings-stub', fullPage: true },
]

/** Expand the route scroll chain so fullPage captures all document content. */
async function expandScrollChain(page: Page, testid: string): Promise<void> {
  await page.evaluate((tid) => {
    let el = document.querySelector(`[data-testid="${tid}"]`) as HTMLElement | null
    while (el && el !== document.documentElement) {
      el.style.setProperty('height', 'auto', 'important')
      el.style.setProperty('max-height', 'none', 'important')
      el.style.setProperty('overflow', 'visible', 'important')
      el = el.parentElement
    }
    document.documentElement.style.setProperty('height', 'auto', 'important')
    document.body.style.setProperty('height', 'auto', 'important')
  }, testid)
}

async function shoot(page: Page, fileName: string, fullPage: boolean): Promise<void> {
  fs.mkdirSync(OUT_DIR, { recursive: true })
  await page.screenshot({
    path: path.join(OUT_DIR, fileName),
    fullPage,
    animations: 'disabled',
  })
}

test.describe('route matrix @screenshots', () => {
  for (const theme of ['light', 'dark'] as const) {
    for (const route of ROUTES) {
      test(`${route.name} ${theme}`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: theme })
        await gotoApp(page, route.hash)
        await expect(page.getByTestId(route.ready)).toBeVisible()
        await page.waitForTimeout(400) // settle mock latency + lists
        if (route.fullPage) await expandScrollChain(page, route.ready)
        await shoot(page, `${route.name}_${viewportTag(page)}_${theme}.png`, route.fullPage)
      })
    }
  }
})

test.describe('scenario states @screenshots', () => {
  onProjects(DESKTOP)

  const STATES: Array<{
    state: string
    route: string
    hash: string
    scenario: string
    ready: string
    fullPage?: boolean
  }> = [
    { state: 'empty', route: 'applications', hash: '#/applications', scenario: 'no_applications', ready: 'applications-page', fullPage: true },
    { state: 'error', route: 'applications', hash: '#/applications', scenario: 'service_offline', ready: 'error-state', fullPage: true },
    { state: 'waiting', route: 'approvals', hash: '#/approvals', scenario: 'approval_pending', ready: 'approval-row', fullPage: true },
    { state: 'blocked', route: 'orchestration', hash: `#/app/${CTO}/workbench/orchestration`, scenario: 'orchestration_unavailable', ready: 'orchestration-unavailable' },
    { state: 'loading', route: 'conversation', hash: `#/app/${CTO}/conversation`, scenario: 'conversation_loading', ready: 'conversation-loading' },
  ]

  for (const s of STATES) {
    test(`${s.route} ${s.state}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: 'light' })
      await gotoApp(page, s.hash, s.scenario)
      await expect(page.getByTestId(s.ready)).toBeVisible()
      await page.waitForTimeout(400)
      if (s.fullPage) await expandScrollChain(page, s.route === 'approvals' ? 'approvals-stub' : 'applications-page')
      await shoot(page, `${s.route}_${viewportTag(page)}_light_${s.state}.png`, s.fullPage ?? false)
    })
  }

  test('deployments danger (failed operation)', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    // Approve the seeded start plan, then run it — the scenario fails the run.
    await gotoApp(page, '#/approvals/appr_0001', 'infra_failed')
    await page.getByTestId('approve-button').click()
    await expect(page.getByTestId('decision-result')).toContainText('Approved')

    await gotoApp(page, `#/app/${NIXOS}/workbench/deployments`, 'infra_failed')
    await page.getByTestId('plan-run').click()
    const outcome = page.getByTestId('run-outcome')
    await expect(outcome).toBeVisible({ timeout: 20_000 })
    await expect(outcome).toContainText('Failed')
    await page.waitForTimeout(300)
    await shoot(page, `deployments_${viewportTag(page)}_light_danger.png`, false)
  })

  test('applications with collapsed sidebar', async ({ page }) => {
    await seedWorkspacePrefs(page, { sidebar: 'collapsed', sidebarUserChosen: true })
    await page.emulateMedia({ colorScheme: 'light' })
    await gotoApp(page, '#/applications')
    await expect(page.getByTestId('sidebar-rail')).toBeVisible()
    await expandScrollChain(page, 'applications-page')
    await shoot(page, `applications_${viewportTag(page)}_light_collapsed.png`, true)
  })

  test('applications at 125% font scale', async ({ page }) => {
    await seedWorkspacePrefs(page, { fontScale: 125 })
    await page.emulateMedia({ colorScheme: 'light' })
    await gotoApp(page, '#/applications')
    await expect(page.getByTestId('applications-page')).toBeVisible()
    const scale = await page.evaluate(() =>
      document.documentElement.style.getPropertyValue('--font-scale'),
    )
    expect(scale).toBe('1.25')
    await page.waitForTimeout(400)
    await expandScrollChain(page, 'applications-page')
    await shoot(page, `applications_${viewportTag(page)}_light_font125.png`, true)
  })

  test('reduced motion disables animation', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
    await gotoApp(page, '#/applications')
    await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduced')
    // Animations are effectively disabled (all durations → 1 ms) — measured
    // on the sidebar, which normally animates its width.
    const durationMs = await page.evaluate(() => {
      const aside = document.querySelector('[aria-label="Sidebar"]')
      if (!aside) return null
      const d = getComputedStyle(aside).transitionDuration
      return parseFloat(d) * (d.endsWith('ms') ? 1 : 1000)
    })
    expect(durationMs, `sidebar transition-duration ${durationMs}ms under reduced motion`).toBeLessThanOrEqual(1)
    await shoot(page, `applications_${viewportTag(page)}_light_reduced-motion.png`, false)
  })
})

test.describe('mobile states @screenshots', () => {
  onProjects(MOBILE)

  test('mobile drawer open at 390×844', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' })
    await gotoApp(page, '#/applications')
    await page.getByRole('button', { name: 'Open navigation' }).click()
    const drawer = page.getByTestId('mobile-nav-drawer')
    await expect(drawer).toBeVisible()
    await expect(drawer).toHaveAttribute('data-state', 'open')
    await shoot(page, `applications_${viewportTag(page)}_light_drawer.png`, false)
  })
})
