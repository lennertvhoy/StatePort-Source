/**
 * Shared e2e helpers: project gating, scenario URLs, workspace prefs, waits.
 *
 * The 8 configured projects are the 8 validation viewports. Functional specs
 * pin themselves to one project (desktop-1440x900, or mobile-390x844 for
 * mobile behavior) via `onProjects(...)`; the screenshot matrix
 * (`@screenshots`) runs on every project.
 */
import { expect, test, type Page } from '@playwright/test'

export const DESKTOP = 'desktop-1440x900'
export const MOBILE = 'mobile-390x844'

/** Skip the current test unless it runs on one of the named projects. */
export function onProjects(...names: string[]): void {
  // Playwright requires the first argument to use the object destructuring
  // pattern even when no fixture is needed.
  // eslint-disable-next-line no-empty-pattern
  test.beforeEach(({}, testInfo) => {
    test.skip(
      !names.includes(testInfo.project.name),
      `functional test — runs on ${names.join(', ')} only`,
    )
  })
}

export const INSTANCES = {
  ctoPilot: 'ins_cto_pilot',
  studyAlpha: 'ins_study_alpha',
  checklistSample: 'ins_checklist_sample',
  nixosInfra: 'ins_nixos_infra',
} as const

/** Build the app URL. Scenario is read from `window.location.search` (before the hash). */
export function appUrl(hash: string, scenario?: string, capture?: 'studystate'): string {
  const h = hash.startsWith('#') ? hash : `#${hash}`
  const params = new URLSearchParams()
  if (scenario) params.set('scenario', scenario)
  if (capture) params.set('capture', capture)
  const query = params.toString()
  return `/${query ? `?${query}` : ''}${h}`
}

/** Navigate and wait for the shell to be up. */
export async function gotoApp(page: Page, hash: string, scenario?: string, capture?: 'studystate'): Promise<void> {
  await page.goto(appUrl(hash, scenario, capture))
  await expect(page.getByTestId('app-shell')).toBeVisible()
}

/**
 * Seed workspace prefs (sidebar, fontScale, …) before the app boots.
 * Mirrors the zustand persist envelope of `stateport.workspace.v1` (version 1).
 */
export async function seedWorkspacePrefs(
  page: Page,
  prefs: Record<string, unknown>,
): Promise<void> {
  await page.addInitScript((p) => {
    try {
      const raw = window.localStorage.getItem('stateport.workspace.v1')
      const parsed = raw ? JSON.parse(raw) : {}
      const state = { ...(parsed.state ?? {}), ...p }
      window.localStorage.setItem(
        'stateport.workspace.v1',
        JSON.stringify({ state, version: 1 }),
      )
    } catch {
      /* storage unavailable — ignore */
    }
  }, prefs)
}

/** Assert the document itself does not scroll horizontally (design §16 defect class). */
export async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    return { scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth }
  })
  expect(
    overflow.scrollWidth,
    `document scrollWidth ${overflow.scrollWidth} exceeds clientWidth ${overflow.clientWidth}`,
  ).toBeLessThanOrEqual(overflow.clientWidth + 1)
}

/**
 * Assert no descendant of `[data-testid=testid]` is painted with the danger
 * text/background tokens (the "never red for merely disconnected" contract).
 */
export async function expectNoDangerColor(page: Page, testid: string): Promise<void> {
  const offenders = await page.evaluate((tid) => {
    const rootStyle = getComputedStyle(document.documentElement)
    const toRgb = (hex: string): string | null => {
      const m = /^#([0-9a-f]{6})$/i.exec(hex.trim())
      if (!m) return null
      const n = parseInt(m[1]!, 16)
      return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`
    }
    const dangerText = toRgb(rootStyle.getPropertyValue('--status-danger-text'))
    const dangerBg = toRgb(rootStyle.getPropertyValue('--status-danger-bg'))
    const root = document.querySelector(`[data-testid="${tid}"]`)
    if (!root) return [`container ${tid} not found`]
    const bad: string[] = []
    const nodes = [root, ...root.querySelectorAll('*')]
    for (const node of nodes) {
      const cs = getComputedStyle(node)
      if (dangerText && cs.color === dangerText) bad.push(`${node.tagName} color`)
      if (dangerBg && dangerBg !== 'rgb(0, 0, 0)' && cs.backgroundColor === dangerBg)
        bad.push(`${node.tagName} background`)
    }
    return bad
  }, testid)
  expect(offenders, `danger-colored elements inside ${testid}: ${offenders.join(', ')}`).toEqual([])
}

/** Current viewport tag used in screenshot file names, e.g. "1440x900". */
export function viewportTag(page: Page): string {
  const vp = page.viewportSize()
  if (!vp) throw new Error('no viewport')
  return `${vp.width}x${vp.height}`
}
