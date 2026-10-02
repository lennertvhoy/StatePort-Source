/**
 * Visual-preference closure: the two high-contrast bases, both densities,
 * 125% text, and reduced motion remain usable on representative desktop and
 * mobile viewports. This complements the route-wide default-theme axe matrix.
 *
 * Set STATEPORT_CAPTURE_VISUAL_CLOSURE=1 to refresh bounded evidence under
 * output/playwright/mobile-visual-closure without changing product docs.
 */
import { AxeBuilder } from '@axe-core/playwright'
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

const CAPTURE = process.env.STATEPORT_CAPTURE_VISUAL_CLOSURE === '1'
const OUT_DIR = path.resolve(
  process.cwd(),
  '../../output/playwright/mobile-visual-closure',
)

const CASES = [
  {
    name: 'desktop-hc-light-compact-font125-reduced',
    project: DESKTOP,
    viewport: { width: 1440, height: 900 },
    colorScheme: 'light',
    expectedTheme: 'hc-light',
    density: 'compact',
  },
  {
    name: 'desktop-hc-dark-comfortable-font125-reduced',
    project: DESKTOP,
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    expectedTheme: 'hc-dark',
    density: 'comfortable',
  },
  {
    name: 'mobile-hc-light-comfortable-font125-reduced',
    project: MOBILE,
    viewport: { width: 390, height: 844 },
    colorScheme: 'light',
    expectedTheme: 'hc-light',
    density: 'comfortable',
  },
  {
    name: 'mobile-hc-dark-compact-font125-reduced',
    project: 'mobile-320x568',
    viewport: { width: 320, height: 568 },
    colorScheme: 'dark',
    expectedTheme: 'hc-dark',
    density: 'compact',
  },
] as const

async function seedAppearance(
  page: Page,
  density: 'compact' | 'comfortable',
): Promise<void> {
  await page.addInitScript((selectedDensity) => {
    window.localStorage.setItem(
      'stateport.workspace.v1',
      JSON.stringify({
        state: {
          theme: 'high_contrast',
          highContrast: true,
          density: selectedDensity,
          fontScale: 125,
          reducedMotion: true,
        },
        version: 1,
      }),
    )
  }, density)
}

async function expectNoTopbarCollision(page: Page): Promise<void> {
  const collisions = await page.getByTestId('topbar').evaluate((header) => {
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
}

async function expectShellBrandTier(page: Page): Promise<void> {
  const mark = page.getByTestId('brand-mark').first()
  await expect(mark).toHaveAttribute('data-brand-size', '40')
  await expect(mark.locator('[data-brand-asset="compact"]')).toHaveCount(0)
  await expect(mark.locator('[data-brand-asset="light"]')).toHaveCount(1)
  await expect(mark.locator('[data-brand-asset="dark"]')).toHaveCount(0)
}

test.describe('visual preference matrix', () => {
  onProjects(DESKTOP, MOBILE, 'mobile-320x568')

  for (const visualCase of CASES) {
    test(visualCase.name, async ({ page }, testInfo) => {
      test.skip(
        testInfo.project.name !== visualCase.project,
        `visual case belongs to ${visualCase.project}`,
      )
      expect(page.viewportSize()).toEqual(visualCase.viewport)
      await page.emulateMedia({
        colorScheme: visualCase.colorScheme,
        reducedMotion: 'reduce',
      })
      await seedAppearance(page, visualCase.density)
      await gotoApp(
        page,
        `#/app/${INSTANCES.ctoPilot}/conversation`,
      )
      await expect(page.getByTestId('conversation-surface')).toBeVisible()

      const root = page.locator('html')
      await expect(root).toHaveAttribute(
        'data-theme',
        visualCase.expectedTheme,
      )
      await expect(root).toHaveAttribute(
        'data-density',
        visualCase.density,
      )
      await expect(root).toHaveAttribute('data-motion', 'reduced')
      await expect(root).toHaveAttribute('data-focus', 'strong')
      await expect
        .poll(() =>
          root.evaluate((element) =>
            element.style.getPropertyValue('--font-scale'),
          ),
        )
        .toBe('1.25')

      await expectNoHorizontalOverflow(page)
      await expectNoTopbarCollision(page)

      if (visualCase.viewport.width < 768) {
        await page.getByRole('button', { name: 'Open navigation' }).click()
        await expect(page.getByTestId('mobile-nav-drawer')).toBeVisible()
        await expectShellBrandTier(page)
      } else {
        await expectShellBrandTier(page)
      }

      const durationMs = await page
        .getByTestId('app-switcher')
        .evaluate((trigger) => {
          const duration = getComputedStyle(trigger).transitionDuration
          const value = Number.parseFloat(duration)
          return value * (duration.endsWith('ms') ? 1 : 1000)
        })
      expect(durationMs).toBeLessThanOrEqual(1)

      const results = await new AxeBuilder({ page })
        .include('[data-testid="app-shell"]')
        .analyze()
      const serious = results.violations.filter(
        (violation) =>
          violation.impact === 'serious' ||
          violation.impact === 'critical',
      )
      expect(
        serious.map((violation) => ({
          id: violation.id,
          impact: violation.impact,
          targets: violation.nodes.map((node) => node.target),
        })),
      ).toEqual([])

      if (CAPTURE) {
        fs.mkdirSync(OUT_DIR, { recursive: true })
        await page.screenshot({
          path: path.join(OUT_DIR, `${visualCase.name}.png`),
          fullPage: false,
          animations: 'disabled',
        })
        if (visualCase.viewport.width < 768) {
          await page
            .getByTestId('topbar')
            .getByRole('button', { name: 'More actions' })
            .click()
          await expect(
            page.getByRole('menuitem', { name: 'Search or command' }),
          ).toBeVisible()
          await page.screenshot({
            path: path.join(
              OUT_DIR,
              `${visualCase.name}-actions-open.png`,
            ),
            fullPage: false,
            animations: 'disabled',
          })
        }
      }
    })
  }
})
