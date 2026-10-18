import { defineConfig, devices } from '@playwright/test'
import { availableParallelism } from 'node:os'
import path from 'node:path'

const artifactRoot = process.env.STATEPORT_BROWSER_ARTIFACT_ROOT
const e2ePortValue = process.env.STATEPORT_E2E_PORT
const e2eBaseUrl = process.env.STATEPORT_E2E_BASE_URL
const maxWorkers = Math.max(1, Math.min(2, availableParallelism()))

if (!e2ePortValue || !e2eBaseUrl) {
  throw new Error('STATEPORT_E2E_PORT and STATEPORT_E2E_BASE_URL are required')
}

const e2ePort = Number.parseInt(e2ePortValue, 10)
if (
  !Number.isInteger(e2ePort) ||
  e2ePort < 1024 ||
  e2ePort > 65535 ||
  e2eBaseUrl !== `http://127.0.0.1:${e2ePort}`
) {
  throw new Error('STATEPORT_E2E_PORT and STATEPORT_E2E_BASE_URL must identify the same loopback port')
}

/**
 * E2E + responsive screenshot matrix.
 *
 * The 8 projects below are the 8 validation viewports from the product brief
 * (design.md §9.8 / §16). They are intentionally plain viewport projects (not
 * device-emulation descriptors) so pixel dimensions are exact:
 *
 *   1440×900 · 1280×800 · 1024×768 · 768×1024 · 430×932 · 390×844 · 360×800 · 320×568
 *
 * Browsers are NOT downloaded by the platform agent — run
 * `npx playwright install chromium` once in the environment that executes e2e.
 */
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 1,
  // Browser processes are expensive even when tests are IO-bound. Keep the
  // full viewport matrix bounded on developer hosts and 2-core sandboxes.
  workers: maxWorkers,
  reporter: artifactRoot
    ? [
        ['list'],
        ['json', { outputFile: path.join(artifactRoot, 'results.json') }],
      ]
    : process.env.CI
      ? 'github'
      : 'list',
  outputDir: artifactRoot
    ? path.join(artifactRoot, 'test-results')
    : 'test-results',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: e2eBaseUrl,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    // Preview the isolated demo build (.env.demo forces the deterministic
    // mock adapter). This is the reviewer/e2e artifact in dist-demo, never the
    // service-eligible production/HTTP artifact in dist.
    command: `npm run build:demo && npm run preview:demo -- --host 127.0.0.1 --port ${e2ePort} --strictPort`,
    url: e2eBaseUrl,
    // Never attach to a developer process or stale preview. The strict port
    // below makes an occupied port a visible failure instead of false evidence.
    reuseExistingServer: false,
    timeout: 180_000,
  },
  projects: [
    {
      name: 'desktop-1440x900',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'desktop-1280x800',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'desktop-1024x768',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1024, height: 768 } },
    },
    {
      name: 'tablet-768x1024',
      use: { ...devices['Desktop Chrome'], viewport: { width: 768, height: 1024 }, hasTouch: true },
    },
    {
      name: 'mobile-430x932',
      use: { ...devices['Desktop Chrome'], viewport: { width: 430, height: 932 }, hasTouch: true, isMobile: true },
    },
    {
      name: 'mobile-390x844',
      use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true },
    },
    {
      name: 'mobile-360x800',
      use: { ...devices['Desktop Chrome'], viewport: { width: 360, height: 800 }, hasTouch: true, isMobile: true },
    },
    {
      name: 'mobile-320x568',
      use: { ...devices['Desktop Chrome'], viewport: { width: 320, height: 568 }, hasTouch: true, isMobile: true },
    },
  ],
})
