import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'

const artifactRoot =
  process.env.STATEPORT_BROWSER_ARTIFACT_ROOT ??
  path.resolve('.playwright-mcp', 'canonical-source-current')

export default defineConfig({
  testDir: './tests',
  testMatch: 'canonical-source.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 12_000 },
  outputDir: path.join(artifactRoot, 'test-results'),
  reporter: [
    ['line'],
    ['json', { outputFile: path.join(artifactRoot, 'results.json') }],
  ],
  use: {
    ...devices['Desktop Chrome'],
    browserName: 'chromium',
    headless: true,
    serviceWorkers: 'block',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
})
