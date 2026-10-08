import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'

const artifactRoot =
  process.env.STATEPORT_BROWSER_ARTIFACT_ROOT ??
  path.resolve('../..', 'output', 'playwright', 'live-core-current')

export default defineConfig({
  testDir: './tests',
  testMatch: 'live-core.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  // 180_000, not 120_000, and the reason is arithmetic rather than optimism.
  // `at-run-artifacts-batch3` died with a bare `"beforeAll" hook timeout of
  // 120000ms exceeded`, 40 fixture/hook trace events, no test event at all, a
  // 0-byte service.log and NO named cause. The cause is the failure path eating
  // its own diagnostic: waitForService caps readiness at 30s, startService's
  // catch then calls stopChild, whose SIGTERM wait is 95s under
  // STATEPORT_UI_REAL_WORKSPACES=1, so the real 'service startup timed out' error
  // is thrown at ~127s -- past a 120s hook, which replaces it with a bare
  // timeout. 180_000 cannot mask a broken service: readiness still caps at 30s,
  // the error still propagates, SIGTERM still escalates to SIGKILL, and the
  // arithmetic is 30 + 95 + 2 = 127s, so the real diagnostic is thrown at ~127s
  // whether the budget is 120s or 180s. The budget only decides whether that
  // message survives to be read.
  //
  // SCOPE, stated because it is easy to overclaim: the argument above is about
  // the `beforeAll` hook, but `timeout` is the default for EVERY test in the
  // file. Roughly 32 of this suite's declarations carry no explicit budget and
  // so inherit this raise, which is a ~50% unmeasured increase for them on the
  // strength of a startup-path argument that does not apply to them. The longest
  // leg measured in any retained artifact is 30.27s, so nothing is near either
  // bound and this is not a live risk -- but the justification is narrower than
  // the effect, and that is recorded rather than glossed. The per-test
  // `test.setTimeout` sites in the spec restate this value deliberately; they are
  // pins, not overrides.
  timeout: 180_000,
  expect: { timeout: 20_000 },
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
    viewport: { width: 1440, height: 900 },
  },
})
