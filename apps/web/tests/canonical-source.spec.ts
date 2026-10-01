/**
 * Real-service canonical-source acceptance for the current React frontend.
 *
 * The caller supplies an owner-private Git repository or recovery bundle
 * containing the already pinned candidate commit. It is verified through a
 * disposable clone and never copied into screenshots, logs, or repository
 * evidence.
 */
import { expect, test } from '@playwright/test'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { closeSync, mkdirSync, mkdtempSync, openSync, readdirSync, rmSync, statSync } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WEB_ROOT = path.resolve(HERE, '..')
const ROOT = path.resolve(WEB_ROOT, '../..')
const PYTHON = '/usr/bin/python3'
const ARTIFACT_ROOT =
  process.env.STATEPORT_BROWSER_ARTIFACT_ROOT ??
  path.join(WEB_ROOT, '.playwright-mcp', 'canonical-source-current')

const SOURCE_ID = 'stateport.source.studystate'
const COMMIT = 'cffc45a2f69f8719b950abce37988667b1712830'
const TREE = 'e518c185fab3dbd1624cf76d017f566e4aad317f'
const MANIFEST = 'sha256:425008e382cc87076e05a3ae02a6915167107bcbb74dc2ffe7236650c0591671'
const SOURCE = 'sha256:0e575f528d962095ee0c2a9ed3bd2d45ad3d126869686a556ae96f675a0e5222'
const REPOSITORY = 'https://github.com/lennertvhoy/StudyDD_Template.git'

function sourceRoots(parent: string): string[] {
  return readdirSync(parent)
    .map((name) => path.join(parent, name, 'src'))
    .filter((candidate) => {
      try {
        return statSync(candidate).isDirectory()
      } catch {
        return false
      }
    })
}

const PYTHONPATH = [
  ...sourceRoots(path.join(ROOT, 'packages')),
  ...sourceRoots(path.join(ROOT, 'apps')),
].join(path.delimiter)

let disposableRoot = ''
let candidateMirror = ''
let localService: RunningService
let operatorService: RunningService
const children: ChildProcess[] = []

interface RunningService {
  child: ChildProcess
  url: string
}

function git(repository: string, args: string[]): string {
  return execFileSync('git', ['-C', repository, ...args], {
    encoding: 'utf8',
    timeout: 30_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

async function freePort(): Promise<number> {
  const server = net.createServer()
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : 0
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
  if (!port) throw new Error('could not reserve a loopback test port')
  return port
}

async function waitForService(
  role: 'local_user' | 'platform_operator',
  url: string,
  child: ChildProcess,
  logPath: string,
): Promise<void> {
  const deadline = Date.now() + 20_000
  let lastError = 'service did not answer'
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `service startup failed role=${role} exitCode=${child.exitCode} signal=${child.signalCode ?? 'none'} log=${logPath}`,
      )
    }
    try {
      const response = await fetch(`${url}/session`, { signal: AbortSignal.timeout(1_000) })
      if (response.status === 200) return
      lastError = `service returned ${response.status}`
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(
    `service startup timed out role=${role} exitCode=${child.exitCode ?? 'none'} signal=${child.signalCode ?? 'none'} log=${logPath}: ${lastError}`,
  )
}

async function startService(role: 'local_user' | 'platform_operator'): Promise<RunningService> {
  const port = await freePort()
  const root = path.join(disposableRoot, role)
  mkdirSync(root, { recursive: true, mode: 0o700 })
  const environment = {
    ...process.env,
    PYTHONPATH,
    XDG_CONFIG_HOME: path.join(root, 'xdg', 'config'),
    XDG_DATA_HOME: path.join(root, 'xdg', 'data'),
    XDG_STATE_HOME: path.join(root, 'xdg', 'state'),
    STATEPORT_STUDYDD_MIRROR: candidateMirror,
  }
  if (role === 'platform_operator') {
    execFileSync(
      PYTHON,
      [
        path.join(HERE, 'platform-statebench-fixture.py'),
        '--repo-root',
        ROOT,
      ],
      {
        cwd: ROOT,
        env: environment,
        timeout: 30_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    )
    const authority = path.join(root, 'xdg', 'config', 'stateport', 'platform-operator-authority')
    const descriptor = openSync(authority, 'wx', 0o600)
    closeSync(descriptor)
    expect(statSync(authority).mode & 0o777).toBe(0o600)
  }
  const logPath = path.join(ARTIFACT_ROOT, role, 'service.log')
  mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 })
  const log = openSync(logPath, 'a', 0o600)
  const child = spawn(
    PYTHON,
    [
      '-m',
      'stateport_persistent_app.service_process',
      '--port',
      String(port),
      '--repo-root',
      ROOT,
      '--actor-role',
      role,
    ],
    {
      cwd: ROOT,
      env: environment,
      stdio: ['ignore', log, log],
    },
  )
  closeSync(log)
  children.push(child)
  const url = `http://127.0.0.1:${port}`
  await waitForService(role, url, child, logPath)
  return { child, url }
}

async function stopChild(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.exitCode !== null) return
  child.kill('SIGTERM')
  const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()))
  const timedOut = await Promise.race([
    exited.then(() => false),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 5_000)),
  ])
  if (timedOut && child.exitCode === null) {
    child.kill('SIGKILL')
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 2_000))])
  }
}

function browserSignals(page: import('@playwright/test').Page) {
  const value = {
    console: [] as string[],
    pageErrors: [] as string[],
    requestFailures: [] as string[],
    errorResponses: [] as string[],
    requests: [] as string[],
  }
  page.on('console', (message) => {
    if (message.type() === 'error') value.console.push(message.text())
  })
  page.on('pageerror', (error) => value.pageErrors.push(error.message))
  page.on('requestfailed', (request) => {
    value.requestFailures.push(`${request.method()} ${request.url()} ${request.failure()?.errorText ?? 'failed'}`)
  })
  page.on('request', (request) => {
    value.requests.push(new URL(request.url()).pathname)
  })
  page.on('response', (response) => {
    if (response.status() >= 400) value.errorResponses.push(`${response.status()} ${response.url()}`)
  })
  return value
}

function expectClean(signals: ReturnType<typeof browserSignals>): void {
  expect(signals.console, 'browser console errors').toEqual([])
  expect(signals.pageErrors, 'uncaught page errors').toEqual([])
  expect(signals.requestFailures, 'failed browser requests').toEqual([])
  expect(signals.errorResponses, 'unexpected error responses').toEqual([])
}

async function openSources(page: import('@playwright/test').Page, service: RunningService): Promise<void> {
  await page.goto(`${service.url}/#/sources`, { waitUntil: 'domcontentloaded', timeout: 20_000 })
  await expect(page.getByRole('heading', { level: 1, name: 'Application sources' })).toBeVisible()
  await expect(page.getByText('Application source is awaiting a verified release.', { exact: true })).toBeVisible()
}

test.beforeAll(async () => {
  mkdirSync(ARTIFACT_ROOT, { recursive: true, mode: 0o700 })
  const sourceRepository = process.env.STATEPORT_BROWSER_STUDYDD_REPOSITORY
  if (!sourceRepository) {
    throw new Error(
      'STATEPORT_BROWSER_STUDYDD_REPOSITORY must name an owner-private Git repository or bundle containing the pinned candidate',
    )
  }
  disposableRoot = mkdtempSync(path.join(os.tmpdir(), 'stateport-canonical-source-browser-'))
  candidateMirror = path.resolve(sourceRepository)
  const verificationClone = path.join(disposableRoot, 'studydd-candidate-verification')
  execFileSync('git', ['clone', '--quiet', '--no-checkout', candidateMirror, verificationClone], {
    timeout: 30_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  git(verificationClone, ['checkout', '--quiet', '--detach', COMMIT])
  git(verificationClone, ['remote', 'set-url', 'origin', REPOSITORY])
  expect(git(verificationClone, ['rev-parse', 'HEAD'])).toBe(COMMIT)
  expect(git(verificationClone, ['rev-parse', 'HEAD^{tree}'])).toBe(TREE)
  localService = await startService('local_user')
  operatorService = await startService('platform_operator')
})

test.afterAll(async () => {
  for (const child of [...children].reverse()) await stopChild(child)
  if (disposableRoot) rmSync(disposableRoot, { recursive: true, force: true })
})

test('normal user receives only bounded public release status', async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
  const page = await context.newPage()
  const signals = browserSignals(page)
  await openSources(page, localService)

  await expect(page.getByText('Awaiting verified release', { exact: true })).toBeVisible()
  await expect(page.getByText('Production install: unavailable', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Inspect provenance' })).toHaveCount(0)
  await expect(page.getByText(/Scenario data is shown/)).toHaveCount(0)
  await expect(page.locator('body')).not.toContainText(REPOSITORY)
  await expect(page.locator('body')).not.toContainText(COMMIT)

  await page.goto(`${localService.url}/#/sources/${SOURCE_ID}`)
  await expect(page.getByText('Operator access required')).toBeVisible()
  await expect(page.getByTestId('source-operator-detail')).toHaveCount(0)
  await page.getByTestId('source-list').screenshot({
    path: path.join(ARTIFACT_ROOT, 'normal-user-source-status.png'),
  })

  await page.goto(`${localService.url}/#/statebench`)
  await expect(page.getByRole('heading', { level: 1, name: 'StateBench evidence' })).toBeVisible()
  await expect(page.getByText('Operator access required')).toBeVisible()
  expect(signals.requests.filter((requestPath) => requestPath === '/v1/platform/statebench')).toEqual([])
  expectClean(signals)
  await context.close()
})

test('platform operator inspects and verifies one exact development candidate', async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
  const page = await context.newPage()
  const signals = browserSignals(page)
  await openSources(page, operatorService)

  await page.getByRole('button', { name: 'Inspect provenance' }).click()
  const detail = page.getByTestId('source-operator-detail')
  await expect(detail).toBeVisible()
  await expect(detail.getByText('Not a release', { exact: true })).toBeVisible()
  for (const value of [REPOSITORY, COMMIT, TREE, MANIFEST, SOURCE]) {
    await expect(detail).toContainText(value)
  }
  await expect(detail).toContainText('Production install')
  await expect(detail).toContainText('Not allowed')

  await page.getByTestId('verify-development-candidate').click()
  await expect(page.getByTestId('confirm-dialog')).toBeVisible()
  await page.getByTestId('confirm-action').click()
  await expect(page.getByText('Development verification recorded')).toBeVisible()
  await expect(page.getByText(/Production install remains unavailable/)).toBeVisible()
  await expect(page.getByText(/No — declarations were matched only/)).toBeVisible()
  await expect(page.getByTestId('verify-development-candidate')).toBeDisabled()
  // The verification confirmation is a nested modal. Wait for its dismissable
  // layer to leave the DOM before exercising Escape on the underlying source
  // drawer; visibility alone can race Radix's close animation and send Escape
  // to the already-closing confirmation instead.
  await expect(page.getByTestId('confirm-dialog')).toHaveCount(0)
  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'operator-source-evidence.png'),
    fullPage: true,
  })

  await page.keyboard.press('Escape')
  await expect(detail).not.toBeVisible()
  await page.getByTestId('open-platform-statebench').click()
  await expect(page).toHaveURL(/#\/statebench$/)
  await expect(page.getByRole('heading', { level: 1, name: 'StateBench evidence' })).toBeVisible()
  await expect(page.getByTestId('statebench-verified-count')).toHaveText('1')
  await expect(page.getByTestId('statebench-rejected-count')).toHaveText('0')
  await expect(page.getByTestId('statebench-authority-claim')).toHaveText(
    'authoritativePerformanceClaim: false',
  )
  await expect(page.getByTestId('platform-statebench-table')).toContainText('operator-browser-proof')
  await expect(page.getByTestId('platform-statebench-table')).toContainText('stateport.synthetic-reference')
  await expect(page.getByTestId('platform-statebench-table')).toContainText('synthetic-action')
  await page.getByTestId('inspect-statebench-operator-browser-proof').click()
  const statebenchDetail = page.getByTestId('platform-statebench-detail')
  await expect(statebenchDetail).toContainText('Canonical state preserved')
  await expect(statebenchDetail).toContainText('Unauthorized mutations')
  await expect(statebenchDetail.getByText(/^sha256:[0-9a-f]{64}$/)).toBeVisible()
  await expect(page.locator('body')).not.toContainText(disposableRoot)
  expect(signals.requests).toContain('/v1/platform/statebench')
  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'operator-statebench-evidence.png'),
    fullPage: true,
  })
  expectClean(signals)
  await context.close()
})

test('bounded status remains usable at the narrow mobile acceptance viewport', async ({ browser }) => {
  const context = await browser.newContext({
    viewport: { width: 320, height: 568 },
    hasTouch: true,
    isMobile: true,
  })
  const page = await context.newPage()
  const signals = browserSignals(page)
  await openSources(page, localService)
  await expect(page.getByTestId('source-list')).toBeVisible()
  expect(
    await page.evaluate(
      () => document.scrollingElement!.scrollWidth <= document.scrollingElement!.clientWidth + 1,
    ),
  ).toBe(true)
  await page.getByTestId('source-list').screenshot({
    path: path.join(ARTIFACT_ROOT, 'mobile-source-status.png'),
  })
  expectClean(signals)
  await context.close()
})
