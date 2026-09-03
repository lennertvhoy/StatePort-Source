/**
 * Real AppServer acceptance for the current-backed Runs, Context lifecycle,
 * and governed Files surfaces. No route is mocked or intercepted.
 */
import { expect, test } from '@playwright/test'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import {
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WEB_ROOT = path.resolve(HERE, '..')
const ROOT = path.resolve(WEB_ROOT, '../..')
const ARTIFACT_ROOT =
  process.env.STATEPORT_BROWSER_ARTIFACT_ROOT ??
  path.join(ROOT, 'output', 'playwright', 'live-core-current')

const PROJECT_ID = 'live-core-project'
const STUDY_ID = 'live-core-study'
const STUDY_APPLICATION_ID = 'studystate.sample'
const INFRASTRUCTURE_ID = 'live-core-infra'
const UNAVAILABLE_INFRASTRUCTURE_ID = 'live-core-infra-unavailable'
const IMPORT_CANDIDATE_NAME = 'nixos-homelab'
const EVIDENCE_SUMMARY = 'Completed the real governed browser evidence exercise.'

function sourceRoots(parent: string): string[] {
  return execFileSync('find', [parent, '-mindepth', '2', '-maxdepth', '2', '-type', 'd', '-name', 'src'], {
    encoding: 'utf8',
    timeout: 5_000,
  })
    .trim()
    .split('\n')
    .filter(Boolean)
}

const PYTHONPATH = [
  ...sourceRoots(path.join(ROOT, 'packages')),
  ...sourceRoots(path.join(ROOT, 'apps')),
].join(path.delimiter)

interface RunningService {
  child: ChildProcess
  url: string
}

interface WebBuildIdentity {
  formatVersion: string
  adapter: string
  mode: string
  sourceCommit: string
  sourceTree: string
  sourceDirty: boolean
}

interface BrowserSignals {
  console: string[]
  pageErrors: string[]
  requestFailures: string[]
  errorResponses: Array<{ status: number; method: string; path: string }>
  responses: Array<{ status: number; method: string; path: string }>
  requests: Array<{ method: string; path: string; body?: unknown }>
}

interface TerminalSocketFrame {
  direction: 'sent' | 'received'
  binary: boolean
  text: string
}

interface TerminalSocketSignals {
  urls: string[]
  frames: TerminalSocketFrame[]
  errors: string[]
  closes: number
}

interface TerminalConstructorObservation {
  url: string
  requestedProtocols: string[]
  negotiatedProtocol?: string
}

let disposableRoot = ''
let projectRoot = ''
let studyRoot = ''
let importCandidateRoot = ''
let infrastructureRoot = ''
let unavailableInfrastructureRoot = ''
let importCandidateHeadBefore = ''
let projectCanonicalBefore = ''
let projectHeadBefore = ''
let infrastructureCanonicalBefore = ''
let infrastructureHeadBefore = ''
let infrastructureStatusBefore = ''
let service: RunningService
const matrix: Record<string, unknown> = {
  formatVersion: 'stateport.live-core-browser-evidence/v1',
  adapter: 'http',
  service: 'real AppServer',
  fixtureClassification: 'public_safe_disposable',
  surfaces: {},
  blocked: [
    'No provider/model execution was attempted; the governed run used the production-ineligible deterministic synthetic engine.',
    'StudyState does not declare benchmark_evidence, so its per-run StateBench request remained capability-gated.',
    'Infrastructure is service-fixture-live: host libvirt, Nix, Make, SSH, and destructive scripts were not invoked, so environment-live infrastructure acceptance remains separate.',
  ],
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

async function waitForService(url: string, child: ChildProcess): Promise<void> {
  const deadline = Date.now() + 30_000
  let lastError = 'service did not answer'
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`service child exited with ${child.exitCode}`)
    try {
      const response = await fetch(`${url}/session`, { signal: AbortSignal.timeout(1_000) })
      if (response.status === 200) return
      lastError = `service returned ${response.status}`
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`service startup timed out: ${lastError}`)
}

async function startService(): Promise<RunningService> {
  const port = await freePort()
  const xdg = path.join(disposableRoot, 'xdg')
  const podmanRoot = path.join(disposableRoot, 'podman')
  const podmanStorageConfig = path.join(podmanRoot, 'storage.conf')
  mkdirSync(podmanRoot, { recursive: true, mode: 0o700 })
  writeFileSync(
    podmanStorageConfig,
    [
      '[storage]',
      'driver = "vfs"',
      `runroot = ${JSON.stringify(path.join(podmanRoot, 'runroot'))}`,
      `graphroot = ${JSON.stringify(path.join(podmanRoot, 'graphroot'))}`,
      '',
    ].join('\n'),
    { encoding: 'utf8', mode: 0o600 },
  )
  mkdirSync(ARTIFACT_ROOT, { recursive: true, mode: 0o700 })
  const log = openSync(path.join(ARTIFACT_ROOT, 'service.log'), 'w', 0o600)
  const child = spawn(
    'python3',
    [
      path.join(HERE, 'live-core-fixture.py'),
      '--port',
      String(port),
      '--repo-root',
      ROOT,
    ],
    {
      cwd: ROOT,
      env: {
        ...process.env,
        CONTAINERS_STORAGE_CONF: podmanStorageConfig,
        PYTHONPATH,
        XDG_CONFIG_HOME: path.join(xdg, 'config'),
        XDG_DATA_HOME: path.join(xdg, 'data'),
        XDG_STATE_HOME: path.join(xdg, 'state'),
      },
      stdio: ['ignore', log, log],
    },
  )
  closeSync(log)
  const url = `http://127.0.0.1:${port}`
  await waitForService(url, child)
  projectRoot = path.join(xdg, 'data', 'stateport', 'instances', PROJECT_ID)
  studyRoot = path.join(xdg, 'data', 'stateport', 'instances', STUDY_ID)
  importCandidateRoot = path.join(
    xdg,
    'data',
    'stateport',
    'live-core-import-candidates',
    IMPORT_CANDIDATE_NAME,
  )
  infrastructureRoot = path.join(
    xdg,
    'data',
    'stateport',
    'live-core-infrastructure',
    'available',
    'nixos-homelab',
  )
  unavailableInfrastructureRoot = path.join(
    xdg,
    'data',
    'stateport',
    'live-core-infrastructure',
    'unavailable',
    'nixos-homelab',
  )
  if (!statSync(projectRoot).isDirectory() || !statSync(studyRoot).isDirectory()) {
    throw new Error('the disposable fixture instances were not materialized')
  }
  if (!statSync(importCandidateRoot).isDirectory()) {
    throw new Error('the disposable repository-import candidate was not materialized')
  }
  if (
    !statSync(infrastructureRoot).isDirectory() ||
    !statSync(unavailableInfrastructureRoot).isDirectory()
  ) {
    throw new Error('the disposable infrastructure fixtures were not materialized')
  }
  return { child, url }
}

function validateServedBuildIdentity(): void {
  const expectedCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 5_000,
  }).trim()
  const expectedTree = execFileSync('git', ['rev-parse', 'HEAD^{tree}'], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 5_000,
  }).trim()
  const identity = JSON.parse(
    readFileSync(path.join(WEB_ROOT, 'dist', 'stateport-build.json'), 'utf8'),
  ) as WebBuildIdentity
  const bundle = readdirSync(path.join(WEB_ROOT, 'dist', 'assets'))
    .filter((file) => file.endsWith('.js'))
    .map((file) => readFileSync(path.join(WEB_ROOT, 'dist', 'assets', file), 'utf8'))
    .join('\n')
  expect(identity).toEqual(expect.objectContaining({
    formatVersion: 'stateport.web-build/v3',
    adapter: 'http',
    mode: 'production',
    sourceCommit: expectedCommit,
    sourceTree: expectedTree,
    sourceDirty: false,
  }))
  expect(bundle).toContain(expectedCommit)
  expect(bundle).not.toContain(`${expectedCommit}+dirty`)
  expect(bundle).not.toContain(`${expectedCommit.slice(0, 12)}+dirty`)
  for (const olderCommit of execFileSync('git', ['log', '--format=%H', '-n', '20'], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 5_000,
  }).trim().split('\n').filter((commit) => commit && commit !== expectedCommit)) {
    expect(bundle, `served bundle contains older source commit ${olderCommit}`).not.toContain(olderCommit)
    expect(bundle, `served bundle contains older dirty marker ${olderCommit.slice(0, 12)}+dirty`).not.toContain(
      `${olderCommit.slice(0, 12)}+dirty`,
    )
  }
  matrix.serviceValidatedBuildCommit = identity.sourceCommit
  matrix.serviceValidatedBuildTree = identity.sourceTree
  matrix.serviceValidatedBuildDirty = identity.sourceDirty
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

function browserSignals(page: import('@playwright/test').Page): BrowserSignals {
  const value: BrowserSignals = {
    console: [],
    pageErrors: [],
    requestFailures: [],
    errorResponses: [],
    responses: [],
    requests: [],
  }
  page.on('console', (message) => {
    if (message.type() === 'error') value.console.push(message.text())
  })
  page.on('pageerror', (error) => value.pageErrors.push(error.message))
  page.on('request', (request) => {
    const url = new URL(request.url())
    if (
      url.origin === service.url &&
      (url.pathname === '/session' || url.pathname.startsWith('/v1/'))
    ) {
      let body: unknown
      if (request.postData()) {
        try {
          body = request.postDataJSON()
        } catch {
          body = request.postData()
        }
      }
      value.requests.push({ method: request.method(), path: url.pathname, body })
    }
  })
  page.on('requestfailed', (request) => {
    value.requestFailures.push(
      `${request.method()} ${request.url()} ${request.failure()?.errorText ?? 'failed'}`,
    )
  })
  page.on('response', (response) => {
    const request = response.request()
    const url = new URL(response.url())
    if (
      url.origin !== service.url ||
      (url.pathname !== '/session' && !url.pathname.startsWith('/v1/'))
    ) {
      return
    }
    const observation = {
      status: response.status(),
      method: request.method(),
      path: url.pathname,
    }
    value.responses.push(observation)
    if (response.status() >= 400) value.errorResponses.push(observation)
  })
  return value
}

function terminalSocketSignals(
  page: import('@playwright/test').Page,
): TerminalSocketSignals {
  const value: TerminalSocketSignals = {
    urls: [],
    frames: [],
    errors: [],
    closes: 0,
  }
  page.on('websocket', (socket) => {
    const url = new URL(socket.url())
    if (url.pathname !== '/v1/terminal/socket') return
    value.urls.push(socket.url())
    socket.on('framesent', ({ payload }) => {
      value.frames.push({
        direction: 'sent',
        binary: typeof payload !== 'string',
        text: typeof payload === 'string' ? payload : payload.toString('utf8'),
      })
    })
    socket.on('framereceived', ({ payload }) => {
      value.frames.push({
        direction: 'received',
        binary: typeof payload !== 'string',
        text: typeof payload === 'string' ? payload : payload.toString('utf8'),
      })
    })
    socket.on('socketerror', (error) => value.errors.push(error))
    socket.on('close', () => {
      value.closes += 1
    })
  })
  return value
}

async function installTerminalConstructorProbe(
  page: import('@playwright/test').Page,
): Promise<void> {
  await page.addInitScript(() => {
    const observedWindow = window as typeof window & {
      __stateportTerminalConstructors?: Array<{
        url: string
        requestedProtocols: string[]
        negotiatedProtocol?: string
      }>
    }
    observedWindow.__stateportTerminalConstructors = []
    const NativeWebSocket = window.WebSocket
    class ObservedWebSocket extends NativeWebSocket {
      constructor(url: string | URL, protocols?: string | string[]) {
        super(url, protocols)
        const observation = {
          url: String(url),
          requestedProtocols:
            typeof protocols === 'string'
              ? [protocols]
              : Array.isArray(protocols)
                ? [...protocols]
                : [],
        }
        observedWindow.__stateportTerminalConstructors!.push(observation)
        this.addEventListener('open', () => {
          observation.negotiatedProtocol = this.protocol
        })
      }
    }
    window.WebSocket = ObservedWebSocket
  })
}

function parsedTerminalControls(
  signals: TerminalSocketSignals,
  direction: TerminalSocketFrame['direction'],
): Array<Record<string, unknown>> {
  return signals.frames
    .filter((frame) => frame.direction === direction && !frame.binary)
    .flatMap((frame) => {
      try {
        const parsed: unknown = JSON.parse(frame.text)
        return parsed && typeof parsed === 'object'
          ? [parsed as Record<string, unknown>]
          : []
      } catch {
        return []
      }
    })
}

function expectClean(
  signals: BrowserSignals,
  allowedErrors: Array<{ status: number; method: string; path: string }> = [],
  allowedRequestFailures: string[] = [],
): void {
  const statusReason: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    409: 'Conflict',
    503: 'Service Unavailable',
  }
  const allowedConsoleErrors = allowedErrors.map(
    ({ status }) =>
      `Failed to load resource: the server responded with a status of ${status} (${statusReason[status] ?? 'Error'})`,
  )
  // Chromium's console emission for a handled non-2xx fetch is not a stable
  // network contract: current builds may omit the generic resource error.
  // The response observer below remains authoritative and exact; console
  // diagnostics are accepted only when they correspond to that allowlist.
  expect(
    signals.console.filter((message) => !allowedConsoleErrors.includes(message)),
    'unexpected browser console errors',
  ).toEqual([])
  expect(signals.pageErrors, 'uncaught page errors').toEqual([])
  expect(
    signals.requestFailures.filter(
      (failure) => !allowedRequestFailures.includes(failure),
    ),
    'unexpected failed browser requests',
  ).toEqual([])
  expect(signals.errorResponses, 'unexpected HTTP error responses').toEqual(allowedErrors)
}

function expectRequest(
  signals: BrowserSignals,
  method: string,
  predicate: string | RegExp,
): void {
  expect(
    signals.requests.some(
      (request) =>
        request.method === method &&
        (typeof predicate === 'string'
          ? request.path === predicate
          : predicate.test(request.path)),
    ),
    `${method} ${String(predicate)} was not observed`,
  ).toBe(true)
}

async function openApplicationRoute(
  page: import('@playwright/test').Page,
  hash: string,
): Promise<void> {
  await page.goto(`${service.url}/#${hash}`, {
    waitUntil: 'domcontentloaded',
    timeout: 30_000,
  })
  await expect(page.getByTestId('app-shell')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('Scenario data is shown')
  await expect(page.locator('body')).not.toContainText(disposableRoot)
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async () => {
  disposableRoot = mkdtempSync(path.join(os.tmpdir(), 'stateport-live-core-browser-'))
  service = await startService()
  validateServedBuildIdentity()
  projectCanonicalBefore = readFileSync(
    path.join(projectRoot, 'state', 'PROJECT.yaml'),
    'utf8',
  )
  projectHeadBefore = execFileSync(
    'git',
    ['-C', projectRoot, 'rev-parse', 'HEAD'],
    { encoding: 'utf8', timeout: 5_000 },
  ).trim()
  importCandidateHeadBefore = execFileSync(
    'git',
    ['-C', importCandidateRoot, 'rev-parse', 'HEAD'],
    { encoding: 'utf8', timeout: 5_000 },
  ).trim()
  infrastructureCanonicalBefore = readFileSync(
    path.join(infrastructureRoot, 'state', 'PROJECT.yaml'),
    'utf8',
  )
  infrastructureHeadBefore = execFileSync(
    'git',
    ['-C', infrastructureRoot, 'rev-parse', 'HEAD'],
    { encoding: 'utf8', timeout: 5_000 },
  ).trim()
  infrastructureStatusBefore = execFileSync(
    'git',
    ['-C', infrastructureRoot, 'status', '--short'],
    { encoding: 'utf8', timeout: 5_000 },
  )
  if (!infrastructureStatusBefore.includes('local-operator-note.txt')) {
    throw new Error('the infrastructure fixture must preserve one explicit dirty repository fact')
  }
})

test.afterAll(async () => {
  writeFileSync(
    path.join(ARTIFACT_ROOT, 'matrix.json'),
    `${JSON.stringify(matrix, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600 },
  )
  await stopChild(service?.child)
  if (disposableRoot) {
    const podmanRoot = path.join(disposableRoot, 'podman')
    const containerStorage = path.join(podmanRoot, 'graphroot')
    if (existsSync(containerStorage)) {
      const xdg = path.join(disposableRoot, 'xdg')
      // Rootless Podman keeps a pause process for its mount namespace. Reset
      // only this fixture's XDG-scoped store before removing the temp tree.
      execFileSync('podman', ['system', 'reset', '--force'], {
        env: {
          ...process.env,
          XDG_CONFIG_HOME: path.join(xdg, 'config'),
          XDG_DATA_HOME: path.join(xdg, 'data'),
          XDG_STATE_HOME: path.join(xdg, 'state'),
          CONTAINERS_STORAGE_CONF: path.join(podmanRoot, 'storage.conf'),
        },
        timeout: 30_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    }
    rmSync(disposableRoot, { recursive: true, force: true })
  }
})

test('Bootstrap establishes the real session and application-scoped experience gates', async ({ page }) => {
  const signals = browserSignals(page)
  const statusResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      new URL(response.url()).pathname === '/v1/status',
  )

  await openApplicationRoute(page, '/applications')
  const statusResponse = await statusResponsePromise
  expect(statusResponse.status()).toBe(200)
  const statusPayload = (await statusResponse.json()) as {
    result: {
      actor: {
        role: string
        actorId: string
        platformOperationsAllowed: boolean
      }
    }
  }
  expect(statusPayload.result.actor).toEqual({
    role: 'local_user',
    actorId: 'local-user',
    platformOperationsAllowed: false,
    statebenchInspectionAllowed: false,
  })

  await expect(page.getByTestId('applications-page')).toBeVisible()
  await expect(page.getByTestId(`instance-row-${PROJECT_ID}`)).toContainText(
    'Live Core Project',
  )
  await expect(page.getByTestId(`instance-row-${STUDY_ID}`)).toContainText(
    'Live Core Study',
  )
  await expect(page.getByTestId('service-chip')).toHaveAttribute(
    'aria-label',
    'Local service: Connected',
  )

  await page
    .getByTestId(`instance-row-${PROJECT_ID}`)
    .locator('button')
    .first()
    .click()
  await expect(page).toHaveURL(new RegExp(`#\\/app\\/${PROJECT_ID}$`))
  await expect(page.getByTestId('app-switcher')).toContainText('Live Core Project')
  await expect(page.getByRole('link', { name: 'Workbench' })).toBeVisible()

  await page.getByTestId('app-switcher').click()
  await page.getByRole('menuitem', { name: 'Live Core Study' }).click()
  await expect(page).toHaveURL(new RegExp(`#\\/app\\/${STUDY_ID}$`))
  await expect(page.getByTestId('app-switcher')).toContainText('Live Core Study')
  await expect(page.getByRole('link', { name: 'Learning' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Workbench' })).toHaveCount(0)

  await page.goto(`${service.url}/#/applications`)
  await expect(page.getByTestId('continue-section')).toContainText('Live Core Study')

  expectRequest(signals, 'GET', '/session')
  expectRequest(signals, 'GET', '/v1/status')
  expectRequest(signals, 'GET', '/v1/instances')
  expectRequest(signals, 'GET', `/v1/instances/${PROJECT_ID}/experience`)
  expectRequest(signals, 'GET', `/v1/instances/${STUDY_ID}/experience`)
  expect(
    signals.responses.filter(
      (response) => response.path === '/session' && response.status === 200,
    ).length,
  ).toBeGreaterThanOrEqual(1)
  expect(
    signals.responses.some((response) => response.status === 401),
    'bootstrap must not enter an authentication loop',
  ).toBe(false)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'bootstrap-applications-and-gates.png'),
    fullPage: true,
  })
  // StudyState does not grant CTO orchestration. Receipt aggregation must use
  // the effective capability projection and omit the goal-execution source
  // before issuing any request, rather than probing an unauthorized endpoint.
  expect(
    signals.requests.some(
      (request) =>
        request.method === 'GET' &&
        request.path === `/v1/instances/${STUDY_ID}/goal-execution`,
    ),
    'StudyState must not probe the unauthorized goal-execution source',
  ).toBe(false)
  expect(
    signals.requests.some(
      (request) =>
        request.method === 'GET' &&
        request.path === `/v1/instances/${PROJECT_ID}/goal-execution`,
    ),
    'CTO-capable project must probe the authorized goal-execution source',
  ).toBe(true)
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    bootstrapApplications: {
      status: 'live-tested',
      session: 'same-origin loopback session established',
      actor: 'local_user/local-user',
      service: 'connected',
      instances: [PROJECT_ID, STUDY_ID],
      applicationSwitcher: 'live-tested',
      continuity: 'last application resumed',
      experienceDescriptors: 'live-tested',
      capabilityGates: {
        projectWorkbench: 'available',
        studyWorkbench: 'absent',
        studyGoalExecutionReceiptSource: 'omitted before network request',
      },
    },
  }
})

test('Catalog installs a reviewed fixture and imports an allowlisted repository by exact identity', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/catalog')

  const installButton = page.getByTestId(
    'install-stateport.development-reference',
  )
  await expect(installButton).toBeVisible()
  await expect(installButton).toHaveText('New instance')
  await installButton.click()
  const review = page.getByTestId('install-review')
  await expect(review).toBeVisible()
  await expect(review).toContainText(
    'Installing this package requires your confirmation.',
  )
  await page.getByTestId('instance-name-input').fill('Browser Installed Project')

  const installResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/v1/application-fixtures/install',
  )
  await page.getByTestId('confirm-install').click()
  const installResponse = await installResponsePromise
  expect(installResponse.status()).toBe(200)
  const installRequest = installResponse.request().postDataJSON() as {
    applicationId: string
    instanceId: string
    name: string
    applicationDescriptorDigest: string
    applicationPackageDigest: string
    experienceDescriptorDigest: string
  }
  expect(installRequest.applicationId).toBe('stateport.development-reference')
  expect(installRequest.instanceId).toMatch(/^ins_[0-9a-f]{16}$/)
  expect(installRequest.name).toBe('Browser Installed Project')
  expect(installRequest.applicationDescriptorDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )
  expect(installRequest.applicationPackageDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )
  expect(installRequest.experienceDescriptorDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )

  const installPayload = (await installResponse.json()) as {
    result: {
      entry: { instanceId: string }
      receipt: { receiptId: string }
    }
  }
  expect(installPayload.result.entry.instanceId).toBe(installRequest.instanceId)
  expect(installPayload.result.receipt.receiptId).toContain(
    installRequest.instanceId,
  )
  await expect(page.getByTestId('install-success')).toContainText(
    'Browser Installed Project is installed',
  )
  await page.getByTestId('view-install-receipt').click()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'application.install.fixture',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    installPayload.result.receipt.receiptId,
  )

  await page.goto(`${service.url}/#/catalog`)
  await expect(page.getByTestId('package-list')).toBeVisible()
  await page.getByRole('button', { name: 'More catalog actions' }).click()
  await page
    .getByRole('menuitem', { name: 'Import a local repository' })
    .click()
  const candidateButton = page.getByTestId(
    `import-candidate-${IMPORT_CANDIDATE_NAME}`,
  )
  await expect(candidateButton).toBeVisible()

  const inspectionResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/v1/repository-import/inspect',
  )
  await candidateButton.click()
  const inspectionResponse = await inspectionResponsePromise
  expect(inspectionResponse.status()).toBe(200)
  const inspectionRequest = inspectionResponse.request().postDataJSON() as {
    candidateId: string
  }
  expect(inspectionRequest).toEqual({
    candidateId: expect.stringMatching(/^repo-[0-9a-f]{32}$/),
  })
  const inspectionPayload = (await inspectionResponse.json()) as {
    result: {
      candidateId: string
      inspectionDigest: string
      sourceIdentity: {
        branch: string
        headCommit: string
        dirty: boolean
      }
      mutated: boolean
    }
  }
  expect(inspectionPayload.result.candidateId).toBe(
    inspectionRequest.candidateId,
  )
  expect(inspectionPayload.result.inspectionDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )
  expect(inspectionPayload.result.sourceIdentity).toMatchObject({
    branch: 'main',
    headCommit: importCandidateHeadBefore,
    dirty: false,
  })
  expect(inspectionPayload.result.mutated).toBe(false)
  await expect(page.getByTestId('import-review')).toContainText('Clean')
  await expect(page.getByTestId('import-register')).toBeDisabled()
  await page
    .getByRole('checkbox', {
      name: 'Approve registration of the exact inspected repository',
    })
    .click()

  const registrationResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/v1/repository-import/register',
  )
  await page.getByTestId('import-register').click()
  const registrationResponse = await registrationResponsePromise
  expect(registrationResponse.status()).toBe(200)
  const registrationRequest =
    registrationResponse.request().postDataJSON() as {
      candidateId: string
      inspectionDigest: string
      instanceId: string
      name: string
      approval: {
        decision: string
        actorId: string
        proposalDigest: string
      }
    }
  expect(registrationRequest.candidateId).toBe(inspectionRequest.candidateId)
  expect(registrationRequest.inspectionDigest).toBe(
    inspectionPayload.result.inspectionDigest,
  )
  expect(registrationRequest.instanceId).toMatch(/^ins-[0-9a-f]{16}$/)
  expect(registrationRequest.name).toBe(IMPORT_CANDIDATE_NAME)
  expect(registrationRequest.approval).toEqual({
    decision: 'approve',
    actorId: 'local-user',
    proposalDigest: inspectionPayload.result.inspectionDigest,
  })
  const registrationPayload = (await registrationResponse.json()) as {
    result: {
      entry: { instanceId: string }
      inspection: { candidateId: string; inspectionDigest: string }
      receipt: { receiptId: string; approval: { proposalDigest: string } }
    }
  }
  expect(registrationPayload.result.entry.instanceId).toBe(
    registrationRequest.instanceId,
  )
  expect(registrationPayload.result.inspection.candidateId).toBe(
    inspectionRequest.candidateId,
  )
  expect(registrationPayload.result.inspection.inspectionDigest).toBe(
    inspectionPayload.result.inspectionDigest,
  )
  expect(registrationPayload.result.receipt.approval.proposalDigest).toBe(
    inspectionPayload.result.inspectionDigest,
  )
  await expect(page.getByTestId('import-done')).toContainText(
    `${IMPORT_CANDIDATE_NAME} is registered`,
  )

  expect(
    execFileSync('git', ['-C', importCandidateRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(importCandidateHeadBefore)
  expect(
    execFileSync('git', ['-C', importCandidateRoot, 'status', '--short'], {
      encoding: 'utf8',
      timeout: 5_000,
    }),
  ).toBe('')

  await page.getByTestId('import-view-receipt').click()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'repository.import',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    registrationPayload.result.receipt.receiptId,
  )

  await page.goto(`${service.url}/#/app/${registrationRequest.instanceId}`)
  await expect(page.getByTestId('app-overview-stub')).toBeVisible()
  await expect(page.locator('body')).not.toContainText(importCandidateRoot)

  expectRequest(signals, 'GET', '/v1/applications')
  expectRequest(signals, 'POST', '/v1/application-fixtures/install')
  expectRequest(signals, 'GET', '/v1/repository-import/local-candidates')
  expectRequest(signals, 'POST', '/v1/repository-import/inspect')
  expectRequest(signals, 'GET', '/v1/status')
  expectRequest(signals, 'POST', '/v1/repository-import/register')

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'catalog-repository-import-receipt.png'),
    fullPage: true,
  })
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    catalogRepositoryImport: {
      status: 'live-tested',
      reviewedFixtureInstall: {
        exactDescriptorIdentities: 'verified',
        explicitConfirmation: 'live-tested',
        installationReceipt: 'opened',
      },
      localRepositoryImport: {
        allowlistedDiscovery: 'live-tested',
        inspection: 'read-only and exact-identity bound',
        approval: 'local actor and inspection digest bound',
        registration: 'live-tested',
        repositoryGitState: 'unchanged',
        receipt: 'opened',
      },
    },
  }
})

test('Settings retries one expired session, rolls back exact backend state, and keeps app preferences local', async ({ page }) => {
  const signals = browserSignals(page)
  const initialSettingsResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      new URL(response.url()).pathname === '/v1/settings',
  )
  await openApplicationRoute(page, '/settings/appearance')
  const initialSettingsResponse = await initialSettingsResponsePromise
  const initialSettingsPayload = (await initialSettingsResponse.json()) as {
    result: { revision: number }
  }
  const initialRevision = initialSettingsPayload.result.revision

  await expect(page.getByTestId('settings-group-appearance')).toBeVisible()
  await page.getByRole('radio', { name: 'Dark' }).click()
  await page
    .getByRole('radio', { name: 'Large (112.5%)' })
    .click()
  await expect(page.getByTestId('settings-save-bar')).toBeVisible()

  // Expire only the browser session after the client has cached its CSRF
  // token. The transport must make one failed mutation, refresh /session once,
  // retry the exact body once, and then stop.
  await page.context().addCookies([
    {
      name: 'stateport_session',
      value: 'expired-live-core-session',
      url: service.url,
      httpOnly: true,
      sameSite: 'Strict',
    },
  ])
  const unauthorizedResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/v1/settings' &&
      response.status() === 401,
  )
  const savedResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/v1/settings' &&
      response.status() === 200,
  )
  await page.getByTestId('settings-save').click()
  await unauthorizedResponsePromise
  const savedResponse = await savedResponsePromise
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)

  const settingsPosts = signals.requests.filter(
    (request) => request.method === 'POST' && request.path === '/v1/settings',
  )
  expect(settingsPosts).toHaveLength(2)
  expect(settingsPosts[0].body).toEqual({
    expectedRevision: initialRevision,
    changes: { 'general.appearance': 'dark' },
  })
  expect(settingsPosts[1].body).toEqual(settingsPosts[0].body)
  const settingsResponses = signals.responses.filter(
    (response) =>
      response.method === 'POST' && response.path === '/v1/settings',
  )
  expect(settingsResponses.map((response) => response.status)).toEqual([
    401,
    200,
  ])
  expect(
    signals.requests.filter(
      (request) => request.method === 'GET' && request.path === '/session',
    ).length,
  ).toBeGreaterThanOrEqual(2)

  const savedPayload = (await savedResponse.json()) as {
    result: {
      projection: { revision: number }
      receipt: {
        receiptId: string
        revision: number
        action: string
        changes: Record<string, unknown>
      }
    }
  }
  expect(savedPayload.result.projection.revision).toBe(initialRevision + 1)
  expect(savedPayload.result.receipt).toMatchObject({
    revision: initialRevision + 1,
    action: 'settings.patch',
    changes: { 'general.appearance': 'dark' },
  })
  const settingsReceiptId = savedPayload.result.receipt.receiptId
  const globalOverlay = await page.evaluate(() =>
    JSON.parse(
      localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}',
    ),
  )
  expect(globalOverlay.appearance.fontScale).toBe(112.5)
  expect(globalOverlay.appearance.theme).toBeUndefined()

  await page.goto(`${service.url}/#/settings/advanced`)
  await expect(page.getByTestId('global-settings-history')).toContainText(
    `Current backend revision ${initialRevision + 1}`,
  )
  const rollbackButton = page.getByTestId(
    `settings-rollback-${settingsReceiptId}`,
  )
  await expect(rollbackButton).toBeVisible()
  await rollbackButton.click()
  await expect(page.getByTestId('confirm-dialog')).toContainText(
    `Global settings receipt ${settingsReceiptId}`,
  )
  await expect(page.getByTestId('confirm-dialog')).toContainText(
    'Browser-only preferences and application settings are not affected',
  )

  const rollbackResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/v1/settings/rollback',
  )
  await page.getByTestId('confirm-action').click()
  const rollbackResponse = await rollbackResponsePromise
  expect(rollbackResponse.status()).toBe(200)
  expect(rollbackResponse.request().postDataJSON()).toEqual({
    expectedRevision: initialRevision + 1,
    receiptId: settingsReceiptId,
  })
  const rollbackPayload = (await rollbackResponse.json()) as {
    result: {
      projection: { revision: number }
      receipt: { action: string; revision: number }
    }
  }
  expect(rollbackPayload.result.projection.revision).toBe(initialRevision + 2)
  expect(rollbackPayload.result.receipt).toMatchObject({
    action: 'settings.rollback',
    revision: initialRevision + 2,
  })
  await expect(page.getByTestId('global-settings-history')).toContainText(
    `Current backend revision ${initialRevision + 2}`,
  )
  expect(
    await page.evaluate(
      () =>
        JSON.parse(
          localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}',
        ).appearance.fontScale,
    ),
  ).toBe(112.5)

  const staleResult = await page.evaluate(
    async ({ expectedRevision }) => {
      const sessionResponse = await fetch('/session', {
        method: 'POST',
        credentials: 'same-origin',
      })
      const session = (await sessionResponse.json()) as {
        result: { csrfToken: string }
      }
      const response = await fetch('/v1/settings', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'content-type': 'application/json',
          'x-stateport-csrf': session.result.csrfToken,
        },
        body: JSON.stringify({
          expectedRevision,
          changes: { 'general.appearance': 'light' },
        }),
      })
      return {
        status: response.status,
        body: (await response.json()) as {
          error?: { code?: string; message?: string }
        },
      }
    },
    { expectedRevision: initialRevision },
  )
  expect(staleResult.status).toBe(409)
  expect(staleResult.body.error?.code).toBe('settings_request_refused')
  expect(staleResult.body.error?.message).toContain('revision is stale')

  const backendAfterStale = await page.evaluate(async () => {
    const response = await fetch('/v1/settings', {
      credentials: 'same-origin',
    })
    return (await response.json()) as {
      result: {
        revision: number
        sections: Array<{
          fields: Array<{ key: string; value: unknown }>
        }>
      }
    }
  })
  expect(backendAfterStale.result.revision).toBe(initialRevision + 2)
  const backendAppearance = backendAfterStale.result.sections
    .flatMap((section) => section.fields)
    .find((field) => field.key === 'general.appearance')
  expect(backendAppearance?.value).toBe('system')

  const appSettingsPostsBefore = signals.requests.filter(
    (request) =>
      request.method === 'POST' &&
      request.path.includes(`/v1/instances/${PROJECT_ID}/settings`),
  ).length
  await page.goto(
    `${service.url}/#/app/${PROJECT_ID}/settings?group=notifications`,
  )
  const notificationLevel = page.getByRole('combobox', {
    name: 'Notification level',
  })
  await expect(notificationLevel).toHaveValue('inherit')
  await notificationLevel.selectOption('none')
  await expect(page.getByTestId('settings-save-bar')).toContainText(
    'Unsaved browser preferences',
  )
  await page.getByTestId('app-settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  await expect(
    page.getByRole('status').filter({ hasText: 'Browser preferences saved' }),
  ).toBeVisible()
  expect(
    signals.requests.filter(
      (request) =>
        request.method === 'POST' &&
        request.path.includes(`/v1/instances/${PROJECT_ID}/settings`),
    ).length,
  ).toBe(appSettingsPostsBefore)
  expect(
    await page.evaluate(
      ({ instanceId }) =>
        JSON.parse(
          localStorage.getItem('stateport.http.app-ui-settings.v1') ?? '{}',
        )[instanceId].notificationLevel,
      { instanceId: PROJECT_ID },
    ),
  ).toBe('none')
  await expect(notificationLevel).toHaveValue('none')
  expect(readFileSync(path.join(projectRoot, 'state', 'PROJECT.yaml'), 'utf8')).toBe(
    projectCanonicalBefore,
  )
  expect(
    execFileSync('git', ['-C', projectRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(projectHeadBefore)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'settings-local-preference-after-rollback.png'),
    fullPage: true,
  })
  expectClean(signals, [
    { status: 401, method: 'POST', path: '/v1/settings' },
    { status: 409, method: 'POST', path: '/v1/settings' },
  ], [
    // Chromium reports the deliberately expired first fetch as aborted after
    // the transport consumes its 401 and immediately performs the one allowed
    // session refresh + exact retry. The corresponding 401 response is also
    // asserted above, so this is not a hidden network failure.
    `POST ${service.url}/v1/settings net::ERR_ABORTED`,
  ])

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    settings: {
      status: 'live-tested',
      globalRead: 'live-tested',
      globalSave: 'exact revision and backend-owned field only',
      sessionRecovery: 'one 401, one /session refresh, one exact retry',
      globalRollback: 'receipt and current revision bound',
      staleRevision: '409 fail-closed; state unchanged',
      browserOnlyGlobalPreference: 'preserved across backend rollback',
      applicationRead: 'live-tested',
      applicationPreference: 'browser-local and explicitly labelled',
      applicationCanonicalState: 'unchanged',
      applicationRollback:
        'not applicable: current application projection exposes no writable backend fields',
    },
  }
})

test('Notifications mark real attention read without claiming the condition was resolved', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}`)

  await page
    .getByTestId('topbar')
    .getByRole('button', { name: /^Notifications/ })
    .click()
  const popover = page.getByTestId('notifications-popover')
  await expect(popover).toBeVisible()
  const notification = popover
    .getByRole('button')
    .filter({ hasText: 'No verified backup recorded' })
    .first()
  await expect(notification).toBeVisible()

  const readResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'POST' &&
      /^\/v1\/instances\/[^/]+\/activity\/recovery-backup\/read$/.test(
        url.pathname,
      )
    )
  })
  await notification.click()
  const readResponse = await readResponsePromise
  expect(readResponse.status()).toBe(200)
  const readPath = new URL(readResponse.url()).pathname
  const readRequest = readResponse.request().postDataJSON() as {
    expectedVersion: number
  }
  expect(readRequest.expectedVersion).toBeGreaterThanOrEqual(1)
  const readPayload = (await readResponse.json()) as {
    result: {
      attention: {
        attentionId: string
        readAt: string
        acknowledgedAt: string | null
        version: number
      }
      receipt: {
        action: string
        effect: string
        attentionVersion: number
      }
    }
  }
  expect(readPayload.result.attention).toMatchObject({
    attentionId: 'recovery-backup',
    acknowledgedAt: null,
    version: readRequest.expectedVersion + 1,
  })
  expect(readPayload.result.attention.readAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  expect(readPayload.result.receipt).toMatchObject({
    action: 'attention.read',
    effect: 'local_operational_attention_state_only',
    attentionVersion: readRequest.expectedVersion + 1,
  })

  const staleRead = await page.evaluate(
    async ({ path: requestPath, body }) => {
      const sessionResponse = await fetch('/session', {
        method: 'POST',
        credentials: 'same-origin',
      })
      const session = (await sessionResponse.json()) as {
        result: { csrfToken: string }
      }
      const response = await fetch(requestPath, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'content-type': 'application/json',
          'x-stateport-csrf': session.result.csrfToken,
        },
        body: JSON.stringify(body),
      })
      return {
        status: response.status,
        body: (await response.json()) as {
          error?: { code?: string; message?: string }
        },
      }
    },
    { path: readPath, body: readRequest },
  )
  expect(staleRead.status).toBe(409)
  expect(staleRead.body.error?.code).toBe('activity_receipts_refused')
  expect(staleRead.body.error?.message).toContain('changed')

  const owningInstanceId = readPath.split('/')[3]
  const currentFacts = await page.evaluate(
    async ({ instanceId }) => {
      const [instanceResponse, activityResponse] = await Promise.all([
        fetch(`/v1/instances/${instanceId}`, { credentials: 'same-origin' }),
        fetch(`/v1/instances/${instanceId}/activity`, {
          credentials: 'same-origin',
        }),
      ])
      return {
        instance: (await instanceResponse.json()) as {
          result: { recovery: { status: string } }
        },
        activity: (await activityResponse.json()) as {
          result: {
            attention: Array<{
              attentionId: string
              readAt: string | null
              acknowledgedAt: string | null
            }>
          }
        },
      }
    },
    { instanceId: owningInstanceId },
  )
  expect(currentFacts.instance.result.recovery.status).toBe('no_backup')
  expect(
    currentFacts.activity.result.attention.find(
      (item) => item.attentionId === 'recovery-backup',
    ),
  ).toMatchObject({
    readAt: expect.any(String),
    acknowledgedAt: null,
  })

  await page
    .getByTestId('topbar')
    .getByRole('button', { name: /^Notifications/ })
    .click()
  await expect(
    page
      .getByTestId('notifications-popover')
      .getByRole('button')
      .filter({ hasText: 'No verified backup recorded' })
      .first(),
  ).toBeVisible()
  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'activity-read-condition-unresolved.png'),
    fullPage: true,
  })
  expectClean(signals, [
    { status: 409, method: 'POST', path: readPath },
  ])

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    activity: {
      status: 'live-tested',
      notificationRead: 'version-bound and receipted',
      staleVersion: '409 fail-closed',
      underlyingCondition: 'still no_backup after read',
      acknowledged: false,
      claim: 'read state is not condition resolution',
    },
  }
})

test('Approvals inbox routes a prepared run decision to its owning exact-revision endpoint', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${STUDY_ID}/runs`)

  await page
    .getByTestId('runs-action-studystate.sample.record-evidence/v1')
    .click()
  await page
    .getByLabel('What did you learn?')
    .fill('The global approvals inbox preserves the exact run authority.')
  const prepareResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${STUDY_ID}/execution/prepare`,
  )
  await page.getByTestId('run-prepare').click()
  const prepareResponse = await prepareResponsePromise
  expect(prepareResponse.status()).toBe(200)
  const prepareRequest = prepareResponse.request().postDataJSON() as {
    expectedInstanceId: string
    actionId: string
    engineId: string
    inputs: Record<string, unknown>
  }
  expect(prepareRequest).toMatchObject({
    expectedInstanceId: STUDY_ID,
    actionId: 'studystate.sample.record-evidence/v1',
    engineId: 'synthetic',
  })
  const preparePayload = (await prepareResponse.json()) as {
    result: {
      run: {
        runId: string
        instanceId: string
        revision: number
        runSpecDigest: string
      }
    }
  }
  const preparedRun = preparePayload.result.run
  const runSpecDigest = preparedRun.runSpecDigest
  expect(preparedRun.instanceId).toBe(STUDY_ID)
  expect(runSpecDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  await expect(page.getByTestId('run-exact-status')).toHaveText(
    'Awaiting Approval',
  )

  const approvalId = `run_approval:${preparedRun.runId}`
  await page.goto(
    `${service.url}/#/approvals/${encodeURIComponent(approvalId)}`,
  )
  const detail = page.getByTestId('approval-detail')
  await expect(detail).toBeVisible()
  // The title renders the declared action display name (the additive
  // actionDisplayName hint); the raw action identifier stays visible in the
  // exact scope so the decision remains bound to the exact action identity.
  await expect(detail).toContainText(
    'Approve Complete activity and record evidence',
  )
  await expect(detail).toContainText('studystate.sample.record-evidence/v1')
  await expect(detail).toContainText(preparedRun.runId)
  await expect(detail).toContainText(
    `/v1/runs/${preparedRun.runId}/approve`,
  )
  await expect(page.getByTestId('approve-button')).toBeVisible()

  const approveResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/runs/${preparedRun.runId}/approve`,
  )
  await page.getByTestId('approve-button').click()
  const approveResponse = await approveResponsePromise
  expect(approveResponse.status()).toBe(200)
  expect(approveResponse.request().postDataJSON()).toEqual({
    expectedInstanceId: STUDY_ID,
    expectedRevision: preparedRun.revision,
  })
  const approvePayload = (await approveResponse.json()) as {
    result: {
      runId: string
      instanceId: string
      revision: number
      status: string
      runSpecDigest: string
    }
  }
  expect(approvePayload.result).toMatchObject({
    runId: preparedRun.runId,
    instanceId: STUDY_ID,
    revision: preparedRun.revision + 1,
    status: 'approved',
    runSpecDigest,
  })
  await expect(page.getByTestId('decision-result')).toContainText('Approved')
  await expect(page.getByTestId('pending-count')).toHaveText('0 pending')

  expectRequest(signals, 'GET', '/v1/approvals')
  expectRequest(signals, 'POST', `/v1/runs/${preparedRun.runId}/approve`)
  expect(
    signals.requests.some((request) => request.path === '/v1/approvals/decision'),
    'no invented generic approval endpoint may be called',
  ).toBe(false)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'approval-owning-run-endpoint.png'),
    fullPage: true,
  })
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    approvals: {
      status: 'live-tested',
      index: 'live-tested',
      detail: 'exact run, instance, revision, and digest reviewed',
      decision: 'routed to run authority',
      genericEndpoint: 'not used',
      resultingState: 'approved; execution remains separate',
    },
  }
})

test('StudyState completes the exact governed run lifecycle without receiving Workbench', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${STUDY_ID}/runs`)

  await expect(page.getByRole('heading', { level: 1, name: 'Governed runs' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Learning' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Workbench' })).toHaveCount(0)
  await expect(page.getByTestId('run-engines')).toContainText('Deterministic fixture; production-ineligible.')

  await page
    .getByTestId('runs-action-studystate.sample.record-evidence/v1')
    .click()
  await page.getByLabel('What did you learn?').fill(EVIDENCE_SUMMARY)
  await page.getByTestId('run-prepare').click()
  await expect(page.getByTestId('run-exact-status')).toHaveText('Awaiting Approval')

  await page.getByTestId('run-approve').click()
  await expect(page.getByTestId('run-exact-status')).toHaveText('Approved')

  await page.getByTestId('run-execute').click()
  await expect(page.getByTestId('run-exact-status')).toHaveText('State Change Proposed')
  await expect(page.getByTestId('run-proposal-approve')).toBeVisible()

  await page.getByTestId('run-proposal-approve').click()
  await expect(page.getByTestId('run-exact-status')).toHaveText('State Change Approved')

  const applyResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'POST' &&
      /^\/v1\/runs\/[^/]+\/apply$/.test(url.pathname)
    )
  })
  await page.getByTestId('run-apply').click()
  const applyResponse = await applyResponsePromise
  expect(applyResponse.ok()).toBe(true)
  const appliedPayload = (await applyResponse.json()) as {
    result: {
      run: {
        runId: string
        receiptId: string
        closureReceipt: {
          receiptId: string
          runId: string
          instanceId: string
          applicationId: string
          status: string
          validation: { state: string }
          claimState: {
            applied: boolean
            locallyValidated: boolean
            humanAccepted: boolean
            remotelyAccepted: boolean
          }
        }
      }
    }
  }
  const appliedRun = appliedPayload.result.run
  const closureReceipt = appliedRun.closureReceipt
  expect(appliedRun.receiptId).toBe(closureReceipt.receiptId)
  expect(closureReceipt.runId).toBe(appliedRun.runId)
  expect(closureReceipt.instanceId).toBe(STUDY_ID)
  expect(closureReceipt.applicationId).toBe(STUDY_APPLICATION_ID)
  expect(closureReceipt.status).toBe('applied')
  expect(closureReceipt.validation.state).toBe('validated')
  expect(closureReceipt.claimState).toEqual({
    applied: true,
    locallyValidated: true,
    humanAccepted: false,
    remotelyAccepted: false,
  })
  await expect(page.getByTestId('run-exact-status')).toHaveText('Applied')
  await expect(
    page.getByText('Applied; post-apply validation recorded as passed', { exact: true }),
  ).toBeVisible()
  await expect(page.getByTestId('run-validation-truth')).toContainText('Validated')
  expect(readFileSync(path.join(studyRoot, 'state', 'LEARNING.yaml'), 'utf8')).toContain(
    EVIDENCE_SUMMARY,
  )

  await page.getByTestId('run-open-evidence').click()
  await expect(page.getByTestId('run-bundle')).toContainText('Verified')
  await expect(page.getByTestId('run-bundle')).toContainText('Applied bundle')
  await expect(page.getByTestId('run-statebench-gated')).toBeVisible()
  const receiptLink = page.getByRole('link', { name: closureReceipt.receiptId })
  await expect(receiptLink).toBeVisible()
  await page.getByRole('button', { name: 'Raw evidence JSON' }).click()
  await expect(page.getByTestId('run-raw-json')).not.toContainText(disposableRoot)
  await expect(page.getByTestId('run-raw-json')).toContainText(closureReceipt.receiptId)

  await receiptLink.click()
  await expect(page).toHaveURL(
    new RegExp(
      `#\\/app\\/${STUDY_ID}\\/receipts\\/${closureReceipt.receiptId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
    ),
  )
  await expect(page.getByTestId('receipt-detail')).toBeVisible()
  await expect(
    page.getByText('Application changes applied', { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText('governed_run.apply', { exact: true }),
  ).not.toBeVisible()
  await page.getByRole('button', { name: 'IDs, revisions, and digests' }).click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText('Validated')
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    closureReceipt.receiptId,
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'governed_run.apply',
  )
  await page.getByRole('button', { name: 'Raw JSON', exact: true }).click()
  await expect(page.getByTestId('receipt-raw-json')).toContainText(
    'governed_run.apply',
  )
  const receiptRaw = JSON.parse(
    (await page.getByTestId('receipt-raw-json').textContent()) ?? '{}',
  ) as {
    payload?: {
      receiptId?: string
      runId?: string
      instanceId?: string
      claimState?: Record<string, boolean>
    }
  }
  expect(receiptRaw.payload?.receiptId).toBe(closureReceipt.receiptId)
  expect(receiptRaw.payload?.runId).toBe(appliedRun.runId)
  expect(receiptRaw.payload?.instanceId).toBe(STUDY_ID)
  expect(receiptRaw.payload?.claimState).toEqual({
    applied: true,
    locallyValidated: true,
    humanAccepted: false,
    remotelyAccepted: false,
  })

  expectRequest(signals, 'GET', `/v1/instances/${STUDY_ID}/actions`)
  expectRequest(signals, 'GET', '/v1/execution/engines')
  expectRequest(signals, 'GET', `/v1/instances/${STUDY_ID}/execution/history`)
  expectRequest(signals, 'POST', `/v1/instances/${STUDY_ID}/execution/prepare`)
  expectRequest(signals, 'POST', /^\/v1\/runs\/[^/]+\/approve$/)
  expectRequest(signals, 'POST', /^\/v1\/runs\/[^/]+\/execute$/)
  expectRequest(signals, 'POST', /^\/v1\/runs\/[^/]+\/proposal-approve$/)
  expectRequest(signals, 'POST', /^\/v1\/runs\/[^/]+\/apply$/)
  expectRequest(signals, 'GET', /^\/v1\/runs\/[^/]+\/bundle$/)
  expect(signals.requests.some((request) => request.path.endsWith('/statebench'))).toBe(false)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'runs-applied-with-bundle.png'),
    fullPage: true,
  })
  expectClean(signals)

  const fileRequestsBefore = signals.requests.filter((request) =>
    request.path.includes(`/v1/instances/${STUDY_ID}/file-workspace/`),
  ).length
  await page.goto(`${service.url}/#/app/${STUDY_ID}/workbench/files`)
  await expect(page).toHaveURL(new RegExp(`#\\/app\\/${STUDY_ID}$`))
  await expect(page.getByTestId('app-overview-stub')).toBeVisible()
  expect(
    signals.requests.filter((request) =>
      request.path.includes(`/v1/instances/${STUDY_ID}/file-workspace/`),
    ).length,
  ).toBe(fileRequestsBefore)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    runs: {
      status: 'live-tested',
      instance: STUDY_ID,
      engine: 'synthetic',
      lifecycle: [
        'awaiting_approval',
        'approved',
        'state_change_proposed',
        'state_change_approved',
        'applied',
      ],
      runBundle: 'verified',
      closureReceipt: {
        indexed: 'live-tested',
        exactDetail: 'live-tested',
        applied: true,
        locallyValidated: true,
        humanAccepted: false,
        remotelyAccepted: false,
      },
      stateBench: 'capability-gated',
      canonicalMutation: 'disposable public-safe StudyState fixture only',
      workbenchCapability: 'absent and route-guarded',
    },
  }
})

test('Orchestration completes one exact provider-free slice, refuses stale authority, and stops after close', async ({ page }) => {
  const signals = browserSignals(page)
  const objective =
    'Inspect the public-safe project and close one bounded provider-free slice.'
  await openApplicationRoute(
    page,
    `/app/${PROJECT_ID}/workbench/orchestration`,
  )

  await expect(page.getByTestId('orchestration-tool')).toBeVisible()
  await expect(page.getByTestId('orchestration-degraded')).toContainText(
    'Assisted mode only',
  )
  await expect(page.getByTestId('mode-assisted')).toHaveAttribute(
    'aria-checked',
    'true',
  )
  await expect(page.getByTestId('mode-advisory')).toBeDisabled()
  await expect(page.getByTestId('mode-managed_approved_queue')).toBeDisabled()
  await page.getByTestId('orchestration-objective').fill(objective)

  const prepareResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/goal-execution/prepare`,
  )
  await page.getByTestId('orchestration-prepare').click()
  const prepareResponse = await prepareResponsePromise
  expect(prepareResponse.status()).toBe(200)
  const prepareRequest = prepareResponse.request().postDataJSON() as {
    expectedInstanceId: string
    expectedRevision: number
    expectedBaseCommit: string
    mode: string
    intent: string
  }
  expect(prepareRequest).toEqual({
    expectedInstanceId: PROJECT_ID,
    expectedRevision: 0,
    expectedBaseCommit: projectHeadBefore,
    mode: 'assisted',
    intent: objective,
  })
  const preparedPayload = (await prepareResponse.json()) as {
    result: {
      state: string
      revision: number
      providerExecution: boolean
      currentIdentity: {
        baseCommit: string
        repositoryClean: boolean
      }
      slice: {
        planDigest: string
        baseCommit: string
        requiredPermissions: string[]
      }
      selectedItem: {
        objective: string
      }
      delegation: {
        implementerActor: string
        reviewerActor: string
      }
    }
  }
  const prepared = preparedPayload.result
  expect(prepared.state).toBe('proposal_ready')
  expect(prepared.providerExecution).toBe(false)
  expect(prepared.currentIdentity).toEqual({
    baseCommit: projectHeadBefore,
    baseTree: expect.stringMatching(/^[0-9a-f]{40,64}$/),
    repositoryClean: true,
  })
  expect(prepared.slice.baseCommit).toBe(projectHeadBefore)
  expect(prepared.slice.planDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  expect(prepared.slice.requiredPermissions).toEqual(
    expect.arrayContaining(['project.read']),
  )
  expect(prepared.delegation.implementerActor).not.toBe(
    prepared.delegation.reviewerActor,
  )
  await expect(page.getByTestId('stage-review_base')).toBeVisible()
  await expect(page.getByTestId('review-base-identity')).toContainText(
    projectHeadBefore.slice(0, 10),
  )

  // The service must refuse a stale revision without changing the prepared
  // slice. This request uses the real browser session and real endpoint.
  const staleApproval = await page.evaluate(
    async ({ instanceId, revision, planDigest }) => {
      const sessionResponse = await fetch('/session', {
        credentials: 'same-origin',
      })
      const session = (await sessionResponse.json()) as {
        result: { csrfToken: string }
      }
      const response = await fetch(
        `/v1/instances/${encodeURIComponent(instanceId)}/goal-execution/approve`,
        {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'content-type': 'application/json',
            'x-stateport-csrf': session.result.csrfToken,
          },
          body: JSON.stringify({
            expectedInstanceId: instanceId,
            expectedRevision: revision - 1,
            expectedPlanDigest: planDigest,
          }),
        },
      )
      return {
        status: response.status,
        body: (await response.json()) as {
          error?: { code?: string; message?: string }
        },
      }
    },
    {
      instanceId: PROJECT_ID,
      revision: prepared.revision,
      planDigest: prepared.slice.planDigest,
    },
  )
  expect(staleApproval.status).toBe(409)
  expect(staleApproval.body.error?.code).toBe('revision_stale')
  await expect(page.getByTestId('stage-review_base')).toBeVisible()

  for (const stage of [
    'review_plan',
    'review_permissions',
    'review_budget',
    'approve',
  ]) {
    await page.getByTestId('orchestration-mark-reviewed').click()
    await expect(page.getByTestId(`stage-${stage}`)).toBeVisible()
  }
  await expect(page.getByTestId('review-plan-steps')).toHaveCount(0)
  await expect(page.getByTestId('approve-summary')).toContainText(
    prepared.selectedItem.objective,
  )
  await expect(page.getByTestId('approve-summary')).toContainText(
    projectHeadBefore.slice(0, 10),
  )

  const approveResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/goal-execution/approve`,
  )
  await page.getByTestId('orchestration-approve').click()
  const approveResponse = await approveResponsePromise
  expect(approveResponse.status()).toBe(200)
  expect(approveResponse.request().postDataJSON()).toEqual({
    expectedInstanceId: PROJECT_ID,
    expectedRevision: prepared.revision,
    expectedPlanDigest: prepared.slice.planDigest,
  })
  const approvedPayload = (await approveResponse.json()) as {
    result: {
      state: string
      revision: number
      approval: {
        approverActor: string
        planDigest: string
      }
    }
  }
  expect(approvedPayload.result.state).toBe('approved')
  expect(approvedPayload.result.approval).toMatchObject({
    approverActor: 'authenticated-local_user-approver',
    planDigest: prepared.slice.planDigest,
  })
  await expect(page.getByTestId('stage-run')).toBeVisible()

  const executeResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/goal-execution/execute`,
  )
  await page.getByTestId('orchestration-run').click()
  const executeResponse = await executeResponsePromise
  expect(executeResponse.status()).toBe(200)
  expect(executeResponse.request().postDataJSON()).toEqual({
    expectedInstanceId: PROJECT_ID,
    expectedRevision: approvedPayload.result.revision,
    expectedPlanDigest: prepared.slice.planDigest,
  })
  const executedPayload = (await executeResponse.json()) as {
    result: {
      state: string
      revision: number
      canonicalStateEffect: string
      nextItemAutoStart: boolean
      executionResult: {
        executionResultDigest: string
        implementerActor: string
        usedBudget: {
          token: number
          costMinor: number
          timeSeconds: number
          steps: number
        }
      }
    }
  }
  const executed = executedPayload.result
  expect(executed.state).toBe('awaiting_independent_review')
  expect(executed.canonicalStateEffect).toBe('none')
  expect(executed.nextItemAutoStart).toBe(false)
  expect(executed.executionResult.executionResultDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )
  expect(executed.executionResult.usedBudget.steps).toBe(1)
  await expect(page.getByTestId('stage-independent_review')).toBeVisible()
  await expect(page.getByTestId('independent-review-facts')).toContainText(
    'Budget used 1',
  )
  await expect(page.getByText('Send-back is unavailable')).toBeVisible()

  const reviewResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/goal-execution/review`,
  )
  await page.getByTestId('orchestration-accept').click()
  const reviewResponse = await reviewResponsePromise
  expect(reviewResponse.status()).toBe(200)
  expect(reviewResponse.request().postDataJSON()).toEqual({
    expectedInstanceId: PROJECT_ID,
    expectedRevision: executed.revision,
    expectedExecutionResultDigest:
      executed.executionResult.executionResultDigest,
  })
  const reviewedPayload = (await reviewResponse.json()) as {
    result: {
      state: string
      revision: number
      review: {
        reviewerActor: string
        implementerActor: string
        disposition: string
        reviewDigest: string
      }
    }
  }
  const reviewed = reviewedPayload.result
  expect(reviewed.state).toBe('independently_reviewed')
  expect(reviewed.review.reviewerActor).not.toBe(
    reviewed.review.implementerActor,
  )
  expect(reviewed.review.disposition).toBe('accepted')
  await expect(page.getByTestId('stage-close')).toBeVisible()

  const mutationCountBeforeClose = signals.requests.filter(
    (request) =>
      request.method === 'POST' &&
      request.path.includes(
        `/v1/instances/${PROJECT_ID}/goal-execution/`,
      ),
  ).length
  const closeResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/goal-execution/close`,
  )
  await page.getByTestId('orchestration-close').click()
  const closeResponse = await closeResponsePromise
  expect(closeResponse.status()).toBe(200)
  expect(closeResponse.request().postDataJSON()).toEqual({
    expectedInstanceId: PROJECT_ID,
    expectedRevision: reviewed.revision,
    expectedReviewDigest: reviewed.review.reviewDigest,
  })
  const closedPayload = (await closeResponse.json()) as {
    result: {
      state: string
      nextItemAutoStart: boolean
      canonicalStateEffect: string
      receipt: {
        receiptId: string
        approvalDigest: string
        executionResultDigest: string
        reviewDigest: string
        canonicalStateEffect: string
      }
    }
  }
  const closed = closedPayload.result
  expect(closed.state).toBe('closed')
  expect(closed.nextItemAutoStart).toBe(false)
  expect(closed.canonicalStateEffect).toBe('none')
  expect(closed.receipt).toMatchObject({
    approvalDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    executionResultDigest: executed.executionResult.executionResultDigest,
    reviewDigest: reviewed.review.reviewDigest,
    canonicalStateEffect: 'none',
  })
  await expect(page.getByTestId('stage-receipt')).toBeVisible()
  await expect(page.getByTestId('orchestration-new-slice')).toBeVisible()

  await page.waitForTimeout(750)
  expect(
    signals.requests.filter(
      (request) =>
        request.method === 'POST' &&
        request.path.includes(
          `/v1/instances/${PROJECT_ID}/goal-execution/`,
        ),
    ).length,
    'closing must not start or prepare another item',
  ).toBe(mutationCountBeforeClose + 1)
  expect(
    signals.requests.some((request) =>
      /goal-execution\/(next|continue|loop)/.test(request.path),
    ),
  ).toBe(false)

  expect(readFileSync(path.join(projectRoot, 'state', 'PROJECT.yaml'), 'utf8')).toBe(
    projectCanonicalBefore,
  )
  expect(
    execFileSync('git', ['-C', projectRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(projectHeadBefore)
  expect(
    execFileSync('git', ['-C', projectRoot, 'status', '--short'], {
      encoding: 'utf8',
      timeout: 5_000,
    }),
  ).toBe('')

  await page.getByTestId('orchestration-close-receipt').click()
  await expect(
    page.getByText('Orchestration item closed', { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByTestId('drawer').getByText('No changes', { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText('goal_execution.close', { exact: true }),
  ).not.toBeVisible()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'goal_execution.close',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    closed.receipt.receiptId,
  )

  expectRequest(
    signals,
    'POST',
    `/v1/instances/${PROJECT_ID}/goal-execution/prepare`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${PROJECT_ID}/goal-execution/approve`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${PROJECT_ID}/goal-execution/execute`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${PROJECT_ID}/goal-execution/review`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${PROJECT_ID}/goal-execution/close`,
  )

  await page.screenshot({
    path: path.join(
      ARTIFACT_ROOT,
      'orchestration-closed-provider-free-receipt.png',
    ),
    fullPage: true,
  })
  expectClean(signals, [
    {
      status: 409,
      method: 'POST',
      path: `/v1/instances/${PROJECT_ID}/goal-execution/approve`,
    },
  ])

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    orchestration: {
      status: 'live-tested',
      classification: 'real AppServer; provider-free disposable fixture',
      instance: PROJECT_ID,
      lifecycle: [
        'prepare',
        'exact approval',
        'execute',
        'independent review',
        'close',
      ],
      staleRevision: 'refused without transition',
      exactDigests: 'plan, execution result, review, and receipt verified',
      providerExecution: false,
      canonicalStateEffect: 'none; repository and canonical file unchanged',
      nextItemAutoStart: false,
      receipt: 'exact indexed detail opened',
      environmentLiveProvider: 'not attempted',
    },
  }
})

test('Infrastructure hides every operation when the deterministic target is unavailable', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(
    page,
    `/app/${UNAVAILABLE_INFRASTRUCTURE_ID}/workbench/deployments`,
  )

  const unavailable = page.getByTestId('deployments-unavailable')
  await expect(unavailable).toBeVisible()
  await expect(unavailable).toContainText('Target unavailable')
  await expect(unavailable).toContainText(
    'Grant, plan, and operation controls are hidden',
  )
  await expect(page.getByTestId('actions-row')).toHaveCount(0)
  await expect(page.getByTestId('authorization-card')).toHaveCount(0)
  await expect(page.getByTestId('plan-card')).toHaveCount(0)
  expectRequest(
    signals,
    'GET',
    `/v1/instances/${UNAVAILABLE_INFRASTRUCTURE_ID}/infrastructure`,
  )
  expect(
    signals.requests.some(
      (request) =>
        request.method === 'POST' &&
        request.path.includes(
          `/v1/instances/${UNAVAILABLE_INFRASTRUCTURE_ID}/infrastructure/`,
        ),
    ),
  ).toBe(false)

  await page.screenshot({
    path: path.join(
      ARTIFACT_ROOT,
      'infrastructure-unavailable-service-fixture.png',
    ),
    fullPage: true,
  })
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    infrastructureUnavailable: {
      status: 'live-tested',
      classification: 'service-fixture-live',
      target: 'deterministically unavailable',
      controls: 'hidden',
      mutationRequests: 0,
      environmentLive: 'not claimed',
    },
  }
})

test('Infrastructure preserves dirty and stopped truth through read-only, exact-approved, grant-covered, and destructive gates', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(
    page,
    `/app/${INFRASTRUCTURE_ID}/workbench/deployments`,
  )

  await expect(page.getByTestId('deployments-tool')).toBeVisible()
  await expect(page.getByTestId('identity-strip')).toContainText(
    'Uncommitted changes',
  )
  await expect(page.getByTestId('identity-strip')).toContainText(
    infrastructureHeadBefore.slice(0, 10),
  )
  await expect(page.getByTestId('fact-vm')).toHaveAttribute(
    'data-state',
    'neutral',
  )
  await expect(page.getByTestId('fact-vm')).toContainText('Stopped')
  await expect(page.getByRole('link', { name: 'Receipts', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Runs', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'CTO advisory' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Why: VM power' }).click()
  await expect(page.getByTestId('fact-explanation')).toContainText(
    'Stopped is neutral, not a failure',
  )

  // Read-only observation: plan and run are separate, and no approval route
  // is touched.
  const observePlanResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/plan`,
  )
  await page.getByTestId('op-observe').click()
  const observePlanResponse = await observePlanResponsePromise
  const observePlan = (await observePlanResponse.json()) as {
    result: {
      planDigest: string
      operation: string
      approvalRequired: boolean
      repository: { dirty: boolean; headCommit: string }
    }
  }
  expect(observePlan.result).toMatchObject({
    operation: 'observe',
    approvalRequired: false,
    repository: {
      dirty: true,
      headCommit: infrastructureHeadBefore,
    },
  })
  expect(observePlan.result.planDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  await expect(page.getByTestId('plan-approval-state')).toContainText(
    'Read-only — no approval required',
  )
  const approvalsBeforeObserveRun = signals.requests.filter((request) =>
    request.path.endsWith('/infrastructure/approve'),
  ).length
  const observeRunResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/run`,
  )
  await page.getByTestId('plan-run').click()
  const observeRunResponse = await observeRunResponsePromise
  expect(observeRunResponse.status()).toBe(200)
  expect(observeRunResponse.request().postDataJSON()).toEqual({
    planDigest: observePlan.result.planDigest,
  })
  expect(
    signals.requests.filter((request) =>
      request.path.endsWith('/infrastructure/approve'),
    ).length,
  ).toBe(approvalsBeforeObserveRun)
  await expect(page.getByTestId('run-outcome')).toContainText('Completed')
  const observeRun = (await observeRunResponse.json()) as {
    result: { receipt: { receiptId: string; planDigest: string } }
  }
  expect(observeRun.result.receipt.planDigest).toBe(
    observePlan.result.planDigest,
  )

  // A mutating create/update plan must deep-link to the exact approval-index
  // identity, return to the same observed plan, and run only after approval.
  const updatePlanResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/plan`,
  )
  await page.getByTestId('op-create_or_update').click()
  const updatePlanResponse = await updatePlanResponsePromise
  const updatePlan = (await updatePlanResponse.json()) as {
    result: {
      planDigest: string
      operation: string
      approvalRequired: boolean
      authorization: { mode: string }
    }
  }
  expect(updatePlan.result).toMatchObject({
    operation: 'create_or_update',
    approvalRequired: true,
    authorization: { mode: 'exact_plan_approval' },
  })
  await expect(page.getByTestId('plan-approval-state')).toContainText(
    'Awaiting approval',
  )
  await page.getByRole('button', { name: 'Go to approval' }).click()
  const expectedPlanApprovalId = `infrastructure_plan:${updatePlan.result.planDigest}`
  await expect(page).toHaveURL(
    new RegExp(
      `#\\/approvals\\/${expectedPlanApprovalId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
    ),
  )
  const planApprovalDetail = page.getByTestId('approval-detail')
  await expect(planApprovalDetail).toContainText('Approve create or update')
  await expect(planApprovalDetail).toContainText(
    `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/approve`,
  )
  const planApproveResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/approve`,
  )
  await page.getByTestId('approve-button').click()
  const planApproveResponse = await planApproveResponsePromise
  expect(planApproveResponse.status()).toBe(200)
  expect(planApproveResponse.request().postDataJSON()).toEqual({
    planDigest: updatePlan.result.planDigest,
  })
  const planApproval = (await planApproveResponse.json()) as {
    result: {
      instanceId: string
      planDigest: string
      approvalDigest: string
    }
  }
  expect(planApproval.result).toMatchObject({
    instanceId: INFRASTRUCTURE_ID,
    planDigest: updatePlan.result.planDigest,
  })
  expect(planApproval.result.approvalDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )
  await page.getByRole('link', { name: 'Related plan in Deployments' }).click()
  await expect(page.getByTestId('plan-approval-state')).toContainText(
    'Approved — ready to run',
  )
  const updateRunResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/run`,
  )
  await page.getByTestId('plan-run').click()
  const updateRunResponse = await updateRunResponsePromise
  expect(updateRunResponse.status()).toBe(200)
  const updateRun = (await updateRunResponse.json()) as {
    result: {
      operation: string
      planDigest: string
      state: string
      receipt: {
        receiptId: string
        planDigest: string
        approvalDigest: string
      }
    }
  }
  expect(updateRun.result).toMatchObject({
    operation: 'create_or_update',
    planDigest: updatePlan.result.planDigest,
    state: 'completed',
    receipt: {
      planDigest: updatePlan.result.planDigest,
      approvalDigest: planApproval.result.approvalDigest,
    },
  })
  await expect(page.getByTestId('run-outcome')).toBeVisible()

  // The daily-driver grant has its own exact proposal/approval receipt. It
  // covers routine start but never destruction.
  await page.getByTestId('authorization-propose').click()
  await expect(page.getByTestId('authorization-card')).toContainText(
    'Proposed',
  )
  await expect(page.getByTestId('authorization-review-grant')).toBeVisible()
  await page.getByTestId('authorization-review-grant').click()
  const grantDetail = page.getByTestId('approval-detail')
  await expect(grantDetail).toContainText(
    'Activate daily-driver authorization',
  )
  await expect(grantDetail.getByText('vm.start', { exact: true })).toBeVisible()
  const grantApproveResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/grant/approve`,
  )
  await page.getByTestId('approve-button').click()
  const grantApproveResponse = await grantApproveResponsePromise
  expect(grantApproveResponse.status()).toBe(200)
  const grantApprovalRequest =
    grantApproveResponse.request().postDataJSON() as {
      proposalDigest: string
    }
  expect(grantApprovalRequest.proposalDigest).toMatch(
    /^sha256:[0-9a-f]{64}$/,
  )
  const grantApproval = (await grantApproveResponse.json()) as {
    result: {
      status: string
      proposalDigest: string
      grantDigest: string
      deniedOperations: string[]
      receipt: {
        receiptId: string
        proposalDigest: string
        grantDigest: string
      }
    }
  }
  expect(grantApproval.result).toMatchObject({
    status: 'active',
    proposalDigest: grantApprovalRequest.proposalDigest,
    deniedOperations: expect.arrayContaining(['vm.destroy']),
    receipt: {
      proposalDigest: grantApprovalRequest.proposalDigest,
    },
  })
  expect(grantApproval.result.receipt.grantDigest).toBe(
    grantApproval.result.grantDigest,
  )

  await page.goto(
    `${service.url}/#/app/${INFRASTRUCTURE_ID}/workbench/deployments`,
  )
  await expect(page.getByTestId('authorization-card')).toContainText('Active')
  await expect(
    page.getByTestId('authorization-revoke-unavailable'),
  ).toBeVisible()
  const startPlanResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/plan`,
  )
  await page.getByTestId('op-start').click()
  const startPlanResponse = await startPlanResponsePromise
  const startPlan = (await startPlanResponse.json()) as {
    result: {
      operation: string
      planDigest: string
      approvalRequired: boolean
      authorization: {
        mode: string
        grantId: string
        grantDigest: string
      }
    }
  }
  expect(startPlan.result).toMatchObject({
    operation: 'start',
    approvalRequired: false,
    authorization: {
      mode: 'durable_grant',
      grantDigest: grantApproval.result.grantDigest,
    },
  })
  await expect(page.getByTestId('plan-approval-state')).toContainText(
    'Covered by the active daily-driver authorization',
  )
  const startRunResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/run`,
  )
  await page.getByTestId('plan-run').click()
  const startRunResponse = await startRunResponsePromise
  expect(startRunResponse.status()).toBe(200)
  const startRun = (await startRunResponse.json()) as {
    result: {
      operation: string
      state: string
      receipt: {
        receiptId: string
        planDigest: string
        authorization: {
          type: string
          grantId: string
          grantDigest: string
        }
      }
    }
  }
  expect(startRun.result).toMatchObject({
    operation: 'start',
    state: 'completed',
    receipt: {
      planDigest: startPlan.result.planDigest,
      authorization: {
        type: 'durable_grant',
        grantId: startPlan.result.authorization.grantId,
        grantDigest: grantApproval.result.grantDigest,
      },
    },
  })
  await expect(page.getByTestId('fact-vm')).toHaveAttribute(
    'data-state',
    'neutral',
  )
  await expect(page.getByTestId('fact-vm')).toContainText('Running')
  // The adapter performs a post-run health observation. This fixture has no
  // enrolled SSH host identity, so running remains distinct from healthy and
  // the check is honestly unavailable rather than reported as success.
  await expect(page.getByTestId('fact-health')).toHaveAttribute(
    'data-state',
    'blocked',
  )
  await expect(page.getByTestId('fact-health')).toContainText('Unavailable')

  const infrastructureRunCountBeforeDestruction = signals.requests.filter(
    (request) =>
      request.method === 'POST' &&
      request.path ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/run`,
  ).length
  await page.getByTestId('operations-menu-trigger').click()
  await page.getByTestId('prepare-destruction').click()
  await expect(page.getByTestId('confirm-dialog')).toContainText(
    'Running it still requires a separate exact approval',
  )
  await expect(page.getByTestId('confirm-action')).toBeDisabled()
  await page
    .getByTestId('confirm-typed-input')
    .fill('Persistent local NixOS VM')
  const destroyPlanResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/plan`,
  )
  await page.getByTestId('confirm-action').click()
  const destroyPlanResponse = await destroyPlanResponsePromise
  const destroyPlan = (await destroyPlanResponse.json()) as {
    result: {
      operation: string
      planDigest: string
      approvalRequired: boolean
      authorization: { mode: string }
    }
  }
  expect(destroyPlan.result).toMatchObject({
    operation: 'destroy',
    approvalRequired: true,
    authorization: { mode: 'exact_plan_approval' },
  })
  await expect(page.getByTestId('plan-approval-state')).toContainText(
    'Destructive — always needs its own exact approval',
  )
  expect(
    signals.requests.filter(
      (request) =>
        request.method === 'POST' &&
        request.path ===
          `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/run`,
    ).length,
    'preparing destruction must not run it',
  ).toBe(infrastructureRunCountBeforeDestruction)

  await page.getByRole('button', { name: 'Go to approval' }).click()
  await expect(page).toHaveURL(
    new RegExp(
      `#\\/approvals\\/infrastructure_plan:${destroyPlan.result.planDigest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
    ),
  )
  await expect(page.getByTestId('approval-detail')).toContainText('Destructive')
  await page.getByTestId('approve-button').click()
  await expect(page.getByTestId('confirm-dialog')).toContainText(
    'This is a destructive action',
  )
  await expect(page.getByTestId('confirm-action')).toBeDisabled()
  await page.getByRole('button', { name: 'Cancel' }).click()
  expect(
    signals.requests.some(
      (request) =>
        request.method === 'POST' &&
        request.path.endsWith('/infrastructure/approve') &&
        (request.body as { planDigest?: string } | undefined)?.planDigest ===
          destroyPlan.result.planDigest,
    ),
    'the destructive approval must remain undecided',
  ).toBe(false)

  expect(
    readFileSync(
      path.join(infrastructureRoot, 'state', 'PROJECT.yaml'),
      'utf8',
    ),
  ).toBe(infrastructureCanonicalBefore)
  expect(
    execFileSync('git', ['-C', infrastructureRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(infrastructureHeadBefore)
  expect(
    execFileSync('git', ['-C', infrastructureRoot, 'status', '--short'], {
      encoding: 'utf8',
      timeout: 5_000,
    }),
  ).toBe(infrastructureStatusBefore)

  await page.goto(
    `${service.url}/#/app/${INFRASTRUCTURE_ID}/workbench/receipts/${startRun.result.receipt.receiptId}`,
  )
  await expect(
    page.getByTestId('drawer').getByRole('heading', {
      name: 'Virtual machine started',
      exact: true,
    }),
  ).toBeVisible()
  await expect(
    page.getByText('libvirt.start', { exact: true }),
  ).not.toBeVisible()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'libvirt.start',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    startRun.result.receipt.receiptId,
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    startPlan.result.planDigest,
  )

  expectRequest(
    signals,
    'POST',
    `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/plan`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/approve`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/run`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/grant/prepare`,
  )
  expectRequest(
    signals,
    'POST',
    `/v1/instances/${INFRASTRUCTURE_ID}/infrastructure/grant/approve`,
  )
  expect(
    signals.requests.some(
      (request) =>
        request.path.includes('/infrastructure/revoke') ||
        request.path.includes('/infrastructure/destroy'),
    ),
  ).toBe(false)

  await page.screenshot({
    path: path.join(
      ARTIFACT_ROOT,
      'infrastructure-service-fixture-live-receipt.png',
    ),
    fullPage: true,
  })
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    infrastructure: {
      status: 'live-tested',
      classification:
        'real AppServer and LocalLibvirtAdapter with deterministic subprocess boundary',
      environmentLive: 'not claimed; host libvirt/Nix/Make/SSH not invoked',
      repository: 'real disposable Git identity; dirty fact preserved',
      stopped: 'neutral',
      readOnlyPlan: 'prepared and run without approval',
      exactPlanApproval: 'create/update digest approved through owning endpoint',
      exactPlanRun: 'completed with matching approval and receipt',
      dailyDriverGrant: 'exact proposal, approval, activation receipt',
      start:
        'grant-covered plan and run; running remained neutral while post-run health was unavailable without an enrolled SSH identity',
      destructive: 'typed prepare plus separate exact approval remained pending; never run',
      receipts: {
        operation: startRun.result.receipt.receiptId,
        grant: grantApproval.result.receipt.receiptId,
      },
      canonicalApplicationState: 'unchanged',
    },
  }
})

test('Context view, compact, and handoff use exact real-service continuity identities', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/conversation`)

  const message = 'Prepare a truthful provider handoff for this disposable project.'
  await page.getByTestId('composer-input').fill(message)
  await page.getByTestId('composer-send').click()
  await expect(page.getByTestId('message-user')).toContainText(message)

  await page.goto(`${service.url}/#/app/${PROJECT_ID}/settings?group=context`)
  const lifecycle = page.getByTestId('app-settings-context-lifecycle')
  await expect(lifecycle).toBeVisible()
  await expect(lifecycle).toContainText('Operational context, not application truth')
  await expect(lifecycle).toContainText('Available')
  await expect(lifecycle).toContainText(projectHeadBefore)
  await expect(lifecycle).toContainText('Candidate default — not benchmarked')
  await expect(page.getByTestId('context-segments')).toHaveCount(0)

  await page.getByTestId('context-compact').click()
  await expect(page.getByTestId('confirm-dialog')).toBeVisible()
  await page.getByTestId('confirm-action').click()
  await expect(page.getByTestId('context-transition-receipt')).toContainText('Receipt:')
  await expect(lifecycle).toContainText('canonical application state is unchanged')

  await page.getByTestId('context-handoff').click()
  await expect(page.getByTestId('confirm-dialog')).toBeVisible()
  await page.getByTestId('confirm-action').click()
  await expect(page.getByTestId('context-transition-receipt')).toContainText('Receipt:')
  await expect(lifecycle).toContainText('canonical application state is unchanged')

  expect(readFileSync(path.join(projectRoot, 'state', 'PROJECT.yaml'), 'utf8')).toBe(
    projectCanonicalBefore,
  )
  expect(
    execFileSync('git', ['-C', projectRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(projectHeadBefore)

  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/conversation/messages`)
  expectRequest(signals, 'GET', `/v1/instances/${PROJECT_ID}/context-lifecycle`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/context-lifecycle/compact`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/context-lifecycle/handoff`)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'context-handoff-recorded.png'),
    fullPage: true,
  })
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    context: {
      status: 'live-tested',
      instance: PROJECT_ID,
      projection: 'exact effective policy, Git identity, continuity binding',
      compact: 'receipted',
      handoff: 'receipted',
      canonicalState: 'unchanged',
      segments: 'not exposed by production contract',
    },
  }
})

test('Conversation attachments, idempotent retry, export, and clear preserve canonical state and exact receipts', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/conversation`)

  await expect(page.getByTestId('message-user')).toContainText(
    'Prepare a truthful provider handoff for this disposable project.',
  )

  // Uploading and then removing a service-stored attachment invokes the exact
  // application-scoped deletion transition; hiding a local chip alone would
  // leave private bytes retained without evidence.
  const discardedName = 'discard-before-send.txt'
  const discardedUploadResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/conversation/attachments`,
  )
  await page.getByTestId('composer-file-input').setInputFiles({
    name: discardedName,
    mimeType: 'text/plain',
    buffer: Buffer.from('Public-safe disposable attachment to remove.\n'),
  })
  const discardedUploadResponse = await discardedUploadResponsePromise
  expect(discardedUploadResponse.status()).toBe(200)
  const discardedUpload = (await discardedUploadResponse.json()) as {
    result: { attachment: { attachmentId: string } }
  }
  const discardedAttachmentId =
    discardedUpload.result.attachment.attachmentId
  const discardedChip = page
    .getByTestId('attachment-ready')
    .filter({ hasText: discardedName })
  await expect(discardedChip).toBeVisible()
  const deletePath =
    `/v1/instances/${PROJECT_ID}/conversation/attachments/` +
    `${encodeURIComponent(discardedAttachmentId)}/delete`
  const deleteResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === deletePath,
  )
  await discardedChip
    .getByRole('button', { name: `Remove ${discardedName}` })
    .click()
  const deleteResponse = await deleteResponsePromise
  expect(deleteResponse.status()).toBe(200)
  await expect(discardedChip).toHaveCount(0)

  // Fault-inject only the first message POST. The UI must retain the failed
  // message and attachment, then retry the exact idempotent body against the
  // real service rather than inventing a success or a new message identity.
  const sentName = 'retry-bound-evidence.txt'
  const sentBytes = Buffer.from(
    'Public-safe attachment retained across an idempotent retry.\n',
  )
  const sentUploadResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/conversation/attachments`,
  )
  await page.getByTestId('composer-file-input').setInputFiles({
    name: sentName,
    mimeType: 'text/plain',
    buffer: sentBytes,
  })
  const sentUploadResponse = await sentUploadResponsePromise
  expect(sentUploadResponse.status()).toBe(200)
  const sentUpload = (await sentUploadResponse.json()) as {
    result: {
      attachment: {
        attachmentId: string
        name: string
        mediaType: string
        sizeBytes: number
        digest: string
      }
    }
  }
  await expect(
    page.getByTestId('attachment-ready').filter({ hasText: sentName }),
  ).toBeVisible()

  const messagesPath =
    `/v1/instances/${PROJECT_ID}/conversation/messages`
  let injectedFailure = false
  await page.route(`**${messagesPath}`, async (route) => {
    if (
      !injectedFailure &&
      route.request().method() === 'POST'
    ) {
      injectedFailure = true
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          error: {
            code: 'live_core_retry_once',
            message: 'Deterministic first-attempt interruption.',
          },
        }),
      })
      return
    }
    await route.continue()
  })

  const sentText =
    'Keep this public-safe attachment bound across the exact retry.'
  await page.getByTestId('composer-input').fill(sentText)
  await page.getByTestId('composer-send').click()
  const failedMessage = page
    .getByTestId('message-user')
    .filter({ hasText: sentText })
  await expect(failedMessage).toContainText('Not sent')
  await expect(failedMessage).toContainText(sentName)

  const successfulSendResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === messagesPath &&
      response.status() === 200,
  )
  await failedMessage
    .getByRole('button', { name: 'Retry', exact: true })
    .click()
  const successfulSendResponse = await successfulSendResponsePromise
  expect(successfulSendResponse.status()).toBe(200)
  await page.unroute(`**${messagesPath}`)

  const messagePosts = signals.requests.filter(
    (request) =>
      request.method === 'POST' && request.path === messagesPath,
  )
  expect(messagePosts).toHaveLength(2)
  expect(messagePosts[1].body).toEqual(messagePosts[0].body)
  const messageBody = messagePosts[1].body as {
    clientMessageId: string
    text: string
    replyToExternalMessageId: null
    attachments: Array<{
      attachmentId: string
      name: string
      mediaType: string
      sizeBytes: number
      digest: string
    }>
  }
  expect(messageBody.clientMessageId).toMatch(/^cmsg_[0-9a-f]{32}$/)
  expect(messageBody.text).toBe(sentText)
  expect(messageBody.replyToExternalMessageId).toBeNull()
  const {
    attachmentId,
    name,
    mediaType,
    sizeBytes,
    digest,
  } = sentUpload.result.attachment
  expect(messageBody.attachments).toEqual([
    { attachmentId, name, mediaType, sizeBytes, digest },
  ])

  const acceptedMessage = page
    .getByTestId('message-user')
    .filter({ hasText: sentText })
  await expect(acceptedMessage).toBeVisible()
  await expect(acceptedMessage).toContainText(sentName)
  await expect(page.getByTestId('conversation-announcer')).toHaveText(
    'Message accepted. No assistant processor is connected to this conversation.',
  )
  await expect(page.getByTestId('streaming-indicator')).toHaveCount(0)
  await expect(page.getByTestId('message-assistant')).toHaveCount(0)

  const [exportResponse, download] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname ===
          `/v1/instances/${PROJECT_ID}/conversation/export`,
    ),
    page.waitForEvent('download'),
    page.getByTestId('export-button').click(),
  ])
  expect(exportResponse.status()).toBe(200)
  expect(await download.createReadStream()).not.toBeNull()
  const exportPayload = (await exportResponse.json()) as {
    result: { receipt: { receiptId: string } }
  }
  const exportReceiptId = exportPayload.result.receipt.receiptId
  const exportToast = page.getByTestId('toast').filter({ hasText: 'Conversation exported' })
  await expect(exportToast).toContainText(exportReceiptId)
  await exportToast.locator('button').first().click()
  const exportDrawer = page.getByTestId('drawer')
  await expect(
    exportDrawer.getByRole('heading', {
      name: 'Conversation exported',
      exact: true,
    }),
  ).toBeVisible()
  await expect(
    page.getByText('conversation.export', { exact: true }),
  ).not.toBeVisible()
  await expect(
    exportDrawer.getByText('No changes', { exact: true }),
  ).toBeVisible()
  await exportDrawer
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'conversation.export',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    exportReceiptId,
  )

  await page.goto(`${service.url}/#/app/${PROJECT_ID}/conversation`)
  await expect(page.getByTestId('message-user').first()).toBeVisible()
  await page.getByTestId('thread-overflow').click()
  await page.getByRole('menuitem', { name: /Clear history/ }).click()
  await expect(page.getByTestId('confirm-dialog')).toBeVisible()

  const clearResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname ===
        `/v1/instances/${PROJECT_ID}/conversation/clear`,
  )
  await page.getByTestId('confirm-action').click()
  const clearResponse = await clearResponsePromise
  expect(clearResponse.status()).toBe(200)
  const clearPayload = (await clearResponse.json()) as {
    result: { receipt: { receiptId: string } }
  }
  const clearReceiptId = clearPayload.result.receipt.receiptId
  await expect(page.getByText('No messages yet')).toBeVisible()
  const clearToast = page.getByTestId('toast').filter({ hasText: 'Conversation cleared' })
  await expect(clearToast).toContainText(clearReceiptId)
  await clearToast.locator('button').first().click()
  const clearDrawer = page.getByTestId('drawer')
  await expect(
    clearDrawer.getByRole('heading', {
      name: 'Conversation cleared',
      exact: true,
    }),
  ).toBeVisible()
  await expect(
    page.getByText('conversation.clear', { exact: true }),
  ).not.toBeVisible()
  await expect(
    clearDrawer.getByText('No changes', { exact: true }),
  ).toBeVisible()
  await clearDrawer
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'conversation.clear',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    clearReceiptId,
  )

  expect(readFileSync(path.join(projectRoot, 'state', 'PROJECT.yaml'), 'utf8')).toBe(
    projectCanonicalBefore,
  )
  expect(
    execFileSync('git', ['-C', projectRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(projectHeadBefore)

  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/conversation/export`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/conversation/clear`)
  expectRequest(signals, 'POST', deletePath)
  expectRequest(signals, 'GET', `/v1/instances/${PROJECT_ID}/receipts/${exportReceiptId}`)
  expectRequest(signals, 'GET', `/v1/instances/${PROJECT_ID}/receipts/${clearReceiptId}`)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'conversation-clear-receipt.png'),
    fullPage: true,
  })
  expectClean(signals, [
    { status: 503, method: 'POST', path: messagesPath },
  ])

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    conversationLifecycle: {
      status: 'live-tested',
      instance: PROJECT_ID,
      attachmentDelete: 'service-stored attachment deleted through the exact owning endpoint',
      idempotentRetry:
        'one deterministic 503 followed by an exact-body retry with the same clientMessageId and attachment reference',
      processorState:
        'accepted user message retained; no assistant processor produced no fake assistant message or streaming state',
      export: 'downloaded and exact receipt opened',
      clear: 'transcript removed and exact receipt opened',
      canonicalState: 'unchanged',
      receiptResult: 'completed_without_change',
    },
  }
})

test('ProjectState Terminal uses the exact live PTY protocol and preserves canonical state', async ({ page }) => {
  const signals = browserSignals(page)
  const socketSignals = terminalSocketSignals(page)
  await installTerminalConstructorProbe(page)

  // StudyState has no Workbench or terminal capability. A direct hash route
  // must fail closed at the application overview without preparing a ticket.
  await openApplicationRoute(page, `/app/${STUDY_ID}/workbench/terminal`)
  await expect(page).toHaveURL(new RegExp(`#\\/app\\/${STUDY_ID}$`))
  await expect(page.getByTestId('terminal-tool')).toHaveCount(0)
  expect(
    signals.requests.some(
      (request) =>
        request.path === `/v1/instances/${STUDY_ID}/terminal/prepare`,
    ),
  ).toBe(false)
  expect(socketSignals.urls).toEqual([])

  await openApplicationRoute(page, `/app/${PROJECT_ID}/workbench/terminal`)
  await expect(page.getByTestId('terminal-start')).toContainText('Ready to connect')
  await expect(page.getByTestId('terminal-state-label')).toHaveCount(0)
  await expect(page.getByTestId('terminal-canvas')).toHaveCount(0)
  expect(
    signals.requests.some(
      (request) =>
        request.path === `/v1/instances/${PROJECT_ID}/terminal/prepare`,
    ),
  ).toBe(false)
  expect(socketSignals.urls).toEqual([])

  const [prepareResponse] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname ===
          `/v1/instances/${PROJECT_ID}/terminal/prepare`,
    ),
    page.getByTestId('terminal-connect').first().click(),
  ])
  expect(prepareResponse.status()).toBe(200)
  const prepareBody = prepareResponse.request().postDataJSON() as {
    expectedInstanceId: string
    columns: number
    rows: number
  }
  expect(prepareBody).toEqual({
    expectedInstanceId: PROJECT_ID,
    columns: 80,
    rows: 24,
  })
  const preparePayload = (await prepareResponse.json()) as {
    result: {
      formatVersion: string
      socketPath: string
      subprotocol: string
      sessionId: string
      oneUseToken: string
      purpose: string
      target: { targetClass: string }
    }
  }
  const ticket = preparePayload.result
  expect(ticket.formatVersion).toBe('stateport.terminal-socket/v1')
  expect(ticket.socketPath).toBe('/v1/terminal/socket')
  expect(ticket.subprotocol).toBe('stateport.terminal.v1')
  expect(ticket.purpose).toBe('create')
  expect(ticket.target.targetClass).toBe('local_pty')
  expect(ticket.oneUseToken.length).toBeGreaterThanOrEqual(32)

  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await expect(page.getByTestId('terminal-canvas')).toBeVisible()
  await expect.poll(() => socketSignals.frames.length).toBeGreaterThan(1)

  const authIndex = socketSignals.frames.findIndex((frame) => {
    if (
      frame.direction !== 'sent' ||
      frame.binary
    ) {
      return false
    }
    try {
      return (JSON.parse(frame.text) as { type?: string }).type === 'authenticate'
    } catch {
      return false
    }
  })
  const readyIndex = socketSignals.frames.findIndex((frame) => {
    if (
      frame.direction !== 'received' ||
      frame.binary
    ) {
      return false
    }
    try {
      return (JSON.parse(frame.text) as { type?: string }).type === 'ready'
    } catch {
      return false
    }
  })
  expect(authIndex).toBe(0)
  expect(readyIndex).toBeGreaterThan(authIndex)
  expect(
    socketSignals.frames
      .slice(0, readyIndex)
      .some((frame) => frame.direction === 'sent' && frame.binary),
    'raw terminal input was sent before the strict ready frame',
  ).toBe(false)

  const auth = JSON.parse(socketSignals.frames[authIndex]!.text) as Record<
    string,
    unknown
  >
  expect(auth).toEqual({
    formatVersion: ticket.formatVersion,
    type: 'authenticate',
    instanceId: PROJECT_ID,
    sessionId: ticket.sessionId,
    purpose: ticket.purpose,
    oneUseToken: ticket.oneUseToken,
    columns: prepareBody.columns,
    rows: prepareBody.rows,
  })
  expect(Object.keys(auth).sort()).toEqual([
    'columns',
    'formatVersion',
    'instanceId',
    'oneUseToken',
    'purpose',
    'rows',
    'sessionId',
    'type',
  ])

  const constructorObservations = await page.evaluate(
    () =>
      (
        window as typeof window & {
          __stateportTerminalConstructors?: TerminalConstructorObservation[]
        }
      ).__stateportTerminalConstructors ?? [],
  )
  expect(constructorObservations).toHaveLength(1)
  expect(constructorObservations[0]?.requestedProtocols).toEqual([
    'stateport.terminal.v1',
  ])
  expect(constructorObservations[0]?.negotiatedProtocol).toBe(
    'stateport.terminal.v1',
  )
  const socketUrl = new URL(constructorObservations[0]!.url)
  expect(socketUrl.origin).toBe(service.url.replace('http:', 'ws:'))
  expect(socketUrl.pathname).toBe('/v1/terminal/socket')
  expect(socketUrl.search).toBe('')
  expect(socketUrl.href).not.toContain(ticket.oneUseToken)

  const terminalInput = page
    .getByTestId('terminal-canvas')
    .locator('.xterm-helper-textarea')
  await expect(terminalInput).toBeAttached()
  await terminalInput.focus()
  await page.keyboard.type("printf 'STATEPORT_LIVE_TERMINAL_OK\\n'")
  await page.keyboard.press('Enter')
  await expect
    .poll(() =>
      socketSignals.frames
        .filter((frame) => frame.direction === 'received' && frame.binary)
        .map((frame) => frame.text)
        .join(''),
    )
    .toContain('STATEPORT_LIVE_TERMINAL_OK')

  // Search is against the xterm buffer, so a non-zero result also proves the
  // real PTY output reached the rendered terminal rather than only the socket.
  await page.keyboard.press('Control+f')
  await expect(page.getByTestId('terminal-find-bar')).toBeVisible()
  await page.getByTestId('terminal-find-input').fill('STATEPORT_LIVE_TERMINAL_OK')
  await page.getByTestId('terminal-find-input').press('Enter')
  await expect(
    page
      .getByTestId('terminal-find-bar')
      .locator('span[aria-live="polite"]'),
  ).toHaveText(/Match|\d+\/[1-9]\d*|[1-9]\d* matches?/)
  await page.getByRole('button', { name: 'Close find' }).click()

  const resizeCountBeforeFocus = parsedTerminalControls(
    socketSignals,
    'sent',
  ).filter((control) => control.type === 'resize').length
  await page.getByRole('button', { name: 'Maximize terminal' }).click()
  await expect(page.getByRole('button', { name: 'Exit focus mode' })).toBeVisible()
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await expect(page.getByTestId('terminal-canvas')).toBeVisible()
  await expect
    .poll(
      () =>
        parsedTerminalControls(socketSignals, 'sent').filter(
          (control) => control.type === 'resize',
        ).length,
    )
    .toBeGreaterThan(resizeCountBeforeFocus)
  expect(socketSignals.urls).toHaveLength(1)
  expect(
    signals.requests.filter(
      (request) =>
        request.method === 'POST' &&
        request.path === `/v1/instances/${PROJECT_ID}/terminal/prepare`,
    ),
  ).toHaveLength(1)

  const resizeFrames = parsedTerminalControls(socketSignals, 'sent').filter(
    (control) => control.type === 'resize',
  )
  const fitted = resizeFrames[resizeFrames.length - 1]!
  expect(fitted.formatVersion).toBe('stateport.terminal-socket/v1')
  expect(fitted.columns).toEqual(expect.any(Number))
  expect(fitted.rows).toEqual(expect.any(Number))
  const outputFrameCount = socketSignals.frames.length
  await terminalInput.focus()
  await page.keyboard.type('stty size')
  await page.keyboard.press('Enter')
  await expect
    .poll(() =>
      socketSignals.frames
        .slice(outputFrameCount)
        .filter((frame) => frame.direction === 'received' && frame.binary)
        .map((frame) => frame.text)
        .join(''),
    )
    .toContain(`${String(fitted.rows)} ${String(fitted.columns)}`)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'terminal-live-pty.png'),
    fullPage: true,
  })

  await page.getByTestId('terminal-end').click()
  await expect(page.getByTestId('terminal-ended-bar')).toContainText(
    'Session ended',
  )
  await expect(
    page.getByTestId('terminal-ended-bar').getByTestId('terminal-reconnect'),
  ).toBeVisible()
  await expect.poll(() => socketSignals.closes).toBe(1)
  expect(
    parsedTerminalControls(socketSignals, 'sent').some(
      (control) =>
        control.formatVersion === 'stateport.terminal-socket/v1' &&
        control.type === 'end',
    ),
  ).toBe(true)
  expect(socketSignals.urls).toHaveLength(1)
  expect(socketSignals.errors).toEqual([])

  expect(readFileSync(path.join(projectRoot, 'state', 'PROJECT.yaml'), 'utf8')).toBe(
    projectCanonicalBefore,
  )
  expect(
    execFileSync('git', ['-C', projectRoot, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 5_000,
    }).trim(),
  ).toBe(projectHeadBefore)

  expectRequest(
    signals,
    'POST',
    `/v1/instances/${PROJECT_ID}/terminal/prepare`,
  )
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    terminal: {
      status: 'live-tested',
      instance: PROJECT_ID,
      capabilityGate: 'StudyState direct route refused without prepare',
      connect: 'explicit user action only',
      prepare: 'exact instance identity and bounded initial dimensions',
      socket:
        'same-origin, query-free, exact stateport.terminal.v1 subprotocol',
      authentication:
        'one-use token in the first text frame; no raw input before strict ready',
      inputOutput: 'real disposable local PTY marker observed and searchable',
      resize: 'xterm fit forwarded and verified with stty size',
      maximize: 'same live session and socket retained',
      end: 'explicit broker end control; no automatic reconnect',
      transcriptPersistence: 'none',
      canonicalState: 'PROJECT.yaml and Git HEAD unchanged',
    },
  }
})

test('Recovery creates a verified backup and accepts the backend nested receipt', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}`)

  await expect(page.getByTestId('recovery-state')).toContainText('Backup due')
  await page.getByRole('button', { name: 'Back up now' }).click()
  await expect(page.getByText('Backup completed')).toBeVisible()
  await expect(page.getByTestId('recovery-state')).toContainText('Backed up')
  await page.getByRole('link', { name: 'Backup receipt' }).click()
  await expect(page.getByTestId('receipt-detail')).toBeVisible()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText('backup.create')
  await expect(page.getByTestId('receipt-verify')).toHaveCount(0)

  const backupRoot = path.join(
    disposableRoot,
    'xdg',
    'data',
    'stateport',
    'backups',
    PROJECT_ID,
  )
  expect(
    readdirSync(backupRoot).some((entry) => entry.endsWith('.tar')),
    'the real backup subsystem did not create an archive',
  ).toBe(true)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/backup`)
  expectClean(signals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    recovery: {
      status: 'live-tested',
      instance: PROJECT_ID,
      backup: 'real verified archive',
      receipt:
        'nested backend backupReceipt mapped, identity-checked, and opened from the live receipt projection',
      canonicalStateEffect: 'none',
      scope: 'public-safe disposable fixture only',
    },
  }
})

test('Files lists, reads, writes, and refuses escape and stale commit in the disposable fixture', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/workbench/files`)

  await page.getByTestId('tree-row-src').click()
  await page.getByTestId('tree-row-src/main.py').click()
  const editor = page
    .getByTestId('editor-host-primary-src/main.py')
    .locator('.cm-content')
  await expect(editor).toBeVisible()
  await expect(editor).toContainText('answer = 41')
  await editor.click()
  await page.keyboard.press('Control+a')
  await page.keyboard.type('answer = 42')
  await expect(page.getByTestId('editor-status-strip')).toContainText('Unsaved changes')

  await page.keyboard.press('Control+s')
  await expect(page.getByTestId('save-preview')).toBeVisible()
  await expect(page.getByTestId('save-preview')).toContainText('answer = 42')
  await expect(page.getByTestId('affected-paths')).toContainText('src/main.py')
  await page.getByTestId('confirm-save').click()
  await expect(page.getByTestId('save-preview')).not.toBeVisible()
  await expect(page.getByTestId('status-receipt-link')).toBeVisible()
  expect(readFileSync(path.join(projectRoot, 'src', 'main.py'), 'utf8').trim()).toBe('answer = 42')

  // The service has no receipt-integrity verification contract. Production
  // must therefore omit the mock-only control instead of presenting
  // "unavailable" as a failed integrity check.
  await page.getByTestId('status-receipt-link').click()
  await expect(page.getByTestId('receipt-detail')).toBeVisible()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    'file_workspace.commitWrite',
  )
  await expect(page.getByTestId('receipt-verify')).toHaveCount(0)
  await page.getByText('Raw JSON', { exact: true }).click()
  const savedReceipt = page.getByTestId('receipt-raw-json')
  await expect(savedReceipt).toContainText('stateport.file-workspace/v1')
  await expect(savedReceipt).toContainText('commitWrite')
  await expect(savedReceipt).toContainText('src/main.py')
  await expect(savedReceipt).toContainText('contentRetained')
  await page.goBack()
  await expect(page.getByTestId('editor-status-strip')).toBeVisible()

  // Create is not a shortcut around governance: the product reviews the
  // exact path/content, while the adapter performs create → preview → exact
  // commit and reads the result back at the receipted revision.
  await page.getByTestId('file-create-root').click()
  await page.getByTestId('file-create-path').fill('src/created.py')
  await page.getByTestId('file-create-content').fill('created = True\n')
  await page.getByTestId('file-create-confirm').click()
  await expect(page.getByTestId('file-create-dialog')).not.toBeVisible()
  await expect(page.getByTestId('tree-row-src/created.py')).toBeVisible()
  expect(readFileSync(path.join(projectRoot, 'src', 'created.py'), 'utf8')).toBe('created = True\n')

  // Rename begins with a fresh broker read, binds the reviewed content hash
  // and Git base, and reconciles both the tree and open editor identity.
  await page.getByTestId('tree-row-src/created.py').click({ button: 'right' })
  await page.getByText('Rename reviewed file', { exact: true }).click()
  await page.getByTestId('file-rename-path').fill('src/renamed.py')
  await page.getByTestId('file-rename-confirm').click()
  await expect(page.getByTestId('file-rename-dialog')).not.toBeVisible()
  await expect(page.getByTestId('tree-row-src/created.py')).toHaveCount(0)
  await expect(page.getByTestId('tree-row-src/renamed.py')).toBeVisible()
  expect(existsSync(path.join(projectRoot, 'src', 'created.py'))).toBe(false)
  expect(readFileSync(path.join(projectRoot, 'src', 'renamed.py'), 'utf8')).toBe('created = True\n')

  // Delete has its own destructive review and keeps the operation visible
  // until the response/receipt validation finishes.
  await page.getByTestId('tree-row-src/renamed.py').click({ button: 'right' })
  await page.getByText('Delete reviewed file', { exact: true }).click()
  await expect(page.getByTestId('file-delete-dialog')).toContainText('No automatic restore is promised')
  await page.getByTestId('file-delete-confirm').click()
  await expect(page.getByTestId('file-delete-dialog')).not.toBeVisible()
  await expect(page.getByTestId('tree-row-src/renamed.py')).toHaveCount(0)
  expect(existsSync(path.join(projectRoot, 'src', 'renamed.py'))).toBe(false)

  // The receipt toast is a real deep link, not a transient success claim.
  await page.getByTestId('toast').filter({ hasText: 'File deleted' }).getByRole('button').first().click()
  await expect(page.getByTestId('receipt-detail')).toBeVisible()
  await page
    .getByRole('button', { name: 'IDs, revisions, and digests' })
    .click()
  await expect(page.getByTestId('receipt-exact-record')).toContainText('file_workspace.deletePath')
  await page.getByText('Raw JSON', { exact: true }).click()
  await expect(page.getByTestId('receipt-raw-json')).toContainText('src/renamed.py')
  expect(page.url()).toMatch(/\/receipts\/file-[^/?#]+/)
  await page.goBack()
  await expect(page.getByTestId('files-stub')).toBeVisible()

  const escape = await page.evaluate(async ({ instanceId }) => {
    const response = await fetch(
      `/v1/instances/${encodeURIComponent(instanceId)}/file-workspace/readFile?path=${encodeURIComponent('../outside.txt')}`,
    )
    return { status: response.status, body: await response.json() }
  }, { instanceId: PROJECT_ID })
  expect(escape.status).toBe(409)
  expect(escape.body.error.code).toBe('file_workspace_refused')

  const prepared = await page.evaluate(async ({ instanceId }) => {
    const session = await fetch('/session').then((response) => response.json())
    const prefix = `/v1/instances/${encodeURIComponent(instanceId)}/file-workspace`
    const current = await fetch(
      `${prefix}/readFile?path=${encodeURIComponent('src/main.py')}`,
    ).then((response) => response.json())
    const headers = {
      'Content-Type': 'application/json',
      'X-StatePort-CSRF': session.result.csrfToken,
    }
    const prepare = await fetch(`${prefix}/prepareWrite`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        path: 'src/main.py',
        content: 'answer = 43\n',
        expectedContentHash: current.result.metadata.contentHash,
        expectedBaseSha: current.result.metadata.baseSha,
      }),
    }).then((response) => response.json())
    const preview = await fetch(`${prefix}/previewDiff`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ preparedWriteId: prepare.result.preparedWriteId }),
    }).then((response) => response.json())
    return {
      preparedWriteId: prepare.result.preparedWriteId,
      diffDigest: preview.result.diffDigest,
      csrf: session.result.csrfToken,
    }
  }, { instanceId: PROJECT_ID })

  writeFileSync(path.join(projectRoot, 'src', 'main.py'), 'answer = 99\n', 'utf8')
  const conflict = await page.evaluate(async ({ instanceId, preparedWriteId, diffDigest, csrf }) => {
    const prefix = `/v1/instances/${encodeURIComponent(instanceId)}/file-workspace`
    const headers = {
      'Content-Type': 'application/json',
      'X-StatePort-CSRF': csrf,
    }
    const response = await fetch(`${prefix}/commitWrite`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        preparedWriteId,
        confirmedDiffDigest: diffDigest,
      }),
    })
    const body = await response.json()
    await fetch(`${prefix}/discardWrite`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ preparedWriteId }),
    })
    return { status: response.status, body }
  }, { instanceId: PROJECT_ID, ...prepared })
  expect(conflict.status).toBe(409)
  expect(conflict.body.error.code).toBe('file_workspace_refused')
  expect(readFileSync(path.join(projectRoot, 'src', 'main.py'), 'utf8')).toBe('answer = 99\n')

  expectRequest(signals, 'GET', `/v1/instances/${PROJECT_ID}/file-workspace/listDirectory`)
  expectRequest(signals, 'GET', `/v1/instances/${PROJECT_ID}/file-workspace/readFile`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/prepareWrite`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/previewDiff`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/commitWrite`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/discardWrite`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/createFile`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/renamePath`)
  expectRequest(signals, 'POST', `/v1/instances/${PROJECT_ID}/file-workspace/deletePath`)

  await page.screenshot({
    path: path.join(ARTIFACT_ROOT, 'files-governed-write.png'),
    fullPage: true,
  })
  expectClean(signals, [
    {
      status: 409,
      method: 'GET',
      path: `/v1/instances/${PROJECT_ID}/file-workspace/readFile`,
    },
    {
      status: 409,
      method: 'POST',
      path: `/v1/instances/${PROJECT_ID}/file-workspace/commitWrite`,
    },
  ])

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    files: {
      status: 'live-tested',
      instance: PROJECT_ID,
      list: 'real broker',
      read: 'real broker',
      write: 'prepare, diff preview, exact confirmation, commit, receipt',
      create: 'reviewed path/content, prepare, diff preview, exact confirmation, receipt',
      rename: 'fresh read basis, exact source/destination identity, receipt',
      delete: 'separate destructive review, exact read basis, receipt',
      receiptDeepLink:
        'exact indexed save and delete receipts opened with raw broker evidence',
      pathEscape: 'refused',
      staleCommit: 'refused without overwriting externally changed content',
      receiptVerification: 'mock-only control absent from production',
      scope: 'disposable fixture only',
    },
  }
})
