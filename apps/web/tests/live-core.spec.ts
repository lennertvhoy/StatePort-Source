/**
 * Real AppServer acceptance for the current-backed Runs, Context lifecycle,
 * and governed Files surfaces. No route is mocked or intercepted.
 */
import { expect, test, type Page } from '@playwright/test'
import { createHash } from 'node:crypto'
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

// Resolve the interpreter before replacing XDG roots; toolchain shims can
// otherwise consult unrelated, untrusted configuration in the disposable home.
const PYTHON = execFileSync('python3', ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8', timeout: 5_000 }).trim()
// Keep the same installed development libraries when HOME is isolated. These
// are interpreter dependency locations, not provider configuration or secrets.
const PYTHON_LIBRARIES = JSON.parse(execFileSync(PYTHON, ['-c', 'import json,site; print(json.dumps(site.getsitepackages()+[site.getusersitepackages()]))'], { encoding: 'utf8', timeout: 5_000 })) as string[]

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
  inFlight: Set<import('@playwright/test').Request>
  navigationAbortCandidates: WeakSet<import('@playwright/test').Request>
  navigationReadAborts: string[]
  navigationAbortsWaived: string[]
  errorResponses: Array<{ status: number; method: string; path: string }>
  responses: Array<{ status: number; method: string; path: string }>
  requests: Array<{ method: string; path: string; body?: unknown }>
}

/** Reviewed R24 classification: a deliberate same-document/hash/link/goto
 * navigation may abort in-flight read-only fixture bootstrap GETs. Waive such
 * an abort only with proven recovery (same method+path later 2xx); never waive
 * mutations, non-abort errors, or unrecovered reads. Applies per-caller. */
interface NavigationAbortWaiver {
  pathPattern: RegExp
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

async function startService(resume = false, actorRole: 'local_user' | 'platform_operator' = 'local_user', authorityProof = false, providerIsolation = false): Promise<RunningService> {
  const port = await freePort()
  const xdg = path.join(disposableRoot, 'xdg')
  const privateHome = path.join(disposableRoot, 'provider-private-home')
  const privateCodexHome = path.join(privateHome, 'codex')
  const privateRuntime = path.join(privateHome, 'runtime')
  const privateTemp = path.join(privateHome, 'tmp')
  if (providerIsolation) for (const directory of [privateHome, privateCodexHome, privateRuntime, privateTemp]) mkdirSync(directory, { recursive: true, mode: 0o700 })
  if (providerIsolation) {
    // Explicit disposable OS-owned operator setup, independent of preceding
    // serial cases. This never stands in for installed operator authentication.
    const boundary = path.join(xdg, 'config', 'stateport', 'platform-operator-authority')
    if (!existsSync(boundary)) writeFileSync(boundary, 'Private provider source-browser operator fixture.\n', { mode: 0o600, flag: 'wx' })
  }
  const serviceEnvironment = providerIsolation
    ? { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8', HOME: privateHome, CODEX_HOME: privateCodexHome, XDG_RUNTIME_DIR: privateRuntime, TMPDIR: privateTemp }
    : process.env

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
  const log = openSync(path.join(ARTIFACT_ROOT, resume ? 'service-restarted.log' : 'service.log'), resume ? 'a' : 'w', 0o600)
  const child = spawn(
    PYTHON,
    [
      path.join(HERE, 'live-core-fixture.py'),
      ...(resume ? ['--resume'] : []),
      '--actor-role', actorRole,
      ...(authorityProof ? ['--authority-proof'] : []),
      '--port',
      String(port),
      '--repo-root',
      ROOT,
    ],
    {
      cwd: ROOT,
      env: {
        ...serviceEnvironment,
        CONTAINERS_STORAGE_CONF: podmanStorageConfig,
        PYTHONPATH: providerIsolation ? [PYTHONPATH, ...PYTHON_LIBRARIES].join(path.delimiter) : PYTHONPATH,
        STATEPORT_UI_ENGINE_ENV: JSON.stringify(Object.fromEntries([
          'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CONTAINERS_STORAGE_CONF', 'CONTAINERS_CONF', 'CONTAINERS_CONF_OVERRIDE',
        ].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]))),
        XDG_CONFIG_HOME: path.join(xdg, 'config'),
        XDG_DATA_HOME: path.join(xdg, 'data'),
        XDG_STATE_HOME: path.join(xdg, 'state'),
      },
      stdio: ['ignore', log, log],
    },
  )
  closeSync(log)
  const url = `http://127.0.0.1:${port}`
  try {
    await waitForService(url, child)
  } catch (error) {
    await stopChild(child)
    throw error
  }
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
    new Promise<boolean>((resolve) => setTimeout(() => resolve(true), process.env.STATEPORT_UI_REAL_WORKSPACES === '1' ? 95_000 : 5_000)),
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
    inFlight: new Set(),
    navigationAbortCandidates: new WeakSet(),
    navigationReadAborts: [],
    navigationAbortsWaived: [],
    errorResponses: [],
    responses: [],
    requests: [],
  }
  page.on('console', (message) => {
    if (message.type() === 'error') value.console.push(message.text())
  })
  page.on('pageerror', (error) => value.pageErrors.push(error.message))
  page.on('request', (request) => {
    value.inFlight.add(request)
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
  page.on('requestfinished', (request) => value.inFlight.delete(request))
  page.on('requestfailed', (request) => {
    value.inFlight.delete(request)
    const failure = `${request.method()} ${request.url()} ${request.failure()?.errorText ?? 'failed'}`
    if (value.navigationAbortCandidates.has(request) && request.failure()?.errorText === 'net::ERR_ABORTED') {
      value.navigationReadAborts.push(failure)
    } else value.requestFailures.push(failure)
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

/** A deliberate full document reload may cancel its existing read-only fetches.
 * Track exact Request objects, never waive other failures or mutation requests. */
async function reloadWithReadObservation(page: import('@playwright/test').Page, signals: BrowserSignals): Promise<void> {
  for (const request of signals.inFlight) {
    const url = new URL(request.url())
    if (request.method() === 'GET' && url.origin === service.url && (url.pathname === '/session' || url.pathname.startsWith('/v1/') || url.pathname.startsWith('/assets/'))) {
      signals.navigationAbortCandidates.add(request)
    }
  }
  await page.reload()
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
        const observation: TerminalConstructorObservation = {
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
  navigationAbortWaiver?: NavigationAbortWaiver,
): void {
  matrix.navigationReadAborts = [...((matrix.navigationReadAborts as string[] | undefined) ?? []), ...signals.navigationReadAborts]
  const waived: string[] = []
  const unwaived = signals.requestFailures.filter((failure) => {
    if (allowedRequestFailures.includes(failure)) return false
    if (!navigationAbortWaiver) return true
    // Failure shape: `METHOD <absolute-url> <errorText>`.
    const firstSpace = failure.indexOf(' ')
    const lastSpace = failure.lastIndexOf(' ')
    if (firstSpace < 0 || lastSpace <= firstSpace) return true
    const method = failure.slice(0, firstSpace)
    const rawUrl = failure.slice(firstSpace + 1, lastSpace)
    const errorText = failure.slice(lastSpace + 1)
    if (method !== 'GET' || errorText !== 'net::ERR_ABORTED') return true
    let url: URL
    try {
      url = new URL(rawUrl)
    } catch {
      return true
    }
    if (url.origin !== service.url) return true
    if (!navigationAbortWaiver.pathPattern.test(url.pathname)) return true
    const recovered = signals.responses.some(
      (response) =>
        response.method === 'GET' &&
        response.path === url.pathname &&
        response.status >= 200 &&
        response.status < 300,
    )
    if (!recovered) return true
    waived.push(failure)
    return false
  })
  signals.navigationAbortsWaived.push(...waived)
  matrix.navigationAbortsWaived = [...((matrix.navigationAbortsWaived as string[] | undefined) ?? []), ...waived]
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
    unwaived,
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

test('Shell menu keeps readable hover and keyboard focus across persisted themes', async ({ page }) => {
  for (const theme of ['light', 'dark', 'hc-light', 'hc-dark']) {
    await page.emulateMedia({ colorScheme: theme.endsWith('dark') ? 'dark' : 'light' })
    await openApplicationRoute(page, '/applications')
    const trigger = page.getByRole('button', { name: 'More actions', exact: true })
    await trigger.click()
    await page.getByRole('menuitem', {
      name: theme.startsWith('hc') ? 'High contrast' : theme === 'dark' ? 'Dark' : 'Light',
      exact: true,
    }).click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
    await page.reload()
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
    await trigger.focus()
    await page.keyboard.press('Enter')
    const help = page.getByRole('menuitem', { name: 'Help & shortcuts', exact: true })
    await expect(help).toBeFocused()

    const contrast = async () => help.evaluate((element) => {
      const style = getComputedStyle(element)
      const canvas = document.createElement('canvas')
      canvas.width = canvas.height = 1
      const context = canvas.getContext('2d')!
      const luminance = (color: string) => {
        context.clearRect(0, 0, 1, 1)
        context.fillStyle = color
        context.fillRect(0, 0, 1, 1)
        const rgb = Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3)
          .map((channel) => channel / 255)
          .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4)
        return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722
      }
      const foreground = luminance(style.color)
      const background = luminance(style.backgroundColor)
      return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05)
    })
    expect(await contrast()).toBeGreaterThanOrEqual(theme.startsWith('hc') ? 7 : 4.5)
    await expect(help).toHaveCSS('outline-style', 'solid')
    await page.screenshot({ path: path.join(ARTIFACT_ROOT, `shell-menu-${theme}.png`) })
    await page.keyboard.press('ArrowDown')
    await expect(page.getByRole('menuitem', { name: 'Follow system', exact: true })).toBeFocused()
    await help.hover()
    await expect(help).toHaveAttribute('data-highlighted', '')
    expect(await contrast()).toBeGreaterThanOrEqual(theme.startsWith('hc') ? 7 : 4.5)
    await page.keyboard.press('Escape')
    await expect(trigger).toBeFocused()
    await expect(page.getByRole('menu')).toHaveCount(0)
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

test('Platform is reachable by keyboard and retains denied provider authority on a narrow screen', async ({ page }) => {
  await openApplicationRoute(page, '/applications')
  const platform = page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Platform', exact: true })
  await platform.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('platform-page')).toBeVisible()
  await expect(platform).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('region', { name: 'Workspace readiness' })).toContainText('Local service')
  await expect(page.getByText('Your session does not permit platform operations.', { exact: false })).toBeVisible()
  const provider = page.getByRole('navigation', { name: 'Platform controls' }).getByRole('link', { name: 'Provider setup', exact: false })
  await provider.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Coding provider' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Provider observations' })).toContainText('Billing and quota')
  await expect(page.getByRole('button', { name: 'Save model and enable' })).toBeDisabled()
  const session = await (await page.request.get(`${service.url}/session`)).json()
  const denied = await page.request.post(`${service.url}/v1/provider/configure`, {
    headers: { Origin: service.url, 'X-StatePort-CSRF': session.result.csrfToken }, data: { model: 'test-model' },
  })
  expect(denied.status()).toBe(403)
  await page.setViewportSize({ width: 390, height: 844 })
  const loginInstructions = page.getByRole('button', { name: 'Show installed login command' })
  await loginInstructions.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByLabel('Installed Codex login command')).toBeVisible()
  await page.getByRole('button', { name: 'Select command', exact: true }).focus()
  await page.keyboard.press('Enter')
  expect(await page.evaluate(() => window.getSelection()?.toString())).toContain('stateport_codex login')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'platform-provider-narrow.png'), fullPage: true })
  matrix.platformReadiness = { classification: 'real AppServer browser; disposable fixture; no provider execution', keyboardNavigation: true, deniedProviderMutation: true, narrowViewport: '390x844' }
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
    .getByRole('menuitem', { name: 'Import a repository' })
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
  await page.getByRole('checkbox', {
    name: 'Approve creation of an isolated copy of the exact inspected template',
  }).click()
  const installTemplateResponsePromise = page.waitForResponse(response =>
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/template-import/install',
  )
  await page.getByTestId('import-register').click()
  const registrationResponse = await installTemplateResponsePromise
  expect(registrationResponse.status()).toBe(200)
  const registrationRequest = registrationResponse.request().postDataJSON() as {
    plan: { candidateId: string; inspectionDigest: string; instanceId: string; name: string; planDigest: string }
    approval: { decision: string; actorId: string; planDigest: string }
  }
  expect(registrationRequest.plan.candidateId).toBe(inspectionRequest.candidateId)
  expect(registrationRequest.plan.inspectionDigest).toBe(inspectionPayload.result.inspectionDigest)
  expect(registrationRequest.plan.instanceId).toMatch(/^template-[0-9a-f]{16}$/)
  expect(registrationRequest.plan.name).toBe(IMPORT_CANDIDATE_NAME)
  expect(registrationRequest.approval).toEqual({
    decision: 'approve', actorId: 'local-user', planDigest: registrationRequest.plan.planDigest,
  })
  const registrationPayload = (await registrationResponse.json()) as {
    result: { instanceId: string; receiptId: string; managedCopyCreated: boolean; sourceRepositoryMutated: boolean }
  }
  expect(registrationPayload.result.instanceId).toBe(registrationRequest.plan.instanceId)
  expect(registrationPayload.result.managedCopyCreated).toBe(true)
  expect(registrationPayload.result.sourceRepositoryMutated).toBe(false)
  await expect(page.getByTestId('import-done')).toContainText(`${IMPORT_CANDIDATE_NAME}`)

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
    'template.import',
  )
  await expect(page.getByTestId('receipt-exact-record')).toContainText(
    registrationPayload.result.receiptId,
  )

  await page.goto(`${service.url}/#/app/${registrationRequest.plan.instanceId}`)
  await expect(page.getByTestId('app-overview-stub')).toBeVisible()
  await expect(page.locator('body')).not.toContainText(importCandidateRoot)

  expectRequest(signals, 'GET', '/v1/applications')
  expectRequest(signals, 'POST', '/v1/application-fixtures/install')
  expectRequest(signals, 'GET', '/v1/repository-import/local-candidates')
  expectRequest(signals, 'POST', '/v1/repository-import/inspect')
  expectRequest(signals, 'GET', '/v1/status')
  expectRequest(signals, 'POST', '/v1/template-import/plan')
  expectRequest(signals, 'POST', '/v1/template-import/install')

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
        approval: 'local actor and exact plan digest bound',
        isolatedCopy: 'live-tested',
        repositoryGitState: 'unchanged',
        receipt: 'opened',
      },
    },
  }
})

test('Decorative animation preference changes real styles and survives reload', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/settings/accessibility')
  const toggle = page.locator('#setting-a11y-no-animation').getByRole('switch')
  await expect(toggle).toHaveAttribute('aria-checked', 'false')
  await toggle.click()
  await expect(page.locator('html')).toHaveAttribute('data-decorative-motion', 'none')
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  await page.reload()
  await expect(toggle).toHaveAttribute('aria-checked', 'true')
  await expect(page.locator('html')).toHaveAttribute('data-decorative-motion', 'none')
  await page.getByTestId('topbar').getByRole('button', { name: /^Notifications/ }).click()
  const popover = page.getByTestId('notifications-popover')
  await expect(popover).toBeVisible()
  const animation = await popover.evaluate(element => getComputedStyle(element).animationName)
  expect(animation).toBe('none')
  await page.keyboard.press('Escape')
  await toggle.click()
  await expect(page.locator('html')).toHaveAttribute('data-decorative-motion', 'full')
  await page.getByTestId('settings-discard').click()
  await expect(page.locator('html')).toHaveAttribute('data-decorative-motion', 'none')
  writeFileSync(path.join(ARTIFACT_ROOT, 'decorative-animation-preference.json'), JSON.stringify({ classification: 'source browser local preference and actual computed CSS; no installed proof', savedAndReloaded: true, animation, discardRestored: true }, null, 2))
  expectClean(signals)
})

test('Timestamp preferences persist and preserve application dates at narrow width', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/settings?group=advanced`)
  const installed = page.locator('#setting-app-created time')
  await expect(installed).toBeVisible()
  const canonical = await installed.getAttribute('datetime')
  expect(canonical).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  const observations: Record<string, unknown>[] = []
  for (const mode of ['absolute', 'both']) {
    await page.goto(`${service.url}/#/settings/general`)
    await page.locator('#setting-date-time-format select').selectOption(mode)
    await page.getByTestId('settings-save').click()
    await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
    expect(await page.evaluate(() => JSON.parse(localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}').general?.dateTimeFormat)).toBe(mode)
    await reloadWithReadObservation(page, signals)
    await expect(page.locator('#setting-date-time-format select')).toHaveValue(mode)
    await page.goto(`${service.url}/#/app/${PROJECT_ID}/settings?group=advanced`)
    await expect(installed).toHaveAttribute('datetime', canonical!)
    if (mode === 'both') await expect(installed).toContainText(' · ')
    else await expect(installed).not.toContainText(' · ')
    await page.setViewportSize({ width: 390, height: 844 })
    await expect(installed).toBeVisible()
    const geometry = await installed.evaluate(element => {
      const box = element.getBoundingClientRect()
      return { left: box.left, right: box.right, viewport: innerWidth, whiteSpace: getComputedStyle(element).whiteSpace, text: element.textContent }
    })
    expect(geometry.left).toBeGreaterThanOrEqual(0)
    expect(geometry.right).toBeLessThanOrEqual(geometry.viewport)
    expect(geometry.whiteSpace).toBe('normal')
    observations.push({ mode, canonical, ...geometry })
    await page.screenshot({ path: path.join(ARTIFACT_ROOT, `timestamp-${mode}-narrow.png`) })
    await page.setViewportSize({ width: 1440, height: 900 })
  }
  writeFileSync(path.join(ARTIFACT_ROOT, 'timestamp-preferences.json'), JSON.stringify({ classification: 'source browser; real local settings save and reload, unchanged canonical application date; installed unrun', observations }, null, 2))
  expectClean(signals)
})

test('Bare startup honors saved reopening and landing choice while preserving deep links', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/settings/general')
  const toggle = page.locator('#setting-reopen-app').getByRole('switch')
  await expect(toggle).toBeVisible()
  const save = async () => {
    await page.getByTestId('settings-save').click()
    await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  }
  // Enable explicitly even if earlier tests used another service preference.
  if (await toggle.getAttribute('aria-checked') !== 'true') {
    await toggle.click()
    await save()
  }
  await page.goto(`${service.url}/#/app/${PROJECT_ID}/workbench/files`)
  await expect(page.getByTestId('files-stub')).toBeVisible()
  // Replace only the address, then perform one actual bare-root reload.
  await page.evaluate(url => window.history.replaceState(null, '', url), service.url)
  await reloadWithReadObservation(page, signals)
  await expect(page).toHaveURL(new RegExp(`/app/${PROJECT_ID}$`))
  await expect(page.getByTestId('app-overview-stub')).toBeVisible()
  await page.goto(`${service.url}/#/catalog`)
  await expect(page.getByTestId('package-list')).toBeVisible()
  await expect(page).toHaveURL(/#\/catalog$/)

  await page.goto(`${service.url}/#/settings/general`)
  await toggle.click()
  await page.locator('#setting-landing-page select').selectOption('last_workspace')
  await save()
  await page.goto(`${service.url}/#/app/${PROJECT_ID}/workbench/files`)
  await expect(page.getByTestId('files-stub')).toBeVisible()
  // Replace only the address, then perform one actual bare-root reload.
  await page.evaluate(url => window.history.replaceState(null, '', url), service.url)
  await reloadWithReadObservation(page, signals)
  await expect(page).toHaveURL(new RegExp(`/app/${PROJECT_ID}/workbench/files$`))
  await expect(page.getByTestId('files-stub')).toBeVisible()

  await page.goto(`${service.url}/#/settings/general`)
  await page.locator('#setting-landing-page select').selectOption('applications')
  await save()
  await page.goto(`${service.url}/#/app/${PROJECT_ID}`)
  await expect(page.getByTestId('app-overview-stub')).toBeVisible()
  // Replace only the address, then perform one actual bare-root reload.
  await page.evaluate(url => window.history.replaceState(null, '', url), service.url)
  await reloadWithReadObservation(page, signals)
  await expect(page).toHaveURL(/#\/applications$/)
  writeFileSync(path.join(ARTIFACT_ROOT, 'startup-preferences.json'), JSON.stringify({ classification: 'source browser local preferences and full navigation reload; installed unrun', reopenOverview: true, explicitDeepLinkPreserved: true, lastWorkspaceFiles: true, applicationsFallback: true }, null, 2))
  expectClean(signals)
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
    .locator(`[data-instance-id="${PROJECT_ID}"]`)
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
  const scopedAgain = page.getByTestId('notifications-popover')
    .locator(`[data-instance-id="${owningInstanceId}"]`).getByRole('button').filter({ hasText: 'No verified backup recorded' })
  const repeatedResponse = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === readPath)
  await scopedAgain.click()
  const repeated = await repeatedResponse
  expect(repeated.status()).toBe(200)
  expect(repeated.request().postDataJSON()).toEqual({ expectedVersion: readPayload.result.attention.version })
  const repeatedPayload = await repeated.json()
  expect(repeatedPayload.result.attention.version).toBe(readPayload.result.attention.version + 1)
  writeFileSync(path.join(ARTIFACT_ROOT, 'activity-scoped-repeat.json'), JSON.stringify({ classification: 'source browser/real HTTP attention effect; no provider execution', owningInstanceId, first: readPayload, repeated: repeatedPayload }, null, 2))
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
      notificationRead: 'application-scoped repeated version-bound transitions and receipts',
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

test('Orchestration shows terminal base drift and requires fresh approval after restart', async ({ page }) => {
  const signals = browserSignals(page)
  const objective = 'Inspect this disposable project after an explicit clean-base check.'
  const recoveryObjective = 'Prepare a fresh provider-free slice after the terminal stop.'
  const goalPath = `/v1/instances/${PROJECT_ID}/goal-execution`
  const goalRecordPath = path.join(
    disposableRoot,
    'xdg',
    'state',
    'stateport',
    'goal-execution',
    PROJECT_ID,
    'current.json',
  )

  await openApplicationRoute(page, `/app/${PROJECT_ID}/workbench/orchestration`)
  await expect(page.getByTestId('orchestration-tool')).toBeVisible()

  const newSlice = page.getByTestId('orchestration-new-slice')
  const newObjective = page.getByTestId('orchestration-new-objective')
  const objectiveInput = page.getByTestId('orchestration-objective')
  await expect
    .poll(async () => {
      if (await newSlice.isVisible()) return 'receipt'
      if (await newObjective.isVisible()) return 'stopped'
      if (await objectiveInput.isVisible()) return 'objective'
      return 'loading'
    })
    .toMatch(/receipt|stopped|objective/)
  if (await newSlice.isVisible()) await newSlice.click()
  else if (await newObjective.isVisible()) await newObjective.click()
  await expect(objectiveInput).toBeVisible()

  const currentResponse = await page.request.get(`${service.url}${goalPath}`)
  expect(currentResponse.status()).toBe(200)
  const currentPayload = (await currentResponse.json()) as {
    result: {
      revision: number
      currentIdentity: { baseCommit: string }
    }
  }

  await objectiveInput.fill(objective)
  const prepareResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/prepare`,
  )
  await page.getByTestId('orchestration-prepare').click()
  const prepareResponse = await prepareResponsePromise
  expect(prepareResponse.status()).toBe(200)
  expect(prepareResponse.request().postDataJSON()).toMatchObject({
    expectedInstanceId: PROJECT_ID,
    expectedRevision: currentPayload.result.revision,
    expectedBaseCommit: currentPayload.result.currentIdentity.baseCommit,
    mode: 'assisted',
    intent: objective,
  })
  const prepared = (await prepareResponse.json()).result as {
    revision: number
    slice: { planDigest: string }
    state: string
  }
  expect(prepared.state).toBe('proposal_ready')

  for (const stage of ['review_plan', 'review_permissions', 'review_budget', 'approve']) {
    await page.getByTestId('orchestration-mark-reviewed').click()
    await expect(page.getByTestId(`stage-${stage}`)).toBeVisible()
  }
  const approveResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/approve`,
  )
  await page.getByTestId('orchestration-approve').click()
  const approveResponse = await approveResponsePromise
  expect(approveResponse.status()).toBe(200)
  const approved = (await approveResponse.json()).result as {
    revision: number
    slice: { planDigest: string }
    state: string
  }
  expect(approved.state).toBe('approved')

  const ownedDrift = path.join(projectRoot, 'r8-terminal-ui-owned-drift.txt')
  writeFileSync(ownedDrift, 'owned disposable drift for the browser proof\n', {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  })
  try {
    const executeResponsePromise = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname === `${goalPath}/execute`,
    )
    await page.getByTestId('orchestration-run').click()
    const executeResponse = await executeResponsePromise
    expect(executeResponse.status()).toBe(409)
    expect(executeResponse.request().postDataJSON()).toEqual({
      expectedInstanceId: PROJECT_ID,
      expectedRevision: approved.revision,
      expectedPlanDigest: approved.slice.planDigest,
    })
    expect((await executeResponse.json()).error.code).toBe('base_drift')
    await expect(page.getByTestId('orchestration-terminal-stop')).toBeVisible()
    await expect(page.getByTestId('orchestration-terminal-stop')).toContainText(
      'selected project no longer matches its exact clean snapshot',
    )
    await expect(page.getByTestId('orchestration-run-retry')).toHaveCount(0)
    await expect(page.getByTestId('orchestration-close')).toHaveCount(0)
    await expect(page.getByTestId('orchestration-new-objective')).toBeVisible()

    await expect
      .poll(() => {
        if (!existsSync(goalRecordPath)) return null
        return JSON.parse(readFileSync(goalRecordPath, 'utf8')) as {
          state: string
          revision: number
          stop?: { code: string }
          executionResult?: unknown
          receipt?: unknown
        }
      })
      .toMatchObject({
        state: 'stopped',
        revision: approved.revision + 1,
        stop: { code: 'base_drift' },
        executionResult: null,
        receipt: null,
      })
  } finally {
    rmSync(ownedDrift, { force: true })
  }
  expect(execFileSync('git', ['-C', projectRoot, 'status', '--short'], { encoding: 'utf8', timeout: 5_000 })).toBe('')

  // Confirm the stopped reason through a document reload before exercising a
  // real AppServer restart over the same disposable durable roots.
  await reloadWithReadObservation(page, signals)
  await expect(page.getByTestId('orchestration-terminal-stop')).toContainText(
    'selected project no longer matches its exact clean snapshot',
  )
  const oldPid = service.child.pid
  await expect.poll(() => signals.inFlight.size).toBe(0)
  await page.goto('about:blank')
  await stopChild(service.child)
  service = await startService(true)
  expect(service.child.pid).not.toBe(oldPid)
  const restartedSignals = browserSignals(page)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/workbench/orchestration`)
  await expect(page.getByTestId('orchestration-terminal-stop')).toContainText(
    'selected project no longer matches its exact clean snapshot',
  )
  await expect(page.getByTestId('orchestration-run-retry')).toHaveCount(0)
  await expect(page.getByTestId('orchestration-close')).toHaveCount(0)
  await expect(page.getByTestId('orchestration-new-objective')).toBeVisible()

  await page.getByTestId('orchestration-new-objective').click()
  await page.getByTestId('orchestration-objective').fill(recoveryObjective)
  const recoveryPrepareResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/prepare`,
  )
  await page.getByTestId('orchestration-prepare').click()
  const recoveryPrepareResponse = await recoveryPrepareResponsePromise
  expect(recoveryPrepareResponse.status()).toBe(200)
  const recoveryPrepared = (await recoveryPrepareResponse.json()).result as {
    revision: number
    slice: { planDigest: string }
    state: string
  }
  expect(recoveryPrepared.state).toBe('proposal_ready')
  await expect(page.getByTestId('orchestration-run')).toHaveCount(0)

  // Discard is a separate pre-execution operation, not running cancellation.
  // Prove its real service effect before preparing the final recovery slice.
  await page.getByTestId('orchestration-discard').click()
  const discardResponsePromise = page.waitForResponse(
    (response) => response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/prepare`,
  )
  await page.getByTestId('confirm-action').click()
  const discardResponse = await discardResponsePromise
  expect(discardResponse.status()).toBe(200)
  expect(discardResponse.request().postDataJSON()).toMatchObject({
    mode: 'off', expectedRevision: recoveryPrepared.revision,
  })
  const discarded = (await discardResponse.json()).result as { revision: number; state: string }
  expect(discarded.state).toBe('off')
  expect(discarded.revision).toBe(recoveryPrepared.revision + 1)
  expect(JSON.parse(readFileSync(goalRecordPath, 'utf8'))).toMatchObject({
    state: 'off', revision: discarded.revision, previousState: 'proposal_ready',
    stop: { code: 'operator_disabled' }, providerExecution: false,
  })
  expect(restartedSignals.requests.filter((request) =>
    request.method === 'POST' && request.path === `${goalPath}/execute`)).toHaveLength(0)
  await expect(page.getByTestId('orchestration-objective')).toBeVisible()
  await page.getByTestId('orchestration-objective').fill(recoveryObjective)
  const freshPreparePromise = page.waitForResponse(
    (response) => response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/prepare`,
  )
  await page.getByTestId('orchestration-prepare').click()
  const freshPrepareResponse = await freshPreparePromise
  expect(freshPrepareResponse.status()).toBe(200)
  expect(freshPrepareResponse.request().postDataJSON()).toMatchObject({ expectedRevision: discarded.revision })
  const freshPrepared = (await freshPrepareResponse.json()).result as {
    revision: number; slice: { planDigest: string }; state: string
  }
  expect(freshPrepared.state).toBe('proposal_ready')
  for (const stage of ['review_plan', 'review_permissions', 'review_budget', 'approve']) {
    await page.getByTestId('orchestration-mark-reviewed').click()
    await expect(page.getByTestId(`stage-${stage}`)).toBeVisible()
  }
  await expect(page.getByTestId('orchestration-run')).toHaveCount(0)
  const recoveryApproveResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/approve`,
  )
  await page.getByTestId('orchestration-approve').click()
  const recoveryApproveResponse = await recoveryApproveResponsePromise
  expect(recoveryApproveResponse.status()).toBe(200)
  expect(recoveryApproveResponse.request().postDataJSON()).toMatchObject({
    expectedRevision: freshPrepared.revision, expectedPlanDigest: freshPrepared.slice.planDigest,
  })
  const recoveryApproved = (await recoveryApproveResponse.json()).result as {
    revision: number
    slice: { planDigest: string }
    state: string
  }
  expect(recoveryApproved.state).toBe('approved')

  const recoveryExecuteResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === `${goalPath}/execute`,
  )
  await page.getByTestId('orchestration-run').click()
  const recoveryExecuteResponse = await recoveryExecuteResponsePromise
  expect(recoveryExecuteResponse.status()).toBe(200)
  const recovered = (await recoveryExecuteResponse.json()).result as {
    state: string
    providerExecution: boolean
    backendId: string
    executionResult?: unknown
  }
  expect(recovered).toMatchObject({
    state: 'awaiting_independent_review',
    providerExecution: false,
    backendId: 'fake',
  })
  expect(recovered.executionResult).toBeTruthy()
  await expect(page.getByTestId('stage-independent_review')).toBeVisible()
  await page.getByTestId('orchestration-accept').click()
  await expect(page.getByTestId('stage-close')).toBeVisible()
  await page.getByTestId('orchestration-close').click()
  await expect(page.getByTestId('stage-receipt')).toBeVisible()

  expectRequest(signals, 'POST', `${goalPath}/prepare`)
  expectRequest(signals, 'POST', `${goalPath}/approve`)
  expectRequest(signals, 'POST', `${goalPath}/execute`)
  expectRequest(restartedSignals, 'POST', `${goalPath}/prepare`)
  expectRequest(restartedSignals, 'POST', `${goalPath}/approve`)
  expectRequest(restartedSignals, 'POST', `${goalPath}/execute`)
  expectClean(signals, [
    { status: 409, method: 'POST', path: `${goalPath}/execute` },
  ])
  expectClean(restartedSignals)

  matrix.surfaces = {
    ...(matrix.surfaces as Record<string, unknown>),
    orchestrationTerminalRecovery: {
      status: 'live-tested',
      classification: 'real AppServer browser; deterministic synthetic backend; disposable fixture',
      baseDrift: '409 persisted as terminal stopped state with exact code and no result or receipt',
      browserControls: 'terminal reason visible; retry and close absent',
      restart: 'same reason retained after a real new AppServer process',
      freshSlice: 'new objective, review, explicit approval, provider-free execution, review, close',
      discard: 'prepared slice disabled through exact HTTP revision; durable operator_disabled stop; fresh preparation/approval required',
      providerExecution: false,
      ownedFixtureFile: 'created and removed; repository clean at test end',
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
  await openApplicationRoute(page, '/settings/terminal')
  const ligaturesToggle = page.locator('#setting-terminal-ligatures').getByRole('switch')
  await expect(ligaturesToggle).toHaveAttribute('aria-checked', 'false')
  await ligaturesToggle.click()
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)

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
  ).toHaveText(/Match|\d+\/[1-9]\d*|[1-9]\d* match(?:es)?/)
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

  await terminalInput.focus()
  await page.keyboard.type("printf 'STATEPORT_LIGATURES -> => == != ===\\n'")
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(frame => frame.direction === 'received' && frame.binary).map(frame => frame.text).join('')).toContain('STATEPORT_LIGATURES -> => == != ===')
  await page.evaluate(() => document.fonts.ready)
  const terminalElement = page.getByTestId('terminal-canvas').locator('.xterm')
  await expect(terminalElement).toHaveCSS('font-feature-settings', /"calt"(?: 1)?, "liga"(?: 1)?/)
  const readLigatureRows = () => terminalElement.evaluate(element => ({
    fontFamily: getComputedStyle(element.querySelector('.xterm-rows')!).fontFamily,
    loadedFonts: [...document.fonts].filter(face => face.status === 'loaded').map(face => face.family),
    rows: [...element.querySelectorAll('.xterm-rows > div')]
      .filter(row => row.textContent?.replace(/\u00a0/g, ' ').trim() === 'STATEPORT_LIGATURES -> => == != ===')
      .map(row => ({ text: row.textContent?.replace(/\u00a0/g, ' ').trim(), cursor: row.querySelector('.xterm-cursor') !== null, spans: [...row.querySelectorAll(':scope > span')].map(span => span.textContent) })),
  }))
  await expect.poll(async () => (await readLigatureRows()).rows.some(row => ['->', '=>', '==', '!=', '==='].every(sequence => row.spans.includes(sequence)))).toBe(true)
  const ligaturesOn = await readLigatureRows()
  expect(ligaturesOn.rows.every(row => !row.cursor)).toBe(true)
  expect(ligaturesOn.loadedFonts.some(font => font.includes('JetBrains Mono'))).toBe(true)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'terminal-ligatures-on.png'), fullPage: true })
  await page.goto(`${service.url}/#/settings/terminal`)
  await expect(ligaturesToggle).toHaveAttribute('aria-checked', 'true')
  await ligaturesToggle.click()
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  await page.goto(`${service.url}/#/app/${PROJECT_ID}/workbench/terminal`)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await expect(terminalElement).toHaveCSS('font-feature-settings', '"calt" 0, "liga" 0')
  const ligaturesOff = await readLigatureRows()
  expect(ligaturesOff.rows.map(row => row.text)).toEqual(ligaturesOn.rows.map(row => row.text))
  const readTerminalGeometry = () => page.getByTestId('terminal-canvas').evaluate(element => ({
    viewport: innerWidth, document: document.documentElement.scrollWidth,
    canvas: element.getBoundingClientRect().toJSON(),
    screen: element.querySelector('.xterm-screen')?.getBoundingClientRect().toJSON(),
  }))
  const geometryBeforeFit = await readTerminalGeometry()
  writeFileSync(path.join(ARTIFACT_ROOT, 'terminal-geometry-before.json'), JSON.stringify(geometryBeforeFit, null, 2))
  await expect.poll(async () => {
    const box = await readTerminalGeometry()
    return box.document <= box.viewport && box.canvas.right <= box.viewport && (!box.screen || box.screen.right <= box.canvas.right)
  }).toBe(true)
  const geometryAfterFit = await readTerminalGeometry()
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'terminal-ligatures-off.png'), fullPage: true })
  await page.getByTestId('terminal-overflow').click()
  const exported = page.waitForEvent('download')
  await page.getByRole('menuitem', { name: 'Export session', exact: true }).click()
  const transcript = await exported
  const transcriptPath = path.join(ARTIFACT_ROOT, 'terminal-ligatures-transcript.txt')
  await transcript.saveAs(transcriptPath)
  expect(readFileSync(transcriptPath, 'utf8')).toContain('STATEPORT_LIGATURES -> => == != ===')
  writeFileSync(path.join(ARTIFACT_ROOT, 'terminal-ligatures.json'), JSON.stringify({ classification: 'source browser actual xterm joined spans/font/local PTY and exact text export; installed capsule unrun', on: ligaturesOn, off: ligaturesOff, geometryBeforeFit, geometryAfterFit, rawExportPreserved: true, sockets: socketSignals.urls.length }, null, 2))
  expect(socketSignals.urls).toHaveLength(1)

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
    const discardResponse = await fetch(`${prefix}/discardWrite`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ preparedWriteId }),
    })
    const discarded = await discardResponse.json()
    return { status: response.status, body, discardStatus: discardResponse.status, discarded }
  }, { instanceId: PROJECT_ID, ...prepared })
  expect(conflict.status).toBe(409)
  expect(conflict.body.error.code).toBe('file_workspace_refused')
  expect(conflict.discardStatus).toBe(200)
  expect(conflict.discarded.result).toMatchObject({
    operation: 'discardWrite', preparedWriteId: prepared.preparedWriteId, discarded: true,
  })
  expect(readFileSync(path.join(projectRoot, 'src', 'main.py'), 'utf8')).toBe('answer = 99\n')

  // Recover through the real editor after its cached revision lost a race to
  // an external writer. Reload must replace the reviewed draft without writing
  // it back over the newer file, and the clean disk value survives navigation.
  await page.getByTestId('tree-row-src/main.py').click()
  await editor.click()
  await page.keyboard.press('Control+a')
  await page.keyboard.type('answer = 100')
  await page.keyboard.press('Control+s')
  await page.getByTestId('confirm-save').click()
  await expect(page.getByTestId('conflict-src/main.py')).toBeVisible()
  await page.getByRole('button', { name: 'Reload disk version', exact: true }).click()
  await expect(editor).toContainText('answer = 99')
  await expect(page.getByTestId('editor-status-strip')).not.toContainText('Unsaved changes')
  expect(readFileSync(path.join(projectRoot, 'src', 'main.py'), 'utf8')).toBe('answer = 99\n')
  await page.keyboard.press('Escape')
  await page.reload()
  await page.getByTestId('tree-row-src').click()
  await page.getByTestId('tree-row-src/main.py').click()
  await expect(editor).toContainText('answer = 99')

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
    {
      status: 409,
      method: 'POST',
      path: `/v1/instances/${PROJECT_ID}/file-workspace/prepareWrite`,
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
      conflictReload: 'reviewed draft replaced by real disk read; file unchanged and retained after reload',
      receiptVerification: 'mock-only control absent from production',
      scope: 'disposable fixture only',
    },
  }
})

test('Idle shell records bounded polling and browser resource observations', async ({ page }) => {
  await openApplicationRoute(page, '/applications')
  await expect(page.getByTestId('applications-page')).toBeVisible()
  // Separate initial hydration from steady idle traffic. No requests are mocked.
  await page.waitForTimeout(2_000)
  const counts: Record<string, number> = {}
  page.on('request', request => {
    if (request.method() !== 'GET') return
    const pathname = new URL(request.url()).pathname
    if (pathname.startsWith('/v1/')) counts[pathname] = (counts[pathname] ?? 0) + 1
  })
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('Performance.enable')
  const before = await cdp.send('Performance.getMetrics')
  const startedAt = new Date().toISOString()
  await page.waitForTimeout(65_000)
  const after = await cdp.send('Performance.getMetrics')
  writeFileSync(path.join(ARTIFACT_ROOT, 'idle-shell-observation.json'), JSON.stringify({
    environment: 'Linux source AppServer, disposable fixture, isolated Chromium; not installed WSL or whole-stack qualification',
    startedAt, durationMs: 65_000, getRequests: counts,
    browserMetricsBefore: before.metrics, browserMetricsAfter: after.metrics,
  }, null, 2) + '\n')
  await cdp.detach()
  expect(counts['/v1/status']).toBeGreaterThan(0)
})

test('Manual application ordering persists across reload without changing application data', async ({ page }) => {
  const signals = browserSignals(page)
  const beforeSource = [projectRoot, studyRoot].map(root => execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: root, encoding: 'utf8' }))
  await openApplicationRoute(page, '/applications')
  await page.getByRole('button', { name: /Sort:/ }).click()
  await page.getByRole('menuitemradio', { name: 'Manual', exact: true }).click()
  const storedOrder = () => page.evaluate(() => JSON.parse(localStorage.getItem('stateport.applications.v1')!).state.unpinnedOrder as string[])
  await expect.poll(async () => (await storedOrder()).length).toBeGreaterThanOrEqual(2)
  const before = await storedOrder()
  const movedId = before[1]!
  const expected = [movedId, before[0]!, ...before.slice(2)]
  const row = page.getByTestId(`instance-row-${movedId}`)
  await row.focus()
  await page.keyboard.press('Alt+ArrowUp')
  await expect.poll(storedOrder).toEqual(expected)
  const renderedOrder = () => page.getByTestId('all-applications-section').locator('[data-testid^="instance-row-"]').evaluateAll(elements => elements.map(element => element.getAttribute('data-testid')!.slice('instance-row-'.length)))
  await expect.poll(renderedOrder).toEqual(expected)
  await reloadWithReadObservation(page, signals)
  await expect.poll(renderedOrder).toEqual(expected)
  await expect(page.getByRole('button', { name: /Sort: Manual/ })).toBeVisible()
  const index = (await (await page.request.get(`${service.url}/v1/instances`)).json()).result.instances
  const movedName = index.find((instance: { instanceId: string }) => instance.instanceId === movedId).name as string
  await page.getByTestId('filter-input').fill(movedName)
  await expect(page.getByText('Clear the filter to reorder applications. Hidden applications keep their positions.')).toBeVisible()
  await row.focus()
  await page.keyboard.press('Alt+ArrowDown')
  expect(await storedOrder()).toEqual(expected)
  await page.getByRole('button', { name: 'Clear filter', exact: true }).click()
  await expect.poll(renderedOrder).toEqual(expected)
  expect([projectRoot, studyRoot].map(root => execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: root, encoding: 'utf8' }))).toEqual(beforeSource)
  writeFileSync(path.join(ARTIFACT_ROOT, 'application-manual-order.json'), JSON.stringify({ classification: 'source browser local preference; no catalog/application mutation', before, after: expected, reloaded: await storedOrder(), filterRefused: true, sourceUnchanged: true }, null, 2))
  expectClean(signals)
})

test('Application rename persists through reload and exposes the exact durable receipt', async ({ page }) => {
  await openApplicationRoute(page, '/applications')
  const index = await (await page.request.get(`${service.url}/v1/instances`)).json()
  const originalName = index.result.instances.find((instance: { instanceId: string }) => instance.instanceId === PROJECT_ID).name as string
  const nextName = 'Renamed source project'
  const row = page.getByTestId(`instance-row-${PROJECT_ID}`)
  await row.getByRole('button', { name: `Actions for ${originalName}`, exact: true }).click()
  await page.getByRole('menuitem', { name: 'Rename…', exact: true }).click()
  await page.getByTestId('rename-input').fill(nextName)
  const changed = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith(`/v1/instances/${PROJECT_ID}/rename`))
  await page.getByRole('button', { name: 'Rename', exact: true }).click()
  const response = await changed
  expect(response.status()).toBe(200)
  const result = (await response.json()).result
  expect(result.receipt).toMatchObject({ instanceId: PROJECT_ID, oldName: originalName, newName: nextName, actorId: 'local-user' })
  await expect(page.getByTestId('rename-dialog')).toHaveCount(0)
  await page.reload()
  await expect(row).toContainText(nextName)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/receipts/${result.receipt.receiptId}`)
  await expect(page.getByTestId('receipt-detail')).toBeVisible()
  await expect(page.getByTestId('receipt-detail')).toContainText('Application renamed')
  await page.getByRole('button', { name: 'Raw JSON', exact: true }).click()
  await expect(page.getByTestId('receipt-raw-json')).toContainText(result.receipt.receiptId)
  await expect(page.getByTestId('receipt-raw-json')).toContainText(originalName)
  await expect(page.getByTestId('receipt-raw-json')).toContainText(nextName)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'application-rename-receipt.png') })
  await openApplicationRoute(page, '/applications')
  await row.getByRole('button', { name: `Actions for ${nextName}`, exact: true }).click()
  await page.getByRole('menuitem', { name: 'Rename…', exact: true }).click()
  await page.getByTestId('rename-input').fill(originalName)
  await page.getByRole('button', { name: 'Rename', exact: true }).click()
  await expect(page.getByTestId('rename-dialog')).toHaveCount(0)
  await expect(row).toContainText(originalName)
})


async function applicationWorkspaceJourney(page: Page, actual: boolean) {
  test.skip(process.env.STATEPORT_UI_REAL_WORKSPACES !== '1', 'Requires explicitly booked real Podman fixture mode')
  // Actual mode adds a third template, source verification and removed-volume recovery.
  test.setTimeout(actual ? 300_000 : 180_000)
  const fixturePath = path.join(disposableRoot, 'xdg', 'data', 'stateport', 'ui-workspace-fixture.json')
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
    manifest: string; daemonRoot: string; governedScope: string; workloads: Record<string, string>
    actualTemplates?: { instanceId: string; name: string; adapterId: string; sourceRoot: string; managedRoot: string; sourceCommit: string; installReceiptId: string; sourceReview: { reviewDigest: string; sourceInventory: { path: string; mode: string; contentDigest: string }[] } }[]
  }
  const templates = fixture.actualTemplates
  expect(Boolean(templates)).toBe(actual)
  const projectId = actual ? templates![0]!.instanceId : PROJECT_ID
  const studyId = actual ? templates![1]!.instanceId : STUDY_ID
  const genericId = actual ? templates![2]!.instanceId : ''
  const projectPath = actual ? templates![0]!.managedRoot : projectRoot
  const studyPath = actual ? templates![1]!.managedRoot : studyRoot
  const roots = actual ? templates!.flatMap(row => [row.sourceRoot, row.managedRoot]) : [projectPath, studyPath]
  const sourceState = (root: string) => ({
    status: execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: root, encoding: 'utf8' }),
    diff: execFileSync('git', ['diff', 'HEAD', '--'], { cwd: root, encoding: 'utf8' }),
    commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }),
    bytes: execFileSync(PYTHON, ['-c', 'import hashlib,pathlib,sys,json; r=pathlib.Path(sys.argv[1]); print(json.dumps([(str(p.relative_to(r)),p.stat().st_mode & 4095,hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(r.rglob("*")) if p.is_file() and ".git" not in p.relative_to(r).parts]))', root], { encoding: 'utf8' }),
  })
  const sourceBefore = roots.map(sourceState)
  const a = fixture.workloads[projectId]!
  const b = fixture.workloads[studyId]!
  const c = actual ? fixture.workloads[genericId]! : ''
  const workspaceIds = actual ? templates!.map(row => row.instanceId) : [projectId, studyId]
  const workspaceWorkloads = actual ? [a, b, c] : [a, b]
  const markerNames = actual ? ['ui-marker', 'ui-study-marker', 'ui-generic-marker'] : ['ui-marker', 'ui-study-marker']
  const ledger = (id: string) => JSON.parse(readFileSync(path.join(fixture.daemonRoot, 'state', 'workloads', `${id}.json`), 'utf8'))
  const containment: unknown[] = []
  const verifyContainment = (id: string) => {
    const proof = execFileSync(PYTHON, ['-c', 'import json,sys;sys.path.insert(0,sys.argv[1]);from test_execution_host_daemon import _governed_container_membership;print(json.dumps(_governed_container_membership(sys.argv[2],sys.argv[3])))', path.join(ROOT, 'scripts'), ledger(id).containerId, fixture.governedScope], { env: { ...process.env, PYTHONPATH }, encoding: 'utf8', timeout: 20_000 })
    containment.push(JSON.parse(proof))
    writeFileSync(path.join(ARTIFACT_ROOT, 'workspace-cgroups.json'), JSON.stringify(containment, null, 2))
  }
  const openRuntime = () => openApplicationRoute(page, '/execution-host')
  const openWorkspaceTerminal = async (instanceId: string) => {
    await openRuntime()
    const name = actual ? templates!.find(row => row.instanceId === instanceId)!.name : instanceId === projectId ? 'Live Core Project' : 'Live Core Study'
    const profile = page.getByRole('region', { name: 'Application workspaces' }).locator('div').filter({ has: page.getByText(name, { exact: true }) }).first()
    const [targetResponse] = await Promise.all([
      page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${instanceId}/terminal/target` && r.request().method() === 'GET'),
      profile.getByRole('link', { name: 'Open workspace terminal', exact: true }).click(),
    ])
    expect(targetResponse.status()).toBe(200)
    expect((await targetResponse.json()).result.target.targetClass).toBe('capsule')
  }
  const connectVisibleTerminal = async () => {
    // The header and neutral start pane both expose terminal-connect. Scope to
    // the state pane so the click remains deterministic in the real UI.
    const start = page.getByTestId('terminal-start').getByTestId('terminal-connect')
    if (await start.isVisible()) {
      await start.click()
      return
    }
    const lost = page.getByTestId('terminal-lost').getByTestId('terminal-connect')
    if (await lost.isVisible()) {
      await lost.click()
      return
    }
    const ended = page.getByTestId('terminal-ended-bar').getByTestId('terminal-reconnect')
    if (await ended.isVisible()) {
      await ended.click()
      return
    }
    await expect(page.locator('header').getByTestId('terminal-connect')).toBeVisible()
    await page.locator('header').getByTestId('terminal-connect').click()
  }

  await openRuntime()
  if (actual && process.env.STATEPORT_UI_NO_DEFAULT_GRANT === '1') {
    await expect(page.getByText(/Development workspace authority unavailable: default_grant_not_configured\./)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Create development workspace', exact: true })).toBeDisabled()
  }
  for (const name of (actual ? templates!.map(row => row.name) : ['Live Core Project', 'Live Core Study'])) {
    const profile = page.getByRole('region', { name: 'Application workspaces' }).locator('div').filter({ has: page.getByText(name, { exact: true }) }).first()
    await profile.getByRole('button', { name: 'Create application workspace', exact: true }).click()
    if (actual) {
      const reviewed = templates!.find(row => row.name === name)!
      const dialog = page.getByRole('alertdialog')
      await expect(dialog).toContainText(reviewed.sourceReview.reviewDigest)
      await dialog.getByRole('button', { name: 'Confirm approved source', exact: true }).click()
    }
  }
  for (const id of workspaceWorkloads) {
    await page.getByRole('article', { name: `Workload ${id}`, exact: true }).getByRole('button', { name: 'Start', exact: true }).click()
    await expect.poll(() => ledger(id).state).toBe('running')
    verifyContainment(id)
  }
  const socketSignals = terminalSocketSignals(page)
  let genericTargetId: string | undefined
  let genericSessionId: string | undefined
  let recoveredTargetId: string | undefined
  const workspaceLogMarker = 'STATEPORT_WORKSPACE_C_LOG_MARKER_9d6c'
  let workspaceLogsVerified = false
  let workspaceCancelVerified = false
  const proveSource = async (index: number) => {
    if (!actual) return
    const inventory = templates![index]!.sourceReview.sourceInventory
    const expectedDigest = execFileSync(PYTHON, ['-c', 'import hashlib,json,sys; print(hashlib.sha256(json.dumps(json.load(sys.stdin),sort_keys=True,separators=(",",":")).encode()).hexdigest())'], { input: JSON.stringify(inventory), encoding: 'utf8' }).trim()
    const script = `import hashlib,pathlib,json; root=pathlib.Path('/workspace'); excluded=${JSON.stringify(markerNames)}; rows=[dict(path=str(p.relative_to(root)),mode=('100755' if p.stat().st_mode & 511 == 493 else '100644' if p.stat().st_mode & 511 == 420 else 'invalid'),contentDigest='sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob('*'),key=lambda p:str(p.relative_to(root))) if p.is_file() and str(p.relative_to(root)) not in excluded]; print('APPROVED_'+'SOURCE_'+hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())`
    const quoted = "'" + script.replaceAll("'", "'\\''") + "'"
    socketSignals.frames.length = 0
    await page.getByTestId('terminal-canvas').locator('.xterm-helper-textarea').focus()
    await page.keyboard.type(`python3 -c ${quoted}`)
    await page.keyboard.press('Enter')
    await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain(`APPROVED_SOURCE_${expectedDigest}`)
  }
  await openWorkspaceTerminal(projectId)
  const [prepare] = await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${projectId}/terminal/prepare` && r.request().method() === 'POST'),
    connectVisibleTerminal(),
  ])
  const initialPreparation = (await prepare.json()).result
  expect(initialPreparation.target.targetClass).toBe('capsule')
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await proveSource(0)
  const input = page.getByTestId('terminal-canvas').locator('.xterm-helper-textarea')
  await input.focus()
  await page.keyboard.type("printf capsule-durable > /workspace/ui-marker; printf 'CAPSULE_%s\\n' READY")
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('CAPSULE_READY')
  await openWorkspaceTerminal(studyId)
  const [studyPrepare] = await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${studyId}/terminal/prepare` && r.request().method() === 'POST'),
    connectVisibleTerminal(),
  ])
  expect(studyPrepare.status()).toBe(200)
  const studyPreparation = (await studyPrepare.json()).result
  expect(studyPreparation.target.targetClass).toBe('capsule')
  expect(studyPreparation.target.targetId).not.toBe(initialPreparation.target.targetId)
  expect(studyPreparation.sessionId).not.toBe(initialPreparation.sessionId)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await proveSource(1)
  await input.focus()
  socketSignals.frames.length = 0
  await page.keyboard.type("test ! -e /workspace/ui-marker && printf study-durable > /workspace/ui-study-marker && printf 'STUDY_%s\\n' READY")
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('STUDY_READY')
  if (actual) {
    await openWorkspaceTerminal(genericId)
    const [genericPrepare] = await Promise.all([
      page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${genericId}/terminal/prepare` && r.request().method() === 'POST'),
      connectVisibleTerminal(),
    ])
    expect(genericPrepare.status()).toBe(200)
    const genericPreparation = (await genericPrepare.json()).result
    genericTargetId = genericPreparation.target.targetId
    genericSessionId = genericPreparation.sessionId
    expect(genericPreparation.target.targetClass).toBe('capsule')
    expect(genericPreparation.target.targetId).not.toBe(initialPreparation.target.targetId)
    expect(genericPreparation.target.targetId).not.toBe(studyPreparation.target.targetId)
    expect(genericPreparation.sessionId).not.toBe(initialPreparation.sessionId)
    expect(genericPreparation.sessionId).not.toBe(studyPreparation.sessionId)
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
    await proveSource(2)
    await input.focus()
    socketSignals.frames.length = 0
    await page.keyboard.type("printf generic-durable > /workspace/ui-generic-marker; printf 'GENERIC_%s\\n' READY")
    await page.keyboard.press('Enter')
    await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('GENERIC_READY')
    // The pinned workspace supervisor is PID 1 and the terminal shell has
    // the same sealed UID. Write one bounded marker to the real container
    // stdout so Logs proves engine output rather than an empty response.
    await page.keyboard.type(`printf '${workspaceLogMarker}\\n' > /proc/1/fd/1 && printf 'LOG_MARKER_%s\\n' WRITTEN`)
    await page.keyboard.press('Enter')
    await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('LOG_MARKER_WRITTEN')
    await openRuntime()
    const genericArticle = page.getByRole('article', { name: `Workload ${c}`, exact: true })
    const [workspaceLogs] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === `/v1/execution-host/workloads/${c}/logs` && response.request().method() === 'GET'),
      genericArticle.getByRole('button', { name: 'Logs', exact: true }).click(),
    ])
    expect(workspaceLogs.status()).toBe(200)
    const workspaceLogsEnvelope = (await workspaceLogs.json()).result as {
      accepted: boolean
      result: { workloadId: string; state: string; output: string; byteCount: number; outputByteBound: number; truncated: boolean }
    }
    expect(workspaceLogsEnvelope.accepted).toBe(true)
    const workspaceLogsPayload = workspaceLogsEnvelope.result
    expect(workspaceLogsPayload).toEqual(expect.objectContaining({ workloadId: c, state: 'running' }))
    expect(workspaceLogsPayload.outputByteBound).toBeGreaterThan(0)
    expect(workspaceLogsPayload.outputByteBound).toBeLessThanOrEqual(256 * 1024)
    expect(workspaceLogsPayload.output).toContain(workspaceLogMarker)
    expect(typeof workspaceLogsPayload.output).toBe('string')
    expect(Number.isSafeInteger(workspaceLogsPayload.byteCount)).toBe(true)
    expect(workspaceLogsPayload.byteCount).toBeLessThanOrEqual(workspaceLogsPayload.outputByteBound)
    expect(typeof workspaceLogsPayload.truncated).toBe('boolean')
    const workspaceLogsRegion = page.getByRole('region', { name: `Logs for ${c}` })
    await expect(workspaceLogsRegion).toBeVisible()
    await expect(workspaceLogsRegion).toContainText(workspaceLogMarker)
    workspaceLogsVerified = true
  }
  await openRuntime()
  await page.getByRole('article', { name: `Workload ${a}`, exact: true }).getByRole('button', { name: 'Stop', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger(a).state).toBe('stopped')
  expect(ledger(b).state).toBe('running')
  await page.getByRole('article', { name: `Workload ${a}`, exact: true }).getByRole('button', { name: 'Start', exact: true }).click()
  await expect.poll(() => ledger(a).state).toBe('running')
  await openWorkspaceTerminal(projectId)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Session ended')
  const reconnect = page.getByTestId('terminal-ended-bar').getByTestId('terminal-reconnect')
  await expect(reconnect).toHaveText('Reconnect')
  const [reprepared] = await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${projectId}/terminal/prepare` && r.request().method() === 'POST'),
    reconnect.click(),
  ])
  expect(reprepared.status()).toBe(200)
  const freshPreparation = (await reprepared.json()).result
  expect(freshPreparation.target.targetClass).toBe('capsule')
  expect(freshPreparation.target.targetId).toBe(initialPreparation.target.targetId)
  expect(freshPreparation.sessionId).not.toBe(initialPreparation.sessionId)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await proveSource(0)
  await input.focus()
  socketSignals.frames.length = 0
  await page.keyboard.type("test ! -e /workspace/ui-study-marker && cat /workspace/ui-marker; printf '\\n'")
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('capsule-durable')
  // Operator fixture revokes only A while a capsule session exists; browser cannot write this manifest.
  const manifest = JSON.parse(readFileSync(fixture.manifest, 'utf8'))
  const originalBindings = [...manifest.bindings]
  manifest.bindings = manifest.bindings.filter((row: { workload: { workloadId: string } }) => row.workload.workloadId !== a)
  writeFileSync(fixture.manifest, JSON.stringify(manifest))
  const socketCountBeforeRevocation = socketSignals.urls.length
  const [refusal] = await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${projectId}/terminal/target` && r.request().method() === 'GET'),
    page.reload(),
  ])
  expect(refusal.status()).toBe(403)
  expect(socketSignals.urls).toHaveLength(socketCountBeforeRevocation)
  await expect(page.getByTestId('terminal-canvas')).toHaveCount(0)
  if (!actual) expect(readFileSync(path.join(projectPath, 'state', 'PROJECT.yaml'), 'utf8')).toBe(projectCanonicalBefore)
  expect(existsSync(path.join(projectPath, 'ui-marker'))).toBe(false)
  // Restore exact authority to remove A through its normal UI; B remains independently running.
  manifest.bindings = originalBindings
  writeFileSync(fixture.manifest, JSON.stringify(manifest))
  await openRuntime()
  await page.getByRole('article', { name: `Workload ${a}`, exact: true }).getByRole('button', { name: 'Remove container', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger(a).state).toBe('removed')
  expect(ledger(b).state).toBe('running')
  await openWorkspaceTerminal(studyId)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Session ended')
  const [studyReprepare] = await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${studyId}/terminal/prepare` && r.request().method() === 'POST'),
    connectVisibleTerminal(),
  ])
  expect(studyReprepare.status()).toBe(200)
  const freshStudyPreparation = (await studyReprepare.json()).result
  expect(freshStudyPreparation.target.targetClass).toBe('capsule')
  expect(freshStudyPreparation.target.targetId).toBe(studyPreparation.target.targetId)
  expect(freshStudyPreparation.sessionId).not.toBe(studyPreparation.sessionId)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  await proveSource(1)
  await input.focus()
  socketSignals.frames.length = 0
  await page.keyboard.type("test ! -e /workspace/ui-marker && cat /workspace/ui-study-marker; printf '\\n'")
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('study-durable')
  if (actual) {
    expect(ledger(c).state).toBe('running')
    await openWorkspaceTerminal(genericId)
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Session ended')
    // A full-page revocation reload restores this tab without its old buffer.
    // The lost-session pane offers Connect; the helper also covers ended tabs.
    const [genericReprepare] = await Promise.all([
      page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${genericId}/terminal/prepare` && r.request().method() === 'POST'),
      connectVisibleTerminal(),
    ])
    expect(genericReprepare.status()).toBe(200)
    const freshGenericPreparation = (await genericReprepare.json()).result
    expect(freshGenericPreparation.target.targetClass).toBe('capsule')
    expect(freshGenericPreparation.target.targetId).toBe(genericTargetId)
    expect(freshGenericPreparation.sessionId).not.toBe(genericSessionId)
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
    await proveSource(2)
    await input.focus()
    socketSignals.frames.length = 0
    await page.keyboard.type("test ! -e /workspace/ui-marker && test ! -e /workspace/ui-study-marker && cat /workspace/ui-generic-marker; printf '\\n'")
    await page.keyboard.press('Enter')
    await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('generic-durable')
  }
  if (actual) {
    // Recover the removed owner through the same UI control and prove the
    // retained volume, while the other two independent workspaces stay live.
    await openRuntime()
    const projectProfile = page.getByRole('region', { name: 'Application workspaces' }).locator('div').filter({ has: page.getByText(templates![0]!.name, { exact: true }) }).first()
    await projectProfile.getByRole('button', { name: 'Recover application workspace', exact: true }).click()
    const recoveryDialog = page.getByRole('alertdialog')
    await expect(recoveryDialog).toContainText(templates![0]!.sourceReview.reviewDigest)
    await recoveryDialog.getByRole('button', { name: 'Confirm approved source', exact: true }).click()
    await expect.poll(() => ['created', 'stopped'].includes(ledger(a).state)).toBe(true)
    await page.getByRole('article', { name: `Workload ${a}`, exact: true }).getByRole('button', { name: 'Start', exact: true }).click()
    await expect.poll(() => ledger(a).state).toBe('running')
    expect(ledger(b).state).toBe('running')
    expect(ledger(c).state).toBe('running')
    await openWorkspaceTerminal(projectId)
    // Container recovery rotates the target identity. Keep the old tab bound
    // to its original target, and explicitly create a new, unconnected session.
    const replacementPane = page.getByTestId('terminal-target-unavailable')
    await expect(replacementPane).toBeVisible()
    const socketsBeforeReplacement = socketSignals.urls.length
    await replacementPane.getByRole('button', { name: 'New session', exact: true }).click()
    await expect(page.getByTestId('terminal-start')).toBeVisible()
    expect(socketSignals.urls).toHaveLength(socketsBeforeReplacement)
    const [recoveryPrepare] = await Promise.all([
      page.waitForResponse(r => new URL(r.url()).pathname === `/v1/execution-host/workspaces/${projectId}/terminal/prepare` && r.request().method() === 'POST'),
      connectVisibleTerminal(),
    ])
    expect(recoveryPrepare.status()).toBe(200)
    recoveredTargetId = (await recoveryPrepare.json()).result.target.targetId
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
    await proveSource(0)
    await input.focus()
    socketSignals.frames.length = 0
    await page.keyboard.type("test ! -e /workspace/ui-study-marker && test ! -e /workspace/ui-generic-marker && cat /workspace/ui-marker; printf '\\n'")
    await page.keyboard.press('Enter')
    await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('capsule-durable')
  }
  if (actual) {
    // Workspace cancellation is a real daemon cleanup operation: the
    // container must disappear before the durable state becomes cancelled.
    await openRuntime()
    const cancelArticle = page.getByRole('article', { name: `Workload ${c}`, exact: true })
    await cancelArticle.getByRole('button', { name: 'Cancel work', exact: true }).click()
    const cancelling = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/execution-host/workloads/cancel' && response.request().method() === 'POST')
    await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
    const cancelledResponse = await cancelling
    expect(cancelledResponse.status()).toBe(200)
    const cancelledEnvelope = (await cancelledResponse.json()).result as {
      accepted: boolean
      result: { workloadId: string; state: string }
      receipt: { action: string; status: string; workloadId?: string; operationId: string }
    }
    expect(cancelledEnvelope.accepted).toBe(true)
    expect(cancelledEnvelope.result).toEqual(expect.objectContaining({ workloadId: c, state: 'cancelled' }))
    expect(cancelledEnvelope.receipt).toEqual(expect.objectContaining({ action: 'execution_host.cancel', status: 'accepted', workloadId: c }))
    await expect.poll(() => ledger(c).state).toBe('cancelled')
    const cancelledLedger = ledger(c) as { state: string; receipts?: Array<{ kind?: string; cleanup?: string; detail?: string }> }
    expect(cancelledLedger.state).toBe('cancelled')
    const lastCancelReceipt = cancelledLedger.receipts?.[cancelledLedger.receipts.length - 1]
    expect(lastCancelReceipt).toEqual(expect.objectContaining({ kind: 'cancel', cleanup: 'engine workload absence verified' }))
    const cancelledInventory = await page.request.get(`${service.url}/v1/execution-host/workloads`)
    expect(cancelledInventory.status()).toBe(200)
    const cancelledInventoryEnvelope = (await cancelledInventory.json()).result as {
      accepted: boolean
      result: { workloads: Array<{ workloadId: string; state: string; engineStatus: string }> }
    }
    expect(cancelledInventoryEnvelope.accepted).toBe(true)
    expect(cancelledInventoryEnvelope.result.workloads.find(row => row.workloadId === c)).toEqual(expect.objectContaining({ workloadId: c, state: 'cancelled', engineStatus: 'absent' }))
    workspaceCancelVerified = true

    // Cancelled work is terminal, but the UI's explicit Remove → Recover
    // path must still reattach the preserved application workspace volume.
    const cancelledArticle = page.getByRole('article', { name: `Workload ${c}`, exact: true })
    await cancelledArticle.getByRole('button', { name: 'Remove container', exact: true }).click()
    await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
    await expect.poll(() => ledger(c).state).toBe('removed')
    const genericProfile = page.getByRole('region', { name: 'Application workspaces' }).locator('div').filter({ has: page.getByText(templates![2]!.name, { exact: true }) }).first()
    await genericProfile.getByRole('button', { name: 'Recover application workspace', exact: true }).click()
    const genericRecoveryDialog = page.getByRole('alertdialog')
    await expect(genericRecoveryDialog).toContainText(templates![2]!.sourceReview.reviewDigest)
    await genericRecoveryDialog.getByRole('button', { name: 'Confirm approved source', exact: true }).click()
    await expect.poll(() => ['created', 'stopped'].includes(ledger(c).state)).toBe(true)
    await page.getByRole('article', { name: `Workload ${c}`, exact: true }).getByRole('button', { name: 'Start', exact: true }).click()
    await expect.poll(() => ledger(c).state).toBe('running')
    await openWorkspaceTerminal(genericId)
    const cancelledRecoveryPane = page.getByTestId('terminal-target-unavailable')
    await expect(cancelledRecoveryPane).toBeVisible()
    const socketsBeforeCancelledRecovery = socketSignals.urls.length
    await cancelledRecoveryPane.getByRole('button', { name: 'New session', exact: true }).click()
    await expect(page.getByTestId('terminal-start')).toBeVisible()
    expect(socketSignals.urls).toHaveLength(socketsBeforeCancelledRecovery)
    const [cancelledRecoveryPrepare] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === `/v1/execution-host/workspaces/${genericId}/terminal/prepare` && response.request().method() === 'POST'),
      connectVisibleTerminal(),
    ])
    expect(cancelledRecoveryPrepare.status()).toBe(200)
    const cancelledRecoveryPreparation = (await cancelledRecoveryPrepare.json()).result
    expect(cancelledRecoveryPreparation.target.targetClass).toBe('capsule')
    expect(cancelledRecoveryPreparation.target.targetId).not.toBe(genericTargetId)
    await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
    await proveSource(2)
    await input.focus()
    socketSignals.frames.length = 0
    await page.keyboard.type("test ! -e /workspace/ui-marker && test ! -e /workspace/ui-study-marker && cat /workspace/ui-generic-marker; printf '\\n'")
    await page.keyboard.press('Enter')
    await expect.poll(() => socketSignals.frames.filter(f => f.direction === 'received' && f.binary).map(f => f.text).join('')).toContain('generic-durable')
  }
  await openRuntime()
  const history = page.getByRole('region', { name: 'Execution operation history' })
  await history.getByRole('button', { name: 'Refresh operation history', exact: true }).click()
  await expect(history.locator('details').first()).toBeVisible()
  for (const action of ['execution_host.createWorkload', 'execution_host.start', 'execution_host.stop', 'execution_host.removeWorkload', ...(actual ? ['execution_host.cancel'] : [])]) {
    await expect(history).toContainText(action)
  }
  expect(roots.map(sourceState)).toEqual(sourceBefore)
  for (const root of roots) {
    for (const marker of markerNames) expect(existsSync(path.join(root, marker))).toBe(false)
  }
  await openRuntime()
  await page.getByRole('article', { name: `Workload ${b}`, exact: true }).getByRole('button', { name: 'Stop', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger(b).state).toBe('stopped')
  writeFileSync(path.join(ARTIFACT_ROOT, 'application-workspace-journey.json'), JSON.stringify({
    environment: 'source AppServer and real rootless containers; fixture operator grants; not installed qualification',
    actualTemplates: templates?.map(row => ({ instanceId: row.instanceId, adapterId: row.adapterId, sourceCommit: row.sourceCommit, installReceiptId: row.installReceiptId, sourceReviewDigest: row.sourceReview.reviewDigest, approvedFiles: row.sourceReview.sourceInventory.length })),
    instanceIds: workspaceIds, workloadIds: workspaceWorkloads,
    finalLedgers: workspaceWorkloads.map(id => ledger(id)),
    capsuleTargetIds: [initialPreparation.target.targetId, studyPreparation.target.targetId, genericTargetId, recoveredTargetId].filter(Boolean),
    sourcePreserved: true, independentMarkersVerified: true, containerRestartReconnected: true,
    revokedTargetStatus: refusal.status(), revokedScopeOpenedNoSocket: true,
    removalPreservedOtherWorkload: true, recoveredRemovedWorkspace: actual, operationHistoryInspected: true,
    workspaceLogsVerified, workspaceCancelVerified,
    noDefaultGrant: actual && process.env.STATEPORT_UI_NO_DEFAULT_GRANT === '1',
    serviceRestart: 'not_run', operatorIssuance: 'fixture_preprovisioned',
  }, null, 2))
}

test('Application-owned real workspaces use independent capsule authority', async ({ page }) => {
  test.skip(process.env.STATEPORT_UI_ACTUAL_TEMPLATES === '1', 'Separate actual-template mode has its own case')
  await applicationWorkspaceJourney(page, false)
})

test('Actual pinned ProjectState, StudyState, and generic StateSpec imports seed independent workspaces', async ({ page }) => {
  test.skip(process.env.STATEPORT_UI_ACTUAL_TEMPLATES !== '1', 'Requires explicit actual-template governed fixture mode')
  await applicationWorkspaceJourney(page, true)
})


test('Connected capsule overflow Reconnect opens a fresh session on the same target', async ({ page }) => {
  test.skip(process.env.STATEPORT_UI_REAL_WORKSPACES !== '1', 'Requires explicitly booked real Podman fixture mode')
  test.setTimeout(120_000)
  const signals = browserSignals(page)
  const socketSignals = terminalSocketSignals(page)
  const fixturePath = path.join(disposableRoot, 'xdg', 'data', 'stateport', 'ui-workspace-fixture.json')
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
    daemonRoot: string
    governedScope: string
    workloads: Record<string, string>
    actualTemplates?: Array<{ instanceId: string; name: string; sourceReview?: { reviewDigest: string } }>
  }
  const instanceId = fixture.actualTemplates?.[0]?.instanceId ?? PROJECT_ID
  const workspaceName = fixture.actualTemplates?.[0]?.name ?? 'Live Core Project'
  const workloadId = fixture.workloads[instanceId]!
  const ledgerPath = path.join(fixture.daemonRoot, 'state', 'workloads', `${workloadId}.json`)
  const ledger = () => existsSync(ledgerPath) ? JSON.parse(readFileSync(ledgerPath, 'utf8')) as { state: string; containerId: string } : undefined

  await openApplicationRoute(page, '/execution-host')
  const profile = page.getByRole('region', { name: 'Application workspaces' }).locator('div').filter({ has: page.getByText(workspaceName, { exact: true }) }).first()
  const currentState = ledger()?.state
  if (currentState === 'running') {
    const existing = page.getByRole('article', { name: `Workload ${workloadId}`, exact: true })
    await existing.getByRole('button', { name: 'Stop', exact: true }).click()
    await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
    await expect.poll(() => ledger()?.state).toBe('stopped')
  }
  if (['created', 'stopped'].includes(ledger()?.state ?? '')) {
    const existing = page.getByRole('article', { name: `Workload ${workloadId}`, exact: true })
    await existing.getByRole('button', { name: 'Remove container', exact: true }).click()
    await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
    await expect.poll(() => ledger()?.state).toBe('removed')
  }
  await profile.getByRole('button', { name: /^(Create|Recover) application workspace$/, exact: true }).click()
  const review = fixture.actualTemplates?.[0]?.sourceReview
  if (review) {
    const dialog = page.getByRole('alertdialog')
    await expect(dialog).toContainText(review.reviewDigest)
    await dialog.getByRole('button', { name: 'Confirm approved source', exact: true }).click()
  }
  await expect.poll(() => ['created', 'stopped'].includes(ledger()?.state ?? '')).toBe(true)
  await page.getByRole('article', { name: `Workload ${workloadId}`, exact: true }).getByRole('button', { name: 'Start', exact: true }).click()
  await expect.poll(() => ledger()?.state).toBe('running')

  const containment = execFileSync(PYTHON, ['-c', 'import json,sys;sys.path.insert(0,sys.argv[1]);from test_execution_host_daemon import _governed_container_membership;print(json.dumps(_governed_container_membership(sys.argv[2],sys.argv[3])))', path.join(ROOT, 'scripts'), ledger()!.containerId, fixture.governedScope], { env: { ...process.env, PYTHONPATH }, encoding: 'utf8', timeout: 20_000 })
  writeFileSync(path.join(ARTIFACT_ROOT, 'capsule-reconnect-cgroups.json'), containment)

  await openApplicationRoute(page, `/execution-host/workspaces/${instanceId}/terminal`)
  await expect(page.getByTestId('terminal-start').getByTestId('terminal-connect')).toBeVisible()
  const [firstPrepare] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === `/v1/execution-host/workspaces/${instanceId}/terminal/prepare` && response.request().method() === 'POST'),
    page.getByTestId('terminal-start').getByTestId('terminal-connect').click(),
  ])
  expect(firstPrepare.status()).toBe(200)
  const first = (await firstPrepare.json()).result as { sessionId: string; target: { targetId: string; targetClass: string } }
  expect(first.target.targetClass).toBe('capsule')
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  const input = page.getByTestId('terminal-canvas').locator('.xterm-helper-textarea')
  const marker = `CAPSULE_OVERFLOW_RECONNECT_${Date.now()}`
  await input.focus()
  await page.keyboard.type(`printf 'CAPSULE_OVERFLOW_%s' '${marker.slice('CAPSULE_OVERFLOW_'.length)}' > /workspace/ui-overflow-reconnect-marker; cat /workspace/ui-overflow-reconnect-marker; printf '\\n'`)
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(frame => frame.direction === 'received' && frame.binary).map(frame => frame.text).join('')).toContain(marker)

  const socketsBeforeReconnect = socketSignals.urls.length
  socketSignals.frames.length = 0
  await page.getByTestId('terminal-overflow').click()
  const [secondPrepare] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === `/v1/execution-host/workspaces/${instanceId}/terminal/prepare` && response.request().method() === 'POST'),
    page.getByRole('menuitem', { name: 'Reconnect', exact: true }).click(),
  ])
  expect(secondPrepare.status()).toBe(200)
  const second = (await secondPrepare.json()).result as { sessionId: string; purpose: string; target: { targetId: string; targetClass: string } }
  expect(second.purpose).toBe('create')
  expect(second.sessionId).not.toBe(first.sessionId)
  expect(second.target).toMatchObject({ targetClass: 'capsule', targetId: first.target.targetId })
  await expect.poll(() => socketSignals.urls.length).toBe(socketsBeforeReconnect + 1)
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  const sent = parsedTerminalControls(socketSignals, 'sent')
  const received = parsedTerminalControls(socketSignals, 'received')
  expect(sent[0]).toMatchObject({ type: 'authenticate', sessionId: second.sessionId, purpose: 'create' })
  expect(received).toContainEqual(expect.objectContaining({ type: 'ready', sessionId: second.sessionId, purpose: 'create', targetClass: 'capsule', reconnect: false }))
  await input.focus()
  socketSignals.frames.length = 0
  await page.keyboard.type('cat /workspace/ui-overflow-reconnect-marker')
  await page.keyboard.press('Enter')
  await expect.poll(() => socketSignals.frames.filter(frame => frame.direction === 'received' && frame.binary).map(frame => frame.text).join('')).toContain(marker)
  expect(socketSignals.errors).toEqual([])
  expectClean(signals)

  await page.getByTestId('terminal-end').click()
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Session ended')
  await expect.poll(() => socketSignals.closes).toBeGreaterThanOrEqual(2)

  // Leave the disposable workload removed after this isolated proof.
  await openApplicationRoute(page, '/execution-host')
  const workload = page.getByRole('article', { name: `Workload ${workloadId}`, exact: true })
  await workload.getByRole('button', { name: 'Stop', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger()?.state).toBe('stopped')
  await workload.getByRole('button', { name: 'Remove container', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger()?.state).toBe('removed')
})


test('Catalog imports a public HTTPS template at an exact commit and preserves it across process restart', async ({ page }) => {
  test.setTimeout(180_000)
  const url = 'https://github.com/lennertvhoy/ProjectState_Template'
  const revision = '7e4cb7c3397324d09f768eeb1d722316714c46e1'
  const tree = '80cde79f0b235b7a1f7fd911d3074700f799d9d5'
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/catalog')
  await page.getByRole('button', { name: 'More catalog actions' }).click()
  await page.getByRole('menuitem', { name: 'Import a repository' }).click()
  await page.getByLabel('Public HTTPS repository').fill(url)
  await page.getByLabel('Exact Git commit').fill(revision)
  const inspectionResponsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/repository-import/inspect', { timeout: 90_000 })
  await page.getByRole('button', { name: 'Fetch and inspect' }).click()
  const inspectionResponse = await inspectionResponsePromise
  expect(inspectionResponse.status()).toBe(200)
  expect(inspectionResponse.request().postDataJSON()).toEqual({ url, revision })
  const inspected = (await inspectionResponse.json()).result as {
    candidateId: string; inspectionDigest: string; mutated: boolean;
    sourceIdentity: { kind: string; headCommit: string; dirty: boolean };
  }
  expect(inspected.sourceIdentity).toMatchObject({ headCommit: revision, dirty: false })
  expect(inspected.mutated).toBe(false)
  const cache = path.join(disposableRoot, 'xdg', 'data', 'stateport', 'public-repositories', inspected.candidateId, 'repository')
  const git = (...args: string[]) => execFileSync('git', ['-C', cache, ...args], { encoding: 'utf8', timeout: 5_000 }).trim()
  expect(git('rev-parse', 'HEAD')).toBe(revision)
  expect(git('rev-parse', 'HEAD^{tree}')).toBe(tree)
  expect(git('status', '--porcelain')).toBe('')
  await expect(page.getByTestId('import-review')).toContainText('Clean')
  await expect(page.getByTestId('template-adapter-match')).toContainText('projectstate-v6')
  await page.getByTestId('import-name').fill('Public ProjectState Browser')
  await expect(page.getByTestId('import-register')).toBeDisabled()
  await page.getByRole('checkbox', { name: 'Approve creation of an isolated copy of the exact inspected template' }).click()
  const installedResponsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/template-import/install')
  await page.getByTestId('import-register').click()
  const installedResponse = await installedResponsePromise
  expect(installedResponse.status()).toBe(200)
  const body = installedResponse.request().postDataJSON() as {
    plan: { candidateId: string; inspectionDigest: string; planDigest: string };
    approval: { decision: string; actorId: string; planDigest: string };
  }
  expect(body.plan.candidateId).toBe(inspected.candidateId)
  expect(body.plan.inspectionDigest).toBe(inspected.inspectionDigest)
  expect(body.approval).toEqual({ decision: 'approve', actorId: 'local-user', planDigest: body.plan.planDigest })
  const installed = (await installedResponse.json()).result as {
    instanceId: string; receiptId: string; managedCopyCreated: boolean; sourceRepositoryMutated: boolean;
  }
  expect(installed.managedCopyCreated).toBe(true)
  expect(installed.sourceRepositoryMutated).toBe(false)
  await expect(page.getByTestId('import-done')).toContainText('Public ProjectState Browser')
  await page.getByTestId('import-view-receipt').click()
  await page.getByRole('button', { name: 'IDs, revisions, and digests' }).click()
  const receipt = page.getByTestId('receipt-exact-record')
  await expect(receipt).toContainText(installed.receiptId)
  await page.getByRole('button', { name: 'Raw JSON', exact: true }).click()
  const rawReceipt = page.getByTestId('receipt-raw-json')
  await expect(rawReceipt).toContainText(revision)
  await expect(rawReceipt).toContainText(url)
  const receiptBefore = await receipt.textContent()
  const rawReceiptBefore = await rawReceipt.textContent()
  const receiptRoute = new URL(page.url()).hash
  expectClean(signals)

  // Stop the browser's polls before terminating the service, then start a new
  // process over the exact same XDG roots, catalog, receipts and source cache.
  await page.goto('about:blank')
  const oldPid = service.child.pid
  await stopChild(service.child)
  service = await startService(true)
  expect(service.child.pid).not.toBe(oldPid)
  const restartedSignals = browserSignals(page)
  await page.goto(`${service.url}/${receiptRoute}`)
  await page.getByRole('button', { name: 'IDs, revisions, and digests' }).click()
  await expect(page.getByTestId('receipt-exact-record')).toHaveText(receiptBefore ?? '')
  await page.getByRole('button', { name: 'Raw JSON', exact: true }).click()
  await expect(page.getByTestId('receipt-raw-json')).toHaveText(rawReceiptBefore ?? '')
  await page.goto(`${service.url}/#/app/${installed.instanceId}`)
  await expect(page.getByTestId('app-overview-stub')).toBeVisible()
  expect(git('rev-parse', 'HEAD')).toBe(revision)
  expect(git('rev-parse', 'HEAD^{tree}')).toBe(tree)
  expect(git('status', '--porcelain')).toBe('')
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'public-template-import-restarted.png'), fullPage: true })
  expectClean(restartedSignals)
  matrix.surfaces = { ...(matrix.surfaces as Record<string, unknown>), publicTemplateImport: {
    environment: 'Linux source AppServer and isolated browser; not installed Windows qualification',
    sourceUrl: url, sourceCommit: revision, sourceTree: tree, inspectionDigest: inspected.inspectionDigest,
    instanceId: installed.instanceId, receiptId: installed.receiptId, processRestart: 'same durable roots, new process',
    sourceSnapshot: 'unchanged', explicitReviewAndApproval: true, receiptAfterRestart: 'exact same content',
  } }
})


test('Recovery restores a new instance after stale-backup refusal and retains exact receipts across restart', async ({ page }) => {
  test.setTimeout(180_000)
  // The production StudyState installer declares and now emits valid StateSpec.
  // The raw development directory's unsupported handmade lock is not a restore fixture.
  const destinationId = 'live-core-browser-restored'
  const backupRoute = `/app/${STUDY_ID}/settings?group=backup`
  await openApplicationRoute(page, backupRoute)
  await expect(page.getByText('Operator session required', { exact: true })).toBeVisible()
  await expect(page.getByTestId('restore-plan-action')).toBeDisabled()
  await page.goto('about:blank')
  await stopChild(service.child)
  const boundary = path.join(disposableRoot, 'xdg', 'config', 'stateport', 'platform-operator-authority')
  writeFileSync(boundary, 'Disposable source browser operator fixture; not installed authority proof.\n', { mode: 0o600, flag: 'wx' })
  service = await startService(true, 'platform_operator')
  const signals = browserSignals(page)
  const snapshot = (root: string): Record<string, string> => {
    const files: Record<string, string> = {}
    const visit = (relative: string) => {
      for (const entry of readdirSync(path.join(root, relative), { withFileTypes: true })) {
        if (entry.name === '.git') continue
        const child = path.join(relative, entry.name)
        if (entry.isDirectory()) visit(child)
        else if (entry.isFile()) files[child] = createHash('sha256').update(readFileSync(path.join(root, child))).digest('hex')
        else throw new Error(`Unexpected nonregular recovery fixture path: ${child}`)
      }
    }
    visit('')
    return files
  }
  const original = snapshot(studyRoot)
  const head = execFileSync('git', ['-C', studyRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 5_000 }).trim()
  await openApplicationRoute(page, backupRoute)
  const backupResponsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname === `/v1/instances/${STUDY_ID}/backup`)
  await page.getByTestId('recovery-backup-action').click()
  const backupResponse = await backupResponsePromise
  expect(backupResponse.status()).toBe(200)
  const backupId = (await backupResponse.json()).result.backupReceipt.receiptId as string
  const backupIndex = JSON.parse(readFileSync(path.join(disposableRoot, 'xdg', 'data', 'stateport', 'backups', 'index.json'), 'utf8')) as {
    entries: Array<{ archive: string; backupReceipt: { receiptId: string } }>;
  }
  const archive = backupIndex.entries.find(entry => entry.backupReceipt.receiptId === backupId)?.archive
  expect(archive).toBeTruthy()
  if (!archive) throw new Error('Exact browser backup archive is absent')
  expect(path.dirname(archive)).toBe(path.join(disposableRoot, 'xdg', 'data', 'stateport', 'backups', STUDY_ID))
  const archiveBefore = readFileSync(archive)
  const destination = path.join(disposableRoot, 'xdg', 'data', 'stateport', 'instances', destinationId)
  await page.goto(`${service.url}/#${backupRoute}`)
  await expect(page.getByTestId('governed-restore-panel')).toContainText(backupId)
  await page.getByTestId('restore-destination-id').fill(destinationId)
  const planResponsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname.endsWith('/recovery/restore/plan'))
  await page.getByTestId('restore-plan-action').click()
  const planResponse = await planResponsePromise
  expect(planResponse.status()).toBe(200)
  const plan = (await planResponse.json()).result as { planDigest: string; sourceInstanceId: string; destinationInstanceId: string }
  expect(plan).toMatchObject({ sourceInstanceId: STUDY_ID, destinationInstanceId: destinationId })
  await expect(page.getByTestId('governed-restore-panel')).toContainText(plan.planDigest)
  const approvalResponsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname.endsWith('/recovery/restore/approve'))
  await page.getByTestId('restore-approve-action').click()
  const approvalResponse = await approvalResponsePromise
  expect(approvalResponse.status()).toBe(200)
  const approval = (await approvalResponse.json()).result as { approvalDigest: string; planDigest: string }
  expect(approval.planDigest).toBe(plan.planDigest)
  const apply = async () => {
    await page.getByTestId('restore-apply-action').click()
    const responsePromise = page.waitForResponse(response => response.request().method() === 'POST'
      && new URL(response.url()).pathname.endsWith('/recovery/restore/apply'))
    await page.getByTestId('confirm-action').click()
    return responsePromise
  }
  let refusedStatus = 0
  try {
    writeFileSync(archive, Buffer.concat([archiveBefore, Buffer.from('owned stale-backup probe')]))
    const refused = await apply()
    refusedStatus = refused.status()
    expect(refusedStatus).toBe(400)
    expect(refused.request().postDataJSON()).toEqual({ planDigest: plan.planDigest, approvalDigest: approval.approvalDigest })
    await expect(page.getByText('Recovery request refused', { exact: true })).toBeVisible()
    expect(existsSync(destination)).toBe(false)
    expect(snapshot(studyRoot)).toEqual(original)
  } finally {
    writeFileSync(archive, archiveBefore)
  }
  const applied = await apply()
  expect(applied.status()).toBe(200)
  expect(applied.request().postDataJSON()).toEqual({ planDigest: plan.planDigest, approvalDigest: approval.approvalDigest })
  const receipt = (await applied.json()).result as {
    receiptId: string; receiptDigest: string; sourceInstanceId: string; destinationInstanceId: string;
    status: string; result: { validation: { valid: boolean } };
  }
  expect(receipt).toMatchObject({ sourceInstanceId: STUDY_ID, destinationInstanceId: destinationId,
    status: 'validated', result: { validation: { valid: true } } })
  await expect(page.getByTestId('governed-restore-panel')).toContainText(receipt.receiptId)
  await expect(page.getByTestId('governed-restore-panel')).toContainText(receipt.receiptDigest)
  expect(readFileSync(path.join(destination, 'instance.yaml'), 'utf8')).toContain(`id: "${destinationId}"`)
  expect(snapshot(studyRoot)).toEqual(original)
  expect(createHash('sha256').update(readFileSync(path.join(destination, 'README.md'))).digest('hex')).toBe(original['README.md'])
  const receiptFile = path.join(disposableRoot, 'xdg', 'state', 'stateport', 'operations', 'restores', 'receipts', `${plan.planDigest.slice(7)}.json`)
  const receiptBytes = readFileSync(receiptFile)
  expect(JSON.parse(receiptBytes.toString())).toEqual(receipt)
  await page.goto('about:blank')
  const oldPid = service.child.pid
  await stopChild(service.child)
  service = await startService(true, 'platform_operator')
  expect(service.child.pid).not.toBe(oldPid)
  await page.goto(`${service.url}/#${backupRoute}`)
  await expect(page.getByTestId('governed-restore-panel')).toContainText(receipt.receiptId)
  await expect(page.getByTestId('governed-restore-panel')).toContainText('Validated')
  expect(readFileSync(receiptFile)).toEqual(receiptBytes)
  const instancesResponse = await page.request.get(`${service.url}/v1/instances`)
  expect(instancesResponse.status()).toBe(200)
  const instances = (await instancesResponse.json()).result.instances as Array<{ instanceId: string; applicationId: string }>
  expect(instances.find(instance => instance.instanceId === destinationId)?.applicationId).toBe(STUDY_APPLICATION_ID)
  expect(snapshot(studyRoot)).toEqual(original)
  expect(readFileSync(archive)).toEqual(archiveBefore)
  expect(execFileSync('git', ['-C', studyRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 5_000 }).trim()).toBe(head)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'recovery-restored-restarted.png'), fullPage: true })
  expectClean(signals, [{ status: 400, method: 'POST', path: `/v1/instances/${STUDY_ID}/recovery/restore/apply` }])
  matrix.surfaces = { ...(matrix.surfaces as Record<string, unknown>), recoveryRestore: {
    environment: 'Linux source AppServer, disposable OS-owned operator fixture and isolated browser; not installed authority proof',
    sourceInstanceId: STUDY_ID, destinationInstanceId: destinationId, backupReceiptId: backupId,
    planDigest: plan.planDigest, approvalDigest: approval.approvalDigest, receipt,
    staleBackupRefusalStatus: refusedStatus, refusalBeforeDestinationWrite: true, exactApprovedRetry: true,
    sourceFilesAndGit: 'unchanged', backupArchiveRestored: 'exact original bytes', processRestart: 'same durable roots, new PID',
    durableReceipt: 'byte-identical after restart', browserSignals: signals,
  } }
})


test('Authority UI pause and revoke enforce two scoped file consumers with exact receipts after restart', async ({ page, context }) => {
  test.setTimeout(180_000)
  await page.goto('about:blank')
  await stopChild(service.child)
  const boundary = path.join(disposableRoot, 'xdg', 'config', 'stateport', 'platform-operator-authority')
  if (!existsSync(boundary)) writeFileSync(boundary, 'Disposable authority operator fixture.\n', { mode: 0o600, flag: 'wx' })
  service = await startService(true, 'platform_operator', true)
  const authorityRoot = path.join(disposableRoot, 'xdg', 'data', 'stateport', 'live-core-authority-repository')
  const receipts: Array<{ receiptId: string; receiptDigest: string; result: { status: string } }> = []
  let receiptDirectory = ''
  const consume = (suffix: 'a' | 'b', value: string) => {
    const result = JSON.parse(execFileSync(PYTHON, [path.join(HERE, 'live-core-fixture.py'), '--port', '0',
      '--repo-root', ROOT, '--authority-consume', suffix, '--authority-text', value], {
      env: { ...process.env, PYTHONPATH, XDG_CONFIG_HOME: path.join(disposableRoot, 'xdg/config'),
        XDG_DATA_HOME: path.join(disposableRoot, 'xdg/data'), XDG_STATE_HOME: path.join(disposableRoot, 'xdg/state') },
      encoding: 'utf8', timeout: 15_000,
    })) as { decision: string; reason?: string; receiptDirectory: string;
      receipt: { receiptId: string; receiptDigest: string; result: { status: string } } }
    expect(result.receiptDirectory.startsWith(path.join(disposableRoot, 'xdg/state/stateport/authority') + path.sep)).toBe(true)
    receiptDirectory = result.receiptDirectory
    expect(JSON.parse(readFileSync(path.join(receiptDirectory, `${result.receipt.receiptId}.json`), 'utf8'))).toEqual(result.receipt)
    receipts.push(result.receipt)
    return result
  }
  for (const suffix of ['a', 'b'] as const) {
    expect(consume(suffix, 'before').decision).toBe('executed')
    expect(readFileSync(path.join(authorityRoot, `proof-${suffix}.txt`), 'utf8')).toBe('before')
  }
  const signals = browserSignals(page)
  const indexResponsePromise = page.waitForResponse(response => response.request().method() === 'GET'
    && new URL(response.url()).pathname === '/v1/authority/index')
  await openApplicationRoute(page, '/authority')
  const indexResponse = await indexResponsePromise
  expect(indexResponse.status()).toBe(200)
  const initialIndex = (await indexResponse.json()).result as {
    control: { controlDigest: string }; activeGrants: Array<{ grantId: string; grantDigest: string }>;
  }
  const grantA = initialIndex.activeGrants.find(grant => grant.grantId === 'grant_browser_a')!
  expect(grantA).toBeTruthy()
  const fillPause = async (target: import('@playwright/test').Page, paused: boolean) => {
    await target.getByTestId(paused ? 'authority-pause-start' : 'authority-unpause-start').click()
    await target.getByTestId('authority-directive-input').fill('OD-BROWSER-AUTHORITY-PROOF')
    await target.getByTestId('authority-reason-input').fill('Bounded source authority browser proof')
  }
  const submitPause = async (target: import('@playwright/test').Page) => {
    const responsePromise = target.waitForResponse(response => response.request().method() === 'POST'
      && new URL(response.url()).pathname === '/v1/authority/pause')
    await target.getByTestId('authority-pause-confirm').click()
    return responsePromise
  }
  await fillPause(page, true)
  const other = await context.newPage()
  const otherSignals = browserSignals(other)
  try {
    await other.goto(`${service.url}/#/authority`)
    await fillPause(other, true)
    const paused = await submitPause(other)
    expect(paused.status()).toBe(200)
    expect(paused.request().postDataJSON().controlDigest).toBe(initialIndex.control.controlDigest)
    const pausedResult = (await paused.json()).result
    expect(pausedResult.receipt.receiptDigest).toBe(pausedResult.receiptDigest)
    receipts.push(pausedResult.receipt)
    await expect(other.getByTestId('authority-page')).toContainText(pausedResult.receiptId)
    const stale = await submitPause(page)
    expect(stale.status()).toBe(409)
    expect((await stale.json()).error.code).toBe('authority_digest_mismatch')
    await expect(page.getByText('Authority action could not be confirmed', { exact: true })).toBeVisible()
    await expect(page.getByText('No success was confirmed. Refresh authority state before retrying.', { exact: true })).toBeVisible()
    for (const suffix of ['a', 'b'] as const) {
      expect(consume(suffix, 'must not execute')).toMatchObject({ decision: 'refused', reason: 'autonomous_execution_paused',
        receipt: { result: { status: 'not_executed' } } })
      expect(readFileSync(path.join(authorityRoot, `proof-${suffix}.txt`), 'utf8')).toBe('before')
    }
    expectClean(otherSignals)
  } finally { await other.close() }
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await fillPause(page, false)
  const unpaused = await submitPause(page)
  expect(unpaused.status()).toBe(200)
  receipts.push((await unpaused.json()).result.receipt)
  for (const suffix of ['a', 'b'] as const) expect(consume(suffix, 'unpaused').decision).toBe('executed')
  await page.getByTestId('authority-revoke-start-grant_browser_a').click()
  const revokeForm = page.getByTestId('authority-revoke-form-grant_browser_a')
  await revokeForm.getByLabel('Owner directive id').fill('OD-BROWSER-AUTHORITY-PROOF')
  await revokeForm.getByLabel('Revocation reason').fill('Revoke only scoped grant A')
  const revokeResponsePromise = page.waitForResponse(response => response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/v1/authority/grants/grant_browser_a/revoke')
  await page.getByTestId('authority-revoke-confirm-grant_browser_a').click()
  const revoked = await revokeResponsePromise
  expect(revoked.status()).toBe(200)
  expect(revoked.request().postDataJSON().grantDigest).toBe(grantA.grantDigest)
  const revokedResult = (await revoked.json()).result
  expect(revokedResult.revokedGrantDigest).toBe(grantA.grantDigest)
  receipts.push(revokedResult.receipt)
  await expect(page.getByTestId('authority-page')).toContainText(revokedResult.receiptId)
  await expect(page.getByTestId('authority-revoke-start-grant_browser_a')).toBeDisabled()
  await expect(page.getByTestId('authority-revoke-start-grant_browser_b')).toBeEnabled()
  expect(consume('a', 'must not execute')).toMatchObject({ decision: 'refused', reason: 'grant_revoked' })
  expect(consume('b', 'independent').decision).toBe('executed')
  expect(readFileSync(path.join(authorityRoot, 'proof-a.txt'), 'utf8')).toBe('unpaused')
  expect(readFileSync(path.join(authorityRoot, 'proof-b.txt'), 'utf8')).toBe('independent')
  const retainedReceipts = receipts.map(receipt => {
    const file = path.join(receiptDirectory, `${receipt.receiptId}.json`)
    const bytes = readFileSync(file)
    expect(JSON.parse(bytes.toString())).toEqual(receipt)
    return { file, bytes }
  })
  await page.goto('about:blank')
  const oldPid = service.child.pid
  await stopChild(service.child)
  service = await startService(true, 'platform_operator', true)
  expect(service.child.pid).not.toBe(oldPid)
  await page.goto(`${service.url}/#/authority`)
  await expect(page.getByTestId('authority-revoke-start-grant_browser_a')).toBeDisabled()
  await expect(page.getByTestId('authority-revoke-start-grant_browser_b')).toBeEnabled()
  for (const { file, bytes } of retainedReceipts) expect(readFileSync(file)).toEqual(bytes)
  expect(consume('a', 'must not execute after restart')).toMatchObject({ decision: 'refused', reason: 'grant_revoked' })
  expect(consume('b', 'after restart').decision).toBe('executed')
  expect(readFileSync(path.join(authorityRoot, 'proof-a.txt'), 'utf8')).toBe('unpaused')
  expect(readFileSync(path.join(authorityRoot, 'proof-b.txt'), 'utf8')).toBe('after restart')
  expectClean(signals, [{ status: 409, method: 'POST', path: '/v1/authority/pause' }])
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'authority-scoped-consumers-restarted.png'), fullPage: true })
  matrix.surfaces = { ...(matrix.surfaces as Record<string, unknown>), authorityConsumers: {
    environment: 'Linux source AppServer and real AuthorityManager.execute over private fixture repository; OS-owned operator fixture',
    scope: 'authority primitive/API/browser only; deployment, provider and container enforcement remain separate',
    grants: ['grant_browser_a', 'grant_browser_b'], pausedBothRefused: true, staleUIConfirmation: '409, visible refresh guidance',
    unpausedBothExecuted: true, revokedARefused: true, independentBExecuted: true, sameStateNewProcess: true,
    unchangedReceiptBytesAfterRestart: true, receipts,
  } }
})

// Real pre-execution cancellation only: no provider or child process is launched.
test('Operation center cancels an awaiting approval run durably without executing it', async ({ page }) => {
  const sourceSnapshot = () => {
    const files = execFileSync('git', ['ls-files', '-z'], { cwd: studyRoot, encoding: 'utf8', timeout: 5_000 }).split('\0').filter(Boolean)
    return Object.fromEntries(files.map(file => [file, createHash('sha256').update(readFileSync(path.join(studyRoot, file))).digest('hex')]))
  }
  const before = sourceSnapshot()
  const beforeHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: studyRoot, encoding: 'utf8', timeout: 5_000 })
  const signals = browserSignals(page)
  await openApplicationRoute(page, `/app/${STUDY_ID}/runs`)
  await page.getByTestId('runs-action-studystate.sample.record-evidence/v1').click()
  await page.getByLabel('What did you learn?').fill('This prepared action must never execute or change learning state.')
  const preparing = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === `/v1/instances/${STUDY_ID}/execution/prepare`)
  await page.getByTestId('run-prepare').click()
  const preparedResponse = await preparing
  expect(preparedResponse.status()).toBe(200)
  const prepared = (await preparedResponse.json()).result.run as { runId: string; revision: number; runSpecDigest: string }
  await expect(page.getByTestId('run-exact-status')).toHaveText('Awaiting Approval')
  const listing = await page.request.get(`${service.url}/v1/operations`)
  expect(listing.status()).toBe(200)
  const records = (await listing.json()).result.runs as { runId: string }[]
  expect(records.some(record => record.runId === prepared.runId)).toBe(true)
  await page.getByTestId('operation-center-trigger').click()
  const row = page.locator(`[data-testid="operation-row"][data-operation-id="op_${prepared.runId}"]`)
  await expect(row.locator('[data-state="awaiting_approval"]')).toBeVisible()
  const cancelling = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === `/v1/runs/${prepared.runId}/cancel`)
  await row.getByRole('button', { name: 'Cancel', exact: true }).click()
  const cancelledResponse = await cancelling
  expect(cancelledResponse.status()).toBe(200)
  expect(cancelledResponse.request().postDataJSON()).toEqual({ expectedInstanceId: STUDY_ID, expectedRevision: prepared.revision })
  await expect(row).toContainText('Cancelled')
  await expect(row.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0)

  const operationsRoot = path.join(disposableRoot, 'xdg', 'state', 'stateport', 'operations')
  const storedRun = () => (JSON.parse(readFileSync(path.join(operationsRoot, 'portable-runs.json'), 'utf8')).runs as {
    runId: string; status: string; revision: number; runSpecDigest: string; events: { type: string; from: string; to: string }[];
    runBundle: { path: string; contentDigest: string }; process?: unknown; result?: unknown; receiptId?: string; proposal?: unknown;
  }[]).find(record => record.runId === prepared.runId)!
  const cancelled = storedRun()
  expect(cancelled.status).toBe('cancelled')
  expect(cancelled.revision).toBeGreaterThan(prepared.revision)
  expect(cancelled.runSpecDigest).toBe(prepared.runSpecDigest)
  expect(cancelled.events).toContainEqual(expect.objectContaining({ type: 'state_transition', from: 'awaiting_approval', to: 'cancelled' }))
  expect(cancelled.process).toBeFalsy()
  expect(cancelled.result).toBeFalsy()
  expect(cancelled.proposal).toBeFalsy()
  expect(cancelled.receiptId).toBeFalsy() // No application-change receipt is invented for a pre-execution cancellation.
  const bundlePath = path.join(operationsRoot, 'run-bundles', prepared.runId)
  expect(cancelled.runBundle.path).toBe(bundlePath)
  const bundleSnapshot = () => Object.fromEntries(['bundle-manifest.json', 'SHA256SUMS', 'execution/events.jsonl', 'execution/result.json', 'execution/process.json'].map(file => [file, readFileSync(path.join(bundlePath, file), 'utf8')]))
  const bundleBefore = bundleSnapshot()
  expect(JSON.parse(bundleBefore['execution/result.json'])).toEqual({ status: 'cancelled' })
  expect(JSON.parse(bundleBefore['execution/process.json'])).toEqual({})
  const verified = await page.request.get(`${service.url}/v1/runs/${prepared.runId}/bundle`)
  expect(verified.status()).toBe(200)
  expect((await verified.json()).result.verification.verified).toBe(true)
  expect(sourceSnapshot()).toEqual(before)
  expect(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: studyRoot, encoding: 'utf8', timeout: 5_000 })).toBe(beforeHead)
  expect(signals.requests.some(request => /\/runs\/[^/]+\/(execute|apply)$/.test(request.path))).toBe(false)
  expectClean(signals)

  // A direct stale request exercises the real refusal without inventing another UI control.
  const sessionResponse = await page.request.get(`${service.url}/session`)
  expect(sessionResponse.status()).toBe(200)
  const session = await sessionResponse.json() as { result: { csrfToken: string } }
  const stale = await page.request.post(`${service.url}/v1/runs/${prepared.runId}/cancel`, {
    headers: { Origin: service.url, 'X-StatePort-CSRF': session.result.csrfToken }, data: { expectedInstanceId: STUDY_ID, expectedRevision: prepared.revision },
  })
  // Existing handler maps RunStore's ValueError to 400; refusal remains durable.
  expect(stale.status()).toBe(400)
  expect(storedRun()).toEqual(cancelled)
  expect(bundleSnapshot()).toEqual(bundleBefore)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'operation-cancelled-before-execution.png'), fullPage: true })
  await page.goto('about:blank')
  const oldPid = service.child.pid
  await stopChild(service.child)
  service = await startService(true)
  expect(service.child.pid).not.toBe(oldPid)
  expect(storedRun()).toEqual(cancelled)
  expect(bundleSnapshot()).toEqual(bundleBefore)
  expect(sourceSnapshot()).toEqual(before)
  await openApplicationRoute(page, `/app/${STUDY_ID}/runs`)
  const restartedBundle = await page.request.get(`${service.url}/v1/runs/${prepared.runId}/bundle`)
  expect(restartedBundle.status()).toBe(200)
  expect((await restartedBundle.json()).result.verification.verified).toBe(true)
  await page.getByTestId('operation-center-trigger').click()
  await expect(row).toContainText('Cancelled')
  matrix.surfaces = { ...(matrix.surfaces as Record<string, unknown>), operationCancellation: {
    environment: 'Linux source AppServer; pre-execution cancellation only, no active process/provider or installed proof',
    runId: prepared.runId, runSpecDigest: prepared.runSpecDigest, cancelledRevision: cancelled.revision,
    bundleDigest: cancelled.runBundle.contentDigest, staleRevisionStatus: stale.status(),
    sourceBytes: 'unchanged', restart: 'same RunStore and bundle bytes, new service PID',
    closureReceipt: 'not applicable: no application change executed',
  } }
})

test('Provider selection persists OpenCode refusal across an isolated service restart', async ({ page }) => {
  test.setTimeout(120_000)
  const home = path.join(disposableRoot, 'provider-private-home')
  const codexHome = path.join(home, 'codex')
  expect(existsSync(home)).toBe(false)
  await page.goto('about:blank')
  await stopChild(service.child)
  service = await startService(true, 'platform_operator', false, true)
  const firstPid = service.child.pid
  expect(firstPid).toBeTruthy()
  const verifyPrivateEnvironment = () => {
    const environment = readFileSync(`/proc/${service.child.pid}/environ`, 'utf8').split('\0')
    expect(environment).toContain(`HOME=${home}`)
    expect(environment).toContain(`CODEX_HOME=${codexHome}`)
    expect(environment.some(row => /^(OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY|OPENCODE_API_KEY|SSH_AUTH_SOCK|DBUS_SESSION_BUS_ADDRESS)=/.test(row))).toBe(false)
    expect(readdirSync(codexHome)).toEqual([])
  }
  verifyPrivateEnvironment()
  await page.goto(`${service.url}/#/settings/provider`)
  const form = page.getByRole('form', { name: 'Provider configuration' })
  await form.getByLabel('Coding provider', { exact: true }).selectOption('opencode')
  const model = 'openai/gpt-5.4'
  await form.getByLabel('OpenCode model identifier', { exact: true }).fill(model)
  const [savedResponse] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/v1/provider/configure' && response.request().method() === 'POST'),
    form.getByRole('button', { name: 'Save provider selection', exact: true }).click(),
  ])
  expect(savedResponse.status()).toBe(200)
  expect(savedResponse.request().postDataJSON()).toEqual({ model, providerId: 'opencode' })
  const saved = (await savedResponse.json()).result
  expect(saved).toMatchObject({ providerId: 'opencode', configured: true, connected: false, model, executionRefusal: 'sandboxed_validation_not_implemented', authenticationStatus: 'unavailable', requestStatus: 'unverified' })
  const profilePath = path.join(disposableRoot, 'xdg', 'config', 'stateport', 'provider-router.json')
  const disabledPath = path.join(disposableRoot, 'xdg', 'config', 'stateport', 'provider-router.disabled')
  const profileBefore = readFileSync(profilePath, 'utf8')
  const profile = JSON.parse(profileBefore)
  expect(profile.provider.backendId).toBe('opencode')
  expect(profile.model).toEqual({ id: model })
  expect(profile.profileDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  expect(statSync(profilePath).mode & 0o777).toBe(0o600)
  const disabledBefore = readFileSync(disabledPath, 'utf8')
  expect(disabledBefore).toBe('StatePort provider work disabled\n')
  expect(statSync(disabledPath).mode & 0o777).toBe(0o600)
  const observations = page.getByRole('region', { name: 'Provider observations' })
  await expect(observations).toContainText('OpenCode')
  await expect(observations).toContainText('No Codex fallback is enabled.')
  const [checkedResponse] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/v1/provider/verify' && response.request().method() === 'POST'),
    page.getByRole('button', { name: 'Check selected adapter', exact: true }).click(),
  ])
  expect(checkedResponse.status()).toBe(200)
  const checked = (await checkedResponse.json()).result
  expect(checked).toMatchObject({ providerId: 'opencode', connected: false, model, executionRefusal: 'sandboxed_validation_not_implemented', authenticationStatus: 'unavailable', requestStatus: 'failed' })
  expect(readFileSync(profilePath, 'utf8')).toBe(profileBefore)
  expect(readFileSync(disabledPath, 'utf8')).toBe(disabledBefore)
  verifyPrivateEnvironment()
  await page.goto('about:blank')
  await stopChild(service.child)
  service = await startService(true, 'platform_operator', false, true)
  expect(service.child.pid).not.toBe(firstPid)
  verifyPrivateEnvironment()
  // Let the browser establish its fresh service session before observing status.
  const [newSession, reopenedStatus] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/session' && response.request().method() === 'GET' && response.status() === 200),
    page.waitForResponse(response => new URL(response.url()).pathname === '/v1/provider/status' && response.request().method() === 'GET' && response.status() === 200),
    page.goto(`${service.url}/#/settings/provider`),
  ])
  expect(newSession.status()).toBe(200)
  const restored = (await reopenedStatus.json()).result
  expect(restored).toMatchObject({ providerId: 'opencode', configured: true, connected: false, model, executionRefusal: 'sandboxed_validation_not_implemented', authenticationStatus: 'unavailable', executableStatus: 'unverified', requestStatus: 'unverified' })
  await expect(page.getByRole('combobox', { name: 'Coding provider', exact: true })).toHaveValue('opencode')
  await expect(page.getByLabel('OpenCode model identifier', { exact: true })).toHaveValue(model)
  await expect(page.getByRole('region', { name: 'Provider observations' })).toContainText('Not checked in this service session')
  expect(readFileSync(profilePath, 'utf8')).toBe(profileBefore)
  expect(readFileSync(disabledPath, 'utf8')).toBe(disabledBefore)
  writeFileSync(path.join(ARTIFACT_ROOT, 'provider-selection-restart.json'), JSON.stringify({ classification: 'source HTTP/browser; private credential-free home; selection and refusal only', firstPid, restartedPid: service.child.pid, providerId: 'opencode', model, profileDigest: profile.profileDigest, configure: saved, adapterCheck: checked, afterRestart: restored, authenticationAttempted: false, providerExecutionAttempted: false }, null, 2))
})


test('Panel contrast changes real separators and survives saved reload', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/settings/appearance')
  const setting = page.locator('#setting-panel-contrast')
  const topbar = page.getByTestId('topbar')
  const read = () => topbar.evaluate(element => {
    const style = getComputedStyle(element)
    return { color: style.borderBottomColor, width: style.borderBottomWidth, background: style.backgroundColor }
  })
  await expect(setting.getByRole('radio', { name: 'Normal', exact: true })).toHaveAttribute('aria-checked', 'true')
  const before = await read()
  await setting.getByRole('radio', { name: 'Increased', exact: true }).click()
  await expect(page.locator('html')).toHaveAttribute('data-panel-contrast', 'increased')
  const preview = await read()
  expect(preview.color).not.toBe(before.color)
  expect(preview.width).toBe(before.width)
  expect(preview.background).toBe(before.background)
  await page.getByTestId('settings-discard').click()
  await expect(page.locator('html')).toHaveAttribute('data-panel-contrast', 'default')
  expect(await read()).toEqual(before)
  await setting.getByRole('radio', { name: 'Increased', exact: true }).click()
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  await reloadWithReadObservation(page, signals)
  await expect(page.locator('html')).toHaveAttribute('data-panel-contrast', 'increased')
  expect(await read()).toEqual(preview)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'panel-contrast-saved.png') })
  writeFileSync(path.join(ARTIFACT_ROOT, 'panel-contrast.json'), JSON.stringify({ classification: 'source browser saved local preference; actual computed separator colors, installed unrun', before, preview, reload: await read(), discardRestored: true }, null, 2))
  expectClean(signals)
})

test('Saved Workbench tool order changes real tabs and numbered navigation after reload', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/settings/navigation')
  await page.getByRole('button', { name: 'Move Files up', exact: true }).click()
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}').navigation?.workbenchToolOrder)
  expect(saved[0]).toBe('files')
  await page.goto(`${service.url}/#/app/${PROJECT_ID}/workbench/terminal`)
  const first = page.getByTestId('tool-header').getByRole('link').first()
  await expect(first).toHaveText('Files')
  await page.keyboard.press('Control+1')
  await expect(page).toHaveURL(new RegExp(`/app/${PROJECT_ID}/workbench/files$`))
  await expect(page.getByTestId('files-stub')).toBeVisible()
  await expect(page.getByTestId('tree-row-src')).toBeVisible()
  await reloadWithReadObservation(page, signals)
  await expect(first).toHaveText('Files')
  await expect(page.getByTestId('tree-row-src')).toBeVisible()
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'workbench-tool-order.png') })
  writeFileSync(path.join(ARTIFACT_ROOT, 'workbench-tool-order.json'), JSON.stringify({ classification: 'source browser local preference and actual tabs/keyboard navigation/reload; installed unrun', saved, firstTool: await first.textContent(), numberedNavigation: true }, null, 2))
  expectClean(signals)
})

test('Saved startup focus reaches the real Workbench once and respects explicit focus', async ({ page }) => {
  const signals = browserSignals(page)
  await openApplicationRoute(page, '/settings/general')
  const toggle = page.locator('#setting-focus-mode').getByRole('switch')
  await expect(toggle).toHaveAttribute('aria-checked', 'false')
  await toggle.click()
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}').general?.startInFocusMode)).toBe(true)
  await page.goto(`${service.url}/#/applications`)
  await reloadWithReadObservation(page, signals)
  await expect(page.getByTestId('all-applications-section')).toBeVisible()
  // A hash navigation preserves the same document and AppShell session.
  await page.evaluate(route => { window.location.hash = route }, `/app/${PROJECT_ID}/workbench/files?view=wide`)
  await expect(page.getByTestId('workbench-focus')).toBeVisible()
  await expect(page.getByTestId('files-stub')).toBeVisible()
  await expect(page).toHaveURL(/view=wide&focus=1$/)
  await expect(page.getByTestId('topbar')).toHaveCount(0)
  await page.getByRole('button', { name: 'Restore · Esc', exact: true }).click()
  await expect(page.getByTestId('workbench-shell')).toBeVisible()
  await expect(page.getByTestId('tree-row-src')).toBeVisible()
  await page.getByTestId('workbench-shell').getByRole('link', { name: 'Terminal', exact: true }).click()
  await expect(page.getByTestId('workbench-shell')).toBeVisible()
  await expect(page.getByTestId('workbench-focus')).toHaveCount(0)
  await expect(page).not.toHaveURL(/focus=1/)
  await page.goto(`${service.url}/#/app/${PROJECT_ID}/workbench/files?focus=0&view=wide`)
  // Establish the real Files result before the separate reload. Immediate
  // goto+reload raced newly scheduled bootstrap reads after observation began.
  await expect(page.getByTestId('workbench-shell')).toBeVisible()
  await expect(page.getByTestId('tree-row-src')).toBeVisible()
  await reloadWithReadObservation(page, signals)
  await expect(page.getByTestId('workbench-shell')).toBeVisible()
  await expect(page.getByTestId('files-stub')).toBeVisible()
  await expect(page).toHaveURL(/focus=0&view=wide$/)
  await expect(page.getByTestId('tree-row-src')).toBeVisible()
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'startup-focus-explicit-off.png') })
  writeFileSync(path.join(ARTIFACT_ROOT, 'startup-focus.json'), JSON.stringify({ classification: 'source browser actual guarded Workbench and saved local preference; installed unrun', firstEligibleFromApplications: true, realFocusLayout: true, restoreAndLaterToolPreserved: true, explicitOffPreserved: true }, null, 2))
  // Reviewed R24 classification: this test performs 6 deliberate navigations
  // (settings goto, applications goto+reload, same-document hash nav, two tool
  // clicks, explicit-off goto+reload). In-flight read-only fixture bootstrap
  // GETs aborted by those navigations are excused only with a later 2xx for
  // the same path; all other failures stay strict.
  expectClean(signals, [], [], { pathPattern: /^\/v1\/instances(\/live-core-[\w-]+(\/experience)?)?$/ })
})


for (const restoreView of [false, true]) {
  for (const restoreTool of [false, true]) {
    test(`Saved resume preferences restore view=${restoreView} tool=${restoreTool} after document reload`, async ({ page }) => {
      const signals = browserSignals(page)
      const saveToggle = async (route: string, anchor: string, value: boolean) => {
        await openApplicationRoute(page, route)
        const toggle = page.locator(`#setting-${anchor}`).getByRole('switch')
        await expect(toggle).toHaveAttribute('aria-checked', /^(true|false)$/)
        // Exercise an actual save even when this case requests the default.
        if ((await toggle.getAttribute('aria-checked')) === String(value)) {
          await toggle.click()
          await page.getByTestId('settings-save').click()
          await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
        }
        await toggle.click()
        await page.getByTestId('settings-save').click()
        await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
        await expect(toggle).toHaveAttribute('aria-checked', String(value))
      }
      await saveToggle('/settings/general', 'reopen-app', true)
      await saveToggle('/settings/general', 'reopen-view', restoreView)
      await saveToggle('/settings/navigation', 'restore-tool', restoreTool)
      const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}'))
      expect(saved.general.reopenLastApplication).toBe(true)
      expect(saved.general.reopenLastApplicationView).toBe(restoreView)
      expect(saved.navigation.restoreLastTool).toBe(restoreTool)

      // Populate continuity by using the real Files view, never by seeding storage.
      await openApplicationRoute(page, `/app/${PROJECT_ID}/workbench/files`)
      await expect(page.getByTestId('tree-row-src')).toBeVisible()
      await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem('stateport.workspace.v1') ?? '{}').state)).toMatchObject({
        lastInstanceId: PROJECT_ID,
        lastView: 'workbench',
        lastWorkbenchTool: 'files',
      })
      const expectedRoute = `/app/${PROJECT_ID}${restoreView ? `/workbench${restoreTool ? '/files' : ''}` : ''}`
      await page.goto(`${service.url}/`, { waitUntil: 'domcontentloaded' })
      await expect(page).toHaveURL(`${service.url}/#${expectedRoute}`)
      await expect(page.getByTestId(restoreView ? 'workbench-shell' : 'app-overview-page')).toBeVisible()
      if (restoreView && restoreTool) await expect(page.getByTestId('tree-row-src')).toBeVisible()
      expect(await page.evaluate(() => JSON.parse(localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}'))).toEqual(saved)
      const startupUrl = page.url()
      // Continue is an explicit action: it restores the saved view even when
      // automatic view reopening is off, but still obeys Restore last tool.
      await openApplicationRoute(page, `/app/${PROJECT_ID}/workbench/files`)
      await expect(page.getByTestId('tree-row-src')).toBeVisible()
      await openApplicationRoute(page, '/applications')
      const hero = page.getByTestId('continue-hero')
      await expect(hero).toContainText(restoreTool ? 'Files' : 'Workbench')
      await hero.getByRole('button', { name: /^Continue in / }).click()
      const continueRoute = `/app/${PROJECT_ID}/workbench${restoreTool ? '/files' : ''}`
      await expect(page).toHaveURL(`${service.url}/#${continueRoute}`)
      await expect(page.getByTestId('workbench-shell')).toBeVisible()
      if (restoreTool) await expect(page.getByTestId('tree-row-src')).toBeVisible()
      writeFileSync(path.join(ARTIFACT_ROOT, `resume-view-${restoreView}-tool-${restoreTool}.json`), JSON.stringify({
        classification: 'source browser, real AppServer application lookup and Files listing; saved local UI preference and natural continuity; installed unrun',
        restoreView, restoreTool, expectedRoute, startupUrl, continueRoute, continueUrl: page.url(), saved,
      }, null, 2))
      expectClean(signals, [], [], { pathPattern: /^\/v1\/instances(\/live-core-[\w-]+(\/experience)?)?$/ })
    })
  }
}

test('Saved message delivery details expose real inbound acceptance after reload', async ({ page }) => {
  const signals = browserSignals(page)
  const save = async (enabled: boolean) => {
    await openApplicationRoute(page, '/settings/conversation')
    const toggle = page.locator('#setting-delivery-details').getByRole('switch')
    await expect(toggle).toHaveAttribute('aria-checked', /^(true|false)$/)
    if ((await toggle.getAttribute('aria-checked')) !== String(enabled)) {
      await toggle.click()
      await page.getByTestId('settings-save').click()
      await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
    }
  }
  await save(true)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/conversation`)
  const messageText = 'Public-safe delivery preference acceptance proof.'
  const acceptedResponse = page.waitForResponse(response =>
    response.request().method() === 'POST' && new URL(response.url()).pathname === `/v1/instances/${PROJECT_ID}/conversation/messages`)
  await page.getByTestId('composer-input').fill(messageText)
  await page.getByTestId('composer-send').click()
  const accepted = await (await acceptedResponse).json()
  const wire = accepted.result.presentation.messages.find((message: { body?: string }) => message.body === messageText)
  expect(wire).toBeDefined()
  expect(wire.display).toMatchObject({ inboundAccepted: true, deliveryState: [] })
  const row = page.getByTestId('message-user').filter({ hasText: messageText })
  await expect(row).toBeVisible()
  await reloadWithReadObservation(page, signals)
  await expect(row.getByTestId('message-delivery-details')).toContainText('Recorded inbound acceptance')
  await expect(row.getByTestId('message-delivery-details')).toContainText('No delivery receipt recorded')
  await expect(row.getByTestId('message-delivery-details')).not.toContainText('Delivered')

  // Observe the independently persisted message, not just a successful POST.
  const stored = JSON.parse(execFileSync(PYTHON, ['-c',
    'import json,sqlite3,sys; c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); r=c.execute("SELECT payload FROM messages WHERE message_id=?",(sys.argv[2],)).fetchone(); print(r[0] if r else "null")',
    path.join(disposableRoot, 'xdg', 'state', 'stateport', 'conversation.sqlite3'), wire.messageId,
  ], { encoding: 'utf8', timeout: 5_000 }))
  expect(stored.messageId).toBe(wire.messageId)
  expect(stored.externalIdentity.direction).toBe('inbound')

  await save(false)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/conversation`)
  await reloadWithReadObservation(page, signals)
  await expect(row).toBeVisible()
  await expect(row.getByTestId('message-delivery-details')).toHaveCount(0)
  await expect(page.getByTestId('thread-header')).toBeVisible()
  await expect(page.getByTestId('composer-input')).toBeVisible()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem('stateport.http.global-ui-settings.v1') ?? '{}').conversation?.showDeliveryDetails)).toBe(false)

  await save(true)
  await openApplicationRoute(page, `/app/${PROJECT_ID}/conversation`)
  await reloadWithReadObservation(page, signals)
  await expect(row.getByTestId('message-delivery-details')).toContainText('Recorded inbound acceptance')
  await expect(page.getByTestId('composer-input')).toBeVisible()
  expect(readFileSync(path.join(projectRoot, 'state', 'PROJECT.yaml'), 'utf8')).toBe(projectCanonicalBefore)
  writeFileSync(path.join(ARTIFACT_ROOT, 'message-delivery-preference.json'), JSON.stringify({
    classification: 'source browser with real Web ingest, persisted SQLite message and presentation; local saved preference; no external outbound delivery or human-read acknowledgement claim; installed unrun',
    messageId: wire.messageId, recordedDisplay: wire.display, persistedExternalIdentity: stored.externalIdentity,
    savedOffHidesDetails: true, savedOnRestoresAfterReload: true, composerRetained: true,
  }, null, 2))
  expectClean(signals, [], [], { pathPattern: /^\/v1\/instances(\/live-core-[\w-]+(\/experience)?)?$/ })
})

test('Saved search history records, reuses, disables and clears real palette searches', async ({ page }) => {
  const signals = browserSignals(page)
  const storedHistory = () => page.evaluate(() => JSON.parse(localStorage.getItem('stateport.workspace.v1') ?? '{}').state?.searchHistory ?? [])
  const openPalette = async () => {
    const settingsRead = page.waitForResponse(response => response.request().method() === 'GET' && new URL(response.url()).pathname === '/v1/settings')
    await page.keyboard.press('Control+k')
    await (await settingsRead).finished()
    await expect(page.getByRole('combobox', { name: 'Search commands' })).toBeVisible()
  }
  await openApplicationRoute(page, '/settings/general')
  const toggle = page.locator('#setting-search-history').getByRole('switch')
  // Save a real true value even when this is the fresh default.
  await expect(toggle).toHaveAttribute('aria-checked', 'true')
  for (const enabled of [false, true]) {
    await toggle.click()
    await page.getByTestId('settings-save').click()
    await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
    await expect(toggle).toHaveAttribute('aria-checked', String(enabled))
  }
  await openPalette()
  const search = page.getByRole('combobox', { name: 'Search commands' })
  await search.fill('Applications')
  await page.getByRole('option', { name: 'Go to Applications', exact: true }).click()
  await expect(page).toHaveURL(`${service.url}/#/applications`)
  await expect(page.getByTestId('all-applications-section')).toBeVisible()
  await expect.poll(storedHistory).toEqual(['Applications'])
  await reloadWithReadObservation(page, signals)
  await openPalette()
  await page.getByTestId('command-palette-search-history-item').filter({ hasText: /^Applications$/ }).click()
  await expect(search).toHaveValue('Applications')
  for (let index = 0; index < 20; index += 1) {
    await search.fill(`unmatched-public-search-${index}`)
    await expect(page.getByText('No matching commands.', { exact: true })).toBeVisible()
    await search.press('Enter')
  }
  await expect.poll(storedHistory).toHaveLength(20)
  const retained = await storedHistory()
  await search.fill('')
  await page.setViewportSize({ width: 390, height: 600 })
  const history = page.getByTestId('command-palette-search-history')
  await expect(page.getByTestId('command-palette-search-history-item')).toHaveCount(20)
  expect(await history.evaluate(element => element.scrollHeight > element.clientHeight)).toBe(true)
  const bounds = await page.getByTestId('command-palette').boundingBox()
  expect(bounds).not.toBeNull()
  expect(bounds!.y).toBeGreaterThanOrEqual(0)
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(600)
  await page.getByTestId('command-palette-search-history-item').last().click()
  await expect(search).toHaveValue(retained[retained.length - 1])
  await search.press('Escape')
  await page.setViewportSize({ width: 1440, height: 900 })

  await openApplicationRoute(page, '/settings/general')
  await toggle.click()
  await page.getByTestId('settings-save').click()
  await expect(page.getByTestId('settings-save-bar')).toHaveCount(0)
  await openPalette()
  await expect(history).toHaveCount(0)
  await search.fill('off-search-must-not-persist')
  await search.press('Enter')
  expect(await storedHistory()).toEqual(retained)
  await search.press('Escape')
  await openApplicationRoute(page, '/settings/privacy')
  await page.locator('#setting-clear-search').getByRole('button', { name: 'Clear search history', exact: true }).click()
  await expect.poll(storedHistory).toEqual([])
  await reloadWithReadObservation(page, signals)
  expect(await storedHistory()).toEqual([])
  await expect(page.locator('#setting-clear-search').getByRole('button', { name: 'Clear search history', exact: true })).toBeDisabled()
  writeFileSync(path.join(ARTIFACT_ROOT, 'search-history-preference.json'), JSON.stringify({
    classification: 'source browser real palette navigation/search, local persistent history and saved preference; installed unrun',
    selectedCommandReachedApplications: true, restoredSearch: 'Applications', retainedCount: retained.length,
    allEntriesAccessibleAt390x600: true, paletteBounds: bounds, offDidNotRecord: true, clearedAfterReload: true,
  }, null, 2))
  expectClean(signals, [], [], { pathPattern: /^\/v1\/instances(\/live-core-[\w-]+(\/experience)?)?$/ })
})

test('Reviewed source authority prepares and downloads exact committed facts without issuing a grant', async ({ page }) => {
  test.skip(process.env.STATEPORT_UI_SOURCE_AUTHORITY !== '1', 'Requires explicit source-authority publication fixture')
  const signals = browserSignals(page)
  const authorityRoot = path.join(disposableRoot, 'xdg', 'config', 'stateport', 'workspace-authority-fixture')
  const authorityFiles: string[] = []
  const authorityDirectories = [authorityRoot]
  if (process.env.STATEPORT_UI_REVIEWED_ISSUANCE === '1') {
    const fixture = JSON.parse(readFileSync(path.join(disposableRoot, 'xdg', 'data', 'stateport', 'ui-workspace-fixture.json'), 'utf8')) as { manifest: string; reviewedIssuance: { grantsDir: string } }
    authorityFiles.push(fixture.manifest)
    authorityDirectories.push(fixture.reviewedIssuance.grantsDir)
  }
  const authorityState = () => Object.fromEntries([...authorityFiles, ...authorityDirectories.flatMap(directory => readdirSync(directory).map(name => path.join(directory, name)))].filter(file => statSync(file).isFile()).map(file => [file, readFileSync(file, 'utf8')]))
  const before = authorityState()
  await openApplicationRoute(page, '/execution-host')
  const panel = page.getByRole('region', { name: `Workspace authority ${PROJECT_ID}`, exact: true })
  await panel.getByRole('button', { name: 'Review workspace authority', exact: true }).click()
  await expect(panel).toContainText('stateport.reviewed-source-workspace-terminal/v1')
  const endpoint = `/v1/execution-host/workspaces/${PROJECT_ID}/authority/prepare`
  const selectedExpiry = new Date(Date.now() + 30 * 60 * 1000).toISOString().slice(0, 19)
  await panel.getByLabel('Authority expires at (UTC)').fill(selectedExpiry)
  await expect(panel.getByRole('button', { name: 'Prepare authority request', exact: true })).toBeEnabled()
  const [response] = await Promise.all([
    page.waitForResponse(row => new URL(row.url()).pathname === endpoint && row.request().method() === 'POST'),
    panel.getByRole('button', { name: 'Prepare authority request', exact: true }).click(),
  ])
  expect(response.status()).toBe(200)
  expect(Object.keys(response.request().postDataJSON()).sort()).toEqual(['grantExpiresAt', 'profileDigest', 'sourceMode'])
  const result = (await response.json()).result as import('../src/client/client').WorkspaceAuthorityPreparation
  if (result.request.formatVersion !== 'stateport.workspace-authority-request/v2') throw new Error('source request format differs')
  const request = result.request
  expect(request.sourceMode).toBe('reviewed-commit')
  expect(request.instanceId).toBe(PROJECT_ID)
  expect(request.source.baseRevision).toBe(projectHeadBefore)
  expect(request.source.sourceInventory.some(row => row.path === 'application.yaml')).toBe(true)
  expect(request.source.sourceArchive.fileCount).toBe(request.source.sourceInventory.length)
  await expect(panel.getByRole('region', { name: 'Prepared workspace authority request', exact: true })).toContainText('Pending operator approval')
  await expect(panel).toContainText(request.source.baseRevision)
  await expect(panel).toContainText(request.sourceDigest)
  await panel.locator('summary').filter({ hasText: 'Reviewed source inventory (' }).click()
  const preparedSource = panel.getByRole('region', { name: 'Prepared reviewed source', exact: true })
  const firstSourceFile = request.source.sourceInventory[0]!
  await expect(preparedSource.locator('pre')).toBeVisible()
  await expect(preparedSource.locator('pre')).toContainText(`${firstSourceFile.path} · mode ${firstSourceFile.mode} · ${firstSourceFile.contentDigest}`)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'source-authority-prepared-inventory.png'), fullPage: true })
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    panel.getByRole('link', { name: 'Download authority request', exact: true }).click(),
  ])
  const downloaded = path.join(ARTIFACT_ROOT, 'reviewed-source-request.json')
  await download.saveAs(downloaded)
  expect(JSON.parse(readFileSync(downloaded, 'utf8'))).toEqual(request)
  // Exercise the production pure verifier against actual source bytes. The
  // current UID is a source-fixture owner, never installed root authentication.
  const verified = execFileSync(PYTHON, ['-c', [
    'import json,os,sys',
    'from execution_host.application_workspaces import validate_workspace_authority_request',
    'from execution_host.workspace_source import verify_source_commit',
    'request=validate_workspace_authority_request(json.load(open(sys.argv[1])))',
    'fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)',
    'try: verify_source_commit(fd,request["source"],owner_uid=os.geteuid())',
    'finally: os.close(fd)',
    'print("verified")',
  ].join('\n'), downloaded, projectRoot], { env: { ...process.env, PYTHONPATH }, encoding: 'utf8', timeout: 30_000 })
  expect(verified.trim()).toBe('verified')
  await panel.getByRole('button', { name: 'Check operator approval', exact: true }).click()
  await expect(panel).toContainText('Pending operator approval')
  expect(authorityState()).toEqual(before)
  const sourcePath = path.join(projectRoot, 'application.yaml')
  const sourceBefore = readFileSync(sourcePath)
  try {
    writeFileSync(sourcePath, Buffer.concat([sourceBefore, Buffer.from('\n# unreviewed fixture change\n')]))
    await panel.getByRole('button', { name: 'Review workspace authority', exact: true }).click()
    await panel.getByLabel('Authority expires at (UTC)').fill(selectedExpiry)
    await expect(panel.getByRole('button', { name: 'Prepare authority request', exact: true })).toBeEnabled()
    const [refused] = await Promise.all([
      page.waitForResponse(row => new URL(row.url()).pathname === endpoint && row.request().method() === 'POST'),
      panel.getByRole('button', { name: 'Prepare authority request', exact: true }).click(),
    ])
    expect(refused.status()).toBe(409)
    expect(JSON.stringify(await refused.json())).toContain('workspace_source_review_failed')
    await expect(panel.getByRole('alert')).toBeVisible()
    await expect(panel.getByRole('link', { name: 'Download authority request', exact: true })).toHaveCount(0)
    expect(authorityState()).toEqual(before)
  } finally {
    writeFileSync(sourcePath, sourceBefore)
  }
  expectClean(signals, [{ status: 409, method: 'POST', path: endpoint }])
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'source-authority-dirty-refusal.png'), fullPage: true })
  writeFileSync(path.join(ARTIFACT_ROOT, 'source-authority-browser.json'), JSON.stringify({
    instanceId: PROJECT_ID, requestDigest: request.requestDigest, sourceDigest: request.sourceDigest,
    baseRevision: request.source.baseRevision, fileCount: request.source.sourceInventory.length,
    archiveBytes: request.source.sourceArchive.archiveBytes, downloadedExactRequest: true,
    actualSourceVerifierPassed: true, dirtySourceRefused: true, authorityUnchanged: true,
    environment: process.env.STATEPORT_UI_REVIEWED_ISSUANCE === '1'
      ? 'real source AppServer/browser/rootless daemon; explicit publication/default-grant fixture; preparation leaves grant store unchanged; no installed root authentication'
      : 'real source AppServer/browser; explicit publication fixture; no root authentication or daemon grant issuance',
  }, null, 2))
})


test('Reviewed source authority download reaches a real capsule after explicit fixture operator issuance', async ({ page }) => {
  test.skip(process.env.STATEPORT_UI_REVIEWED_ISSUANCE !== '1', 'Requires booked real daemon and explicit test-UID operator transaction')
  test.setTimeout(180_000)
  const signals = browserSignals(page)
  const sockets = terminalSocketSignals(page)
  const sourceBefore = readFileSync(path.join(projectRoot, 'application.yaml'))
  await openApplicationRoute(page, '/execution-host')
  const panel = page.getByRole('region', { name: `Workspace authority ${PROJECT_ID}`, exact: true })
  await panel.getByRole('button', { name: 'Review workspace authority', exact: true }).click()
  await panel.getByLabel('Authority expires at (UTC)').fill(new Date(Date.now() + 30 * 60 * 1000).toISOString().slice(0, 19))
  const [preparation] = await Promise.all([
    page.waitForResponse(row => new URL(row.url()).pathname === `/v1/execution-host/workspaces/${PROJECT_ID}/authority/prepare` && row.request().method() === 'POST'),
    panel.getByRole('button', { name: 'Prepare authority request', exact: true }).click(),
  ])
  expect(preparation.status()).toBe(200)
  const result = (await preparation.json()).result as import('../src/client/client').WorkspaceAuthorityPreparation
  if (result.request.formatVersion !== 'stateport.workspace-authority-request/v2') throw new Error('source request format differs')
  const request = result.request
  expect(request.source.baseRevision).toBe(projectHeadBefore)
  const hostSourceSnapshot = () => request.source.sourceInventory.map(row => ({
    path: row.path, mode: statSync(path.join(projectRoot, row.path)).mode & 0o777,
    contentDigest: 'sha256:' + createHash('sha256').update(readFileSync(path.join(projectRoot, row.path))).digest('hex'),
  }))
  const hostSourceBefore = hostSourceSnapshot()
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    panel.getByRole('link', { name: 'Download authority request', exact: true }).click(),
  ])
  const downloaded = path.join(ARTIFACT_ROOT, 'issued-source-request.json')
  await download.saveAs(downloaded)
  expect(JSON.parse(readFileSync(downloaded, 'utf8'))).toEqual(request)
  // Explicit source-fixture OS transaction: production issuance and FD source
  // verification run with test UID substitutions, never installed sudo auth.
  const issued = JSON.parse(execFileSync(PYTHON, [
    path.join(HERE, 'live-core-fixture.py'), '--port', '0', '--repo-root', ROOT,
    '--issue-source-request', downloaded, '--reviewed-request-digest', request.requestDigest,
  ], {
    cwd: ROOT,
    env: { ...process.env, PYTHONPATH,
      XDG_CONFIG_HOME: path.join(disposableRoot, 'xdg', 'config'),
      XDG_DATA_HOME: path.join(disposableRoot, 'xdg', 'data'),
      XDG_STATE_HOME: path.join(disposableRoot, 'xdg', 'state') },
    encoding: 'utf8', timeout: 30_000,
  })) as { workloadId: string; receiptDigest: string; status: string }
  expect(issued.status).toBe('issued')
  expect(issued.receiptDigest).toMatch(/^sha256:[a-f0-9]{64}$/)
  const fixture = JSON.parse(readFileSync(path.join(disposableRoot, 'xdg', 'data', 'stateport', 'ui-workspace-fixture.json'), 'utf8')) as { daemonRoot: string; governedScope: string }
  const ledger = () => JSON.parse(readFileSync(path.join(fixture.daemonRoot, 'state', 'workloads', `${issued.workloadId}.json`), 'utf8')) as { state: string; containerId: string }
  await panel.getByRole('button', { name: 'Check operator approval', exact: true }).click()
  await expect(panel.locator('summary').filter({ hasText: 'Daemon-verified workspace binding' })).toBeVisible()
  await expect(panel.getByRole('region', { name: 'Prepared workspace authority request', exact: true })).toHaveCount(0)
  const profile = page.getByRole('region', { name: 'Application workspaces' }).locator('div').filter({ has: page.getByText('Live Core Project', { exact: true }) }).first()
  await profile.getByRole('button', { name: 'Create application workspace', exact: true }).click()
  const review = page.getByRole('alertdialog')
  await expect(review).toContainText(request.source.baseRevision)
  await review.getByRole('button', { name: 'Confirm approved source', exact: true }).click()
  const workload = page.getByRole('article', { name: `Workload ${issued.workloadId}`, exact: true })
  await workload.getByRole('button', { name: 'Start', exact: true }).click()
  await expect.poll(() => ledger().state).toBe('running')
  const containment = execFileSync(PYTHON, ['-c', 'import json,sys;sys.path.insert(0,sys.argv[1]);from test_execution_host_daemon import _governed_container_membership;print(json.dumps(_governed_container_membership(sys.argv[2],sys.argv[3])))', path.join(ROOT, 'scripts'), ledger().containerId, fixture.governedScope], { env: { ...process.env, PYTHONPATH }, encoding: 'utf8', timeout: 20_000 })
  writeFileSync(path.join(ARTIFACT_ROOT, 'issued-source-cgroups.json'), containment)
  const [target] = await Promise.all([
    page.waitForResponse(row => new URL(row.url()).pathname === `/v1/execution-host/workspaces/${PROJECT_ID}/terminal/target` && row.request().method() === 'GET'),
    profile.getByRole('link', { name: 'Open workspace terminal', exact: true }).click(),
  ])
  expect(target.status()).toBe(200)
  expect((await target.json()).result.target.targetClass).toBe('capsule')
  await page.getByTestId('terminal-start').getByTestId('terminal-connect').click()
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Connected')
  const expected = createHash('sha256').update(JSON.stringify(request.source.sourceInventory.map(row => [row.path, row.mode, row.contentDigest]))).digest('hex')
  const script = "import hashlib,pathlib,json; r=pathlib.Path('/workspace'); rows=[[str(p.relative_to(r)),('100755' if p.stat().st_mode & 511 == 493 else '100644' if p.stat().st_mode & 511 == 420 else 'invalid'),'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()] for p in sorted(r.rglob('*'),key=lambda p:str(p.relative_to(r))) if p.is_file()]; print('ISSUED_'+'SOURCE_'+hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest())"
  await page.getByTestId('terminal-canvas').locator('.xterm-helper-textarea').focus()
  await page.keyboard.type("python3 -c '" + script.replaceAll("'", "'\\''") + "'")
  await page.keyboard.press('Enter')
  await expect.poll(() => sockets.frames.filter(row => row.direction === 'received' && row.binary).map(row => row.text).join('')).toContain(`ISSUED_SOURCE_${expected}`)
  await page.screenshot({ path: path.join(ARTIFACT_ROOT, 'issued-source-capsule.png'), fullPage: true })
  await page.getByTestId('terminal-end').click()
  await expect(page.getByTestId('terminal-state-label')).toHaveText('Session ended')
  await openApplicationRoute(page, '/execution-host')
  await workload.getByRole('button', { name: 'Stop', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger().state).toBe('stopped')
  await workload.getByRole('button', { name: 'Remove container', exact: true }).click()
  await page.getByRole('button', { name: 'Confirm operation', exact: true }).click()
  await expect.poll(() => ledger().state).toBe('removed')
  expect(readFileSync(path.join(projectRoot, 'application.yaml'))).toEqual(sourceBefore)
  expect(hostSourceSnapshot()).toEqual(hostSourceBefore)
  expect(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: projectRoot, encoding: 'utf8' }).trim()).toBe(projectHeadBefore)
  expect(sockets.errors).toEqual([])
  expectClean(signals)
  writeFileSync(path.join(ARTIFACT_ROOT, 'issued-source-browser.json'), JSON.stringify({
    requestDigest: request.requestDigest, sourceDigest: request.sourceDigest,
    baseRevision: request.source.baseRevision, workloadId: issued.workloadId,
    receiptDigest: issued.receiptDigest, downloadedExactRequest: true,
    daemonVerifiedGrant: true, capsuleInventoryAndModesVerified: true, sourceUnchanged: true,
    environment: 'production browser/AppServer/rootless daemon; production transaction primitive with explicit test UID substitutions; installed root-helper identity/context/authentication checks unrun',
  }, null, 2))
})
