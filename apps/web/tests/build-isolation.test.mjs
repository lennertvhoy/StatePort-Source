import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const VITE = path.join(WEB_ROOT, 'node_modules', 'vite', 'bin', 'vite.js')
const PRODUCTION_ROOT = path.join(WEB_ROOT, 'dist')
const DEMO_ROOT = path.join(WEB_ROOT, 'dist-demo')
const MARKER = 'stateport-build.json'
const TEST_TEMP_ROOT = path.join(WEB_ROOT, 'node_modules', '.tmp')
mkdirSync(TEST_TEMP_ROOT, { recursive: true })

function temporaryBuildRoot(prefix) {
  return mkdtempSync(path.join(TEST_TEMP_ROOT, prefix))
}

function identity(root) {
  return JSON.parse(readFileSync(path.join(root, MARKER), 'utf8'))
}

function assertBuildIdentity(root, adapter, mode) {
  const value = identity(root)
  assert.deepEqual(Object.keys(value).sort(), [
    'adapter',
    'builtAt',
    'formatVersion',
    'mode',
    'sourceCommit',
    'sourceDirty',
    'sourceRef',
    'sourceTree',
  ])
  assert.equal(value.formatVersion, 'stateport.web-build/v3')
  assert.equal(value.adapter, adapter)
  assert.equal(value.mode, mode)
  assert.match(value.sourceCommit, /^(unknown|[0-9a-f]{40})$/)
  assert.match(value.sourceTree, /^(unknown|[0-9a-f]{40})$/)
  assert.equal(value.sourceCommit === 'unknown', value.sourceTree === 'unknown')
  assert.equal(typeof value.sourceDirty, 'boolean')
  if (value.sourceCommit === 'unknown') {
    assert.equal(
      value.sourceDirty,
      true,
      'an unavailable source commit must never be labeled clean',
    )
  }
  assert.match(value.sourceRef, /^(unknown|[A-Za-z0-9._/@:+-]{1,200})$/)
  assert.match(
    value.builtAt,
    /^(unknown|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z)$/,
  )
  return value
}

function manifest(root) {
  return JSON.parse(
    readFileSync(path.join(root, '.vite', 'manifest.json'), 'utf8'),
  )
}

function treeDigest(root) {
  const digest = createHash('sha256')
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
      (left, right) => left.name.localeCompare(right.name),
    )) {
      const absolute = path.join(directory, entry.name)
      const relative = path.relative(root, absolute)
      if (entry.isDirectory()) {
        visit(absolute)
      } else {
        assert.equal(entry.isFile(), true, `unexpected build entry: ${relative}`)
        digest.update(relative)
        digest.update('\0')
        digest.update(readFileSync(absolute))
      }
    }
  }
  visit(root)
  return digest.digest('hex')
}

function javascript(root) {
  return readdirSync(path.join(root, 'assets'))
    .filter((name) => name.endsWith('.js'))
    .map((name) => readFileSync(path.join(root, 'assets', name), 'utf8'))
    .join('\n')
}

function viteBuild(environment, ...arguments_) {
  const mergedEnvironment = { ...process.env, ...environment }
  for (const [name, value] of Object.entries(mergedEnvironment)) {
    if (value === undefined) delete mergedEnvironment[name]
  }
  return spawnSync(process.execPath, [VITE, 'build', ...arguments_], {
    cwd: WEB_ROOT,
    env: mergedEnvironment,
    encoding: 'utf8',
    maxBuffer: 5 * 1024 * 1024,
    timeout: 180_000,
  })
}

test('demo and production artifacts stay isolated and production refuses mock', () => {
  assert.equal(statSync(path.join(PRODUCTION_ROOT, 'index.html')).isFile(), true)
  const productionIdentity = assertBuildIdentity(
    PRODUCTION_ROOT,
    'http',
    'production',
  )
  assert.match(productionIdentity.sourceCommit, /^[0-9a-f]{40}$/)
  const exactTree = spawnSync(
    'git',
    ['rev-parse', '--verify', `${productionIdentity.sourceCommit}^{tree}`],
    { cwd: WEB_ROOT, encoding: 'utf8', timeout: 5_000 },
  )
  assert.equal(exactTree.status, 0, exactTree.stderr)
  assert.equal(productionIdentity.sourceTree, exactTree.stdout.trim())
  assert.doesNotMatch(
    javascript(PRODUCTION_ROOT),
    /["']code-path["']/,
    'production JavaScript must not disclose source file locations',
  )
  assert.doesNotMatch(
    javascript(PRODUCTION_ROOT),
    /stateport\.mock\/v1|ins_cto_pilot|photography-portfolio/,
    'production JavaScript must not contain the mock database or seeded identities',
  )
  assert.ok(
    manifest(PRODUCTION_ROOT)['index.html']?.dynamicImports?.includes(
      'src/features/workbench/WorkbenchIntegrations.tsx',
    ),
    'the optional Workbench integrations must stay outside the initial application chunk',
  )
  const productionBeforeDemo = treeDigest(PRODUCTION_ROOT)

  const demo = viteBuild({ VITE_STATEPORT_ADAPTER: 'mock' }, '--mode', 'demo')
  assert.equal(
    demo.status,
    0,
    `demo build failed:\n${demo.stdout}\n${demo.stderr}`,
  )
  assert.equal(treeDigest(PRODUCTION_ROOT), productionBeforeDemo)
  assert.equal(statSync(path.join(DEMO_ROOT, 'index.html')).isFile(), true)
  assertBuildIdentity(DEMO_ROOT, 'mock', 'demo')
  assert.match(
    javascript(DEMO_ROOT),
    /["']code-path["']/,
    'the isolated review artifact should retain inspectable source locations',
  )
  assert.match(
    javascript(DEMO_ROOT),
    /ins_cto_pilot/,
    'the isolated demo artifact should carry its deterministic seeded identities',
  )

  const exactIdentityRoot = temporaryBuildRoot(
    'stateport-exact-build-identity-',
  )
  try {
    const exact = viteBuild(
      {
        VITE_STATEPORT_ADAPTER: 'http',
        STATEPORT_BUILD_SOURCE_COMMIT: 'a'.repeat(40),
        STATEPORT_BUILD_SOURCE_TREE: 'b'.repeat(40),
        STATEPORT_BUILD_SOURCE_REF: 'refs/heads/release/v1',
        STATEPORT_BUILD_SOURCE_DIRTY: 'false',
        SOURCE_DATE_EPOCH: '0',
      },
      '--mode',
      'production',
      '--outDir',
      exactIdentityRoot,
    )
    assert.equal(
      exact.status,
      0,
      `exact-identity build failed:\n${exact.stdout}\n${exact.stderr}`,
    )
    assert.deepEqual(identity(exactIdentityRoot), {
      formatVersion: 'stateport.web-build/v3',
      adapter: 'http',
      mode: 'production',
      sourceCommit: 'a'.repeat(40),
      sourceTree: 'b'.repeat(40),
      sourceRef: 'refs/heads/release/v1',
      sourceDirty: false,
      builtAt: '1970-01-01T00:00:00.000Z',
    })
  } finally {
    rmSync(exactIdentityRoot, { recursive: true, force: true })
  }

  const injectedWithoutDirtyRoot = temporaryBuildRoot(
    'stateport-injected-without-dirty-',
  )
  try {
    const injectedWithoutDirty = viteBuild(
      {
        VITE_STATEPORT_ADAPTER: 'http',
        STATEPORT_BUILD_SOURCE_COMMIT: 'a'.repeat(40),
        STATEPORT_BUILD_SOURCE_TREE: 'b'.repeat(40),
        STATEPORT_BUILD_SOURCE_DIRTY: undefined,
        SOURCE_DATE_EPOCH: '0',
      },
      '--mode',
      'production',
      '--outDir',
      injectedWithoutDirtyRoot,
    )
    assert.equal(
      injectedWithoutDirty.status,
      0,
      `injected identity build failed:\n${injectedWithoutDirty.stdout}\n${injectedWithoutDirty.stderr}`,
    )
    assert.equal(identity(injectedWithoutDirtyRoot).sourceDirty, true)
  } finally {
    rmSync(injectedWithoutDirtyRoot, { recursive: true, force: true })
  }

  const dirtyProbeRoot = temporaryBuildRoot(
    'stateport-dirty-build-identity-',
  )
  const dirtyProbe = path.join(
    WEB_ROOT,
    `source-dirty-probe-${process.pid}.tmp`,
  )
  try {
    writeFileSync(dirtyProbe, 'untracked frontend input\n')
    const dirty = viteBuild(
      { VITE_STATEPORT_ADAPTER: 'http' },
      '--mode',
      'production',
      '--outDir',
      dirtyProbeRoot,
    )
    assert.equal(
      dirty.status,
      0,
      `dirty-identity build failed:\n${dirty.stdout}\n${dirty.stderr}`,
    )
    assert.equal(identity(dirtyProbeRoot).sourceDirty, true)
  } finally {
    rmSync(dirtyProbe, { force: true })
    rmSync(dirtyProbeRoot, { recursive: true, force: true })
  }

  for (const [label, partialIdentity] of [
    [
      'commit-only',
      {
        STATEPORT_BUILD_SOURCE_COMMIT: 'a'.repeat(40),
        STATEPORT_BUILD_SOURCE_TREE: undefined,
      },
    ],
    [
      'tree-only',
      {
        STATEPORT_BUILD_SOURCE_COMMIT: undefined,
        STATEPORT_BUILD_SOURCE_TREE: 'b'.repeat(40),
      },
    ],
  ]) {
    const partialRoot = temporaryBuildRoot(
      `stateport-${label}-identity-refusal-`,
    )
    try {
      const partial = viteBuild(
        {
          VITE_STATEPORT_ADAPTER: 'http',
          ...partialIdentity,
        },
        '--mode',
        'production',
        '--outDir',
        partialRoot,
      )
      assert.notEqual(partial.status, 0)
      assert.match(
        `${partial.stdout}\n${partial.stderr}`,
        /STATEPORT_BUILD_SOURCE_COMMIT and STATEPORT_BUILD_SOURCE_TREE must be supplied together/,
      )
      assert.equal(existsSync(path.join(partialRoot, MARKER)), false)
    } finally {
      rmSync(partialRoot, { recursive: true, force: true })
    }
  }

  const refusalRoot = temporaryBuildRoot(
    'stateport-production-mock-refusal-',
  )
  try {
    const refused = spawnSync(
      process.execPath,
      [VITE, 'build', '--mode', 'production', '--outDir', refusalRoot],
      {
        cwd: WEB_ROOT,
        env: { ...process.env, VITE_STATEPORT_ADAPTER: 'mock' },
        encoding: 'utf8',
        maxBuffer: 5 * 1024 * 1024,
        timeout: 180_000,
      },
    )
    assert.notEqual(refused.status, 0)
    assert.match(
      `${refused.stdout}\n${refused.stderr}`,
      /production build requires the HTTP adapter/,
    )
    assert.equal(existsSync(path.join(refusalRoot, MARKER)), false)
  } finally {
    rmSync(refusalRoot, { recursive: true, force: true })
  }
})
