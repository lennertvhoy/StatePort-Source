import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const SOURCE_ROOT = path.join(WEB_ROOT, 'src')
const UI_ROOT = path.join(SOURCE_ROOT, 'components', 'ui')
const IMPORT = /(?:from\s*|import\s*)['"]([^'"]+)['"]/g

const REMOVED_DIRECT_DEPENDENCIES = [
  '@codemirror/autocomplete',
  '@codemirror/commands',
  '@codemirror/legacy-modes',
  '@floating-ui/react',
  '@hookform/resolvers',
  '@radix-ui/react-accordion',
  '@radix-ui/react-aspect-ratio',
  '@radix-ui/react-avatar',
  '@radix-ui/react-hover-card',
  '@radix-ui/react-menubar',
  '@radix-ui/react-navigation-menu',
  '@radix-ui/react-progress',
  '@radix-ui/react-scroll-area',
  '@radix-ui/react-separator',
  '@radix-ui/react-slider',
  '@radix-ui/react-tabs',
  '@radix-ui/react-toggle',
  '@xterm/addon-clipboard',
  'cmdk',
  'embla-carousel-react',
  'idb',
  'input-otp',
  'next-themes',
  'react-day-picker',
  'react-hook-form',
  'react-router',
  'recharts',
  'sonner',
  'vaul',
]

function sourceFiles(root) {
  const files = []
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const absolute = path.join(root, entry.name)
    if (entry.isDirectory()) {
      files.push(...sourceFiles(absolute))
    } else if (/\.(?:css|js|jsx|mjs|ts|tsx)$/.test(entry.name)) {
      files.push(absolute)
    }
  }
  return files
}

function imports(file) {
  const values = []
  const text = readFileSync(file, 'utf8')
  for (const match of text.matchAll(IMPORT)) values.push(match[1])
  return values
}

test('removed direct dependencies have no direct source imports', () => {
  const packageJson = JSON.parse(
    readFileSync(path.join(WEB_ROOT, 'package.json'), 'utf8'),
  )
  for (const dependency of REMOVED_DIRECT_DEPENDENCIES) {
    assert.equal(
      packageJson.dependencies?.[dependency],
      undefined,
      `${dependency} must not return as an unused direct dependency`,
    )
  }

  const removed = new Set(REMOVED_DIRECT_DEPENDENCIES)
  const staleImports = []
  for (const file of sourceFiles(SOURCE_ROOT)) {
    for (const dependency of imports(file)) {
      if (removed.has(dependency)) {
        staleImports.push(`${path.relative(WEB_ROOT, file)} -> ${dependency}`)
      }
    }
  }
  assert.deepEqual(staleImports, [])
})

test('every retained generated UI module is reachable from product source', () => {
  const modules = new Map()
  for (const entry of readdirSync(UI_ROOT)) {
    const absolute = path.join(UI_ROOT, entry)
    if (!statSync(absolute).isFile() || !/\.(?:ts|tsx)$/.test(entry)) continue
    modules.set(entry.replace(/\.(?:ts|tsx)$/, ''), absolute)
  }

  const roots = new Set()
  for (const file of sourceFiles(SOURCE_ROOT)) {
    if (file.startsWith(`${UI_ROOT}${path.sep}`)) continue
    for (const dependency of imports(file)) {
      if (!dependency.startsWith('@/components/ui/')) continue
      const name = dependency.slice('@/components/ui/'.length).split('/')[0]
      if (modules.has(name)) roots.add(name)
    }
  }

  const reachable = new Set()
  const pending = [...roots]
  while (pending.length) {
    const name = pending.pop()
    if (!name || reachable.has(name)) continue
    reachable.add(name)
    for (const dependency of imports(modules.get(name))) {
      let child
      if (dependency.startsWith('@/components/ui/')) {
        child = dependency.slice('@/components/ui/'.length).split('/')[0]
      } else if (dependency.startsWith('./')) {
        child = dependency.slice(2).split('/')[0]
      }
      if (child && modules.has(child)) pending.push(child)
    }
  }

  assert.deepEqual(
    [...modules.keys()].filter((name) => !reachable.has(name)).sort(),
    [],
    'generated UI modules must be imported by the product or another reachable UI module',
  )
})

test('mock persistence documentation matches the localStorage implementation', () => {
  assert.equal(existsSync(path.join(WEB_ROOT, 'node_modules', 'idb')), false)
  const store = readFileSync(
    path.join(SOURCE_ROOT, 'client', 'mock', 'store.ts'),
    'utf8',
  )
  const integration = readFileSync(
    path.join(WEB_ROOT, 'docs', 'BACKEND_INTEGRATION.md'),
    'utf8',
  )
  assert.match(store, /No IndexedDB store/)
  assert.match(integration, /localStorage persistence/)
  assert.doesNotMatch(integration, /\bidb persistence\b/i)
})
