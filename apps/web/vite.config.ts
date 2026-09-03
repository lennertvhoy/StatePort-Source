import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import react from '@vitejs/plugin-react'
import { inspectAttr } from 'plugin-inspect-react-code'
import { defineConfig, loadEnv } from 'vite'
import type { Plugin } from 'vite'

import {
  resolveWebBuildProvenance,
  resolveWebBuildContract,
  WEB_BUILD_IDENTITY_FILENAME,
} from './src/buildContract'

const webRoot = path.dirname(fileURLToPath(import.meta.url))
const repositoryRoot = path.resolve(webRoot, '../..')

function git(...args: string[]): string | undefined {
  try {
    return execFileSync('git', args, {
      cwd: repositoryRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 5_000,
    }).trim()
  } catch {
    return undefined
  }
}

const injectedSourceCommit = process.env.STATEPORT_BUILD_SOURCE_COMMIT
const injectedSourceTree = process.env.STATEPORT_BUILD_SOURCE_TREE
const hasInjectedSourceIdentity =
  injectedSourceCommit !== undefined && injectedSourceTree !== undefined
if (
  (injectedSourceCommit === undefined) !== (injectedSourceTree === undefined)
) {
  throw new Error(
    'STATEPORT_BUILD_SOURCE_COMMIT and STATEPORT_BUILD_SOURCE_TREE must be supplied together.',
  )
}
const sourceCommit =
  injectedSourceCommit ?? git('rev-parse', '--verify', 'HEAD')
const sourceTree =
  injectedSourceTree ??
  (sourceCommit
    ? git('rev-parse', '--verify', `${sourceCommit}^{tree}`)
    : undefined)
// Protected evidence outside the frontend must not change browser build
// identity; frontend tracked and untracked inputs remain provenance-relevant.
const gitStatus = git('status', '--porcelain', '--untracked-files=all', '--', 'apps/web')
const configuredSourceEpoch =
  process.env.SOURCE_DATE_EPOCH ??
  process.env.STATEPORT_BUILD_SOURCE_DATE_EPOCH ??
  (sourceCommit ? git('show', '-s', '--format=%ct', sourceCommit) : undefined)
const buildProvenance = resolveWebBuildProvenance({
  sourceCommit,
  sourceTree,
  sourceRef:
    process.env.STATEPORT_BUILD_SOURCE_REF ??
    git('symbolic-ref', '--quiet', '--short', 'HEAD'),
  sourceDirty:
    process.env.STATEPORT_BUILD_SOURCE_DIRTY ??
    (hasInjectedSourceIdentity
      ? true
      : gitStatus === undefined
        ? undefined
        : gitStatus !== ''),
  sourceDateEpoch:
    configuredSourceEpoch === 'unknown' ? undefined : configuredSourceEpoch,
})
const buildShort =
  buildProvenance.sourceCommit === 'unknown'
    ? 'unknown'
    : buildProvenance.sourceCommit.slice(0, 12)

function buildIdentityPlugin(
  identity: ReturnType<typeof resolveWebBuildContract>['identity'],
): Plugin {
  return {
    name: 'stateport-web-build-identity',
    apply: 'build',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: WEB_BUILD_IDENTITY_FILENAME,
        source: `${JSON.stringify(identity, null, 2)}\n`,
      })
    },
  }
}

export default defineConfig(({ command, mode }) => {
  const buildContract =
    command === 'build'
      ? resolveWebBuildContract(
          mode,
          loadEnv(mode, __dirname, 'VITE_STATEPORT_').VITE_STATEPORT_ADAPTER,
          buildProvenance,
        )
      : undefined

  return {
    base: './',
    plugins: [
      // Source-location attributes are useful while reviewing the dev/demo
      // surface, but they disclose repository paths and add substantial
      // payload to the product bundle. Production must contain neither.
      ...(mode === 'production' ? [] : [inspectAttr()]),
      react(),
      ...(buildContract ? [buildIdentityPlugin(buildContract.identity)] : []),
    ],
    define: {
      __BUILD_VERSION__: JSON.stringify(
        // A release build injects the exact release version; the package
        // version remains the fallback for ordinary development builds.
        process.env.STATEPORT_BUILD_VERSION ??
          process.env.npm_package_version ??
          '0.1.0',
      ),
      __BUILD_SHA__: JSON.stringify(buildProvenance.sourceCommit),
      __BUILD_SHORT__: JSON.stringify(buildShort),
      __BUILD_BRANCH__: JSON.stringify(buildProvenance.sourceRef),
      __BUILD_TIME__: JSON.stringify(buildProvenance.builtAt),
      __BUILD_DIRTY__: JSON.stringify(buildProvenance.sourceDirty),
      ...(buildContract
        ? {
            'import.meta.env.VITE_STATEPORT_ADAPTER': JSON.stringify(
              buildContract.identity.adapter,
            ),
          }
        : {}),
    },
    server: {
      port: 3000,
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    build: {
      outDir: buildContract?.outDir ?? 'dist',
      emptyOutDir: true,
      manifest: true,
      // AppServer's production CSP deliberately permits only same-origin
      // images. Keep imported brand assets as fingerprinted files instead of
      // Vite data: URLs so the reviewed mascot is not blocked at runtime.
      assetsInlineLimit: 0,
      sourcemap: false,
      target: 'es2022',
      rollupOptions: {
        output: {
          entryFileNames: 'assets/[name]-[hash].js',
          chunkFileNames: 'assets/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash][extname]',
        },
      },
    },
  }
})
