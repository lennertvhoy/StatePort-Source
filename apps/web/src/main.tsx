import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { normalizeLegacyHash } from './legacyRoutes'

const rootElement = document.getElementById('root')
if (rootElement) {
  rootElement.dataset.buildSha = __BUILD_SHA__
  rootElement.dataset.buildShort = __BUILD_SHORT__
  rootElement.dataset.buildBranch = __BUILD_BRANCH__
  rootElement.dataset.buildTime = __BUILD_TIME__
  rootElement.dataset.buildDirty = __BUILD_DIRTY__ ? 'true' : 'false'
}
const buildMeta = document.createElement('meta')
buildMeta.name = 'stateport-build'
buildMeta.content = `${__BUILD_SHA__}${__BUILD_DIRTY__ ? '+dirty' : ''}`
document.head.append(buildMeta)

// Normalize legacy hash routes (#home, #app/<id>, …) before the router
// renders, without adding a history entry.
const normalizedHash = normalizeLegacyHash(window.location.hash)
if (normalizedHash !== window.location.hash) {
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${normalizedHash}`)
}

// The mock adapter and Scenario Lab exist for development and the demo build
// only. The adapter flag is a build-time constant (`http` in a production
// build), so this branch and the dynamic import below are removed from the
// product bundle entirely.
const adapterFlag = import.meta.env.VITE_STATEPORT_ADAPTER
if (adapterFlag === 'mock' || (!adapterFlag && import.meta.env.DEV)) {
  const { installMockAdapter } = await import('./dev/installMock')
  installMockAdapter()
}

// No StrictMode (project convention: avoids double-invoked effects).
createRoot(document.getElementById('root')!).render(<App />)
