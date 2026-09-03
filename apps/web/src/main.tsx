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

// No StrictMode (project convention: avoids double-invoked effects).
createRoot(document.getElementById('root')!).render(<App />)
