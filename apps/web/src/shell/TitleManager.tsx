/**
 * TitleManager — meaningful document titles per route (design.md §16):
 * "Tool · Instance · StatePort". Also moves focus to the main region on
 * route change (§6.4), skipping the first load.
 */
import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'

import { useInstanceName } from './data'

const GLOBAL_TITLES: Record<string, string> = {
  applications: 'Applications',
  catalog: 'Catalog',
  sources: 'Application Sources',
  statebench: 'StateBench Evidence',
  'execution-host': 'Execution Host',
  deployments: 'Platform Deployments',
  authority: 'Standing Authority',
  updater: 'Installed Updater',
  'preview-routes': 'Preview Routes',
  approvals: 'Approvals',
  settings: 'Settings',
}

const TOOL_TITLES: Record<string, string> = {
  files: 'Files',
  terminal: 'Terminal',
  deployments: 'Deployments',
  orchestration: 'Orchestration',
  receipts: 'Receipts',
}

function useRouteTitle(): string {
  const location = useLocation()
  const parts = location.pathname.split('/').filter(Boolean)
  const instanceId = parts[0] === 'app' ? parts[1] : undefined
  const instanceName = useInstanceName(instanceId)

  if (instanceId) {
    const section = parts[2]
    let leaf = 'Overview'
    if (section === 'conversation') leaf = 'Conversation'
    else if (section === 'runs') leaf = 'Governed Runs'
    else if (section === 'settings') leaf = 'Settings'
    else if (section === 'receipts') leaf = 'Receipts'
    else if (section === 'workbench') {
      const tool = parts[3]
      leaf = tool && TOOL_TITLES[tool] ? `${TOOL_TITLES[tool]} · Workbench` : 'Workbench'
    }
    return instanceName ? `${leaf} · ${instanceName} · StatePort` : `${leaf} · StatePort`
  }
  const global = GLOBAL_TITLES[parts[0] ?? '']
  return global ? `${global} · StatePort` : 'StatePort'
}

export function TitleManager() {
  const title = useRouteTitle()
  const location = useLocation()
  const firstLoad = useRef(true)

  useEffect(() => {
    document.title = title
  }, [title])

  // §6.4: move focus to the main region on route change (not on first load).
  useEffect(() => {
    if (firstLoad.current) {
      firstLoad.current = false
      return
    }
    const main = document.getElementById('main-content')
    if (main instanceof HTMLElement) main.focus({ preventScroll: true })
  }, [location.pathname])

  return null
}
