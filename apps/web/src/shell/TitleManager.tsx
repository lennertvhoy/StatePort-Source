/**
 * TitleManager — meaningful document titles per route (design.md §16):
 * "Tool · Instance · StatePort". Also moves focus to the main region on
 * route change (§6.4), skipping the first load.
 */
import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'

import { useInstanceName } from './data'

const GLOBAL_TITLES: Record<string, string> = {
  platform: 'Platform',
  applications: 'Applications',
  catalog: 'Catalog',
  'execution-host': 'Execution Host',
  authority: 'Standing Authority',
  updater: 'Installed Updater',
  approvals: 'Approvals',
  settings: 'Settings',
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
