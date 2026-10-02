/** Bare-root startup only; explicit routes never mount this resolver. */
import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { getClient } from '@/client'
import { SkeletonRows } from '@/components'
import { resumeTargetFor } from '@/features/applications/lib/continuity'
import { useWorkspaceStore } from '@/state'
import { fetchBootstrapSettings } from './data'

export function StartupRoute() {
  const [target, setTarget] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    const workspace = useWorkspaceStore.getState()
    void (async () => {
      let route = '/applications'
      try {
        const settings = await fetchBootstrapSettings()
        if (cancelled) return
        const id = workspace.lastInstanceId
        if (typeof id === 'string' && id.length > 0 && id.length <= 256
          // Reject route delimiters/control bytes in untrusted persisted IDs.
          // eslint-disable-next-line no-control-regex
          && !/[\s/\\?#%\u0000-\u001f]/.test(id)
          && id !== '.' && id !== '..'
          && (settings.general.reopenLastApplication || settings.general.defaultLandingPage === 'last_workspace')) {
          // Revalidate existence instead of trusting browser continuity/cache.
          const instance = await getClient().applications.get(id)
          if (cancelled) return
          if (instance.id === id) {
            const safeInstance = { ...instance, id: encodeURIComponent(id) }
            route = resumeTargetFor(
              safeInstance,
              { ...workspace, lastInstanceId: safeInstance.id },
              {
                restoreLastApplicationView: settings.general.reopenLastApplicationView,
                restoreLastTool: settings.navigation.restoreLastTool,
              },
            ).route
          }
        }
      } catch {
        // Deleted/unknown application or unavailable settings: recover to home.
      }
      if (!cancelled) setTarget(route)
    })()
    return () => { cancelled = true }
  }, [])
  return target ? <Navigate to={target} replace /> : <SkeletonRows rows={4} className="p-4" />
}
