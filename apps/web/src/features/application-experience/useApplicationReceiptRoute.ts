import { useEffect, useState } from 'react'

import { getClient } from '@/client'

import { applicationDestinationAvailable } from './registry'

/** Resolve a receipt list base only after the instance's registered routes are known. */
export function useApplicationReceiptBaseRoute(instanceId: string): string | null {
  const [result, setResult] = useState<{ instanceId: string; baseRoute: string | null } | null>(null)

  useEffect(() => {
    let cancelled = false
    if (!instanceId) return () => undefined

    getClient().applications
      .get(instanceId)
      .then((instance) => {
        if (cancelled) return
        if (!applicationDestinationAvailable(instance, 'receipts')) {
          setResult({ instanceId, baseRoute: null })
          return
        }
        const workbench = applicationDestinationAvailable(instance, 'workbench')
        setResult({
          instanceId,
          baseRoute: workbench ? `/app/${instance.id}/workbench/receipts` : `/app/${instance.id}/receipts`,
        })
      })
      .catch(() => {
        if (!cancelled) setResult({ instanceId, baseRoute: null })
      })

    return () => {
      cancelled = true
    }
  }, [instanceId])

  return result?.instanceId === instanceId ? result.baseRoute : null
}
