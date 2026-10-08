/**
 * Central route guard for application-contributed surfaces. The router stays
 * static and StatePort-owned; a resolved experience may only select whether a
 * reviewed destination is available for this instance.
 */
import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'

import { useCurrentInstance } from '@/shell/currentInstance'

import {
  applicationDestinationAvailable,
  type ApplicationDestination,
} from './registry'

const DESTINATION_LABEL: Record<ApplicationDestination, string> = {
  overview: 'Overview',
  conversation: 'Conversation',
  runs: 'Runs',
  workbench: 'Workbench',
  receipts: 'Receipts',
  settings: 'Settings',
}

export function ApplicationViewGuard({
  destination,
  children,
}: {
  destination: ApplicationDestination
  children: ReactNode
}) {
  const { instance } = useCurrentInstance()
  if (!instance || applicationDestinationAvailable(instance, destination)) return children

  return (
    <Navigate
      to={`/app/${instance.id}`}
      replace
      state={{
        note: `${DESTINATION_LABEL[destination]} is not part of this application’s resolved experience.`,
      }}
    />
  )
}
