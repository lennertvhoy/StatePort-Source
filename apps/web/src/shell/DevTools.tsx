/**
 * Development-only shell tools: the Scenario Lab panel and ribbon, and the
 * palette commands that open it or reset the mock dataset.
 *
 * AppShell loads this module with a dynamic import behind
 * `import.meta.env.DEV`. A product build folds that flag to `false`, so this
 * file, the Scenario Lab and the scenario table are not part of the shipped
 * bundle (`npm run check:bundle` fails if "Scenario Lab" appears there).
 */
import { FlaskConical, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'

import { getClient } from '@/client'
import { ConfirmDialog } from '@/components'
import { useSessionStore } from '@/state'

import type { ShellCommand } from './commands'
import { useRegisterCommands } from './commands'
import { ScenarioLab, ScenarioRibbon } from './ScenarioLab'

export default function DevTools() {
  const setScenarioLabOpen = useSessionStore((s) => s.setScenarioLabOpen)
  const pushToast = useSessionStore((s) => s.pushToast)
  const [resetOpen, setResetOpen] = useState(false)

  const commands = useMemo<ShellCommand[]>(
    () => [
      {
        id: 'dev.scenario_lab',
        title: 'Open Scenario Lab',
        group: 'Help',
        icon: FlaskConical,
        keywords: ['mock', 'state', 'debug', 'scenario'],
        run: () => setScenarioLabOpen(true),
      },
      {
        id: 'dev.reset_mock',
        title: 'Reset mock data…',
        group: 'Actions',
        icon: Trash2,
        keywords: ['reseed', 'mock'],
        run: () => setResetOpen(true),
      },
    ],
    [setScenarioLabOpen],
  )
  useRegisterCommands(commands)

  return (
    <>
      <ScenarioRibbon />
      <ScenarioLab />
      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Reset mock data"
        description="Wipes persisted mock state and reseeds the deterministic baseline."
        target="mock state"
        effect="All mock instances, receipts, and scenario overrides return to the seeded baseline."
        reversibility="Not reversible — unsaved mock edits are lost."
        destructive
        requireTypedConfirmation="reset"
        confirmLabel="Reset mock data"
        onConfirm={async () => {
          await getClient().scenario?.resetMockState()
          pushToast({ kind: 'success', title: 'Mock data reset', body: 'The seeded baseline was restored.' })
        }}
      />
    </>
  )
}
