/**
 * Development, demo and test only: installs the mock adapter and the
 * Scenario Lab store behind the client boundary.
 *
 * Nothing in the product code imports this file. `main.tsx` loads it with a
 * dynamic import guarded by the build-time adapter flag (a production build
 * folds that flag to `http`, so this file and everything it pulls in is not
 * part of the product bundle), and `src/test/setup.ts` loads it for tests.
 */
import { registerMockClient } from '@/client'
import { MockClient } from '@/client/mock/adapter'
import { useScenarioStore } from '@/client/mock/scenarios'
import { registerScenarioBridge, useSessionStore } from '@/state'

let installed = false

export function installMockAdapter(): void {
  if (installed) return
  installed = true
  registerMockClient(() => new MockClient())
  registerScenarioBridge({
    setActive: (id) => useScenarioStore.getState().setActive(id),
    setLabOpen: (open) => useScenarioStore.getState().setLabOpen(open),
  })
  const mirror = (state: ReturnType<typeof useScenarioStore.getState>) => {
    useSessionStore.setState({ activeScenario: state.active, scenarioLabOpen: state.labOpen })
  }
  mirror(useScenarioStore.getState())
  useScenarioStore.subscribe(mirror)
}
