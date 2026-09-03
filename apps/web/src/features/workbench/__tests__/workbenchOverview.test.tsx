/**
 * Workbench Overview integration tests (jsdom, full App render): tools are
 * capability-filtered (CTO Pilot shows no Deployments row/actions), degraded
 * capabilities surface honest reasons, the backup-due nudge appears, recent
 * receipts deep-link, and the layout preset can be changed/reset.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import App from '@/App'
import { resetClientForTests } from '@/client'
import { useWorkspaceStore } from '@/state'

async function renderAt(route: string) {
  window.location.hash = route
  return render(<App />)
}

beforeEach(() => {
  resetClientForTests()
  useWorkspaceStore.setState({ layouts: {}, openFiles: {} })
})

afterEach(() => {
  cleanup()
  window.location.hash = ''
})

const CTO_OVERVIEW = '#/app/ins_cto_pilot/workbench'

describe('workbench overview', () => {
  it("hides unavailable tools' actions — CTO Pilot has no Deployments row", async () => {
    await renderAt(CTO_OVERVIEW)
    const root = await screen.findByTestId('workbench-overview-stub', undefined, { timeout: 10_000 })

    // Available tools are listed with honest one-line statuses…
    expect(await within(root).findByTestId('overview-tool-files', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(within(root).getByTestId('overview-tool-terminal')).toBeTruthy()
    expect(within(root).getByTestId('overview-tool-orchestration')).toBeTruthy()
    expect(within(root).getByTestId('overview-tool-receipts')).toBeTruthy()

    // …but infrastructure is environment_gated on CTO Pilot: no Deployments
    // row and no deployment actions anywhere in the summary.
    expect(within(root).queryByTestId('overview-tool-deployments')).toBeNull()
    expect(within(root).queryByText('Deployments')).toBeNull()

    // The degraded orchestration capability shows its honest reason.
    expect(root.textContent).toContain('Limited to assisted mode during the pilot.')
    // The capability list explains the gated infrastructure capability too.
    const caps = within(root).getAllByTestId('overview-capability').map((el) => el.textContent ?? '')
    expect(caps.some((t) => t.includes('No infrastructure target is registered for this project.'))).toBe(true)
  }, 20_000)

  it('shows the backup-due nudge for an instance whose backup is overdue', async () => {
    await renderAt(CTO_OVERVIEW)
    const root = await screen.findByTestId('workbench-overview-stub', undefined, { timeout: 10_000 })
    expect(await within(root).findByText('Backup due', undefined, { timeout: 10_000 })).toBeTruthy()
    expect(within(root).getByTestId('overview-backup-action').getAttribute('href')).toBe('#/app/ins_cto_pilot')
  }, 20_000)

  it('lists recent receipts with human names deep-linking to the receipts tool', async () => {
    await renderAt(CTO_OVERVIEW)
    const root = await screen.findByTestId('workbench-overview-stub', undefined, { timeout: 10_000 })

    // "File change saved" also appears in Recent activity — scope to receipt rows.
    const rows = await within(root).findAllByTestId('overview-receipt', undefined, { timeout: 10_000 })
    const receiptRow = rows.find((row) => row.textContent?.includes('File change saved'))
    expect(receiptRow).toBeTruthy()
    expect(receiptRow!.getAttribute('href')).toBe('#/app/ins_cto_pilot/workbench/receipts/rcpt_0001')
    // Raw event kinds stay out of the summary too.
    expect(root.textContent).not.toContain('file.write')
    // The section links to the tool itself.
    expect(within(root).getByTestId('overview-receipts-link').getAttribute('href')).toBe('#/app/ins_cto_pilot/workbench/receipts')
  }, 20_000)

  it('shows recent activity for this application', async () => {
    await renderAt(CTO_OVERVIEW)
    const root = await screen.findByTestId('workbench-overview-stub', undefined, { timeout: 10_000 })
    const activity = await within(root).findAllByTestId('overview-activity', undefined, { timeout: 10_000 })
    const text = activity.map((a) => a.textContent).join('\n')
    expect(text).toContain('Backup completed')
  }, 20_000)

  it('changes and resets the layout preset', async () => {
    const user = userEvent.setup()
    await renderAt(CTO_OVERVIEW)
    // The shell remounts the tool subtree on layout change — always re-query.
    await screen.findByTestId('overview-preset', undefined, { timeout: 10_000 })

    await user.click(screen.getByTestId('overview-preset-menu'))
    await user.click(await screen.findByText('Review'))
    await waitFor(() => expect(useWorkspaceStore.getState().layouts.ins_cto_pilot?.preset).toBe('review'))
    // Review preset: nav collapsed, right dock open (design.md §10.2).
    expect(useWorkspaceStore.getState().layouts.ins_cto_pilot?.navCollapsed).toBe(true)
    expect(useWorkspaceStore.getState().layouts.ins_cto_pilot?.rightDockCollapsed).toBe(false)

    // The shell remounts the tool subtree on layout change; the summary
    // re-loads before the layout row re-renders.
    const resetButton = await screen.findByTestId('overview-layout-reset', undefined, { timeout: 10_000 })
    fireEvent.click(resetButton)
    expect(useWorkspaceStore.getState().layouts.ins_cto_pilot?.preset).toBe('code_terminal')
  }, 20_000)

  it('renders available tools for an infrastructure-capable instance', async () => {
    await renderAt('#/app/ins_nixos_infra/workbench')
    const root = await screen.findByTestId('workbench-overview-stub', undefined, { timeout: 10_000 })
    expect(await within(root).findByTestId('overview-tool-deployments', undefined, { timeout: 10_000 })).toBeTruthy()
    // No backup nudge: nixosInfra backup is current.
    expect(within(root).queryByText('Backup due')).toBeNull()
  }, 20_000)
})
