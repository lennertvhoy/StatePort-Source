import { describe, expect, it } from 'vitest'

import { MockClient } from '../mock/adapter'
import { INSTANCE_IDS } from '../mock/seed'

describe('mock seed integrity', () => {
  it('seeds exactly the four required instances with stable ids', async () => {
    const client = new MockClient()
    const instances = await client.applications.list()
    expect(instances.map((i) => i.id).sort()).toEqual(
      [
        INSTANCE_IDS.ctoPilot,
        INSTANCE_IDS.studyAlpha,
        INSTANCE_IDS.checklistSample,
        INSTANCE_IDS.nixosInfra,
      ].sort(),
    )
    expect(instances.map((i) => i.name)).toContain('StatePort CTO Pilot')
    expect(instances.map((i) => i.name)).toContain('NixOS Infrastructure')
  })

  it('gives StudyState Alpha no workbench capability', async () => {
    const client = new MockClient()
    const study = await client.applications.get(INSTANCE_IDS.studyAlpha)
    const workbench = study.capabilities.find((c) => c.id === 'workbench')
    expect(workbench?.status).toBe('unavailable')
    expect(study.packageState?.kind).toBe('study-state')
  })

  it('seeds NixOS Infrastructure with clean repo, stopped VM, unchecked health, one pending approval', async () => {
    const client = new MockClient()
    const infra = await client.applications.get(INSTANCE_IDS.nixosInfra)
    expect(infra.repository).toMatchObject({ name: 'nixos-homelab', branch: 'main', clean: true })

    const target = await client.infrastructure.getTarget(INSTANCE_IDS.nixosInfra)
    expect(target.available).toBe(true)
    expect(target.vm.state).toBe('stopped')
    expect(target.ssh.state).toBe('unavailable_vm_stopped')
    expect(target.health.state).toBe('not_checked')

    const pending = await client.approvals.list({ status: 'pending' })
    expect(pending).toHaveLength(1)
    expect(pending[0].instanceId).toBe(INSTANCE_IDS.nixosInfra)
  })

  it('seeds CTO Pilot with backup due, receipts, and one attention item', async () => {
    const client = new MockClient()
    const cto = await client.applications.get(INSTANCE_IDS.ctoPilot)
    expect(cto.recovery.state).toBe('due')
    expect(cto.attention.length).toBeGreaterThanOrEqual(1)
    expect(cto.receiptIds.length).toBeGreaterThanOrEqual(3)

    const receipts = await client.receipts.list({ instanceId: INSTANCE_IDS.ctoPilot })
    expect(receipts.map((r) => r.actionName)).toContain('File change saved')
  })

  it('seeds catalog with the three package types plus reviewed extras', async () => {
    const client = new MockClient()
    const catalog = await client.catalog.list()
    const names = catalog.map((c) => c.pkg.name)
    expect(names).toContain('project-state')
    expect(names).toContain('study-state')
    expect(names).toContain('checklist-state')
    expect(catalog.length).toBeGreaterThanOrEqual(4)
  })
})
