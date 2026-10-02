import { afterEach, describe, expect, it } from 'vitest'

import { ClientError } from '../types'
import { MockClient } from '../mock/adapter'
import { SCENARIOS, useScenarioStore } from '../mock/scenarios'
import { INSTANCE_IDS } from '../mock/seed'

afterEach(() => {
  useScenarioStore.getState().setActive(null)
})

describe('scenario lab overrides', () => {
  it('registry covers every scenario from the brief', () => {
    // 47 scenarios, grouped; each has a behavior payload.
    expect(SCENARIOS.length).toBe(47)
    for (const s of SCENARIOS) {
      expect(s.label.length).toBeGreaterThan(0)
      expect(s.group.length).toBeGreaterThan(0)
    }
  })

  it('no_applications empties the list without touching seed data', async () => {
    const client = new MockClient()
    useScenarioStore.getState().setActive('no_applications')
    expect(await client.applications.list()).toEqual([])
    useScenarioStore.getState().setActive(null)
    expect((await client.applications.list()).length).toBe(4)
  })

  it('service_offline turns calls into network ClientErrors', async () => {
    const client = new MockClient()
    useScenarioStore.getState().setActive('service_offline')
    await expect(client.applications.list()).rejects.toBeInstanceOf(ClientError)
    await expect(client.applications.list()).rejects.toMatchObject({ kind: 'network' })
    const status = await client.session.getLocalServiceStatus()
    expect(status.state).toBe('offline')
  })

  it('receipts_empty only affects reads', async () => {
    const client = new MockClient()
    useScenarioStore.getState().setActive('receipts_empty')
    expect(await client.receipts.list({})).toEqual([])
    useScenarioStore.getState().setActive(null)
    expect((await client.receipts.list({})).length).toBeGreaterThan(0)
  })

  it('vm_healthy presents a running, healthy target', async () => {
    const client = new MockClient()
    useScenarioStore.getState().setActive('vm_healthy')
    const target = await client.infrastructure.getTarget(INSTANCE_IDS.nixosInfra)
    expect(target.vm.state).toBe('running')
    expect(target.health.state).toBe('healthy')
    expect(target.ssh.state).toBe('ready')
  })

  it('orchestration_unavailable fails closed with an unavailable error', async () => {
    const client = new MockClient()
    useScenarioStore.getState().setActive('orchestration_unavailable')
    await expect(client.orchestration.getCurrent(INSTANCE_IDS.nixosInfra)).rejects.toMatchObject({
      kind: 'unavailable',
    })
  })
})
