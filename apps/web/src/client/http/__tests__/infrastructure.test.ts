/**
 * Current local-libvirt contract tests. These fixtures mirror the service
 * projection and keep the product model honest about an uncreated VM,
 * digest-bound plans, and repository-owned validation.
 */
import { describe, expect, it } from 'vitest'

import { HttpInfrastructureClient } from '../domainsExecution'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const DIGEST = `sha256:${'ab'.repeat(32)}`

const TARGET = {
  targetId: 'libvirt-persistent',
  targetType: 'local_libvirt',
  displayName: 'Persistent local NixOS VM',
  domain: 'ff-nixos-replica-vm-persistent',
  domainUuid: '33cff7f0-f59d-4da5-b47e-f030d2455e5b',
  connection: 'qemu:///session',
  ssh: { host: 'localhost', port: 2223, user: 'ff' },
}

const PROJECTION = {
  formatVersion: 'stateport.infrastructure-local-libvirt/v1',
  instanceId: 'nixos-infrastructure',
  repository: {
    rootDisplay: 'nixos-homelab',
    branch: 'main',
    headCommit: '1'.repeat(40),
    headTree: '2'.repeat(40),
    dirty: false,
    dirtyDigest: `sha256:${'3'.repeat(64)}`,
    remote: null,
  },
  target: TARGET,
  domain: {
    state: 'not_defined',
    availability: 'available',
    domain: 'ff-nixos-replica-vm-persistent',
    error: null,
  },
  dailyDriverGrant: null,
  lastRun: null,
}

const VALIDATE_PLAN = {
  formatVersion: 'stateport.infrastructure-plan/v1',
  instanceId: 'nixos-infrastructure',
  target: TARGET,
  operation: 'validate',
  domainBefore: PROJECTION.domain,
  commands: [['nix', 'flake', 'check', '--no-build']],
  approvalRequired: false,
  authorization: { mode: 'exact_plan_approval' },
  rollback: 'No canonical state is changed.',
  createdAt: '2026-07-18T10:00:00Z',
  expiresAt: '2026-07-18T10:30:00Z',
  planDigest: DIGEST,
}

const VALIDATE_RECEIPT = {
  formatVersion: 'stateport.infrastructure-receipt/v1',
  receiptType: 'stateport.infrastructure-receipt/v1',
  receiptId: 'infra-receipt-1234567890abcdef12345678',
  instanceId: 'nixos-infrastructure',
  action: 'nix.validation',
  status: 'completed',
  sourceKind: 'infrastructure',
  createdAt: '2026-07-18T10:01:00Z',
  planDigest: DIGEST,
  target: TARGET,
  validation: {
    state: 'validated',
    detail: 'The repository-owned Nix flake check completed locally with exit code 0.',
  },
}

const GRANT_PROPOSAL = {
  formatVersion: 'stateport.infrastructure-daily-driver-grant/v1',
  grantId: 'local-nix-daily-driver',
  instanceId: 'nixos-infrastructure',
  applicationId: 'nixos-infrastructure',
  target: TARGET,
  status: 'proposed',
  allowedOperations: ['repository.inspect', 'vm.observe', 'vm.health.read'],
  deniedOperations: ['vm.destroy'],
  createdAt: '2026-07-18T10:00:00Z',
  proposalDigest: `sha256:${'cd'.repeat(32)}`,
}

describe('HttpInfrastructureClient — current local-libvirt contract', () => {
  it('advertises that the current service has no authorization-revoke transition', () => {
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: makeFakeFetch([]).fetchFn }))

    expect(client.canRevokeAuthorization).toBe(false)
  })

  it('keeps a not-yet-defined VM neutral and plannable instead of unavailable', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const target = await client.getTarget('nixos-infrastructure')

    expect(target).toMatchObject({
      id: 'libvirt-persistent',
      // The hypervisor answered and the VM simply does not exist yet: the
      // target stays available so create_or_update remains plannable, while
      // the VM state itself is reported honestly as not_defined.
      available: true,
      unavailableReason: undefined,
      repository: {
        name: 'nixos-homelab',
        branch: 'main',
        revision: '1'.repeat(40),
        clean: true,
      },
      vm: { state: 'not_defined' },
      ssh: { state: 'unavailable_vm_not_defined' },
      health: { state: 'not_checked' },
    })
  })

  it('fails closed as unavailable when the domain cannot be observed at all', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/nixos-infrastructure/infrastructure',
        jsonResponse({
          ...PROJECTION,
          domain: {
            state: 'unavailable',
            availability: 'unavailable',
            domain: 'ff-nixos-replica-vm-persistent',
            error: 'error: failed to connect to the hypervisor',
          },
        }),
      ],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const target = await client.getTarget('nixos-infrastructure')

    expect(target).toMatchObject({
      available: false,
      unavailableReason: 'error: failed to connect to the hypervisor',
      vm: { state: 'unavailable' },
    })
  })

  it.each([
    ['paused', 'stopped'],
    ['idle', 'running'],
    ['in shutdown', 'stopping'],
    ['crashed', 'unavailable'],
    ['pmsuspended', 'stopped'],
  ])('maps virsh domain state "%s" without failing closed', async (virshState, expectedVmState) => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/nixos-infrastructure/infrastructure',
        jsonResponse({
          ...PROJECTION,
          domain: { state: virshState, availability: 'available' },
        }),
      ],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const target = await client.getTarget('nixos-infrastructure')

    expect(target.vm.state).toBe(expectedVmState)
  })

  it('surfaces a run replay-guard refusal with its machine-readable code', async () => {
    const observePlan = {
      ...VALIDATE_PLAN,
      operation: 'observe',
      commands: [['virsh', 'domstate']],
      approvalRequired: false,
    }
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/nixos-infrastructure/infrastructure/plan', jsonResponse(observePlan)],
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
      [
        'POST',
        '/v1/instances/nixos-infrastructure/infrastructure/run',
        jsonResponse(
          {
            ok: false,
            error: {
              code: 'run_reconciliation_required',
              message:
                'the infrastructure run may have started; inspect and reconcile it before any new execution',
            },
          },
          409,
        ),
      ],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const plan = await client.preparePlan('nixos-infrastructure', 'observe')

    const drain = async () => {
      for await (const event of client.runPlan(plan.id)) void event
    }

    await expect(drain()).rejects.toMatchObject({
      kind: 'http',
      code: 'run_reconciliation_required',
      status: 409,
    })
  })

  it('does not present a read-only observation timestamp as a health-check timestamp', async () => {
    const observed = {
      ...PROJECTION,
      domain: { state: 'shut off', availability: 'available' },
      lastRun: {
        operation: 'observe',
        state: 'completed',
        endedAt: '2026-07-18T10:01:00Z',
        result: { ...PROJECTION },
        receipt: { ...VALIDATE_RECEIPT, action: 'libvirt.observe' },
      },
    }
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(observed)],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const target = await client.getTarget('nixos-infrastructure')

    expect(target.vm.state).toBe('stopped')
    expect(target.health).toEqual({ state: 'not_checked', checkedAt: undefined, detail: undefined })
  })

  it('routes configuration validation through an infrastructure validate plan and run', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/nixos-infrastructure/infrastructure/plan', jsonResponse(VALIDATE_PLAN)],
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
      [
        'POST',
        '/v1/instances/nixos-infrastructure/infrastructure/run',
        jsonResponse({
          formatVersion: 'stateport.infrastructure-run/v1',
          runId: 'infra-run-1234567890abcdef12345678',
          instanceId: 'nixos-infrastructure',
          operation: 'validate',
          planDigest: DIGEST,
          state: 'completed',
          receipt: VALIDATE_RECEIPT,
        }),
      ],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const result = await client.validateConfiguration('nixos-infrastructure')

    // Completion and validation remain separate; explicit local evidence is
    // what makes this configuration check pass.
    expect(result.ok).toBe(true)
    expect(result.receipt).toMatchObject({
      id: VALIDATE_RECEIPT.receiptId,
      actionName: 'Infrastructure validation completed',
      eventKind: 'nix.validation',
      result: 'completed',
      validation: {
        state: 'validated',
        detail: 'The repository-owned Nix flake check completed locally with exit code 0.',
      },
    })
    expect(fake.callsTo('/infrastructure/plan')[0].body).toEqual({ operation: 'validate' })
    expect(fake.callsTo('/infrastructure/run')[0].body).toEqual({ planDigest: DIGEST })
    expect(fake.callsTo('/synthetic-run')).toHaveLength(0)
  })

  it('passes create_or_update to the exact backend operation', async () => {
    const createPlan = {
      ...VALIDATE_PLAN,
      operation: 'create_or_update',
      commands: [['make', 'vm-persistent-create']],
      approvalRequired: true,
    }
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/nixos-infrastructure/infrastructure/plan', jsonResponse(createPlan)],
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const plan = await client.preparePlan('nixos-infrastructure', 'create_or_update')

    expect(plan).toMatchObject({
      operation: 'create_or_update',
      state: 'awaiting_approval',
      requiresApproval: true,
      risk: 'medium',
      approvalId: `infrastructure_plan:${DIGEST}`,
    })
    expect(fake.callsTo('/infrastructure/plan')[0].body).toEqual({ operation: 'create_or_update' })
  })

  it('preserves an observed unexpired plan across the same-session approval trip', async () => {
    const observeDigest = `sha256:${'ef'.repeat(32)}`
    const observePlan = {
      ...VALIDATE_PLAN,
      operation: 'observe',
      commands: [['virsh', 'domstate']],
      approvalRequired: false,
      expiresAt: '2099-07-18T10:30:00Z',
      planDigest: observeDigest,
    }
    const createPlan = {
      ...VALIDATE_PLAN,
      operation: 'create_or_update',
      commands: [['make', 'vm-persistent-rebuild']],
      approvalRequired: true,
      expiresAt: '2099-07-18T10:30:00Z',
    }
    let preparedCount = 0
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/nixos-infrastructure/infrastructure/plan',
        () => jsonResponse(preparedCount++ === 0 ? observePlan : createPlan),
      ],
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const observed = await client.preparePlan(
      'nixos-infrastructure',
      'observe',
    )
    const prepared = await client.preparePlan(
      'nixos-infrastructure',
      'create_or_update',
    )
    const afterApprovalTrip = await client.listPlans('nixos-infrastructure')

    expect(afterApprovalTrip).toEqual([prepared, observed])
    expect(afterApprovalTrip[0].approvalId).toBe(
      `infrastructure_plan:${DIGEST}`,
    )
  })

  it('rejects a GET projection for a different instance instead of relabelling it', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/nixos-infrastructure/infrastructure',
        jsonResponse({ ...PROJECTION, instanceId: 'other-instance' }),
      ],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.getTarget('nixos-infrastructure')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it('rejects an infrastructure projection without the current format identity', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/nixos-infrastructure/infrastructure',
        jsonResponse({
          ...PROJECTION,
          formatVersion: 'stateport.infrastructure-local-libvirt/v0',
        }),
      ],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.getTarget('nixos-infrastructure')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it.each([
    ['instance', { instanceId: 'other-instance' }],
    ['target', { target: { ...TARGET, targetId: 'libvirt-other' } }],
  ])('rejects a prepared plan bound to a different %s identity', async (_label, mismatch) => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/nixos-infrastructure/infrastructure/plan',
        jsonResponse({
          ...VALIDATE_PLAN,
          ...mismatch,
        }),
      ],
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(
      client.preparePlan('nixos-infrastructure', 'validate'),
    ).rejects.toMatchObject({ kind: 'validation' })
  })

  it.each([
    ['instance', { instanceId: 'other-instance' }],
    ['target', { target: { ...TARGET, targetId: 'libvirt-other' } }],
  ])('rejects a grant proposal with a mismatched %s identity', async (_label, mismatch) => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/nixos-infrastructure/infrastructure/grant/prepare',
        jsonResponse({ ...GRANT_PROPOSAL, ...mismatch }),
      ],
      ['GET', '/v1/instances/nixos-infrastructure/infrastructure', jsonResponse(PROJECTION)],
    ])
    const client = new HttpInfrastructureClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(
      client.proposeAuthorization('nixos-infrastructure'),
    ).rejects.toMatchObject({ kind: 'validation' })
  })
})
