/**
 * Capability gating contract tests (binding doc §16): instance capabilities
 * come from the experience descriptor; unknown statuses fail closed to
 * 'unavailable'; unknown capability ids are dropped.
 */
import { describe, expect, it } from 'vitest'

import { HttpTransport } from '../transport'
import { HttpApplicationsClient, HttpFilesClient } from '../domainsCore'
import { mapCatalog, mapInstallReceipt, mapInstance } from '../mappers'
import { HttpTerminalClient } from '../terminal'
import { jsonResponse, makeFakeFetch } from './helpers'
import { applicationDestinationAvailable, applicationNavigation } from '@/features/application-experience/registry'

const INSTANCE = {
  id: 'ins_1',
  name: 'homelab-dev',
  applicationId: 'pkg_project_state',
  health: 'ready',
  createdAt: '2026-07-04T08:00:00.000Z',
}

function applicationsClient(experience: unknown) {
  const fake = makeFakeFetch([
    ['GET', '/v1/instances', jsonResponse({ instances: [INSTANCE] })],
    ['GET', '/v1/instances/ins_1/experience', jsonResponse({ ok: true, result: experience })],
    ['GET', '/v1/instances/ins_1', jsonResponse({ ok: true, result: INSTANCE })],
  ])
  return new HttpApplicationsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
}

describe('capability gating from the experience descriptor', () => {
  it('advertises the durable instance rename contract', () => {
    const client = applicationsClient({ capabilities: [] })
    expect(client.canRename).toBe(true)
  })

  it('terminal=unavailable in the descriptor is reflected on the instance', async () => {
    const client = applicationsClient({
      capabilities: [
        { id: 'conversation', status: 'available' },
        { id: 'terminal', status: 'unavailable', reason: 'No local PTY on this host.' },
      ],
    })
    const instance = await client.get('ins_1')
    const terminal = instance.capabilities.find((c) => c.id === 'terminal')
    expect(terminal?.status).toBe('unavailable')
    expect(terminal?.reason).toBe('No local PTY on this host.')
    expect(instance.capabilities.find((c) => c.id === 'conversation')?.status).toBe('available')
    expect(instance.conversationId).toBeUndefined()
  })

  it('all four capability statuses pass through; unknown statuses fail closed to unavailable', async () => {
    const client = applicationsClient({
      capabilities: [
        { id: 'terminal', status: 'degraded' },
        { id: 'file_viewer', status: 'environment_gated' },
        { id: 'editor', status: 'sometimes_works' },
      ],
    })
    const instance = await client.get('ins_1')
    expect(instance.capabilities.find((c) => c.id === 'terminal')?.status).toBe('degraded')
    expect(instance.capabilities.find((c) => c.id === 'file_viewer')?.status).toBe('environment_gated')
    const editor = instance.capabilities.find((c) => c.id === 'editor')
    expect(editor?.status).toBe('unavailable')
  })

  it('unknown capability ids are dropped', async () => {
    const client = applicationsClient({
      capabilities: [
        { id: 'terminal', status: 'available' },
        { id: 'quantum_entanglement', status: 'available' },
      ],
    })
    const instance = await client.get('ins_1')
    expect(instance.capabilities.map((c) => c.id)).toEqual(['terminal'])
  })

  it('record-form capabilities are accepted', async () => {
    const client = applicationsClient({
      capabilities: { terminal: 'environment_gated', conversation: 'available' },
    })
    const instance = await client.get('ins_1')
    expect(instance.capabilities.find((c) => c.id === 'terminal')?.status).toBe('environment_gated')
  })

  it('accepts the backend resolution shape and preserves its usable Workbench capabilities', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      descriptorIdentity: {
        applicationId: 'stateport.development-reference',
        formatVersion: 'stateport.application-experience/v1',
        descriptorDigest: `sha256:${'d'.repeat(64)}`,
      },
      instanceBinding: {
        instanceId: 'ins_1',
        applicationId: 'stateport.development-reference',
        descriptorDigest: `sha256:${'d'.repeat(64)}`,
      },
      capabilities: [
        { id: 'conversation', status: 'available', reasons: [] },
        { id: 'file_viewer', status: 'available', reasons: [] },
        { id: 'editor', status: 'available', reasons: [] },
        { id: 'terminal', status: 'available', reasons: [] },
        { id: 'workbench', status: 'available', reasons: [] },
        { id: 'cto_orchestration', status: 'degraded', reasons: ['runtime_degraded'] },
      ],
      views: [
        {
          viewId: 'project-home',
          label: 'Project',
          component: 'application_home',
          route: '/application',
          capability: 'progress_dashboard',
          status: 'available',
          reasons: [],
          visible: true,
        },
        {
          viewId: 'project-workbench',
          label: 'Workbench',
          component: 'development_workbench',
          route: '/workbench',
          capability: 'workbench',
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
      navigation: [
        {
          contributionId: 'project-home-nav',
          label: 'Project',
          viewId: 'project-home',
          placement: 'application',
          order: 10,
          visible: true,
        },
        {
          contributionId: 'project-workbench-nav',
          label: 'Workbench',
          viewId: 'project-workbench',
          placement: 'advanced',
          order: 30,
          visible: true,
        },
      ],
      advancedControls: [
        {
          controlId: 'project-files',
          label: 'Files',
          component: 'file_viewer',
          capability: 'file_viewer',
          order: 20,
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
    })

    const instance = await client.get('ins_1')
    expect(instance.packageId).toBe('pkg_project_state')
    expect(instance.capabilities).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'conversation', status: 'available' }),
      expect.objectContaining({ id: 'file_viewer', status: 'available' }),
      expect.objectContaining({ id: 'editor', status: 'available' }),
      expect.objectContaining({ id: 'terminal', status: 'available' }),
      expect.objectContaining({ id: 'workbench', status: 'available' }),
      expect.objectContaining({ id: 'cto_orchestration', status: 'degraded' }),
    ]))
    expect(instance.experience).toEqual({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      descriptorDigest: {
        algorithm: 'sha256',
        value: `sha256:${'d'.repeat(64)}`,
      },
      views: [
        expect.objectContaining({
          viewId: 'project-home',
          component: 'application_home',
          declaredRoute: '/application',
          visible: true,
        }),
        expect.objectContaining({
          viewId: 'project-workbench',
          component: 'development_workbench',
          declaredRoute: '/workbench',
          visible: true,
        }),
      ],
      navigation: [
        expect.objectContaining({
          contributionId: 'project-home-nav',
          viewId: 'project-home',
          placement: 'application',
          order: 10,
          visible: true,
        }),
        expect.objectContaining({
          contributionId: 'project-workbench-nav',
          viewId: 'project-workbench',
          placement: 'advanced',
          order: 30,
          visible: true,
        }),
      ],
      advancedControls: [
        {
          controlId: 'project-files',
          label: 'Files',
          component: 'file_viewer',
          capability: 'file_viewer',
          order: 20,
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
    })
    // Catalog/package identity and resolved descriptor identity are distinct
    // authorities; neither is rewritten to look equivalent to the other.
    expect(instance.packageId).not.toBe(instance.experience?.applicationId)
  })

  it('derives usable receipts from a resolved receipt_list advanced control', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'studystate.sample',
      capabilities: [{ id: 'goal_execution', status: 'available' }],
      views: [],
      navigation: [],
      advancedControls: [
        {
          controlId: 'sample-study-receipts',
          label: 'Receipts',
          component: 'receipt_list',
          capability: 'goal_execution',
          order: 40,
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
    })

    const instance = await client.get('ins_1')
    expect(instance.capabilities).toContainEqual({
      id: 'receipts',
      status: 'available',
      reason: undefined,
    })
    expect(instance.experience?.advancedControls).toContainEqual(
      expect.objectContaining({
        component: 'receipt_list',
        capability: 'receipts',
        visible: true,
      }),
    )
    expect(applicationDestinationAvailable(instance, 'receipts')).toBe(true)
    expect(applicationNavigation(instance).map((item) => item.destination)).toContain('receipts')
  })

  it('derives usable receipts from a CTO receipt control without remapping other CTO controls', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'nixos-infrastructure',
      capabilities: [
        { id: 'goal_execution', status: 'available' },
        { id: 'cto_orchestration', status: 'available' },
      ],
      views: [],
      navigation: [],
      advancedControls: [
        {
          controlId: 'nixos-runs',
          label: 'Runs',
          component: 'run_history',
          capability: 'cto_orchestration',
          order: 40,
          status: 'available',
          reasons: [],
          visible: true,
        },
        {
          controlId: 'nixos-receipts',
          label: 'Receipts',
          component: 'receipt_list',
          capability: 'cto_orchestration',
          order: 50,
          status: 'available',
          reasons: [],
          visible: true,
        },
        {
          controlId: 'nixos-cto',
          label: 'CTO advisory',
          component: 'cto_orchestration',
          capability: 'cto_orchestration',
          order: 60,
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
    })

    const instance = await client.get('ins_1')
    expect(instance.capabilities).toEqual(expect.arrayContaining([
      { id: 'goal_execution', status: 'available', reason: undefined },
      { id: 'cto_orchestration', status: 'available', reason: undefined },
      { id: 'receipts', status: 'available', reason: undefined },
    ]))
    expect(instance.experience?.advancedControls).toEqual(expect.arrayContaining([
      expect.objectContaining({
        controlId: 'nixos-runs',
        component: 'run_history',
        capability: 'cto_orchestration',
        visible: true,
      }),
      expect.objectContaining({
        controlId: 'nixos-receipts',
        component: 'receipt_list',
        capability: 'receipts',
        visible: true,
      }),
      expect.objectContaining({
        controlId: 'nixos-cto',
        component: 'cto_orchestration',
        capability: 'cto_orchestration',
        visible: true,
      }),
    ]))
    expect(applicationNavigation(instance).map((item) => item.destination)).toEqual(
      expect.arrayContaining(['runs', 'receipts']),
    )
    expect(applicationNavigation(instance).map((item) => item.destination)).not.toContain('cto_orchestration')
  })

  it('does not derive receipts when no receipt control is declared', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'nixos-infrastructure',
      capabilities: [
        { id: 'goal_execution', status: 'available' },
        { id: 'cto_orchestration', status: 'available' },
      ],
      views: [],
      navigation: [],
      advancedControls: [],
    })

    const instance = await client.get('ins_1')
    expect(instance.capabilities).not.toContainEqual(expect.objectContaining({ id: 'receipts' }))
    expect(applicationDestinationAvailable(instance, 'receipts')).toBe(false)
    expect(applicationNavigation(instance).map((item) => item.destination)).not.toContain('receipts')
  })

  it('keeps hidden, unavailable, invalid, and unregistered receipt controls fail-closed', async () => {
    const cases = [
      {
        name: 'unavailable',
        control: {
          controlId: 'sample-study-receipts',
          label: 'Receipts',
          component: 'receipt_list',
          capability: 'goal_execution',
          order: 40,
          status: 'unavailable',
          reasons: ['receipt_store_unavailable'],
          visible: true,
        },
      },
      {
        name: 'hidden',
        control: {
          controlId: 'sample-study-receipts',
          label: 'Receipts',
          component: 'receipt_list',
          capability: 'goal_execution',
          order: 40,
          status: 'available',
          reasons: [],
          visible: false,
        },
      },
      {
        name: 'unknown wire capability',
        control: {
          controlId: 'sample-study-receipts',
          label: 'Receipts',
          component: 'receipt_list',
          capability: 'receipt_goal',
          order: 40,
          status: 'available',
          reasons: [],
          visible: true,
        },
      },
      {
        name: 'other CTO control',
        control: {
          controlId: 'sample-study-runs',
          label: 'Runs',
          component: 'run_history',
          capability: 'cto_orchestration',
          order: 40,
          status: 'available',
          reasons: [],
          visible: true,
        },
      },
      {
        name: 'unregistered control',
        control: {
          controlId: 'sample-study-receipt-list',
          label: 'Receipts',
          component: 'receipt_list',
          capability: 'goal_execution',
          order: 40,
          status: 'available',
          reasons: [],
          visible: true,
        },
      },
    ] as const

    for (const testCase of cases) {
      const client = applicationsClient({
        formatVersion: 'stateport.application-experience-resolution/v1',
        applicationId: 'studystate.sample',
        capabilities: [{ id: 'goal_execution', status: 'available' }],
        views: [],
        navigation: [],
        advancedControls: [testCase.control],
      })
      const instance = await client.get('ins_1')
      expect(applicationDestinationAvailable(instance, 'receipts'), testCase.name).toBe(false)
      expect(applicationDestinationAvailable(instance, 'workbench'), testCase.name).toBe(false)
      expect(applicationNavigation(instance).map((item) => item.destination), testCase.name).not.toContain('receipts')
      expect(applicationNavigation(instance).map((item) => item.destination), testCase.name).not.toContain('workbench')
      if (testCase.name === 'unavailable' || testCase.name === 'hidden') {
        expect(instance.experience?.advancedControls, testCase.name).toContainEqual(
          expect.objectContaining({
            component: 'receipt_list',
            capability: 'receipts',
            visible: false,
          }),
        )
      } else if (testCase.name === 'unregistered control') {
        // Mapping preserves the validated bridge; the trusted registry still
        // refuses the unregistered control as a navigable destination.
        expect(instance.capabilities, testCase.name).toContainEqual(
          expect.objectContaining({ id: 'receipts', status: 'available' }),
        )
        expect(instance.experience?.advancedControls, testCase.name).toContainEqual(
          expect.objectContaining({ component: 'receipt_list', capability: 'receipts' }),
        )
      } else {
        expect(instance.capabilities, testCase.name).not.toContainEqual(expect.objectContaining({ id: 'receipts' }))
        expect(instance.experience?.advancedControls, testCase.name).not.toContainEqual(
          expect.objectContaining({ component: 'receipt_list', capability: 'receipts' }),
        )
      }
    }
  })

  it('keeps unsupported future renderer identifiers out of the browser experience', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      capabilities: [
        { id: 'conversation', status: 'available', reasons: [] },
      ],
      views: [
        {
          viewId: 'future-view',
          label: 'Future',
          component: 'package_supplied_javascript',
          route: '/conversation',
          capability: 'conversation',
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
      navigation: [
        {
          contributionId: 'future-nav',
          label: 'Future',
          viewId: 'future-view',
          placement: 'conversation',
          order: 1,
          visible: true,
        },
      ],
    })

    const instance = await client.get('ins_1')
    expect(instance.capabilities).toEqual([
      { id: 'conversation', status: 'available', reason: undefined },
    ])
    expect(instance.experience?.views).toEqual([])
    expect(instance.experience?.navigation).toEqual([
      expect.objectContaining({ contributionId: 'future-nav', visible: false }),
    ])
    expect(instance.experience?.advancedControls).toEqual([])
  })

  it('binds a resolved experience to the requested instance identity', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      instanceBinding: {
        instanceId: 'ins_other',
        applicationId: 'stateport.development-reference',
        descriptorDigest: `sha256:${'d'.repeat(64)}`,
      },
      descriptorIdentity: {
        applicationId: 'stateport.development-reference',
        descriptorDigest: `sha256:${'d'.repeat(64)}`,
      },
      capabilities: [{ id: 'goal_execution', status: 'available' }],
      views: [],
      navigation: [],
      advancedControls: [],
    })

    await expect(client.get('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it('fails closed on contradictory application or descriptor bindings', async () => {
    for (const binding of [
      {
        instanceId: 'ins_1',
        applicationId: 'nixos-infrastructure',
        descriptorDigest: `sha256:${'d'.repeat(64)}`,
      },
      {
        instanceId: 'ins_1',
        applicationId: 'stateport.development-reference',
        descriptorDigest: `sha256:${'e'.repeat(64)}`,
      },
    ]) {
      const client = applicationsClient({
        formatVersion: 'stateport.application-experience-resolution/v1',
        applicationId: 'stateport.development-reference',
        instanceBinding: binding,
        descriptorIdentity: {
          applicationId: 'stateport.development-reference',
          descriptorDigest: `sha256:${'d'.repeat(64)}`,
        },
        capabilities: [{ id: 'goal_execution', status: 'available' }],
        views: [],
        navigation: [],
        advancedControls: [],
      })
      await expect(client.get('ins_1')).rejects.toMatchObject({
        kind: 'validation',
      })
    }
  })

  it('hides unknown component, capability, and invalid-order controls', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      capabilities: [
        { id: 'goal_execution', status: 'available' },
        { id: 'cto_orchestration', status: 'available' },
      ],
      views: [],
      navigation: [],
      advancedControls: [
        {
          controlId: 'unknown-component',
          label: 'Unknown component',
          component: 'package_javascript',
          capability: 'goal_execution',
          order: 1,
          status: 'available',
          reasons: [],
          visible: true,
        },
        {
          controlId: 'unknown-capability',
          label: 'Unknown capability',
          component: 'run_history',
          capability: 'root_shell',
          order: 2,
          status: 'available',
          reasons: [],
          visible: true,
        },
        {
          controlId: 'invalid-order',
          label: 'Invalid order',
          component: 'run_history',
          capability: 'goal_execution',
          order: 1001,
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
    })

    await expect(client.get('ins_1')).resolves.toMatchObject({
      experience: { advancedControls: [] },
    })
  })

  it('preserves control label and order but fails closed on its status and visibility', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      capabilities: [{ id: 'goal_execution', status: 'available' }],
      views: [],
      navigation: [],
      advancedControls: [
        {
          controlId: 'project-runs',
          label: 'Backend ordered history',
          component: 'run_history',
          capability: 'goal_execution',
          order: 73,
          status: 'future_state',
          reasons: ['unsupported_runtime_state'],
          visible: true,
        },
      ],
    })

    await expect(client.get('ins_1')).resolves.toMatchObject({
      experience: {
        advancedControls: [{
          controlId: 'project-runs',
          label: 'Backend ordered history',
          order: 73,
          status: 'unavailable',
          visible: false,
        }],
      },
    })
  })

  it('rejects duplicate advanced-control identities', async () => {
    const duplicate = {
      controlId: 'project-runs',
      label: 'Runs',
      component: 'run_history',
      capability: 'goal_execution',
      order: 30,
      status: 'available',
      reasons: [],
      visible: true,
    }
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v1',
      applicationId: 'stateport.development-reference',
      capabilities: [{ id: 'goal_execution', status: 'available' }],
      views: [],
      navigation: [],
      advancedControls: [duplicate, { ...duplicate, label: 'Injected duplicate' }],
    })

    await expect(client.get('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it('fails closed when the backend experience format version is unknown', async () => {
    const client = applicationsClient({
      formatVersion: 'stateport.application-experience-resolution/v999',
      capabilities: [{ id: 'workbench', status: 'available' }],
      views: [],
    })

    await expect(client.get('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it('keeps an explicit unavailable experience routeless without treating it as legacy', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances', jsonResponse({ instances: [INSTANCE] })],
      [
        'GET',
        '/v1/instances/ins_1/experience',
        jsonResponse(
          {
            ok: false,
            error: {
              code: 'experience_unavailable',
              message: 'Application experience is not registered.',
            },
          },
          404,
        ),
      ],
      ['GET', '/v1/instances/ins_1', jsonResponse({ ok: true, result: INSTANCE })],
    ])
    const client = new HttpApplicationsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(client.get('ins_1')).resolves.toMatchObject({
      capabilities: [],
      experience: undefined,
      experienceResolution: 'unavailable',
    })
  })

  it('does not downgrade an experience service failure to legacy capability routes', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances', jsonResponse({ instances: [INSTANCE] })],
      [
        'GET',
        '/v1/instances/ins_1/experience',
        jsonResponse(
          {
            ok: false,
            error: {
              code: 'experience_resolution_failed',
              message: 'Experience resolution failed.',
            },
          },
          503,
        ),
      ],
      ['GET', '/v1/instances/ins_1', jsonResponse({ ok: true, result: INSTANCE })],
    ])
    const client = new HttpApplicationsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(client.get('ins_1')).rejects.toMatchObject({
      kind: 'http',
      status: 503,
      code: 'experience_resolution_failed',
    })
  })

  it('environment-gates path-bound tools when the authoritative catalog path is stale', () => {
    const instance = mapInstance(
      {
        id: 'ins_stale',
        applicationId: 'stateport.development-reference',
        health: 'unavailable',
        instance: { id: 'ins_stale', pathState: 'stale' },
      },
      {
        experience: {
          packageId: 'stateport.development-reference',
          capabilities: [
            { id: 'conversation', status: 'available' },
            { id: 'workbench', status: 'available' },
            { id: 'file_viewer', status: 'available' },
            { id: 'terminal', status: 'available' },
            { id: 'cto_orchestration', status: 'degraded', reason: 'provider-free advisory only' },
            { id: 'receipts', status: 'degraded' },
          ],
        },
      },
    )

    expect(instance.capabilities.find((item) => item.id === 'conversation')?.status).toBe('available')
    expect(instance.capabilities.find((item) => item.id === 'workbench')?.status).toBe('available')
    expect(instance.capabilities.find((item) => item.id === 'receipts')?.status).toBe('degraded')
    for (const id of ['file_viewer', 'terminal', 'cto_orchestration'] as const) {
      expect(instance.capabilities.find((item) => item.id === id)).toMatchObject({
        status: 'environment_gated',
        reason: expect.stringContaining('cataloged application path'),
      })
    }
  })

  it('maps the backend valid health state to a ready application', () => {
    expect(mapInstance(
      {
        health: 'valid',
        instance: { id: 'ins_valid', name: 'Valid fixture', pathState: 'present' },
      },
      {
        experience: {
          packageId: 'stateport.development-reference',
          capabilities: [{ id: 'workbench', status: 'available' }],
        },
      },
    )).toMatchObject({
      id: 'ins_valid',
      health: 'ready',
      capabilities: [{ id: 'workbench', status: 'available' }],
    })
  })

  it('terminal targets derive from capabilities (unavailable → no targets)', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/experience',
        jsonResponse({ capabilities: [{ id: 'terminal', status: 'unavailable' }] }),
      ],
    ])
    const terminal = new HttpTerminalClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await expect(terminal.listTargets('ins_1')).resolves.toEqual([])
  })

  it('terminal targets derive from capabilities (available → local PTY target)', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/experience',
        jsonResponse({ capabilities: [{ id: 'terminal', status: 'available' }] }),
      ],
    ])
    const terminal = new HttpTerminalClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const targets = await terminal.listTargets('ins_1')
    expect(targets).toHaveLength(1)
    expect(targets[0]).toMatchObject({ kind: 'unresolved', label: 'Application terminal — target verified on connect', available: true, instanceId: 'ins_1' })
  })
})

describe('application catalog mapping', () => {
  it('keeps unavailable backend entries whose experience identity is explicitly null', () => {
    const packages = mapCatalog({
      applications: [{
        applicationId: 'stateport.synthetic-reference',
        displayName: 'Synthetic reference',
        description: 'A public-safe unavailable fixture.',
        experienceIdentity: null,
        install: {
          confirmationRequired: true,
          networkPolicy: 'not_evaluated',
          requestedCapabilities: [],
          status: 'unavailable',
        },
      }],
    })

    expect(packages).toHaveLength(1)
    expect(packages[0]).toMatchObject({
      pkg: {
        id: 'stateport.synthetic-reference',
        displayName: 'Synthetic reference',
        capabilities: [],
      },
      installRequiresApproval: true,
      installAvailable: false,
      installUnavailableReason: 'The connected service does not offer this package for installation.',
    })
  })

  it('maps the backend installation result without retrying a completed mutation', () => {
    expect(mapInstallReceipt({
      entry: {
        applicationId: 'stateport.development-reference',
        instanceId: 'ins_frontend_fixture',
        status: 'active',
      },
      receipt: {
        formatVersion: 'stateport.application-install-receipt/v1',
        receiptId: 'application-install.ins_frontend_fixture.abc123abc123',
        receiptDigest: `sha256:${'a'.repeat(64)}`,
      },
    })).toEqual({
      applicationId: 'stateport.development-reference',
      instanceId: 'ins_frontend_fixture',
      receiptId: 'application-install.ins_frontend_fixture.abc123abc123',
      receiptDigest: {
        algorithm: 'sha256',
        value: `sha256:${'a'.repeat(64)}`,
      },
    })
  })
})

describe('file workspace adapter', () => {
  it('maps the governed broker directory projection', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/file-workspace/listDirectory', jsonResponse({
        operation: 'listDirectory',
        path: '',
        baseSha: 'a'.repeat(40),
        truncated: false,
        entries: [{
          path: 'README.md',
          name: 'README.md',
          kind: 'file',
          size: 42,
          readOnly: false,
        }],
      })],
    ])
    const files = new HttpFilesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await expect(files.listTree('ins_1')).resolves.toEqual([
      expect.objectContaining({ path: 'README.md', kind: 'file', sizeBytes: 42 }),
    ])
  })
})
