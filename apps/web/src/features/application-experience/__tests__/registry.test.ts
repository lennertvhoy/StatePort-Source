import { describe, expect, it } from 'vitest'

import type {
  ApplicationInstance,
  ResolvedApplicationExperience,
} from '@/client'
import { schemas } from '@/client'
import { buildSeed } from '@/client/mock/seed'

import {
  applicationDestinationAvailable,
  applicationNavigation,
} from '../registry'

function experience(
  overrides: Partial<ResolvedApplicationExperience> = {},
): ResolvedApplicationExperience {
  return {
    formatVersion: 'stateport.application-experience-resolution/v1',
    applicationId: 'stateport.development-reference',
    views: [
      {
        viewId: 'home',
        label: 'Learning',
        component: 'progress_overview',
        declaredRoute: '/application',
        capability: 'progress_dashboard',
        status: 'available',
        reasons: [],
        visible: true,
      },
      {
        viewId: 'chat',
        label: 'Conversation',
        component: 'conversation_thread',
        declaredRoute: '/conversation',
        capability: 'conversation',
        status: 'available',
        reasons: [],
        visible: true,
      },
      {
        viewId: 'activity',
        label: 'Next activity',
        component: 'goal_actions',
        declaredRoute: '/application/activity',
        capability: 'goal_execution',
        status: 'degraded',
        reasons: ['provider_free_bounded_actions_and_receipts_only'],
        visible: true,
      },
    ],
    navigation: [
      {
        contributionId: 'home-nav',
        label: 'Learning',
        viewId: 'home',
        placement: 'application',
        order: 10,
        visible: true,
      },
      {
        contributionId: 'chat-nav',
        label: 'Conversation',
        viewId: 'chat',
        placement: 'conversation',
        order: 20,
        visible: true,
      },
      {
        contributionId: 'activity-nav',
        label: 'Next activity',
        viewId: 'activity',
        placement: 'application',
        order: 30,
        visible: true,
      },
    ],
    advancedControls: [
      {
        controlId: 'project-runs',
        label: 'Governed history',
        component: 'run_history',
        capability: 'goal_execution',
        order: 25,
        status: 'degraded',
        reasons: ['provider_free_bounded_actions_and_receipts_only'],
        visible: true,
      },
    ],
    ...overrides,
  }
}

function instance(
  resolvedExperience: ResolvedApplicationExperience | null = experience(),
): ApplicationInstance {
  const seeded = buildSeed().instances.find((candidate) =>
    candidate.id === 'ins_study_alpha',
  )
  if (!seeded) throw new Error('StudyState fixture missing')
  return schemas.applicationInstance.parse({
    ...seeded,
    capabilities: [
      { id: 'conversation', status: 'available' },
      { id: 'progress_dashboard', status: 'available' },
      { id: 'goal_execution', status: 'degraded' },
      { id: 'workbench', status: 'available' },
      { id: 'cto_orchestration', status: 'degraded' },
    ],
    experience: resolvedExperience ?? undefined,
  })
}

describe('trusted application-view registry', () => {
  it('uses resolved descriptor labels and order for registered StatePort surfaces', () => {
    expect(applicationNavigation(instance()).map((item) => ({
      destination: item.destination,
      label: item.label,
      source: item.source,
    }))).toEqual([
      { destination: 'overview', label: 'Learning', source: 'descriptor' },
      { destination: 'conversation', label: 'Conversation', source: 'descriptor' },
      { destination: 'runs', label: 'Governed history', source: 'descriptor' },
      { destination: 'settings', label: 'Settings', source: 'stateport' },
    ])
  })

  it('does not turn an unregistered component, route, capability, or placement into navigation', () => {
    const unsafe = experience({
      views: [
        {
          viewId: 'unsafe',
          label: 'Injected',
          component: 'terminal_surface',
          declaredRoute: '/conversation',
          capability: 'conversation',
          status: 'available',
          reasons: [],
          visible: true,
        },
      ],
      navigation: [
        {
          contributionId: 'unsafe-nav',
          label: 'Injected',
          viewId: 'unsafe',
          placement: 'conversation',
          order: 1,
          visible: true,
        },
      ],
    })

    const nav = applicationNavigation(instance(unsafe))
    expect(nav.map((item) => item.label)).not.toContain('Injected')
    expect(nav.map((item) => item.destination)).toEqual([
      'overview',
      'runs',
      'settings',
    ])
    expect(applicationDestinationAvailable(instance(unsafe), 'conversation')).toBe(false)
  })

  it('intersects descriptor visibility with the effective instance capability', () => {
    const value = instance()
    value.capabilities = value.capabilities.map((capability) =>
      capability.id === 'conversation'
        ? { ...capability, status: 'environment_gated' }
        : capability,
    )

    expect(applicationNavigation(value).map((item) => item.destination)).not.toContain('conversation')
    expect(applicationDestinationAvailable(value, 'conversation')).toBe(false)
  })

  it('does not expose Runs from goal_execution capability or goal_actions alone', () => {
    const value = instance(experience({ advancedControls: [] }))

    expect(value.capabilities).toContainEqual(
      expect.objectContaining({ id: 'goal_execution', status: 'degraded' }),
    )
    expect(value.experience?.views).toContainEqual(
      expect.objectContaining({ component: 'goal_actions', visible: true }),
    )
    expect(applicationNavigation(value).map((item) => item.destination)).not.toContain('runs')
    expect(applicationDestinationAvailable(value, 'runs')).toBe(false)
  })

  it('maps only the exact NixOS run-history control with its declared CTO semantics', () => {
    const value = instance(experience({
      applicationId: 'nixos-infrastructure',
      advancedControls: [
        {
          controlId: 'nixos-runs',
          label: 'Infrastructure runs',
          component: 'run_history',
          capability: 'cto_orchestration',
          order: 47,
          status: 'degraded',
          reasons: ['provider_free_advisory_and_governed_receipts_only'],
          visible: true,
        },
      ],
    }))

    expect(applicationNavigation(value)).toContainEqual(expect.objectContaining({
      destination: 'runs',
      label: 'Infrastructure runs',
      order: 47,
      source: 'descriptor',
    }))
    expect(applicationDestinationAvailable(value, 'runs')).toBe(true)

    value.capabilities = value.capabilities.map((capability) =>
      capability.id === 'cto_orchestration'
        ? { ...capability, status: 'environment_gated' }
        : capability,
    )
    expect(applicationNavigation(value).map((item) => item.destination)).not.toContain('runs')
    expect(applicationDestinationAvailable(value, 'runs')).toBe(false)
  })

  it.each([
    ['studydd', 'study-runs'],
    ['studystate.sample', 'sample-study-runs'],
    ['checklistdd', 'checklist-runs'],
  ])(
    'maps the reviewed %s goal-execution history control without granting Workbench',
    (applicationId, controlId) => {
      const value = instance(
        experience({
          applicationId,
          advancedControls: [
            {
              controlId,
              label: 'Governed runs',
              component: 'run_history',
              capability: 'goal_execution',
              order: 35,
              status: 'degraded',
              reasons: ['provider_free_bounded_actions_and_receipts_only'],
              visible: true,
            },
          ],
        }),
      )

      expect(applicationNavigation(value)).toContainEqual(
        expect.objectContaining({
          destination: 'runs',
          label: 'Governed runs',
          source: 'descriptor',
        }),
      )
      expect(applicationDestinationAvailable(value, 'runs')).toBe(true)
      expect(applicationDestinationAvailable(value, 'workbench')).toBe(false)
    },
  )

  it('maps a receipt-only control without requiring goal execution or CTO capability', () => {
    const value = instance(
      experience({
        applicationId: 'studystate.sample',
        advancedControls: [
          {
            controlId: 'sample-study-receipts',
            label: 'Receipts',
            component: 'receipt_list',
            capability: 'receipts',
            order: 40,
            status: 'available',
            reasons: [],
            visible: true,
          },
        ],
      }),
    )
    value.capabilities = value.capabilities
      .filter((capability) => !['workbench', 'goal_execution', 'cto_orchestration'].includes(capability.id))
      .concat({ id: 'receipts', status: 'available' })

    expect(applicationNavigation(value)).toContainEqual(
      expect.objectContaining({
        destination: 'receipts',
        label: 'Receipts',
        to: 'receipts',
        source: 'descriptor',
      }),
    )
    expect(applicationNavigation(value).map((item) => item.destination)).not.toContain('workbench')
    expect(applicationDestinationAvailable(value, 'receipts')).toBe(true)
    expect(applicationDestinationAvailable(value, 'workbench')).toBe(false)
  })

  it('cannot register Runs from unknown or almost-matching advanced controls', () => {
    const controls = [
      {
        controlId: 'package-runs',
        label: 'Injected id',
        component: 'run_history' as const,
        capability: 'goal_execution' as const,
        order: 1,
        status: 'available' as const,
        reasons: [],
        visible: true,
      },
      {
        controlId: 'project-runs',
        label: 'Wrong component',
        component: 'activity_history' as const,
        capability: 'goal_execution' as const,
        order: 2,
        status: 'available' as const,
        reasons: [],
        visible: true,
      },
      {
        controlId: 'project-runs',
        label: 'Wrong capability',
        component: 'run_history' as const,
        capability: 'cto_orchestration' as const,
        order: 3,
        status: 'available' as const,
        reasons: [],
        visible: true,
      },
    ]
    for (const control of controls) {
      const value = instance(experience({ advancedControls: [control] }))
      expect(applicationNavigation(value).map((item) => item.destination)).not.toContain('runs')
      expect(applicationDestinationAvailable(value, 'runs')).toBe(false)
    }
  })

  it('uses the same registered projection for direct routes and navigation', () => {
    const value = instance()
    for (const destination of ['overview', 'conversation', 'runs', 'workbench', 'settings'] as const) {
      expect(applicationDestinationAvailable(value, destination)).toBe(
        applicationNavigation(value).some((item) => item.destination === destination),
      )
    }
  })

  it('preserves capability-gated legacy/mock behavior when no resolved experience exists', () => {
    const value = instance(null)
    expect(applicationNavigation(value).map((item) => item.destination)).toEqual([
      'overview',
      'conversation',
      'runs',
      'workbench',
      'settings',
    ])
  })

  it('does not activate legacy routes when the backend explicitly reports no experience', () => {
    const value = instance(null)
    value.experienceResolution = 'unavailable'

    expect(applicationNavigation(value).map((item) => item.destination)).toEqual([
      'overview',
      'settings',
    ])
    expect(applicationDestinationAvailable(value, 'conversation')).toBe(false)
    expect(applicationDestinationAvailable(value, 'runs')).toBe(false)
    expect(applicationDestinationAvailable(value, 'workbench')).toBe(false)
  })
})
