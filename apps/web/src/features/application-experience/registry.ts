/**
 * Static application-view registry.
 *
 * Backend experience descriptors select from trusted identifiers, but they do
 * not register frontend routes or components. This table is the browser-side
 * half of that boundary: only reviewed StatePort-owned component, capability,
 * route, and placement combinations can resolve to an existing destination.
 */
import type {
  ApplicationInstance,
  ApplicationExperienceComponent,
  ApplicationNavigationPlacement,
  CapabilityId,
  ResolvedApplicationAdvancedControl,
  ResolvedApplicationView,
} from '@/client'

export type ApplicationDestination =
  | 'overview'
  | 'conversation'
  | 'runs'
  | 'workbench'
  | 'receipts'
  | 'settings'

export type ApplicationNavIcon =
  | 'overview'
  | 'conversation'
  | 'runs'
  | 'workbench'
  | 'receipts'
  | 'settings'

export interface ApplicationNavigationItem {
  destination: ApplicationDestination
  to: string
  label: string
  icon: ApplicationNavIcon
  order: number
  end?: boolean
  source: 'descriptor' | 'stateport'
}

interface RegisteredApplicationView {
  destination: 'overview' | 'conversation' | 'workbench' | 'receipts'
  component: ResolvedApplicationView['component']
  capability: CapabilityId
  declaredRoute: string
  placements: readonly ApplicationNavigationPlacement[]
  to: string
  icon: ApplicationNavIcon
  end?: boolean
}

interface RegisteredAdvancedControl {
  applicationId: string
  controlId: string
  destination: 'runs' | 'receipts'
  component: ApplicationExperienceComponent
  capability: CapabilityId
  requiredCapabilities: readonly CapabilityId[]
  to: string
  icon: ApplicationNavIcon
}

/**
 * Deliberately smaller than the backend's trusted-component vocabulary.
 * Components without a shipped product surface remain non-routable.
 */
const VIEW_REGISTRY: readonly RegisteredApplicationView[] = [
  {
    destination: 'overview',
    component: 'application_home',
    capability: 'progress_dashboard',
    declaredRoute: '/application',
    placements: ['application'],
    to: '',
    icon: 'overview',
    end: true,
  },
  {
    destination: 'overview',
    component: 'progress_overview',
    capability: 'progress_dashboard',
    declaredRoute: '/application',
    placements: ['application'],
    to: '',
    icon: 'overview',
    end: true,
  },
  {
    destination: 'conversation',
    component: 'conversation_thread',
    capability: 'conversation',
    declaredRoute: '/conversation',
    placements: ['conversation'],
    to: 'conversation',
    icon: 'conversation',
  },
  {
    destination: 'workbench',
    component: 'development_workbench',
    capability: 'workbench',
    declaredRoute: '/workbench',
    placements: ['advanced'],
    to: 'workbench',
    icon: 'workbench',
  },
  {
    destination: 'receipts',
    component: 'receipt_list',
    capability: 'receipts',
    declaredRoute: '/receipts',
    placements: ['advanced'],
    to: 'receipts',
    icon: 'receipts',
  },
] as const

/**
 * Advanced controls do not register arbitrary routes either. The shipped Runs
 * and native Receipts surfaces are selected only by exact reviewed controls in
 * the canonical application descriptors. In particular, a capability alone or
 * a similarly named component from a different application is insufficient.
 */
const ADVANCED_CONTROL_REGISTRY: readonly RegisteredAdvancedControl[] = [
  {
    applicationId: 'stateport.development-reference',
    controlId: 'project-runs',
    destination: 'runs',
    component: 'run_history',
    capability: 'goal_execution',
    requiredCapabilities: ['goal_execution'],
    to: 'runs',
    icon: 'runs',
  },
  {
    applicationId: 'nixos-infrastructure',
    controlId: 'nixos-runs',
    destination: 'runs',
    component: 'run_history',
    capability: 'cto_orchestration',
    requiredCapabilities: ['goal_execution', 'cto_orchestration'],
    to: 'runs',
    icon: 'runs',
  },
  {
    applicationId: 'studydd',
    controlId: 'study-runs',
    destination: 'runs',
    component: 'run_history',
    capability: 'goal_execution',
    requiredCapabilities: ['goal_execution'],
    to: 'runs',
    icon: 'runs',
  },
  {
    applicationId: 'studystate.sample',
    controlId: 'sample-study-runs',
    destination: 'runs',
    component: 'run_history',
    capability: 'goal_execution',
    requiredCapabilities: ['goal_execution'],
    to: 'runs',
    icon: 'runs',
  },
  {
    applicationId: 'checklistdd',
    controlId: 'checklist-runs',
    destination: 'runs',
    component: 'run_history',
    capability: 'goal_execution',
    requiredCapabilities: ['goal_execution'],
    to: 'runs',
    icon: 'runs',
  },
  {
    applicationId: 'stateport.development-reference',
    controlId: 'project-receipts',
    destination: 'receipts',
    component: 'receipt_list',
    capability: 'receipts',
    requiredCapabilities: ['receipts'],
    to: 'receipts',
    icon: 'receipts',
  },
  {
    applicationId: 'studydd',
    controlId: 'study-receipts',
    destination: 'receipts',
    component: 'receipt_list',
    capability: 'receipts',
    requiredCapabilities: ['receipts'],
    to: 'receipts',
    icon: 'receipts',
  },
  {
    applicationId: 'studystate.sample',
    controlId: 'sample-study-receipts',
    destination: 'receipts',
    component: 'receipt_list',
    capability: 'receipts',
    requiredCapabilities: ['receipts'],
    to: 'receipts',
    icon: 'receipts',
  },
  {
    applicationId: 'checklistdd',
    controlId: 'checklist-receipts',
    destination: 'receipts',
    component: 'receipt_list',
    capability: 'receipts',
    requiredCapabilities: ['receipts'],
    to: 'receipts',
    icon: 'receipts',
  },
  {
    applicationId: 'nixos-infrastructure',
    controlId: 'nixos-receipts',
    destination: 'receipts',
    component: 'receipt_list',
    capability: 'receipts',
    requiredCapabilities: ['receipts'],
    to: 'receipts',
    icon: 'receipts',
  },
] as const

function capabilityUsable(instance: ApplicationInstance, id: CapabilityId): boolean {
  const status = instance.capabilities.find((candidate) => candidate.id === id)?.status
  return status === 'available' || status === 'degraded'
}

function registeredView(
  view: ResolvedApplicationView,
  placement?: ApplicationNavigationPlacement,
): RegisteredApplicationView | undefined {
  return VIEW_REGISTRY.find((candidate) =>
    candidate.component === view.component &&
    candidate.capability === view.capability &&
    candidate.declaredRoute === view.declaredRoute &&
    (placement === undefined || candidate.placements.includes(placement)),
  )
}

function registeredAdvancedControl(
  applicationId: string,
  control: ResolvedApplicationAdvancedControl,
): RegisteredAdvancedControl | undefined {
  return ADVANCED_CONTROL_REGISTRY.find((candidate) =>
    candidate.applicationId === applicationId &&
    candidate.controlId === control.controlId &&
    candidate.component === control.component &&
    candidate.capability === control.capability,
  )
}

/**
 * Route authorization is the intersection of the effective capability and a
 * registered resolved navigation contribution or advanced control. Calling
 * the same projection used by the nav keeps direct deep-link guards and
 * visible navigation in lockstep.
 */
export function applicationDestinationAvailable(
  instance: ApplicationInstance,
  destination: ApplicationDestination,
): boolean {
  return applicationNavigation(instance).some((item) => item.destination === destination)
}

export function applicationNavigation(instance: ApplicationInstance): ApplicationNavigationItem[] {
  const items: ApplicationNavigationItem[] = []
  const seen = new Set<ApplicationDestination>()

  for (const contribution of instance.experience?.navigation ?? []) {
    if (!contribution.visible) continue
    const view = instance.experience?.views.find((candidate) =>
      candidate.viewId === contribution.viewId && candidate.visible,
    )
    if (!view || !capabilityUsable(instance, view.capability)) continue
    const registered = registeredView(view, contribution.placement)
    if (!registered || seen.has(registered.destination)) continue
    seen.add(registered.destination)
    items.push({
      destination: registered.destination,
      to: registered.to,
      label: contribution.label,
      icon: registered.icon,
      order: contribution.order,
      end: registered.end,
      source: 'descriptor',
    })
  }

  for (const control of instance.experience?.advancedControls ?? []) {
    if (!control.visible || !capabilityUsable(instance, control.capability)) continue
    const registered = registeredAdvancedControl(instance.experience!.applicationId, control)
    if (
      !registered ||
      seen.has(registered.destination) ||
      !registered.requiredCapabilities.every((capability) =>
        capabilityUsable(instance, capability)
      )
    ) {
      continue
    }
    seen.add(registered.destination)
    items.push({
      destination: registered.destination,
      to: registered.to,
      label: control.label,
      icon: registered.icon,
      order: control.order,
      source: 'descriptor',
    })
  }

  // The application shell remains usable even if a future/unsupported
  // descriptor contributes no home renderer.
  if (!seen.has('overview')) {
    seen.add('overview')
    items.push({
      destination: 'overview',
      to: '',
      label: 'Overview',
      icon: 'overview',
      order: 0,
      end: true,
      source: 'stateport',
    })
  }

  if (!instance.experience && instance.experienceResolution === undefined) {
    const legacy: Array<{
      destination: 'conversation' | 'runs' | 'workbench' | 'receipts'
      capability: CapabilityId
      to: string
      label: string
      icon: ApplicationNavIcon
      order: number
    }> = [
      {
        destination: 'conversation',
        capability: 'conversation',
        to: 'conversation',
        label: 'Conversation',
        icon: 'conversation',
        order: 20,
      },
      {
        destination: 'runs',
        capability: 'goal_execution',
        to: 'runs',
        label: 'Runs',
        icon: 'runs',
        order: 25,
      },
      {
        destination: 'workbench',
        capability: 'workbench',
        to: 'workbench',
        label: 'Workbench',
        icon: 'workbench',
        order: 30,
      },
      {
        destination: 'receipts',
        capability: 'receipts',
        to: 'receipts',
        label: 'Receipts',
        icon: 'receipts',
        order: 35,
      },
    ]
    for (const candidate of legacy) {
      if (seen.has(candidate.destination) || !capabilityUsable(instance, candidate.capability)) continue
      seen.add(candidate.destination)
      items.push({ ...candidate, source: 'stateport' })
    }
  }

  items.push({
    destination: 'settings',
    to: 'settings',
    label: 'Settings',
    icon: 'settings',
    order: 1000,
    source: 'stateport',
  })

  return items.sort((left, right) =>
    left.order - right.order || left.destination.localeCompare(right.destination),
  )
}
