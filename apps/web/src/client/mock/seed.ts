/**
 * Deterministic mock seed (brief: "Mock runtime").
 *
 * Instances seeded:
 *   - StatePort CTO Pilot    (ProjectState; backup due; receipts; attention item)
 *   - StudyState Alpha       (StudyState; goal/activities/evidence; no workbench)
 *   - ChecklistState Sample  (ChecklistState; no network; several items)
 *   - NixOS Infrastructure   (ProjectState; nixos-homelab repo, clean, VM stopped,
 *                             SSH not ready, health unchecked; one pending approval)
 *
 * Timestamps are computed relative to `Date.now()` at seed time so the product
 * always feels alive. IDs are stable strings; digests are deterministic
 * (fake but well-formed sha256-shaped hex derived from content).
 */
import type {
  ActivityItem,
  ApplicationInstance,
  ApplicationPackage,
  Approval,
  AppSettings,
  AuthorizationGrant,
  Conversation,
  FileNode,
  GlobalSettings,
  InfrastructurePlan,
  InfrastructureTarget,
  NotificationItem,
  OperationRecord,
  OrchestrationSession,
  PlanDigest,
  Receipt,
} from '../types'

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic helpers
// ─────────────────────────────────────────────────────────────────────────────

/** mulberry32 — tiny deterministic PRNG. */
function prng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function hashString(input: string): number {
  let h = 2166136261
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

/** Deterministic sha256-shaped digest (64 hex chars) derived from `input`. */
export function fakeDigest(input: string): PlanDigest {
  const rand = prng(hashString(input))
  let hex = ''
  for (let i = 0; i < 64; i++) hex += Math.floor(rand() * 16).toString(16)
  return { algorithm: 'sha256', value: hex }
}

export function fakeHex(input: string, length: number): string {
  const rand = prng(hashString(input))
  let hex = ''
  for (let i = 0; i < length; i++) hex += Math.floor(rand() * 16).toString(16)
  return hex
}

const HOUR = 3_600_000
const MINUTE = 60_000
const DAY = 24 * HOUR

const iso = (ms: number) => new Date(ms).toISOString()

// ─────────────────────────────────────────────────────────────────────────────
// Database shape (persisted under the mock envelope)
// ─────────────────────────────────────────────────────────────────────────────

export interface MockFileRecord {
  content: string
  revision: string
  readOnly: boolean
  modifiedAt: string
}

export interface MockDatabase {
  packages: ApplicationPackage[]
  instances: ApplicationInstance[]
  conversations: Record<string, Conversation>
  /** instanceId → path → record */
  files: Record<string, Record<string, MockFileRecord>>
  receipts: Record<string, Receipt>
  approvals: Record<string, Approval>
  plans: Record<string, InfrastructurePlan>
  /** instanceId → target */
  infraTargets: Record<string, InfrastructureTarget>
  /** instanceId → grant */
  authorizations: Record<string, AuthorizationGrant>
  /** instanceId → session */
  orchestration: Record<string, OrchestrationSession>
  operations: Record<string, OperationRecord>
  activity: ActivityItem[]
  notifications: NotificationItem[]
  globalSettings: GlobalSettings
  /** Monotonic counters per prefix for stable id minting (rcpt, appr, …). */
  counters: Record<string, number>
}

export const INSTANCE_IDS = {
  ctoPilot: 'ins_cto_pilot',
  studyAlpha: 'ins_study_alpha',
  checklistSample: 'ins_checklist_sample',
  nixosInfra: 'ins_nixos_infra',
} as const

export const CONVERSATION_IDS = {
  ctoPilot: 'conv_cto_pilot',
  studyAlpha: 'conv_study_alpha',
  checklistSample: 'conv_checklist_sample',
  nixosInfra: 'conv_nixos_infra',
} as const

export const TARGET_IDS = {
  nixosVm: 'tgt_nixos_vm',
  ctoPty: 'tgt_cto_pty',
  nixosPty: 'tgt_nixos_pty',
} as const

export function nextId(db: MockDatabase, prefix: string): string {
  const n = (db.counters[prefix] ?? 0) + 1
  db.counters[prefix] = n
  return `${prefix}_${String(n).padStart(4, '0')}`
}

// ─────────────────────────────────────────────────────────────────────────────
// Packages
// ─────────────────────────────────────────────────────────────────────────────

function buildPackages(): ApplicationPackage[] {
  return [
    {
      id: 'pkg_project_state',
      name: 'project-state',
      displayName: 'ProjectState',
      description:
        'A development and project application: files, editor, terminal, deployments, orchestration and a full audit trail.',
      version: '1.4.2',
      releaseStatus: 'stable',
      productionEligible: false,
      publicSafe: true,
      sourceKind: 'bundled_public_fixture',
      privacyClassification: 'public_safe',
      reviewClassification: 'reviewed',
      capabilities: [
        'conversation',
        'workbench',
        'file_viewer',
        'editor',
        'terminal',
        'infrastructure',
        'cto_orchestration',
        'backup',
        'receipts',
        'proactive_notifications',
      ],
      views: ['Overview', 'Conversation', 'Workbench', 'Settings'],
      permissions: {
        fileAccess: 'Reads and writes files inside its project folder only.',
        terminalAccess: 'May open a local terminal scoped to the project.',
        networkAccess: 'No network access by default.',
        dataOwnership: 'All data stays on this machine.',
      },
      networkPolicy: 'local_only',
      dataBoundaries: ['Project folder', 'Application settings', 'Conversation history'],
      workbenchTools: ['overview', 'files', 'terminal', 'deployments', 'orchestration', 'receipts'],
    },
    {
      id: 'pkg_study_state',
      name: 'study-state',
      displayName: 'StudyState',
      description:
        'A durable learning application: goals, activities, evidence and review, with a conversation that can reference your progress.',
      version: '0.9.1',
      releaseStatus: 'beta',
      productionEligible: false,
      publicSafe: true,
      sourceKind: 'bundled_public_fixture',
      privacyClassification: 'public_safe',
      reviewClassification: 'reviewed',
      capabilities: [
        'conversation',
        'progress_dashboard',
        'goal_execution',
        'benchmark_evidence',
        'proactive_notifications',
        'receipts',
      ],
      views: ['Overview', 'Conversation', 'Settings'],
      permissions: {
        fileAccess: 'No file access.',
        terminalAccess: 'No terminal access.',
        networkAccess: 'No network access.',
        dataOwnership: 'All data stays on this machine.',
      },
      networkPolicy: 'none',
      dataBoundaries: ['Learning records', 'Conversation history'],
      workbenchTools: [],
    },
    {
      id: 'pkg_checklist_state',
      name: 'checklist-state',
      displayName: 'ChecklistState',
      description: 'A small reviewed checklist application with conversation and progress tracking.',
      version: '1.0.0',
      releaseStatus: 'stable',
      productionEligible: false,
      publicSafe: true,
      sourceKind: 'bundled_public_fixture',
      privacyClassification: 'public_safe',
      reviewClassification: 'reviewed',
      capabilities: ['conversation', 'progress_dashboard', 'receipts'],
      views: ['Overview', 'Conversation', 'Settings'],
      permissions: {
        fileAccess: 'No file access.',
        terminalAccess: 'No terminal access.',
        networkAccess: 'No network access.',
        dataOwnership: 'All data stays on this machine.',
      },
      networkPolicy: 'none',
      dataBoundaries: ['Checklist data'],
      workbenchTools: [],
    },
    {
      id: 'pkg_notes_state',
      name: 'notes-state',
      displayName: 'NotesState',
      description:
        'A reviewed durable notes application: local markdown notes, conversation, and receipts. Good first sample install.',
      version: '0.6.0',
      releaseStatus: 'beta',
      productionEligible: false,
      publicSafe: true,
      sourceKind: 'bundled_public_fixture',
      privacyClassification: 'public_safe',
      reviewClassification: 'reviewed',
      capabilities: ['conversation', 'file_viewer', 'editor', 'receipts'],
      views: ['Overview', 'Conversation', 'Settings'],
      permissions: {
        fileAccess: 'Reads and writes notes inside its own folder only.',
        terminalAccess: 'No terminal access.',
        networkAccess: 'No network access.',
        dataOwnership: 'All data stays on this machine.',
      },
      networkPolicy: 'none',
      dataBoundaries: ['Notes folder'],
      workbenchTools: [],
    },
    {
      id: 'pkg_ledger_state',
      name: 'ledger-state',
      displayName: 'LedgerState',
      description:
        'A community-submitted personal ledger application. Reviewed for data boundaries; export tools are still experimental.',
      version: '0.3.2',
      releaseStatus: 'experimental',
      productionEligible: false,
      publicSafe: true,
      sourceKind: 'bundled_public_fixture',
      privacyClassification: 'public_safe',
      reviewClassification: 'community',
      capabilities: ['conversation', 'progress_dashboard', 'receipts'],
      views: ['Overview', 'Conversation', 'Settings'],
      permissions: {
        fileAccess: 'No file access.',
        terminalAccess: 'No terminal access.',
        networkAccess: 'No network access.',
        dataOwnership: 'All data stays on this machine.',
      },
      networkPolicy: 'none',
      dataBoundaries: ['Ledger data'],
      workbenchTools: [],
    },
  ]
}

// ─────────────────────────────────────────────────────────────────────────────
// File content (believable project trees)
// ─────────────────────────────────────────────────────────────────────────────

const NIXOS_FLAKE = `{
  description = "nixos-homelab — personal infrastructure flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    home-manager = {
      url = "github:nix-community/home-manager/release-24.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager, ... }@inputs: {
    nixosConfigurations.homelab = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { inherit inputs; };
      modules = [
        ./hosts/homelab/configuration.nix
        home-manager.nixosModules.home-manager
      ];
    };
  };
}
`

const NIXOS_CONFIGURATION = `{ config, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ../../modules/services.nix
  ];

  networking.hostName = "homelab";

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  time.timeZone = "Europe/Berlin";

  users.users.kim = {
    isNormalUser = true;
    extraGroups = [ "wheel" "docker" ];
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7rZ3fexamplekeymaterialhomelab kim@stateport"
    ];
  };

  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
  };

  virtualisation.docker.enable = true;

  system.stateVersion = "24.05";
}
`

const NIXOS_README = `# nixos-homelab

Personal NixOS infrastructure, managed from StatePort.

## Layout

- \`flake.nix\` — entry point, pins nixpkgs 24.05
- \`hosts/homelab/configuration.nix\` — the single homelab host
- \`modules/services.nix\` — service definitions shared across hosts

## Daily use

The local VM target (\`homelab-dev\`) mirrors this configuration. Routine
operations (observe, validate, health check, start, graceful stop, restart)
can be covered by a daily-driver authorization. Destroy and target-identity
changes always require separate approval.

## Checks

\`\`\`sh
nix flake check
\`\`\`
`

const NIXOS_SERVICES = `{ pkgs, ... }:

{
  services.nginx = {
    enable = true;
    virtualHosts."home.local" = {
      locations."/" = {
        return = "200 'homelab ok'";
        extraConfig = ''
          add_header Content-Type text/plain;
        '';
      };
    };
  };

  services.vaultwarden.enable = false;

  environment.systemPackages = with pkgs; [
    git
    htop
    ripgrep
  ];
}
`

const CTO_README = `# StatePort CTO Pilot

Pilot workspace for evaluating StatePort as a daily driver for technical work.

## Goals

- Keep infrastructure work inside governed plans and approvals.
- Use conversation for exploration; keep canonical changes in operations.
- Track everything through receipts.

## Status

Backup is due. Run one from the overview or the recovery section in settings.
`

const CTO_PACKAGE_JSON = `{
  "name": "cto-pilot",
  "private": true,
  "version": "0.2.0",
  "scripts": {
    "check": "tsc --noEmit",
    "test": "vitest run"
  }
}
`

const CTO_NOTES = `# Pilot notes

- Orchestration stays in assisted mode for the first two weeks.
- Approvals inbox is checked every morning.
- The pilot instance intentionally keeps terminal access narrow.
`

function record(content: string, modifiedAt: string, readOnly = false): MockFileRecord {
  return { content, revision: `rev_${fakeHex(content, 12)}`, readOnly, modifiedAt }
}

// ─────────────────────────────────────────────────────────────────────────────
// File trees (structure mirrors the flat `files` map)
// ─────────────────────────────────────────────────────────────────────────────

export function buildFileTree(instanceId: string, files: Record<string, MockFileRecord>): FileNode[] {
  const roots: FileNode[] = []
  const dirs = new Map<string, FileNode>()
  const ensureDir = (path: string): FileNode => {
    const existing = dirs.get(path)
    if (existing) return existing
    const name = path.split('/').pop() ?? path
    const node: FileNode = { path, name, kind: 'directory', children: [] }
    dirs.set(path, node)
    const parentPath = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : ''
    if (parentPath) ensureDir(parentPath).children?.push(node)
    else roots.push(node)
    return node
  }
  for (const [path, rec] of Object.entries(files)) {
    const parts = path.split('/')
    if (parts.length > 1) ensureDir(parts.slice(0, -1).join('/'))
    const node: FileNode = {
      path,
      name: parts[parts.length - 1],
      kind: 'file',
      sizeBytes: rec.content.length,
      modifiedAt: rec.modifiedAt,
      readOnly: rec.readOnly || undefined,
      gitStatus: 'clean',
    }
    const parentPath = parts.slice(0, -1).join('/')
    if (parentPath) dirs.get(parentPath)?.children?.push(node)
    else roots.push(node)
  }
  const sortRec = (nodes: FileNode[]) => {
    nodes.sort((a, b) =>
      a.kind !== b.kind ? (a.kind === 'directory' ? -1 : 1) : a.name.localeCompare(b.name),
    )
    nodes.forEach((n) => n.children && sortRec(n.children))
  }
  sortRec(roots)
  void instanceId
  return roots
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings defaults (brief: Settings sections)
// ─────────────────────────────────────────────────────────────────────────────

export function defaultGlobalSettings(): GlobalSettings {
  return {
    general: {
      defaultLandingPage: 'applications',
      reopenLastApplication: true,
      reopenLastApplicationView: true,
      dateTimeFormat: 'both',
      density: 'compact',
      confirmBeforeDestructive: true,
      defaultApplicationSorting: 'recent',
      showRecentApplications: true,
      restoreWorkspaceLayouts: true,
      startInFocusMode: false,
      rememberSearchHistory: true,
    },
    appearance: {
      theme: 'system',
      highContrastBase: 'dark',
      fontScale: 100,
      density: 'compact',
      reducedMotion: false,
      strongerFocusIndicators: false,
      panelContrast: 'default',
      codeFont: 'JetBrains Mono',
      editorTheme: 'match_interface',
      terminalTheme: 'match_interface',
    },
    navigation: {
      sidebarDefault: 'expanded',
      autoCollapseBelowPx: 1200,
      recentCommands: true,
      workbenchToolOrder: ['overview', 'files', 'terminal', 'deployments', 'orchestration', 'receipts'],
      restoreLastTool: true,
      openLinksIn: 'current_view',
    },
    conversation: {
      enterSends: true,
      draftPersistence: true,
      showMessageTimestamps: true,
      compactMessageLayout: false,
      autoScroll: 'when_at_bottom',
      confirmBeforeClearingHistory: true,
      defaultContext: ['application', 'summary'],
      showDeliveryDetails: false,
      toolEventsExpanded: false,
      soundOnResponseFinished: false,
    },
    editor: {
      fontFamily: 'JetBrains Mono',
      fontSize: 13,
      lineHeight: 1.55,
      tabSize: 2,
      indentWith: 'spaces',
      wordWrap: false,
      minimap: false,
      ligatures: false,
      formatOnSave: false,
      autoCloseBrackets: true,
      showWhitespace: false,
      previewDiffBeforeSave: true,
      restoreOpenFiles: true,
      restoreCursorPositions: true,
      autosave: false,
    },
    terminal: {
      fontFamily: 'JetBrains Mono',
      fontSize: 13,
      lineHeight: 1.35,
      cursorStyle: 'block',
      cursorBlink: true,
      ligatures: false,
      scrollbackLines: 5000,
      copyOnSelect: false,
      rightClickBehavior: 'context_menu',
      multilinePasteConfirmation: true,
      bell: 'off',
      screenReaderMode: false,
      linkHandling: 'confirm',
      restoreSessionTabs: false,
      sessionNaming: 'sequential',
    },
    notifications: {
      level: 'all',
      approvalAlerts: true,
      operationCompleteAlerts: true,
      failureAlerts: true,
      backupReminders: true,
      sound: false,
      quietHours: { enabled: false, from: '22:00', to: '07:00' },
      applicationOverrides: {},
    },
    privacy: {
      defaultModelContext: ['application', 'summary'],
      includeSelectedFilesOnly: true,
      includeSelectedTerminalOutputOnly: true,
      diagnosticLogging: false,
      localTelemetry: false,
    },
    accessibility: {
      fontScale: 100,
      highContrast: false,
      reducedMotion: false,
      strongFocus: false,
      largerControls: false,
      screenReaderEnhancements: false,
      announceOperationProgress: true,
      terminalScreenReaderMode: false,
      disableNonessentialAnimation: false,
    },
    advanced: {
      adapterMode: 'mock',
      localServiceEndpoint: 'http://127.0.0.1:8734',
    },
  }
}

/** Shared frontend-owned app-settings defaults (also the HTTP mapper base). */
export function defaultAppSettings(instanceId: string): AppSettings {
  return {
    instanceId,
    notificationLevel: 'inherit',
    conversation: { defaultContext: ['application', 'summary'] },
    backup: { enabled: true, intervalHours: 24 },
    terminal: {},
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt factory (human names from the brief)
// ─────────────────────────────────────────────────────────────────────────────

interface ReceiptSeed {
  actionName: string
  eventKind: string
  at: number
  actor?: 'user' | 'assistant' | 'system'
  result?: Receipt['result']
  summary: string
  relatedApprovalId?: string
  relatedPlanId?: string
  relatedConversationId?: string
}

function makeReceipt(instanceId: string, packageId: string, n: number, s: ReceiptSeed): Receipt {
  const id = `rcpt_${String(n).padStart(4, '0')}`
  const raw = {
    id,
    event: s.eventKind,
    instance: instanceId,
    actor: s.actor ?? 'user',
    result: s.result ?? 'validated',
    at: iso(s.at),
    payloadDigest: fakeDigest(`${id}:${s.eventKind}`),
  }
  return {
    id,
    instanceId,
    packageId,
    actionName: s.actionName,
    eventKind: s.eventKind,
    actor: s.actor ?? 'user',
    result: s.result ?? 'validated',
    createdAt: iso(s.at),
    planDigest: s.relatedPlanId ? fakeDigest(`plan:${s.relatedPlanId}`) : undefined,
    payloadDigest: fakeDigest(`${id}:${s.eventKind}`),
    validation: { state: 'validated', detail: 'Response matched the expected revision.' },
    summary: s.summary,
    relatedApprovalId: s.relatedApprovalId,
    relatedPlanId: s.relatedPlanId,
    relatedConversationId: s.relatedConversationId,
    rawJson: JSON.stringify(raw, null, 2),
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// The seed
// ─────────────────────────────────────────────────────────────────────────────

export function buildSeed(now = Date.now()): MockDatabase {
  const packages = buildPackages()
  const settings = defaultGlobalSettings()

  // ── Instances ──────────────────────────────────────────────────────────────
  const ctoAttention: ApplicationInstance['attention'] = [
    {
      id: 'attn_0001',
      instanceId: INSTANCE_IDS.ctoPilot,
      title: 'Backup is due',
      detail: 'The last backup of this application is older than the 24-hour interval.',
      severity: 'action_needed',
      createdAt: iso(now - 5 * HOUR),
      read: false,
      acknowledged: false,
      actionRoute: `/app/${INSTANCE_IDS.ctoPilot}`,
    },
  ]

  const instances: ApplicationInstance[] = [
    {
      id: INSTANCE_IDS.ctoPilot,
      name: 'StatePort CTO Pilot',
      packageId: 'pkg_project_state',
      packageName: 'project-state',
      packageDisplayName: 'ProjectState',
      health: 'attention_needed',
      attention: ctoAttention,
      recentActivity: [],
      settings: defaultAppSettings(INSTANCE_IDS.ctoPilot),
      conversationId: CONVERSATION_IDS.ctoPilot,
      capabilities: [
        { id: 'conversation', status: 'available' },
        { id: 'workbench', status: 'available' },
        { id: 'file_viewer', status: 'available' },
        { id: 'editor', status: 'available' },
        { id: 'terminal', status: 'available' },
        { id: 'infrastructure', status: 'environment_gated', reason: 'No infrastructure target is registered for this project.' },
        { id: 'cto_orchestration', status: 'degraded', reason: 'Limited to assisted mode during the pilot.' },
        { id: 'backup', status: 'available' },
        { id: 'receipts', status: 'available' },
        { id: 'proactive_notifications', status: 'available' },
      ],
      receiptIds: [],
      recovery: {
        state: 'due',
        lastBackupAt: iso(now - 31 * HOUR),
        nextDueAt: iso(now - 7 * HOUR),
        detail: 'Backup interval is 24 hours.',
      },
      repository: {
        name: 'cto-pilot',
        branch: 'main',
        revision: fakeHex('cto-pilot@main', 10),
        clean: true,
      },
      provenance: {
        source: {
          templateId: 'project-state',
          repository: 'https://github.com/example/project-state.git',
          resolvedCommit: fakeHex('cto-pilot:source-commit', 40),
          resolvedTree: fakeHex('cto-pilot:source-tree', 40),
          manifestDigest: `sha256:${fakeHex('cto-pilot:manifest', 64)}`,
          sourceDigest: `sha256:${fakeHex('cto-pilot:source', 64)}`,
          sourceKind: 'git',
          sourceClass: 'canonical_source',
          sourceAccessClass: 'canonical_release',
          version: '1.4.0',
          productionEligible: true,
          productionInstallAllowed: true,
        },
        ownership: {
          counts: { template: 3, instance: 2, generated: 1, override: 1 },
          paths: {
            template: ['README.md', 'application.yaml', 'docs/architecture.md'],
            instance: ['AGENTS.md', 'state/project.yaml'],
            generated: ['.statedd/lock.yaml'],
            override: ['overrides/theme.yaml'],
          },
          truncated: { template: false, instance: false, generated: false, override: false },
        },
      },
      pinned: true,
      createdAt: iso(now - 21 * DAY),
      lastOpenedAt: iso(now - 2 * HOUR),
    },
    {
      id: INSTANCE_IDS.studyAlpha,
      name: 'StudyState Alpha',
      packageId: 'pkg_study_state',
      packageName: 'study-state',
      packageDisplayName: 'StudyState',
      health: 'ready',
      attention: [],
      recentActivity: [],
      settings: defaultAppSettings(INSTANCE_IDS.studyAlpha),
      conversationId: CONVERSATION_IDS.studyAlpha,
      capabilities: [
        { id: 'conversation', status: 'available' },
        { id: 'workbench', status: 'unavailable', reason: 'StudyState does not include development tools.' },
        { id: 'progress_dashboard', status: 'available' },
        { id: 'goal_execution', status: 'available' },
        { id: 'benchmark_evidence', status: 'available' },
        { id: 'proactive_notifications', status: 'available' },
        { id: 'receipts', status: 'available' },
      ],
      receiptIds: [],
      recovery: { state: 'current', lastBackupAt: iso(now - 3 * HOUR), nextDueAt: iso(now + 21 * HOUR) },
      packageState: {
        kind: 'study-state',
        goal: 'Pass the NixOS fundamentals assessment',
        goalProgressPercent: 62,
        activities: [
          { id: 'act_s1', title: 'Read: flakes and inputs', state: 'done', updatedAt: iso(now - 2 * DAY) },
          { id: 'act_s2', title: 'Exercise: write a dev shell', state: 'done', updatedAt: iso(now - 26 * HOUR) },
          { id: 'act_s3', title: 'Read: modules and options', state: 'in_progress', updatedAt: iso(now - 4 * HOUR) },
          { id: 'act_s4', title: 'Exercise: parametrize configuration.nix', state: 'not_started', updatedAt: iso(now - 4 * HOUR) },
        ],
        evidence: [
          { id: 'ev_s1', title: 'dev-shell.nix walks through mkShell', state: 'verified', updatedAt: iso(now - 26 * HOUR) },
          { id: 'ev_s2', title: 'Notes: module system mental model', state: 'draft', updatedAt: iso(now - 5 * HOUR) },
          { id: 'ev_s3', title: 'Assessment attempt 1', state: 'missing', updatedAt: iso(now - 8 * DAY) },
        ],
      },
      pinned: true,
      createdAt: iso(now - 14 * DAY),
      lastOpenedAt: iso(now - 26 * HOUR),
    },
    {
      id: INSTANCE_IDS.checklistSample,
      name: 'ChecklistState Sample',
      packageId: 'pkg_checklist_state',
      packageName: 'checklist-state',
      packageDisplayName: 'ChecklistState',
      health: 'ready',
      attention: [],
      recentActivity: [],
      settings: defaultAppSettings(INSTANCE_IDS.checklistSample),
      conversationId: CONVERSATION_IDS.checklistSample,
      capabilities: [
        { id: 'conversation', status: 'available' },
        { id: 'workbench', status: 'unavailable', reason: 'ChecklistState does not include development tools.' },
        { id: 'progress_dashboard', status: 'available' },
        { id: 'receipts', status: 'available' },
      ],
      receiptIds: [],
      recovery: { state: 'not_configured', detail: 'Backups are not configured for this sample.' },
      packageState: {
        kind: 'checklist-state',
        items: [
          { id: 'chk_1', title: 'Review the sample checklist', done: true, updatedAt: iso(now - 3 * DAY) },
          { id: 'chk_2', title: 'Mark an item complete', done: true, updatedAt: iso(now - 2 * DAY) },
          { id: 'chk_3', title: 'Open the receipt for the change', done: false, updatedAt: iso(now - 2 * DAY) },
          { id: 'chk_4', title: 'Try the conversation', done: false, updatedAt: iso(now - 1 * DAY) },
          { id: 'chk_5', title: 'Uninstall the sample when finished', done: false, updatedAt: iso(now - 1 * DAY) },
        ],
      },
      pinned: false,
      createdAt: iso(now - 6 * DAY),
      lastOpenedAt: iso(now - 3 * DAY),
    },
    {
      id: INSTANCE_IDS.nixosInfra,
      name: 'NixOS Infrastructure',
      packageId: 'pkg_project_state',
      packageName: 'project-state',
      packageDisplayName: 'ProjectState',
      health: 'attention_needed',
      attention: [
        {
          id: 'attn_0002',
          instanceId: INSTANCE_IDS.nixosInfra,
          title: 'One approval is waiting',
          detail: 'Starting the virtual machine needs your confirmation.',
          severity: 'action_needed',
          createdAt: iso(now - 40 * MINUTE),
          read: false,
          acknowledged: false,
          actionRoute: '/approvals/appr_0001',
        },
      ],
      recentActivity: [],
      settings: defaultAppSettings(INSTANCE_IDS.nixosInfra),
      conversationId: CONVERSATION_IDS.nixosInfra,
      capabilities: [
        { id: 'conversation', status: 'available' },
        { id: 'workbench', status: 'available' },
        { id: 'file_viewer', status: 'available' },
        { id: 'editor', status: 'available' },
        { id: 'terminal', status: 'available' },
        { id: 'infrastructure', status: 'available' },
        { id: 'cto_orchestration', status: 'available' },
        { id: 'backup', status: 'available' },
        { id: 'receipts', status: 'available' },
        { id: 'proactive_notifications', status: 'available' },
      ],
      receiptIds: [],
      recovery: {
        state: 'current',
        lastBackupAt: iso(now - 9 * HOUR),
        nextDueAt: iso(now + 15 * HOUR),
      },
      repository: {
        name: 'nixos-homelab',
        branch: 'main',
        revision: fakeHex('nixos-homelab@main', 10),
        clean: true,
      },
      runtimeIdentity: 'local-vm:homelab-dev',
      pinned: true,
      createdAt: iso(now - 30 * DAY),
      lastOpenedAt: iso(now - 50 * MINUTE),
    },
  ]

  // ── Files ──────────────────────────────────────────────────────────────────
  const files: MockDatabase['files'] = {
    [INSTANCE_IDS.nixosInfra]: {
      'flake.nix': record(NIXOS_FLAKE, iso(now - 2 * DAY)),
      'README.md': record(NIXOS_README, iso(now - 5 * DAY)),
      'hosts/homelab/configuration.nix': record(NIXOS_CONFIGURATION, iso(now - 26 * HOUR)),
      'hosts/homelab/hardware-configuration.nix': record(
        '{ config, lib, pkgs, modulesPath, ... }:\n\n{\n  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];\n\n  fileSystems."/" = {\n    device = "/dev/disk/by-label/nixos";\n    fsType = "ext4";\n  };\n\n  swapDevices = [ ];\n}\n',
        iso(now - 12 * DAY),
        true,
      ),
      'modules/services.nix': record(NIXOS_SERVICES, iso(now - 3 * DAY)),
    },
    [INSTANCE_IDS.ctoPilot]: {
      'README.md': record(CTO_README, iso(now - 1 * DAY)),
      'package.json': record(CTO_PACKAGE_JSON, iso(now - 4 * DAY)),
      'notes/pilot-notes.md': record(CTO_NOTES, iso(now - 7 * HOUR)),
    },
    [INSTANCE_IDS.studyAlpha]: {},
    [INSTANCE_IDS.checklistSample]: {},
  }

  // ── Infrastructure target (NixOS) ─────────────────────────────────────────
  const infraTargets: MockDatabase['infraTargets'] = {
    [INSTANCE_IDS.nixosInfra]: {
      id: TARGET_IDS.nixosVm,
      instanceId: INSTANCE_IDS.nixosInfra,
      name: 'homelab-dev',
      kind: 'local_vm',
      available: true,
      repository: {
        name: 'nixos-homelab',
        branch: 'main',
        revision: fakeHex('nixos-homelab@main', 10),
        clean: true,
      },
      vm: { state: 'stopped', since: iso(now - 18 * HOUR) },
      ssh: { state: 'unavailable_vm_stopped', detail: 'SSH is unavailable while the virtual machine is stopped.' },
      health: { state: 'not_checked' },
    },
  }

  // ── Plans + approvals ──────────────────────────────────────────────────────
  const startPlanDigest = fakeDigest('plan:plan_0001:start:homelab-dev')
  const plans: MockDatabase['plans'] = {
    plan_0001: {
      id: 'plan_0001',
      instanceId: INSTANCE_IDS.nixosInfra,
      targetId: TARGET_IDS.nixosVm,
      operation: 'start',
      title: 'Start virtual machine',
      state: 'awaiting_approval',
      risk: 'medium',
      requiresApproval: true,
      coveredByAuthorization: false,
      steps: [
        { id: 'ps_1', title: 'Verify target identity', detail: 'stateport target verify homelab-dev', kind: 'check' },
        { id: 'ps_2', title: 'Start the virtual machine', detail: 'stateport vm start homelab-dev', kind: 'command' },
        { id: 'ps_3', title: 'Wait for SSH', detail: 'stateport ssh wait --timeout 120s', kind: 'command' },
        { id: 'ps_4', title: 'Confirm power state', detail: 'stateport vm observe homelab-dev', kind: 'check' },
      ],
      digest: startPlanDigest,
      beforeSummary: 'Virtual machine homelab-dev is stopped.',
      afterSummary: 'Virtual machine homelab-dev is running; SSH becomes ready.',
      rollbackNotes: 'Stop the virtual machine from Deployments. No data is changed by starting.',
      approvalId: 'appr_0001',
      createdAt: iso(now - 45 * MINUTE),
    },
  }

  const approvals: MockDatabase['approvals'] = {
    appr_0001: {
      id: 'appr_0001',
      instanceId: INSTANCE_IDS.nixosInfra,
      kind: 'infrastructure_plan',
      title: 'Start virtual machine',
      operationType: 'Infrastructure · VM start',
      risk: 'medium',
      status: 'pending',
      scope: [
        'Target: homelab-dev (local virtual machine)',
        'Operation: start',
        'Repository: nixos-homelab @ main (clean)',
      ],
      beforeSummary: 'Virtual machine homelab-dev is stopped.',
      afterSummary: 'Virtual machine homelab-dev is running; SSH becomes ready.',
      planDigest: startPlanDigest,
      planId: 'plan_0001',
      targetId: TARGET_IDS.nixosVm,
      whyRequired: 'Starting infrastructure changes what is running on this machine, and no daily-driver authorization covers this target yet.',
      requestedAt: iso(now - 45 * MINUTE),
      expiresAt: iso(now + 23 * HOUR),
      decision: {
        kind: 'infrastructure_plan',
        expectedInstanceId: INSTANCE_IDS.nixosInfra,
        expectedDigest: startPlanDigest.value,
      },
      currentDigest: startPlanDigest,
      relatedConversationId: CONVERSATION_IDS.nixosInfra,
    },
  }

  // ── Receipts ───────────────────────────────────────────────────────────────
  const receipts: MockDatabase['receipts'] = {}
  const receiptList: Receipt[] = [
    makeReceipt(INSTANCE_IDS.ctoPilot, 'pkg_project_state', 1, {
      actionName: 'File change saved',
      eventKind: 'file.write',
      at: now - 7 * HOUR,
      summary: 'notes/pilot-notes.md updated (2 lines added, 1 removed).',
      relatedConversationId: CONVERSATION_IDS.ctoPilot,
    }),
    makeReceipt(INSTANCE_IDS.ctoPilot, 'pkg_project_state', 2, {
      actionName: 'Conversation exported',
      eventKind: 'conversation.export',
      at: now - 26 * HOUR,
      summary: 'Conversation exported as Markdown.',
    }),
    makeReceipt(INSTANCE_IDS.ctoPilot, 'pkg_project_state', 3, {
      actionName: 'Backup completed',
      eventKind: 'recovery.backup',
      at: now - 31 * HOUR,
      actor: 'system',
      summary: 'Application data backed up locally (18 MB).',
    }),
    makeReceipt(INSTANCE_IDS.studyAlpha, 'pkg_study_state', 4, {
      actionName: 'Evidence marked verified',
      eventKind: 'study.evidence.verify',
      at: now - 26 * HOUR,
      summary: '“dev-shell.nix walks through mkShell” verified against the activity.',
    }),
    makeReceipt(INSTANCE_IDS.studyAlpha, 'pkg_study_state', 5, {
      actionName: 'Attention item marked read',
      eventKind: 'attention.read',
      at: now - 2 * DAY,
      summary: 'Weekly review reminder marked read.',
    }),
    makeReceipt(INSTANCE_IDS.checklistSample, 'pkg_checklist_state', 6, {
      actionName: 'Checklist item completed',
      eventKind: 'checklist.item.complete',
      at: now - 2 * DAY,
      summary: '“Mark an item complete” checked off.',
    }),
    makeReceipt(INSTANCE_IDS.nixosInfra, 'pkg_project_state', 7, {
      actionName: 'Configuration validated',
      eventKind: 'infrastructure.validate',
      at: now - 20 * HOUR,
      summary: 'nix flake check passed for nixos-homelab @ main.',
    }),
    makeReceipt(INSTANCE_IDS.nixosInfra, 'pkg_project_state', 8, {
      actionName: 'Virtual machine stopped',
      eventKind: 'infrastructure.stop',
      at: now - 18 * HOUR,
      summary: 'homelab-dev stopped gracefully.',
    }),
    makeReceipt(INSTANCE_IDS.nixosInfra, 'pkg_project_state', 9, {
      actionName: 'Infrastructure plan approved',
      eventKind: 'approval.approve',
      at: now - 2 * DAY,
      summary: 'Graceful stop of homelab-dev was approved.',
    }),
    makeReceipt(INSTANCE_IDS.nixosInfra, 'pkg_project_state', 10, {
      actionName: 'File change saved',
      eventKind: 'file.write',
      at: now - 26 * HOUR,
      summary: 'hosts/homelab/configuration.nix updated (timezone set).',
    }),
  ]
  for (const r of receiptList) receipts[r.id] = r

  const receiptIdsByInstance = (id: string) =>
    receiptList.filter((r) => r.instanceId === id).map((r) => r.id)
  for (const inst of instances) inst.receiptIds = receiptIdsByInstance(inst.id)
  const cto = instances.find((i) => i.id === INSTANCE_IDS.ctoPilot)
  if (cto) cto.recovery.lastReceiptId = 'rcpt_0003'

  // ── Activity ───────────────────────────────────────────────────────────────
  const activity: ActivityItem[] = [
    { id: 'act_0001', instanceId: INSTANCE_IDS.nixosInfra, kind: 'approval.requested', title: 'Approval requested: start virtual machine', detail: 'Waiting for your decision.', createdAt: iso(now - 45 * MINUTE), read: false, route: '/approvals/appr_0001' },
    { id: 'act_0002', instanceId: INSTANCE_IDS.ctoPilot, kind: 'file.write', title: 'File change saved', detail: 'notes/pilot-notes.md', createdAt: iso(now - 7 * HOUR), read: true, relatedReceiptId: 'rcpt_0001' },
    { id: 'act_0003', instanceId: INSTANCE_IDS.nixosInfra, kind: 'infrastructure.validate', title: 'Configuration validated', detail: 'nix flake check passed.', createdAt: iso(now - 20 * HOUR), read: true, relatedReceiptId: 'rcpt_0007' },
    { id: 'act_0004', instanceId: INSTANCE_IDS.studyAlpha, kind: 'study.progress', title: 'Activity in progress', detail: 'Read: modules and options', createdAt: iso(now - 4 * HOUR), read: true },
    { id: 'act_0005', instanceId: INSTANCE_IDS.ctoPilot, kind: 'recovery.backup', title: 'Backup completed', detail: 'Application data backed up locally.', createdAt: iso(now - 31 * HOUR), read: true, relatedReceiptId: 'rcpt_0003' },
  ]

  const notifications: NotificationItem[] = [
    { id: 'ntf_0001', instanceId: INSTANCE_IDS.nixosInfra, title: 'Approval waiting', body: 'Starting homelab-dev needs your confirmation.', importance: 'important', createdAt: iso(now - 40 * MINUTE), read: false, acknowledged: false, route: '/approvals/appr_0001' },
    { id: 'ntf_0002', instanceId: INSTANCE_IDS.ctoPilot, title: 'Backup is due', body: 'Last backup is older than 24 hours.', importance: 'normal', createdAt: iso(now - 5 * HOUR), read: false, acknowledged: false, route: `/app/${INSTANCE_IDS.ctoPilot}` },
  ]

  // ── Conversations ──────────────────────────────────────────────────────────
  const conversations: MockDatabase['conversations'] = {
    [CONVERSATION_IDS.ctoPilot]: {
      id: CONVERSATION_IDS.ctoPilot,
      instanceId: INSTANCE_IDS.ctoPilot,
      title: 'Conversation',
      channel: 'web',
      deliveryState: 'delivered',
      retentionNote: 'History is kept on this machine until you clear it.',
      createdAt: iso(now - 21 * DAY),
      updatedAt: iso(now - 7 * HOUR),
      messages: [
        {
          id: 'msg_0001',
          conversationId: CONVERSATION_IDS.ctoPilot,
          role: 'user',
          content: 'Can you summarize where the pilot stands? I want one paragraph I can paste into the weekly note.',
          createdAt: iso(now - 8 * HOUR),
          state: 'complete',
          attachments: [],
          contextChips: [
            { id: 'chip_1', kind: 'application', label: 'StatePort CTO Pilot', refId: INSTANCE_IDS.ctoPilot, removable: true },
          ],
          toolEvents: [],
          inboundAccepted: true,
          sourceChannel: 'web',
        },
        {
          id: 'msg_0002',
          conversationId: CONVERSATION_IDS.ctoPilot,
          role: 'assistant',
          content:
            'The pilot is in good shape. Conversation, files, terminal and receipts are all in daily use, orchestration stays in assisted mode, and the only open housekeeping item is the overdue backup — it has been 31 hours since the last one, against a 24-hour interval. No approvals are pending for this instance, the project repository is clean, and the last three operations (a file save, a conversation export and the previous backup) all validated and have receipts.',
          createdAt: iso(now - 8 * HOUR + 40_000),
          state: 'complete',
          attachments: [],
          contextChips: [],
          toolEvents: [
            { id: 'tev_1', kind: 'application.summary', summary: 'Read application summary', state: 'validated', createdAt: iso(now - 8 * HOUR + 20_000) },
          ],
          deliveryState: [
            {
              formatVersion: 'stateport.delivery-receipt/v1',
              deliveryId: 'delivery_mock_0002',
              messageId: 'msg_0002',
              conversationId: CONVERSATION_IDS.ctoPilot,
              bindingId: 'binding_web_mock',
              channel: 'web',
              deliveryPolicy: 'source_channel_only',
              deliveryMode: 'full',
              status: 'delivered',
              createdAt: iso(now - 8 * HOUR + 40_000),
              externalMessageId: 'external_mock_0002',
              echoGuard: `sha256:${'2'.repeat(64)}`,
              failureReason: null,
            },
          ],
        },
        {
          id: 'msg_0003',
          conversationId: CONVERSATION_IDS.ctoPilot,
          role: 'user',
          content: 'Draft the backup reminder for tomorrow morning and note it in the pilot notes.',
          createdAt: iso(now - 7 * HOUR - 10 * MINUTE),
          state: 'complete',
          attachments: [],
          contextChips: [{ id: 'chip_2', kind: 'file', label: 'notes/pilot-notes.md', removable: true }],
          toolEvents: [],
        },
        {
          id: 'msg_0004',
          conversationId: CONVERSATION_IDS.ctoPilot,
          role: 'assistant',
          content:
            'I added a short reminder line to `notes/pilot-notes.md`. The change went through the normal save preview and has a receipt (`rcpt_0001`). I did not schedule anything automatically — a reminder needs the notifications setting, which I can point you to if you want.',
          createdAt: iso(now - 7 * HOUR),
          state: 'complete',
          attachments: [],
          contextChips: [],
          toolEvents: [
            { id: 'tev_2', kind: 'file.write', summary: 'Saved notes/pilot-notes.md', detail: 'Receipt rcpt_0001', state: 'validated', createdAt: iso(now - 7 * HOUR) },
          ],
          deliveryState: [
            {
              formatVersion: 'stateport.delivery-receipt/v1',
              deliveryId: 'delivery_mock_0004',
              messageId: 'msg_0004',
              conversationId: CONVERSATION_IDS.ctoPilot,
              bindingId: 'binding_telegram_mock',
              channel: 'telegram',
              deliveryPolicy: 'source_channel_only',
              deliveryMode: 'full',
              status: 'failed',
              createdAt: iso(now - 7 * HOUR),
              externalMessageId: null,
              echoGuard: `sha256:${'4'.repeat(64)}`,
              failureReason: 'telegram-sink-rejected',
            },
          ],
        },
      ],
    },
    [CONVERSATION_IDS.studyAlpha]: {
      id: CONVERSATION_IDS.studyAlpha,
      instanceId: INSTANCE_IDS.studyAlpha,
      title: 'Conversation',
      channel: 'web',
      deliveryState: 'delivered',
      retentionNote: 'History is kept on this machine until you clear it.',
      createdAt: iso(now - 14 * DAY),
      updatedAt: iso(now - 4 * HOUR),
      messages: [
        {
          id: 'msg_0005',
          conversationId: CONVERSATION_IDS.studyAlpha,
          role: 'user',
          content: 'What should I focus on next for the NixOS assessment?',
          createdAt: iso(now - 4 * HOUR - 5 * MINUTE),
          state: 'complete',
          attachments: [],
          contextChips: [{ id: 'chip_3', kind: 'summary', label: 'Progress summary', removable: true }],
          toolEvents: [],
        },
        {
          id: 'msg_0006',
          conversationId: CONVERSATION_IDS.studyAlpha,
          role: 'assistant',
          content:
            'You are 62% toward the goal. The open thread is the module system: finish “Read: modules and options”, then do “Exercise: parametrize configuration.nix” — that pairing is what the assessment weighs most heavily. Your evidence note on the module mental model is still a draft; tightening it after the exercise should take one session.',
          createdAt: iso(now - 4 * HOUR),
          state: 'complete',
          attachments: [],
          contextChips: [],
          toolEvents: [],
        },
      ],
    },
    [CONVERSATION_IDS.checklistSample]: {
      id: CONVERSATION_IDS.checklistSample,
      instanceId: INSTANCE_IDS.checklistSample,
      title: 'Conversation',
      channel: 'web',
      deliveryState: 'delivered',
      retentionNote: 'History is kept on this machine until you clear it.',
      createdAt: iso(now - 6 * DAY),
      updatedAt: iso(now - 6 * DAY),
      messages: [],
    },
    [CONVERSATION_IDS.nixosInfra]: {
      id: CONVERSATION_IDS.nixosInfra,
      instanceId: INSTANCE_IDS.nixosInfra,
      title: 'Conversation',
      channel: 'web',
      deliveryState: 'delivered',
      retentionNote: 'History is kept on this machine until you clear it.',
      createdAt: iso(now - 30 * DAY),
      updatedAt: iso(now - 45 * MINUTE),
      messages: [
        {
          id: 'msg_0007',
          conversationId: CONVERSATION_IDS.nixosInfra,
          role: 'assistant',
          content:
            'A plan to start `homelab-dev` is prepared and waiting for your approval. The repository is clean at `main`, and starting the VM changes nothing on disk — it only powers on the machine so SSH and health checks can run.',
          createdAt: iso(now - 45 * MINUTE),
          state: 'complete',
          attachments: [],
          contextChips: [
            { id: 'chip_4', kind: 'plan', label: 'Start virtual machine', refId: 'plan_0001', removable: true },
            { id: 'chip_5', kind: 'approval', label: 'Approval appr_0001', refId: 'appr_0001', removable: true },
          ],
          toolEvents: [],
          proposal: {
            title: 'Start virtual machine',
            detail: 'Review the exact scope, then approve or reject in the approvals inbox.',
            actionRoute: '/approvals/appr_0001',
          },
        },
      ],
    },
  }

  return {
    packages,
    instances,
    conversations,
    files,
    receipts,
    approvals,
    plans,
    infraTargets,
    authorizations: {},
    orchestration: {},
    operations: {},
    activity,
    notifications,
    globalSettings: settings,
    counters: { rcpt: 10, appr: 1, plan: 1, msg: 7, att: 0, op: 0, orch: 0, authz: 0, term: 0, act: 5, ntf: 2, attn: 2, ins: 4, conv: 4, chip: 5, tev: 2, fc: 0 },
  }
}
