/**
 * AttentionFeed model — builds the combined, de-duplicated "Needs attention"
 * row list shared by the Applications home and the App overview
 * (app-overview.md: "same component as Applications home").
 *
 * De-dup rule: an attention item that merely points at a pending approval
 * (`actionRoute` → `/approvals/:id` in the same feed) is dropped — the
 * approval row carries the richer truth (scope, risk, expiry).
 */
import type { ApplicationInstance, Approval, AttentionItem, OperationRecord } from '@/client'

export type AttentionFeedItem =
  | { kind: 'approval'; approval: Approval; instanceName: string; createdAt: string }
  | { kind: 'attention'; item: AttentionItem; instanceName: string; createdAt: string }
  | { kind: 'failed_operation'; operation: OperationRecord; instanceName: string; createdAt: string }

export function buildAttentionFeed(input: {
  instances: ApplicationInstance[]
  pendingApprovals: Approval[]
  operations: OperationRecord[]
  /** Restrict the feed to one application (overview). */
  instanceId?: string
}): AttentionFeedItem[] {
  const { instances, pendingApprovals, operations, instanceId } = input
  const nameOf = (id: string) => instances.find((i) => i.id === id)?.name ?? 'Unknown application'
  const approvals = pendingApprovals.filter((a) => !instanceId || a.instanceId === instanceId)

  const items: AttentionFeedItem[] = approvals.map((approval) => ({
    kind: 'approval',
    approval,
    instanceName: nameOf(approval.instanceId),
    createdAt: approval.requestedAt,
  }))

  const approvalRoutes = new Set(approvals.map((a) => `/approvals/${a.id}`))
  for (const instance of instances) {
    if (instanceId && instance.id !== instanceId) continue
    for (const item of instance.attention) {
      if (item.acknowledged) continue
      if (item.actionRoute && approvalRoutes.has(item.actionRoute)) continue // approval row covers it
      items.push({ kind: 'attention', item, instanceName: instance.name, createdAt: item.createdAt })
    }
  }

  for (const operation of operations) {
    if (operation.state !== 'failed') continue
    if (instanceId && operation.instanceId !== instanceId) continue
    items.push({ kind: 'failed_operation', operation, instanceName: nameOf(operation.instanceId), createdAt: operation.updatedAt })
  }

  return items.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}
