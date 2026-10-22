/**
 * Recovery (backup) state presentations, composed from the semantic layer's
 * named conditions (§7.2 CONDITION_PRESENTATIONS) plus state-consistent
 * entries for current/running/failed — the semantic module intentionally
 * leaves these to surfaces; no colors are invented here.
 */
import { CircleX, DatabaseBackup, Loader2 } from 'lucide-react'

import type { RecoveryInfo } from '@/client'
import type { SemanticPresentation } from '@/semantic'
import { CONDITION_PRESENTATIONS } from '@/semantic'

export const RECOVERY_PRESENTATION: Record<RecoveryInfo['state'], SemanticPresentation> = {
  current: { state: 'success', label: 'Backed up', icon: DatabaseBackup },
  due: CONDITION_PRESENTATIONS.backupDue,
  running: { state: 'waiting', label: 'Backing up', icon: Loader2, spin: true },
  failed: { state: 'danger', label: 'Backup failed', icon: CircleX },
  not_configured: CONDITION_PRESENTATIONS.notConfigured,
}
