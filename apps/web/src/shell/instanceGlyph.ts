/**
 * Application identity map (design.md §11): package/instance glyphs.
 * Monochrome only — identity comes from the instance name, never color.
 * Lives outside appIcon.tsx so the component module stays a clean
 * fast-refresh boundary.
 */
import { BookOpen, FolderGit2, ListChecks, Package, Snowflake } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type { ApplicationInstance } from '@/client'

export function instanceGlyph(instance: Pick<ApplicationInstance, 'packageName' | 'name'>): LucideIcon {
  if (/nixos/i.test(instance.name) || /nixos/i.test(instance.packageName)) return Snowflake
  switch (instance.packageName) {
    case 'project-state':
      return FolderGit2
    case 'study-state':
      return BookOpen
    case 'checklist-state':
      return ListChecks
    default:
      return Package
  }
}
