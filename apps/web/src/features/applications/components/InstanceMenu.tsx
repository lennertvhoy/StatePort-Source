/**
 * InstanceMenu — the context menu for an installed application row/card
 * (applications.md: Open, Pin/Unpin, Open in new window, Application
 * settings, Rename…; plus Move up/down while the pinned group is reorderable).
 * Rendered inside a DropdownMenuContent by the row.
 */
import {
  ArrowDown,
  ArrowUp,
  ExternalLink,
  PenLine,
  Pin,
  PinOff,
  Play,
  Settings,
} from 'lucide-react'

import type { ApplicationInstance } from '@/client'
import { DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/dropdown-menu'

import { openInstanceInNewWindow } from '../lib/openInstance'

export interface InstanceMenuProps {
  instance: ApplicationInstance
  /** Read-only (service offline): mutating items hide (design: actions hide, not disable). */
  readOnly: boolean
  onOpen: () => void
  onTogglePin: () => void
  /** Omitted when the connected adapter has no durable rename contract. */
  onRename?: () => void
  onOpenSettings: () => void
  /** Pinned-group reorder (undefined → items hidden). */
  onMoveUp?: () => void
  onMoveDown?: () => void
}

export function InstanceMenu({
  instance,
  readOnly,
  onOpen,
  onTogglePin,
  onRename,
  onOpenSettings,
  onMoveUp,
  onMoveDown,
}: InstanceMenuProps) {
  return (
    <>
      <DropdownMenuItem onSelect={onOpen}>
        <Play aria-hidden="true" /> Open
      </DropdownMenuItem>
      {!readOnly ? (
        <DropdownMenuItem onSelect={onTogglePin}>
          {instance.pinned ? <PinOff aria-hidden="true" /> : <Pin aria-hidden="true" />}
          {instance.pinned ? 'Unpin' : 'Pin'}
        </DropdownMenuItem>
      ) : null}
      {!readOnly && onMoveUp ? (
        <DropdownMenuItem onSelect={onMoveUp}>
          <ArrowUp aria-hidden="true" /> Move up
        </DropdownMenuItem>
      ) : null}
      {!readOnly && onMoveDown ? (
        <DropdownMenuItem onSelect={onMoveDown}>
          <ArrowDown aria-hidden="true" /> Move down
        </DropdownMenuItem>
      ) : null}
      <DropdownMenuItem onSelect={() => openInstanceInNewWindow(instance.id)}>
        <ExternalLink aria-hidden="true" /> Open in new window
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem onSelect={onOpenSettings}>
        <Settings aria-hidden="true" /> Application settings
      </DropdownMenuItem>
      {!readOnly && onRename ? (
        <DropdownMenuItem onSelect={onRename}>
          <PenLine aria-hidden="true" /> Rename…
        </DropdownMenuItem>
      ) : null}
    </>
  )
}
