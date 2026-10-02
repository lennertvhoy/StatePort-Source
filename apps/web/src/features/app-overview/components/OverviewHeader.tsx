/**
 * OverviewHeader — the identity header of the App overview: app glyph,
 * instance name, package type + version, ONE dominant StatusBadge, and the
 * actions: primary Continue (resumes the last view/tool with a specific
 * label), secondary Conversation / Workbench (capability-gated — never shown
 * without the capability), and the overflow menu (Pin/Unpin, Open in new
 * window, Application settings, Rename…).
 *
 * Mobile: name compresses to text-xl, Continue goes full-width (44 px),
 * secondary actions collapse to an icon-only row.
 */
import { EllipsisVertical, ExternalLink, MessageSquare, PenLine, Pin, PinOff, Play, Settings, Wrench } from 'lucide-react'

import type { ApplicationInstance } from '@/client'
import { StatusBadge } from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { InstanceGlyphTile } from '@/shell/appIcon'

import type { DominantStatus } from '@/features/applications/lib/dominantStatus'
import { openInstanceInNewWindow } from '@/features/applications/lib/openInstance'

export interface OverviewHeaderProps {
  instance: ApplicationInstance
  status: DominantStatus
  packageVersion: string | null
  continueAction: { route: string; label: string }
  hasWorkbench: boolean
  readOnly: boolean
  onContinue: () => void
  onOpenConversation: () => void
  onOpenWorkbench: () => void
  onOpenSettings: () => void
  onTogglePin: () => void
  /** False when the application surface itself owns the one primary action. */
  showContinueAction?: boolean
  /** Omitted when the connected adapter has no durable rename contract. */
  onRename?: () => void
}

export function OverviewHeader({
  instance,
  status,
  packageVersion,
  continueAction,
  hasWorkbench,
  readOnly,
  onContinue,
  onOpenConversation,
  onOpenWorkbench,
  onOpenSettings,
  onTogglePin,
  showContinueAction = true,
  onRename,
}: OverviewHeaderProps) {
  return (
    <header className="flex flex-wrap items-center gap-x-3 gap-y-2" data-testid="overview-header">
      <InstanceGlyphTile instance={instance} className="size-9 rounded-md max-md:size-8" />
      <div className="min-w-0 flex-1 basis-52">
        <div className="flex items-center gap-2">
          <h1 className="truncate text-2xl text-foreground max-md:text-xl">{instance.name}</h1>
          <StatusBadge
            state={status.presentation.state}
            label={status.presentation.label}
            icon={status.presentation.icon}
            spin={status.presentation.spin}
            className="shrink-0"
          />
        </div>
        <p className="truncate text-sm text-foreground-secondary">
          {instance.packageDisplayName}
          {packageVersion ? ` · v${packageVersion}` : ''}
        </p>
      </div>
      <div className="flex items-center gap-1.5 max-md:w-full max-md:flex-col max-md:items-stretch">
        {showContinueAction ? (
          <Button onClick={onContinue} aria-label={`${continueAction.label} — ${instance.name}`} className="min-h-10 md:min-h-9">
            <Play aria-hidden="true" />
            {continueAction.label}
          </Button>
        ) : null}
        <div className="flex items-center gap-1.5 max-md:w-full">
          <Button
            variant="outline"
            onClick={onOpenConversation}
            aria-label="Conversation"
            className="min-h-10 max-md:flex-1 md:min-h-9"
          >
            <MessageSquare aria-hidden="true" />
            {/* Mobile keeps the label: an icon-only full-width button reads as an empty bar. Only the md–lg band goes icon-only. */}
            <span className="md:max-lg:hidden">Conversation</span>
          </Button>
          {hasWorkbench ? (
            <Button
              variant="outline"
              onClick={onOpenWorkbench}
              aria-label="Workbench"
              className="min-h-10 max-md:flex-1 md:min-h-9"
            >
              <Wrench aria-hidden="true" />
              <span className="md:max-lg:hidden">Workbench</span>
            </Button>
          ) : null}
          <DropdownMenu>
            <DropdownMenuTrigger
              aria-label={`More actions for ${instance.name}`}
              className={cn(
                'inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm border border-border bg-surface text-foreground-secondary',
                'transition-colors duration-instant hover:bg-hover hover:text-foreground md:min-h-9 md:min-w-9',
              )}
            >
              <EllipsisVertical className="size-4" aria-hidden="true" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-surface">
              {!readOnly ? (
                <DropdownMenuItem onSelect={onTogglePin}>
                  {instance.pinned ? <PinOff aria-hidden="true" /> : <Pin aria-hidden="true" />}
                  {instance.pinned ? 'Unpin application' : 'Pin application'}
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuItem onSelect={() => openInstanceInNewWindow(instance.id)}>
                <ExternalLink aria-hidden="true" /> Open in new window
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={onOpenSettings}>
                <Settings aria-hidden="true" /> Application settings
              </DropdownMenuItem>
              {!readOnly && onRename ? (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={onRename}>
                    <PenLine aria-hidden="true" /> Rename…
                  </DropdownMenuItem>
                </>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}
