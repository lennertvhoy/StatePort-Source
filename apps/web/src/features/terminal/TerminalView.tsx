/**
 * TerminalView — the React surface around a SessionRuntime: full-height xterm
 * canvas, fit-on-resize (90 ms debounce), find bar, paste-guard interstitial,
 * safe link activation, context menu, bell flash, and the screen-reader
 * live region. Rendering suspends on unmount (detach); the session and its
 * scrollback stay alive in the module-level runtime registry.
 */
import { ClipboardPaste, Copy, Download, Eraser, MessageSquare, Search, TextSelect } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { TerminalSettings, TerminalTarget } from '@/client'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import { cn } from '@/lib/utils'

import { FindBar } from './FindBar'
import { PasteGuardDialog } from './PasteGuardDialog'
import type { PasteAnalysis } from './pasteGuard'
import { analyzePaste, pasteNeedsConfirmation } from './pasteGuard'
import type { SessionRuntime, SessionRuntimeCallbacks } from './sessionRuntime'
import { ensureRuntime } from './sessionRuntime'
import { downloadTextFile, exportFilenameFor } from './terminalExport'
import { buildXtermTheme } from './terminalTheme'
import type { TerminalThemePreference } from './terminalTheme'
import { resizeTerminal, type TerminalTab } from './terminalManager'
import {
  openTerminalLink,
  validateTerminalLink,
  type TerminalLinkDecision,
} from './terminalLinks'

export interface TerminalViewProps {
  tab: TerminalTab
  instanceId: string
  targetKind: TerminalTarget['kind']
  settings: TerminalSettings
  themePref: TerminalThemePreference
  findOpen: boolean
  onFindOpenChange: (open: boolean) => void
  /** Compact (dock) presentation — same runtime, tighter chrome. */
  compact?: boolean
}

export function TerminalView({
  tab,
  instanceId,
  targetKind,
  settings,
  themePref,
  findOpen,
  onFindOpenChange,
  compact = false,
}: TerminalViewProps) {
  const navigate = useNavigate()
  const containerRef = useRef<HTMLDivElement>(null)
  const [pasteAnalysis, setPasteAnalysis] = useState<PasteAnalysis | null>(null)
  const [linkRequest, setLinkRequest] = useState<TerminalLinkDecision | null>(null)
  const [bellFlash, setBellFlash] = useState(false)
  const [srText, setSrText] = useState('')
  const [hasSelection, setHasSelection] = useState(false)

  // Latest-value refs keep the runtime callbacks stable across renders;
  // they are written inside an effect (never during render).
  const settingsRef = useRef(settings)
  const themePrefRef = useRef(themePref)
  const tabRef = useRef(tab)
  const runtimeRef = useRef<SessionRuntime | null>(null)
  const findOpenChangeRef = useRef(onFindOpenChange)
  const navigateRef = useRef(navigate)
  useEffect(() => {
    settingsRef.current = settings
    themePrefRef.current = themePref
    tabRef.current = tab
    findOpenChangeRef.current = onFindOpenChange
    navigateRef.current = navigate
  })

  const callbacks = useMemo<SessionRuntimeCallbacks>(
    () => ({
      onPasteRequest: (text) => {
        const runtime = runtimeRef.current
        if (!runtime) return
        const analysis = analyzePaste(text)
        if (pasteNeedsConfirmation(analysis, settingsRef.current.multilinePasteConfirmation)) {
          setPasteAnalysis(analysis)
        } else if (analysis.multiline) {
          // Setting "never confirm": raw terminal behavior — lines run.
          void runtime.runLines(analysis.lines.filter((line) => line.trim() !== ''))
        } else {
          runtime.insertAtPrompt(analysis.text)
        }
      },
      onLinkActivate: (uri) => {
        const handling = settingsRef.current.linkHandling
        const decision = validateTerminalLink(uri)
        if (!decision.href || handling === 'confirm') {
          setLinkRequest(decision)
        } else if (handling === 'open') {
          openTerminalLink(decision)
        } else {
          void navigator.clipboard?.writeText(uri).catch(() => undefined)
        }
      },
      onFindRequest: () => findOpenChangeRef.current(true),
      onBell: () => {
        setBellFlash(true)
        window.setTimeout(() => setBellFlash(false), 160)
      },
      onScreenReaderText: (text) => {
        setSrText((prev) => (prev + text + '\n').slice(-6000))
      },
      onResize: (columns, rows) => resizeTerminal(tabRef.current.key, columns, rows),
      getSettings: () => settingsRef.current,
      getTheme: () => buildXtermTheme(themePrefRef.current),
      getPromptParts: () => ({
        user: 'kim',
        host: targetKind === 'ssh' ? 'homelab-dev' : 'stateport',
        cwd: tabRef.current.cwd ?? '~',
      }),
    }),
    [targetKind],
  )

  // ── Runtime lifecycle: create once, attach here, suspend on unmount ───────
  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const runtime = ensureRuntime(tab.key, tab.sessionId, callbacks)
    runtimeRef.current = runtime
    runtime.setCallbacks(callbacks)
    runtime.attach(container)
    if (tabRef.current.state === 'connected' || tabRef.current.state === 'reconnecting') {
      runtime.start()
    }
    const observer = new ResizeObserver(() => runtime.fitSoon())
    observer.observe(container)
    return () => {
      observer.disconnect()
      runtime.detach()
    }
  }, [tab.key, tab.sessionId, callbacks])

  // ── Live settings / theme ──────────────────────────────────────────────────
  useEffect(() => {
    runtimeRef.current?.applySettings()
  }, [settings])

  useEffect(() => {
    runtimeRef.current?.applyTheme()
  }, [themePref])

  useEffect(() => {
    if (themePref !== 'match_interface') return
    const observer = new MutationObserver(() => runtimeRef.current?.applyTheme())
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => observer.disconnect()
  }, [themePref])

  const interactive = tab.state === 'connected'

  const pasteFromClipboard = () => {
    void navigator.clipboard
      ?.readText()
      .then((text) => {
        if (text) callbacks.onPasteRequest(text)
      })
      .catch(() => undefined)
  }

  const sendSelectionToConversation = () => {
    const selection = runtimeRef.current?.getSelection() ?? ''
    if (!selection) return
    sendToBridge({ kind: 'terminal-selection', instanceId, sessionId: tab.sessionId, text: selection })
    void navigateRef.current(`/app/${instanceId}/conversation`)
  }

  const terminalCanvas = (
    <div
      ref={containerRef}
      className={cn('min-h-0 flex-1 overflow-hidden', compact ? 'p-1' : 'p-2')}
      data-testid="terminal-canvas"
      onContextMenu={
        settings.rightClickBehavior === 'paste'
          ? (event) => {
              event.preventDefault()
              pasteFromClipboard()
            }
          : undefined
      }
    />
  )

  return (
    <div
      className="relative flex h-full min-h-0 flex-1 flex-col bg-sunken"
      role="region"
      aria-label={`Terminal — ${tab.name}`}
      data-testid="terminal-view"
    >
      {settings.rightClickBehavior === 'context_menu' ? (
        <ContextMenu
          onOpenChange={(open) => {
            if (open) setHasSelection(runtimeRef.current?.hasSelection() ?? false)
          }}
        >
          <ContextMenuTrigger asChild>{terminalCanvas}</ContextMenuTrigger>
          <ContextMenuContent className="bg-surface" data-testid="terminal-context-menu">
            <ContextMenuItem disabled={!hasSelection} onSelect={() => runtimeRef.current?.copySelection()}>
              <Copy className="size-4" aria-hidden="true" />
              Copy selection
            </ContextMenuItem>
            <ContextMenuItem onSelect={pasteFromClipboard}>
              <ClipboardPaste className="size-4" aria-hidden="true" />
              Paste
            </ContextMenuItem>
            <ContextMenuItem onSelect={() => runtimeRef.current?.selectAll()}>
              <TextSelect className="size-4" aria-hidden="true" />
              Select all
            </ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={() => findOpenChangeRef.current(true)}>
              <Search className="size-4" aria-hidden="true" />
              Find in output
            </ContextMenuItem>
            <ContextMenuItem onSelect={() => runtimeRef.current?.clear()}>
              <Eraser className="size-4" aria-hidden="true" />
              Clear
            </ContextMenuItem>
            <ContextMenuItem onSelect={() => runtimeRef.current?.copyAll()}>
              <Copy className="size-4" aria-hidden="true" />
              Copy all output
            </ContextMenuItem>
            <ContextMenuItem
              onSelect={() => {
                const text = runtimeRef.current?.exportText() ?? ''
                if (text) downloadTextFile(exportFilenameFor(tabRef.current.name), text)
              }}
            >
              <Download className="size-4" aria-hidden="true" />
              Export session output
            </ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuItem disabled={!hasSelection} onSelect={sendSelectionToConversation}>
              <MessageSquare className="size-4" aria-hidden="true" />
              Send selection to Conversation
            </ContextMenuItem>
          </ContextMenuContent>
        </ContextMenu>
      ) : (
        terminalCanvas
      )}

      {findOpen ? (
        <FindBar
          tabKey={tab.key}
          onClose={() => {
            findOpenChangeRef.current(false)
            runtimeRef.current?.focus()
          }}
        />
      ) : null}

      {/* Visual bell flash */}
      <div
        className={cn(
          'pointer-events-none absolute inset-0 border-2 border-accent transition-opacity duration-fast',
          bellFlash ? 'opacity-100' : 'opacity-0',
        )}
        aria-hidden="true"
        data-testid="terminal-bell-flash"
      />

      <PasteGuardDialog
        analysis={pasteAnalysis}
        onResolve={(resolution) => {
          const analysis = pasteAnalysis
          setPasteAnalysis(null)
          const current = runtimeRef.current
          if (!analysis || !current) return
          if (resolution === 'insert') current.insertAtPrompt(analysis.text)
          else if (resolution === 'insert_run') void current.runLines(analysis.lines.filter((line) => line.trim() !== ''))
          current.focus()
        }}
      />

      {/* Safe link activation */}
      <AlertDialog open={linkRequest !== null} onOpenChange={(open) => !open && setLinkRequest(null)}>
        <AlertDialogContent className="bg-surface" data-testid="terminal-link-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-xl">
              {linkRequest?.href ? 'Open link?' : 'Link cannot be opened'}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="flex flex-col gap-1">
                <span>
                  {linkRequest?.href
                    ? 'The terminal reported this http(s) link. It opens in an isolated new tab.'
                    : 'Terminal output is untrusted. This destination stays copy-only for manual review.'}
                </span>
                <span className="tnum break-all font-mono text-xs text-foreground">{linkRequest?.original}</span>
                {linkRequest?.refusal ? (
                  <span className="text-status-attention">{linkRequest.refusal}</span>
                ) : null}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button
              variant="outline"
              onClick={() => {
                if (linkRequest) void navigator.clipboard?.writeText(linkRequest.original).catch(() => undefined)
                setLinkRequest(null)
              }}
            >
              Copy link
            </Button>
            {linkRequest?.href ? (
              <Button
                onClick={() => {
                  openTerminalLink(linkRequest)
                  setLinkRequest(null)
                }}
              >
                Open link
              </Button>
            ) : null}
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Screen-reader mode: line-buffered live region for terminal output */}
      {settings.screenReaderMode ? (
        <div aria-live="polite" aria-label="Terminal output" className="sr-only" data-testid="terminal-sr-region">
          {srText}
        </div>
      ) : null}

      {/* Input state hint while a command runs / during reconnect */}
      {!interactive && tab.state === 'reconnecting' ? (
        <div className="absolute inset-x-0 bottom-0 flex items-center gap-2 border-t border-border bg-surface px-3 py-1 text-xs text-foreground-secondary">
          Input is queued while the session reconnects…
        </div>
      ) : null}
    </div>
  )
}
