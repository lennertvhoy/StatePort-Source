/**
 * SessionRuntime — the live xterm instance behind a terminal tab.
 *
 * One runtime per tab key (`instanceId:sessionId`), kept in a module-level
 * registry so the xterm instance (and its scrollback) survives route
 * changes: `detach()` suspends rendering, the mock session keeps running,
 * and the next `attach()` moves the same host element back into the DOM.
 *
 * Responsibilities:
 * - xterm + addons (fit, search, web-links) lifecycle;
 * - the local prompt loop against `runCommand` in deterministic mock mode;
 * - direct authenticated byte I/O in production raw-PTY mode;
 * - paste interception (capture-phase) routed to the paste guard via callback;
 * - safe link activation callback, bell behavior, copy-on-select;
 * - transcript export / copy-all from the scrollback (ring buffer honesty);
 * - screen-reader text feed (stripped output) alongside xterm's own SR mode.
 *
 * The runtime NEVER connects or runs anything by itself: commands only leave
 * through the LineEditor's Enter path or an explicit "Insert and run".
 */
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import type { ISearchOptions } from '@xterm/addon-search'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { Terminal } from '@xterm/xterm'
import type { ITheme } from '@xterm/xterm'

import type { TerminalSettings, TerminalSessionState } from '@/client'
import { IS_MAC } from '@/shell/platform'

import { LineEditor } from './lineEditor'
import {
  drainBufferedOutput,
  sendTerminalInput,
  setOutputSink,
  setStateHook,
  submitCommand,
  terminalInputMode,
} from './terminalManager'

export interface RuntimePromptParts {
  user: string
  host: string
  cwd: string
}

export interface SessionRuntimeCallbacks {
  /** Pasted text arrives here FIRST — the view runs the paste guard. */
  onPasteRequest: (text: string) => void
  /** Link activation (Ctrl+click) — the view applies the link-handling pref. */
  onLinkActivate: (uri: string) => void
  /** Ctrl/Cmd+F inside the terminal. */
  onFindRequest: () => void
  /** Visual bell flash + copied-selection feedback. */
  onBell: () => void
  /** Stripped output lines for the screen-reader live region. */
  onScreenReaderText: (text: string) => void
  /** Fitted viewport dimensions; the manager gates delivery on connected state. */
  onResize: (columns: number, rows: number) => void
  getSettings: () => TerminalSettings
  getTheme: () => ITheme
  getPromptParts: () => RuntimePromptParts
}

const FIT_DEBOUNCE_MS = 90
// Intentionally matches ANSI escape sequences (screen-reader text stripping).
// eslint-disable-next-line no-control-regex
const ANSI_PATTERN = /\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07/g

export function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, '').replace(/\r/g, '')
}

export class SessionRuntime {
  /** Current manager key — updated by rebind() when the session is replaced. */
  key: string
  sessionId: string
  private callbacks: SessionRuntimeCallbacks
  private term: Terminal | null = null
  private fitAddon: FitAddon | null = null
  private searchAddon: SearchAddon | null = null
  private host: HTMLDivElement | null = null
  private editor: LineEditor
  private readonly rawPty: boolean
  private alive = true
  private started = false
  private executing = false
  private queue: string[] = []
  private fitTimer: number | null = null
  private readonly onPasteCapture = (event: Event): void => {
    event.preventDefault()
    event.stopPropagation()
    const text = (event as ClipboardEvent).clipboardData?.getData('text/plain') ?? ''
    if (text) this.callbacks.onPasteRequest(text)
  }

  constructor(key: string, sessionId: string, callbacks: SessionRuntimeCallbacks) {
    this.key = key
    this.sessionId = sessionId
    this.callbacks = callbacks
    this.rawPty = terminalInputMode() === 'raw_pty'
    this.editor = new LineEditor({
      prompt: () => this.promptText(),
      promptColumns: () => this.promptColumns(),
      onSubmit: (line) => this.enqueue(line),
    })
  }

  setCallbacks(callbacks: SessionRuntimeCallbacks): void {
    this.callbacks = callbacks
  }

  get isAttached(): boolean {
    return Boolean(this.host?.isConnected)
  }

  /** Attach the persistent host element into a container (creates xterm once). */
  attach(container: HTMLElement): void {
    if (!this.term) this.createTerminal()
    const host = this.host!
    if (host.parentElement !== container) container.appendChild(host)
    this.fitSoon()
  }

  /** Suspend rendering; the session + scrollback stay alive. */
  detach(): void {
    this.host?.remove()
  }

  /** First prompt after connecting (replays pre-attach buffered output first). */
  start(): void {
    if (!this.term || this.started || !this.alive) return
    this.started = true
    if (!this.rawPty) this.writePrompt()
  }

  /** User-facing focus. */
  focus(): void {
    this.term?.focus()
  }

  // ── terminal creation + events ─────────────────────────────────────────────

  private createTerminal(): void {
    const settings = this.callbacks.getSettings()
    const term = new Terminal({
      fontFamily: fontStack(settings.fontFamily),
      fontSize: settings.fontSize,
      lineHeight: settings.lineHeight,
      cursorStyle: settings.cursorStyle,
      cursorBlink: settings.cursorBlink,
      scrollback: settings.scrollbackLines,
      screenReaderMode: settings.screenReaderMode,
      rightClickSelectsWord: settings.rightClickBehavior === 'select_word',
      macOptionIsMeta: true,
      drawBoldTextInBrightColors: false,
      theme: this.callbacks.getTheme(),
    })
    this.fitAddon = new FitAddon()
    this.searchAddon = new SearchAddon()
    term.loadAddon(this.fitAddon)
    term.loadAddon(this.searchAddon)
    term.loadAddon(
      new WebLinksAddon((_event, uri) => {
        this.callbacks.onLinkActivate(uri)
      }),
    )

    const host = document.createElement('div')
    host.className = 'terminal-runtime-host'
    host.style.height = '100%'
    host.style.width = '100%'
    host.addEventListener('paste', this.onPasteCapture, true)
    term.open(host)

    term.onData((data) => this.handleData(data))
    term.onResize(({ cols, rows }) => this.callbacks.onResize(cols, rows))
    term.onBell(() => this.handleBell())
    term.onSelectionChange(() => this.handleSelectionChange())
    term.attachCustomKeyEventHandler((event) => this.handleKeyEvent(event))

    this.term = term
    this.host = host

    // Output/state flow via the manager relay (single client subscription).
    setOutputSink(this.key, (text) => this.writeOutput(text))
    setStateHook(this.key, (state) => this.handleState(state))
    // Replay anything the mock emitted before this runtime existed
    // (e.g. the "Connected to …" banner from the connect call).
    for (const chunk of drainBufferedOutput(this.key)) this.writeOutput(chunk)
  }

  private handleState(state: TerminalSessionState): void {
    if (state === 'ended') {
      this.alive = false
      this.queue = []
    } else if (state === 'connected') {
      const wasDead = !this.alive
      this.alive = true
      // Live reconnect path: the mock preserves the buffer; redraw a prompt.
      if (!this.rawPty && this.started && !this.executing && !wasDead) this.writePrompt()
    }
  }

  private handleKeyEvent(event: KeyboardEvent): boolean {
    if (event.type !== 'keydown') return true
    const key = event.key.toLowerCase()
    const mod = IS_MAC ? event.metaKey : event.ctrlKey
    if (mod && !event.shiftKey && key === 'f') {
      this.callbacks.onFindRequest()
      return false
    }
    if (!this.rawPty && event.ctrlKey && !event.shiftKey && key === 'l') {
      this.clear()
      return false
    }
    if (mod && key === 'c' && (event.shiftKey || this.term?.hasSelection())) {
      this.copySelection()
      return false
    }
    // Ctrl/Cmd+V (and Ctrl+Shift+V): let the browser fire its paste event;
    // the capture-phase listener routes it through the paste guard.
    if (mod && key === 'v') return false
    return true
  }

  private handleData(data: string): void {
    if (!this.term || !this.alive) return
    let input = data
    // Mobile sticky-Ctrl latch: convert the next printable char to a control char.
    if (this.ctrlLatch && input.length === 1 && input >= ' ' && input <= '~') {
      input = String.fromCharCode(input.charCodeAt(0) & 0x1f)
      this.ctrlLatch = false
    }
    if (this.rawPty) {
      try {
        sendTerminalInput(this.key, input)
      } catch (err) {
        this.writeError(err)
      }
      return
    }
    if (this.executing) return // no interactive programs in the mock PTY
    const ops = this.editor.input(input)
    if (ops.length > 0) this.term.write(ops.join(''))
  }

  private ctrlLatch = false

  /** Mobile accessory row: inject data as if typed (Esc/Tab/arrows/`|`/`~`). */
  sendData(data: string): void {
    this.handleData(data)
    this.focus()
  }

  /** Mobile accessory row: sticky Ctrl — applies to the next typed character. */
  setCtrlLatch(on: boolean): void {
    this.ctrlLatch = on
  }

  get ctrlLatchActive(): boolean {
    return this.ctrlLatch
  }

  private handleBell(): void {
    const bell = this.callbacks.getSettings().bell
    if (bell === 'visual') {
      this.callbacks.onBell()
    } else if (bell === 'sound') {
      beep()
    }
  }

  private handleSelectionChange(): void {
    if (!this.callbacks.getSettings().copyOnSelect) return
    const selection = this.term?.getSelection() ?? ''
    if (selection) void copyText(selection)
  }

  // ── prompt loop ────────────────────────────────────────────────────────────

  private promptText(): string {
    const parts = this.callbacks.getPromptParts()
    return `\x1b[1;32m${parts.user}@${parts.host}\x1b[0m:\x1b[1;34m${parts.cwd}\x1b[0m$ `
  }

  private promptColumns(): number {
    const parts = this.callbacks.getPromptParts()
    return `${parts.user}@${parts.host}:${parts.cwd}$ `.length
  }

  private writePrompt(): void {
    if (!this.term || !this.alive || this.rawPty) return
    this.term.write(this.editor.promptOp())
  }

  private enqueue(line: string): void {
    if (this.rawPty) return
    this.queue.push(line)
    if (!this.executing) void this.drainQueue()
  }

  private async drainQueue(): Promise<void> {
    if (!this.term) return
    this.executing = true
    try {
      while (this.queue.length > 0 && this.alive) {
        const line = this.queue.shift()!
        if (line.trim()) {
          try {
            await submitCommand(this.key, line)
          } catch (err) {
            this.writeError(err)
          }
        }
        if (this.alive) this.writePrompt()
      }
      this.queue = []
    } finally {
      this.executing = false
    }
  }

  private writeError(err: unknown): void {
    const message = err instanceof Error ? err.message : 'Command failed'
    this.term?.write(`\x1b[31m${message}\x1b[0m\r\n`)
  }

  // ── paste + insert paths (all review-first; never auto-run) ───────────────

  /** Programmatic paste entry (context menu / tests): routes to the guard. */
  requestPaste(text: string): void {
    if (text) this.callbacks.onPasteRequest(text)
  }

  /** Paste guard: "Insert without running" / command drafts — never submits. */
  insertAtPrompt(text: string): void {
    if (!this.term || !this.alive) return
    if (this.rawPty) {
      // Bash/readline bracketed-paste keeps embedded newlines reviewable at
      // the live prompt until the user explicitly presses Enter.
      const input = text.includes('\n') ? `\x1b[200~${text}\x1b[201~` : text
      try {
        sendTerminalInput(this.key, input)
      } catch (err) {
        this.writeError(err)
      }
      this.focus()
      return
    }
    const ops = this.editor.insertText(text)
    if (ops.length > 0) this.term.write(ops.join(''))
    this.focus()
  }

  /** Paste guard: explicit "Insert and run" — lines execute one by one. */
  async runLines(lines: string[]): Promise<void> {
    if (!this.term || !this.alive) return
    if (this.rawPty) {
      for (const line of lines) {
        if (!this.alive || !line.trim()) continue
        sendTerminalInput(this.key, `${line}\r`)
      }
      this.focus()
      return
    }
    this.executing = true
    try {
      for (const line of lines) {
        if (!this.alive) break
        if (!line.trim()) continue
        this.term.write(`${line}\r\n`)
        try {
          await submitCommand(this.key, line)
        } catch (err) {
          this.writeError(err)
        }
        if (this.alive) this.writePrompt()
      }
    } finally {
      this.executing = false
    }
    void this.drainQueue()
  }

  // ── view operations ────────────────────────────────────────────────────────

  clear(): void {
    if (!this.term) return
    this.term.clear()
    if (this.alive) {
      this.term.write(this.editor.promptOp() + this.editor.echoBuffer())
    }
  }

  copySelection(): void {
    const selection = this.term?.getSelection() ?? ''
    if (selection) void copyText(selection)
  }

  getSelection(): string {
    return this.term?.getSelection() ?? ''
  }

  hasSelection(): boolean {
    return this.term?.hasSelection() ?? false
  }

  selectAll(): void {
    this.term?.selectAll()
  }

  /** Full scrollback transcript (ring buffer — exports are explicit). */
  exportText(): string {
    if (!this.term) return ''
    const buffer = this.term.buffer.active
    const lines: string[] = []
    for (let i = 0; i < buffer.length; i += 1) {
      lines.push(buffer.getLine(i)?.translateToString(true) ?? '')
    }
    while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop()
    return lines.join('\n')
  }

  copyAll(): void {
    const text = this.exportText()
    if (text) void copyText(text)
  }

  findNext(term: string, options?: ISearchOptions): boolean {
    return this.searchAddon?.findNext(term, options) ?? false
  }

  findPrevious(term: string, options?: ISearchOptions): boolean {
    return this.searchAddon?.findPrevious(term, options) ?? false
  }

  onSearchResults(listener: (result: { resultIndex: number; resultCount: number } | undefined) => void): () => void {
    const disposable = this.searchAddon?.onDidChangeResults((e) => listener(e ? { resultIndex: e.resultIndex, resultCount: e.resultCount } : undefined))
    return () => {
      disposable?.dispose()
      this.searchAddon?.clearDecorations()
    }
  }

  clearSearch(): void {
    this.searchAddon?.clearDecorations()
  }

  /** Live-apply settings (font, cursor, scrollback, SR mode, …) + fit. */
  applySettings(): void {
    if (!this.term) return
    const settings = this.callbacks.getSettings()
    this.term.options = {
      fontFamily: fontStack(settings.fontFamily),
      fontSize: settings.fontSize,
      lineHeight: settings.lineHeight,
      cursorStyle: settings.cursorStyle,
      cursorBlink: settings.cursorBlink,
      scrollback: settings.scrollbackLines,
      screenReaderMode: settings.screenReaderMode,
      rightClickSelectsWord: settings.rightClickBehavior === 'select_word',
    }
    this.fitSoon()
  }

  applyTheme(): void {
    if (!this.term) return
    this.term.options = { theme: this.callbacks.getTheme() }
  }

  fit(): void {
    if (!this.host?.isConnected) return
    try {
      this.fitAddon?.fit()
    } catch {
      // zero-sized containers during layout transitions — next resize fits
    }
  }

  fitSoon(): void {
    if (this.fitTimer !== null) window.clearTimeout(this.fitTimer)
    this.fitTimer = window.setTimeout(() => {
      this.fitTimer = null
      this.fit()
    }, FIT_DEBOUNCE_MS)
  }

  /** Re-point at a replacement session (ended/lost → reconnect), keep buffer. */
  rebind(newKey: string, newSessionId: string): void {
    this.key = newKey
    this.sessionId = newSessionId
    this.alive = true
    this.editor.buffer = ''
    this.queue = []
    this.term?.write('\r\n\x1b[2m— new session started —\x1b[0m\r\n')
    this.writePrompt()
  }

  private writeOutput(text: string): void {
    this.term?.write(text)
    const stripped = stripAnsi(text).trim()
    if (stripped) this.callbacks.onScreenReaderText(stripped)
  }

  dispose(): void {
    if (this.fitTimer !== null) window.clearTimeout(this.fitTimer)
    this.fitTimer = null
    setOutputSink(this.key, null)
    setStateHook(this.key, null)
    this.host?.removeEventListener('paste', this.onPasteCapture, true)
    this.host?.remove()
    this.term?.dispose()
    this.term = null
    this.host = null
  }
}

// ── Runtime registry (module-level; survives navigation) ─────────────────────

const runtimes = new Map<string, SessionRuntime>()

export function getRuntime(key: string): SessionRuntime | undefined {
  return runtimes.get(key)
}

export function ensureRuntime(key: string, sessionId: string, callbacks: SessionRuntimeCallbacks): SessionRuntime {
  const existing = runtimes.get(key)
  if (existing) {
    existing.setCallbacks(callbacks)
    return existing
  }
  const runtime = new SessionRuntime(key, sessionId, callbacks)
  runtimes.set(key, runtime)
  return runtime
}

/** Re-key + rebind a runtime after its tab's session was replaced (restart flow). */
export function moveRuntime(oldKey: string, newKey: string, newSessionId: string): void {
  const runtime = runtimes.get(oldKey)
  if (!runtime) return
  const collision = runtimes.get(newKey)
  if (collision && collision !== runtime) collision.dispose()
  runtimes.delete(oldKey)
  runtimes.set(newKey, runtime)
  runtime.rebind(newKey, newSessionId)
}

export function disposeRuntime(key: string): void {
  const runtime = runtimes.get(key)
  if (!runtime) return
  runtimes.delete(key)
  runtime.dispose()
}

/** Test seam. */
export function disposeAllRuntimes(): void {
  for (const key of [...runtimes.keys()]) disposeRuntime(key)
}

// ── helpers ──────────────────────────────────────────────────────────────────

function fontStack(family: string): string {
  return `${family}, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`
}

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // Clipboard permission denied — the selection stays visible; no crash.
  }
}

let audioContext: AudioContext | null = null

function beep(): void {
  try {
    audioContext ??= new AudioContext()
    const oscillator = audioContext.createOscillator()
    const gain = audioContext.createGain()
    gain.gain.value = 0.04
    oscillator.frequency.value = 880
    oscillator.connect(gain)
    gain.connect(audioContext.destination)
    oscillator.start()
    oscillator.stop(audioContext.currentTime + 0.08)
  } catch {
    // Audio unavailable — bell is best-effort.
  }
}
