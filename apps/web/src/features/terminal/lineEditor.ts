/**
 * LineEditor — the local prompt line editor for the mock PTY.
 *
 * Pure string-in / string-out: every method returns the exact terminal write
 * ops (echo) needed to render the change; the runtime writes them to xterm in
 * order. No DOM, no xterm imports — fully unit-testable.
 *
 * Model: a single editable buffer that may contain `\n` (paste-inserted
 * multiline text under review). The cursor is always at the END of the
 * buffer, which keeps echo truthful and simple:
 * - printable input appends and echoes;
 * - backspace pops one char (`\b \b`, or move-up when joining lines);
 * - Enter (`\r`) submits the buffer via `onSubmit` — the RUN keystroke is
 *   always the user's; pasted content never submits by itself when inserted
 *   through `insertText`.
 */

export interface LineEditorOptions {
  /** The ANSI-decorated prompt (e.g. `kim@stateport:~/app$ ` with color). */
  prompt: () => string
  /** Visible column width of the prompt (no ANSI), for line-join math. */
  promptColumns: () => number
  /** Called once per submitted line (Enter). Never called by insertText. */
  onSubmit: (line: string) => void
  historySize?: number
}

const ERASE = '\b \b'

export class LineEditor {
  /** Current edit buffer; may contain `\n` from review-inserts. */
  buffer = ''
  private history: string[] = []
  private historyIndex: number | null = null
  private stash = ''
  private readonly prompt: () => string
  private readonly promptColumns: () => number
  private readonly onSubmit: (line: string) => void
  private readonly historySize: number

  constructor(options: LineEditorOptions) {
    this.prompt = options.prompt
    this.promptColumns = options.promptColumns
    this.onSubmit = options.onSubmit
    this.historySize = options.historySize ?? 100
  }

  /** The prompt op itself. */
  promptOp(): string {
    return this.prompt()
  }

  /** Echo of the current buffer (used after screen clears). */
  echoBuffer(): string {
    return echoOf(this.buffer)
  }

  get historyEntries(): readonly string[] {
    return this.history
  }

  /** Process one xterm `onData` chunk (typed keys, control chars, raw paste). */
  input(data: string): string[] {
    const ops: string[] = []
    let i = 0
    while (i < data.length) {
      const ch = data[i]
      // Escape sequences arrive as a unit ("\x1b[A" etc.) — handle & skip.
      if (ch === '\x1b') {
        const seq = data.slice(i, i + 3)
        if (seq === '\x1b[A') ops.push(...this.historyUp())
        else if (seq === '\x1b[B') ops.push(...this.historyDown())
        // Left, Right, Home, End, and unknown escapes are ignored; the cursor stays at the end.
        i += seq.startsWith('\x1b[') && seq.length === 3 ? 3 : 1
        continue
      }
      if (ch === '\r') {
        // Enter — submit the buffer. The only path that runs anything.
        const line = this.buffer
        this.buffer = ''
        this.historyIndex = null
        this.stash = ''
        if (line.trim()) {
          this.history.push(line)
          if (this.history.length > this.historySize) this.history.shift()
        }
        ops.push('\r\n')
        this.onSubmit(line)
        i += 1
        continue
      }
      if (ch === '\n') {
        ops.push(...this.appendOps('\n'))
        i += 1
        continue
      }
      if (ch === '\x7f') {
        ops.push(...this.backspaceOp())
        i += 1
        continue
      }
      if (ch === '\x03') {
        // Ctrl+C — cancel the line.
        this.buffer = ''
        this.historyIndex = null
        ops.push('^C', '\r\n', this.promptOp())
        i += 1
        continue
      }
      if (ch === '\x15') {
        // Ctrl+U — erase the whole buffer.
        ops.push(...this.eraseAllOps())
        i += 1
        continue
      }
      if (ch === '\x0c') {
        // Ctrl+L — clear screen, redraw prompt + buffer.
        ops.push('\x1b[2J\x1b[H', this.promptOp(), this.echoBuffer())
        i += 1
        continue
      }
      if (ch === '\t' || ch < ' ') {
        // Tab (no completion in the mock) and other control chars: ignored.
        i += 1
        continue
      }
      ops.push(...this.appendOps(ch))
      i += 1
    }
    return ops
  }

  /**
   * Insert text at the prompt WITHOUT running it (paste guard's
   * "Insert without running", assistant command drafts). Newlines are kept
   * as buffer newlines so the user reviews the exact text before pressing
   * Enter themselves.
   */
  insertText(text: string): string[] {
    const normalized = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    return this.appendOps(normalized)
  }

  /** Older history entry (Up). */
  historyUp(): string[] {
    if (this.history.length === 0) return []
    if (this.historyIndex === null) {
      this.stash = this.buffer
      this.historyIndex = this.history.length - 1
    } else {
      this.historyIndex = Math.max(0, this.historyIndex - 1)
    }
    return this.replaceBufferOps(this.history[this.historyIndex] ?? '')
  }

  /** Newer history entry / back to the stashed line (Down). */
  historyDown(): string[] {
    if (this.historyIndex === null) return []
    if (this.historyIndex >= this.history.length - 1) {
      this.historyIndex = null
      return this.replaceBufferOps(this.stash)
    }
    this.historyIndex += 1
    return this.replaceBufferOps(this.history[this.historyIndex] ?? '')
  }

  // ── internals ────────────────────────────────────────────────────────────

  private appendOps(text: string): string[] {
    this.buffer += text
    return [echoOf(text)]
  }

  private backspaceOp(): string[] {
    if (this.buffer.length === 0) return []
    const last = this.buffer[this.buffer.length - 1]
    this.buffer = this.buffer.slice(0, -1)
    if (last !== '\n') return [ERASE]
    // Joining lines: cursor sat at column 0 of the visual line after the
    // newline; move up one row and right to the end of the previous visual
    // line (which includes the prompt width when it is the buffer's first).
    const remaining = this.buffer
    const nl = remaining.lastIndexOf('\n')
    const prevSegment = nl === -1 ? remaining : remaining.slice(nl + 1)
    const targetColumn = prevSegment.length + (nl === -1 ? this.promptColumns() : 0)
    return [`\x1b[A${targetColumn > 0 ? `\x1b[${targetColumn}C` : ''}`]
  }

  private eraseAllOps(): string[] {
    const ops: string[] = []
    while (this.buffer.length > 0) ops.push(...this.backspaceOp())
    return ops
  }

  private replaceBufferOps(next: string): string[] {
    return [...this.eraseAllOps(), ...this.appendOps(next)]
  }
}

function echoOf(text: string): string {
  return text.replace(/\n/g, '\r\n')
}
