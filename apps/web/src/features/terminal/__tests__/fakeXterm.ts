/**
 * Fake xterm Terminal for jsdom tests — records everything written to it.
 * Imported by vi.mock factories (kept in a module so hoisted factories can
 * reach it) and by tests to drive input and assert output.
 */
export class FakeTerminal {
  static instances: FakeTerminal[] = []
  written: string[] = []
  options: Record<string, unknown>
  dataHandler: ((data: string) => void) | null = null
  resizeHandler: ((size: { cols: number; rows: number }) => void) | null = null
  bellHandler: (() => void) | null = null
  selectionHandler: (() => void) | null = null
  keyHandler: ((event: KeyboardEvent) => boolean) | null = null
  buffer = {
    active: {
      length: 0,
      getLine: () => undefined as { translateToString: (trim: boolean) => string } | undefined,
    },
  }

  constructor(options: Record<string, unknown>) {
    this.options = options
    FakeTerminal.instances.push(this)
  }
  open(): void {}
  write(data: string): void {
    this.written.push(data)
  }
  loadAddon(): void {}
  onData(cb: (data: string) => void): { dispose(): void } {
    this.dataHandler = cb
    return { dispose: () => undefined }
  }
  onResize(cb: (size: { cols: number; rows: number }) => void): { dispose(): void } {
    this.resizeHandler = cb
    return { dispose: () => undefined }
  }
  onBell(cb: () => void): { dispose(): void } {
    this.bellHandler = cb
    return { dispose: () => undefined }
  }
  onSelectionChange(cb: () => void): { dispose(): void } {
    this.selectionHandler = cb
    return { dispose: () => undefined }
  }
  attachCustomKeyEventHandler(cb: (event: KeyboardEvent) => boolean): void {
    this.keyHandler = cb
  }
  focus(): void {}
  clear(): void {
    this.written.push('[clear]')
  }
  dispose(): void {}
  getSelection(): string {
    return ''
  }
  hasSelection(): boolean {
    return false
  }
  selectAll(): void {}
  paste(data: string): void {
    this.dataHandler?.(data)
  }
  get text(): string {
    return this.written.join('')
  }
}

export function lastFakeTerminal(): FakeTerminal {
  const term = FakeTerminal.instances[FakeTerminal.instances.length - 1]
  if (!term) throw new Error('no FakeTerminal created')
  return term
}

export function resetFakeTerminals(): void {
  FakeTerminal.instances = []
}
