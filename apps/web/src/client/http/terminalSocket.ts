/**
 * TerminalSocket — the production terminal transport (contract §15).
 *
 * Protocol (binding):
 *   1. `POST /v1/instances/:id/terminal/prepare` yields a one-use ticket
 *      (`stateport.terminal-socket/v1`).
 *   2. Open a SAME-ORIGIN WebSocket to the ticket's `socketPath` with the
 *      subprotocol `stateport.terminal.v1`.
 *   3. The FIRST frame the client sends is one `authenticate` message
 *      carrying the one-use token — the token NEVER goes in the URL.
 *   4. The service answers with a `ready` frame that must match the ticket's
 *      sessionId / purpose / targetClass / formatVersion. No terminal input
 *      is sent before authentication completes.
 *   5. After `ready`, frames are raw PTY I/O.
 *
 * There is no automatic reconnection and never a cross-origin dial: a lost
 * socket is reported honestly, and reconnecting means a fresh prepare +
 * socket from the terminal client.
 */
import { ClientError } from '../types'
import type { TerminalTicket } from './mappers'

/** Minimal WebSocket surface so tests can inject a fake. */
export interface WebSocketLike {
  readyState: number
  send(data: string | ArrayBuffer | ArrayBufferView): void
  close(): void
  onopen: ((event: unknown) => void) | null
  onmessage: ((event: { data: unknown }) => void) | null
  onclose: ((event: { code: number; reason: string }) => void) | null
  onerror: ((event: unknown) => void) | null
}

export type WebSocketFactory = (url: string, protocols: string | string[]) => WebSocketLike

export interface TerminalSocketOptions {
  ticket: TerminalTicket
  instanceId: string
  columns: number
  rows: number
  /** Injectable for tests; defaults to the platform WebSocket. */
  webSocketFactory?: WebSocketFactory
  /** Injectable origin for tests (e.g. 'https://stateport.test'). */
  origin?: string
}

interface ReadyFrame {
  type: 'ready'
  formatVersion: string
  sessionId: string
  purpose: string
  targetClass: string
  reconnect: boolean
}

const WS_OPEN = 1
const READY_FRAME_KEYS = [
  'formatVersion',
  'purpose',
  'reconnect',
  'sessionId',
  'targetClass',
  'type',
] as const

function defaultFactory(url: string, protocols: string | string[]): WebSocketLike {
  return new WebSocket(url, protocols) as unknown as WebSocketLike
}

export class TerminalSocket {
  readonly sessionId: string
  private readonly ticket: TerminalTicket
  private readonly instanceId: string
  private readonly columns: number
  private readonly rows: number
  private readonly factory: WebSocketFactory
  private readonly origin?: string
  private ws: WebSocketLike | null = null
  private readyFlag = false
  private dataListeners = new Set<(text: string) => void>()
  private closeListeners = new Set<(event: { code: number; reason: string }) => void>()

  constructor(options: TerminalSocketOptions) {
    this.ticket = options.ticket
    this.instanceId = options.instanceId
    this.columns = options.columns
    this.rows = options.rows
    this.factory = options.webSocketFactory ?? defaultFactory
    this.origin = options.origin
    this.sessionId = options.ticket.sessionId
  }

  get ready(): boolean {
    return this.readyFlag
  }

  /** Same-origin ws(s) URL for the ticket's socket path. */
  private socketUrl(): string {
    const origin =
      this.origin ?? (typeof window !== 'undefined' && window.location?.origin ? window.location.origin : 'http://localhost')
    const url = new URL(this.ticket.socketPath, origin)
    const current = new URL(origin)
    if (url.origin !== current.origin) {
      throw new ClientError('validation', 'Terminal socket path resolved to a foreign origin — refusing to connect', {
        detail: `socketPath "${this.ticket.socketPath}" vs origin "${current.origin}"`,
      })
    }
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
    // The one-use token is NEVER placed in the URL (contract §15).
    return url.toString()
  }

  /**
   * Open the socket, send the single authenticate frame first, and resolve
   * once the `ready` frame has been validated against the ticket. Rejects
   * on socket error, pre-ready close, or a mismatched/invalid ready frame.
   */
  connect(): Promise<void> {
    if (this.ws) return Promise.reject(new ClientError('http', 'Terminal socket is already connecting or connected', { status: 409 }))
    let url: string
    try {
      url = this.socketUrl()
    } catch (err) {
      return Promise.reject(err instanceof ClientError ? err : new ClientError('validation', 'Invalid terminal socket path'))
    }
    const ticket = this.ticket

    return new Promise<void>((resolve, reject) => {
      let settled = false
      const fail = (error: ClientError) => {
        if (settled) return
        settled = true
        this.teardown()
        reject(error)
      }
      const succeed = () => {
        if (settled) return
        settled = true
        resolve()
      }

      let ws: WebSocketLike
      try {
        ws = this.factory(url, ticket.subprotocol)
      } catch (cause) {
        reject(
          new ClientError('network', 'Terminal socket could not be opened', {
            detail: cause instanceof Error ? cause.message : String(cause),
          }),
        )
        return
      }
      this.ws = ws

      ws.onopen = () => {
        // FIRST frame: the single authenticate message (token in-band only).
        const frame = {
          formatVersion: ticket.formatVersion,
          type: 'authenticate' as const,
          instanceId: this.instanceId,
          sessionId: ticket.sessionId,
          purpose: ticket.purpose,
          oneUseToken: ticket.oneUseToken,
          columns: this.columns,
          rows: this.rows,
        }
        try {
          ws.send(JSON.stringify(frame))
        } catch (cause) {
          fail(
            new ClientError('network', 'Terminal authenticate frame could not be sent', {
              detail: cause instanceof Error ? cause.message : String(cause),
            }),
          )
        }
      }

      ws.onerror = () => {
        if (!this.readyFlag) {
          fail(new ClientError('network', 'Terminal socket failed before authentication completed'))
        }
      }

      ws.onclose = (event) => {
        const wasReady = this.readyFlag
        this.readyFlag = false
        this.ws = null
        if (!wasReady) {
          fail(
            new ClientError('network', 'Terminal socket closed before authentication completed', {
              detail: `close code ${event.code}${event.reason ? `: ${event.reason}` : ''}`,
            }),
          )
          return
        }
        for (const listener of this.closeListeners) listener({ code: event.code, reason: event.reason })
      }

      ws.onmessage = (event) => {
        if (!this.readyFlag) {
          this.handlePreReady(event.data, succeed, fail, ticket)
          return
        }
        void this.emitData(event.data)
      }
    })
  }

  private handlePreReady(
    data: unknown,
    succeed: () => void,
    fail: (error: ClientError) => void,
    ticket: TerminalTicket,
  ): void {
    if (typeof data !== 'string') {
      fail(new ClientError('validation', 'Terminal pre-ready frame was not a text frame'))
      return
    }
    let frame: unknown
    try {
      frame = JSON.parse(data)
    } catch {
      fail(new ClientError('validation', 'Terminal pre-ready frame was not valid JSON'))
      return
    }
    if (typeof frame !== 'object' || frame === null) {
      fail(new ClientError('validation', 'Terminal pre-ready frame was not an object'))
      return
    }
    const candidate = frame as { type?: string; message?: string } & Partial<Omit<ReadyFrame, 'type'>>
    if (candidate.type === 'error') {
      fail(
        new ClientError('http', candidate.message ?? 'Terminal authentication was rejected', {
          detail: 'The service returned an error frame before ready.',
        }),
      )
      return
    }
    if (candidate.type !== 'ready') {
      fail(new ClientError('validation', `Unexpected terminal frame before ready: "${String(candidate.type)}"`))
      return
    }
    const receivedKeys = Object.keys(candidate).sort()
    const expectedKeys = [...READY_FRAME_KEYS].sort()
    if (
      receivedKeys.length !== expectedKeys.length ||
      receivedKeys.some((key, index) => key !== expectedKeys[index])
    ) {
      fail(
        new ClientError('validation', 'Terminal ready frame had an unexpected shape', {
          detail: JSON.stringify({ expectedKeys, receivedKeys }),
        }),
      )
      return
    }
    // The ready frame must match every prepared identity and the backend's
    // reconnect contract exactly before input is accepted.
    if (
      candidate.formatVersion !== ticket.formatVersion ||
      candidate.sessionId !== ticket.sessionId ||
      candidate.purpose !== ticket.purpose ||
      candidate.targetClass !== ticket.targetClass ||
      candidate.reconnect !== (ticket.targetClass === 'local_pty')
    ) {
      fail(
        new ClientError('validation', 'Terminal ready frame did not match the prepared ticket', {
          detail: JSON.stringify({
            expected: {
              formatVersion: ticket.formatVersion,
              sessionId: ticket.sessionId,
              purpose: ticket.purpose,
              targetClass: ticket.targetClass,
              reconnect: ticket.targetClass === 'local_pty',
            },
            received: {
              formatVersion: candidate.formatVersion,
              sessionId: candidate.sessionId,
              purpose: candidate.purpose,
              targetClass: candidate.targetClass,
              reconnect: candidate.reconnect,
            },
          }),
        }),
      )
      return
    }
    this.readyFlag = true
    succeed()
  }

  private async emitData(data: unknown): Promise<void> {
    let text: string
    if (typeof data === 'string') {
      text = data
    } else if (data instanceof ArrayBuffer) {
      text = new TextDecoder().decode(data)
    } else if (ArrayBuffer.isView(data)) {
      text = new TextDecoder().decode(data)
    } else if (typeof Blob !== 'undefined' && data instanceof Blob) {
      text = new TextDecoder().decode(await data.arrayBuffer())
    } else {
      return
    }
    for (const listener of this.dataListeners) listener(text)
  }

  /** Raw input — only after the ready frame has been validated. */
  send(data: string): void {
    if (!this.ws || !this.readyFlag || this.ws.readyState !== WS_OPEN) {
      throw new ClientError('unavailable', 'Terminal is not connected — input was not sent', {
        detail: 'Input is never sent before authentication completes (contract §15).',
      })
    }
    // The service deliberately reserves text frames for bounded JSON
    // controls. PTY bytes always travel as a binary WebSocket frame.
    this.ws.send(new TextEncoder().encode(data))
  }

  resize(columns: number, rows: number): void {
    if (!this.ws || !this.readyFlag || this.ws.readyState !== WS_OPEN) return
    this.ws.send(JSON.stringify({
      formatVersion: this.ticket.formatVersion,
      type: 'resize',
      columns,
      rows,
    }))
  }

  /** End the broker-owned PTY, distinct from detaching the transport. */
  end(): void {
    if (!this.ws || !this.readyFlag || this.ws.readyState !== WS_OPEN) {
      this.teardown()
      return
    }
    this.ws.send(JSON.stringify({
      formatVersion: this.ticket.formatVersion,
      type: 'end',
    }))
    try {
      this.ws.close()
    } finally {
      this.ws = null
      this.readyFlag = false
    }
  }

  onData(listener: (text: string) => void): () => void {
    this.dataListeners.add(listener)
    return () => {
      this.dataListeners.delete(listener)
    }
  }

  onClose(listener: (event: { code: number; reason: string }) => void): () => void {
    this.closeListeners.add(listener)
    return () => {
      this.closeListeners.delete(listener)
    }
  }

  private teardown(): void {
    const ws = this.ws
    this.ws = null
    this.readyFlag = false
    if (ws) {
      ws.onopen = null
      ws.onmessage = null
      ws.onclose = null
      ws.onerror = null
      try {
        ws.close()
      } catch {
        // close() on a connecting socket may throw — the socket is dead anyway.
      }
    }
  }

  /** End the session deliberately (user Disconnect / End). */
  close(): void {
    this.teardown()
  }
}
