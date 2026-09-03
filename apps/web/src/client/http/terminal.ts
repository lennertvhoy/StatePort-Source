/**
 * HTTP terminal client — the production terminal transport (contract §15).
 *
 * - Opening the Terminal view NEVER connects: sessions start `idle` and only
 *   an explicit `connect()` prepares a ticket and opens the socket.
 * - The one-use token travels in the first (authenticate) frame, never the
 *   URL; input is refused until the ready frame has been validated.
 * - No automatic reconnection: a lost socket is reported honestly;
 *   `reconnect()` means a fresh prepare + socket against the SAME origin.
 * - Sessions are client-side records (the contract has no session index);
 *   they are deliberately in-memory, so a refresh never silently reconnects.
 * - `runCommand` (the mock PTY's line discipline) has no request/response
 *   equivalent on a raw PTY: it fails closed; raw input goes through
 *   `sendInput`.
 */
import { z } from 'zod'

import type { TerminalClient } from '../client'
import type {
  CommandResult,
  TerminalSession,
  TerminalSessionEvent,
  TerminalTarget,
} from '../types'
import { ClientError } from '../types'
import { endpoints } from './endpoints'
import { mapExperience, mapTerminalTicket, terminalTargetsFromCapabilities } from './mappers'
import type { TerminalTicket } from './mappers'
import { HttpTransport } from './transport'
import { TerminalSocket } from './terminalSocket'
import type { WebSocketFactory } from './terminalSocket'

const unknownPayload = z.unknown()

export interface HttpTerminalClientOptions {
  /** Injectable for tests. */
  webSocketFactory?: WebSocketFactory
  /** Injectable origin for tests. */
  origin?: string
}

interface SessionRuntime {
  session: TerminalSession
  socket: TerminalSocket | null
  /** True while a close was requested by the user (not a failure). */
  intentionalClose: boolean
}

export class HttpTerminalClient implements TerminalClient {
  readonly inputMode = 'raw_pty' as const
  private sessions = new Map<string, SessionRuntime>()
  private listeners = new Map<string, Set<(event: TerminalSessionEvent) => void>>()
  private sequence = 0
  private readonly transport: HttpTransport
  private readonly options: HttpTerminalClientOptions

  constructor(transport: HttpTransport, options: HttpTerminalClientOptions = {}) {
    this.transport = transport
    this.options = options
  }

  private emit(sessionId: string, event: TerminalSessionEvent): void {
    this.listeners.get(sessionId)?.forEach((listener) => listener(event))
  }

  private requireSession(sessionId: string): SessionRuntime {
    const runtime = this.sessions.get(sessionId)
    if (!runtime) throw new ClientError('http', `Terminal session not found: ${sessionId}`, { status: 404 })
    return runtime
  }

  /** Targets derive from the experience descriptor's terminal capability. */
  async listTargets(instanceId: string): Promise<TerminalTarget[]> {
    const payload = await this.transport.request(endpoints.instanceExperience(instanceId), {
      schema: unknownPayload,
    })
    const experience = mapExperience(payload, instanceId)
    return terminalTargetsFromCapabilities(instanceId, experience.capabilities)
  }

  async listSessions(instanceId: string): Promise<TerminalSession[]> {
    return [...this.sessions.values()].map((r) => r.session).filter((s) => s.instanceId === instanceId)
  }

  /** Local record only — nothing connects until an explicit connect(). */
  async createSession(instanceId: string, targetId: string, name?: string): Promise<TerminalSession> {
    this.sequence += 1
    const bytes = new Uint8Array(4)
    crypto.getRandomValues(bytes)
    const session: TerminalSession = {
      id: `term_${[...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')}`,
      targetId,
      instanceId,
      name: name ?? `Terminal ${this.sequence}`,
      state: 'idle',
      cwd: '~',
      createdAt: new Date().toISOString(),
    }
    this.sessions.set(session.id, { session, socket: null, intentionalClose: false })
    return session
  }

  async renameSession(sessionId: string, name: string): Promise<TerminalSession> {
    const runtime = this.requireSession(sessionId)
    runtime.session = { ...runtime.session, name }
    return runtime.session
  }

  private async openSocket(
    runtime: SessionRuntime,
    ticket: TerminalTicket,
    columns: number,
    rows: number,
  ): Promise<void> {
    const socket = new TerminalSocket({
      ticket,
      instanceId: runtime.session.instanceId,
      columns,
      rows,
      webSocketFactory: this.options.webSocketFactory,
      origin: this.options.origin,
    })
    socket.onData((text) => this.emit(runtime.session.id, { type: 'output', text }))
    socket.onClose(({ code, reason }) => {
      const wasIntentional = runtime.intentionalClose
      runtime.socket = null
      if (runtime.session.state === 'ended') return
      if (wasIntentional) {
        runtime.session = { ...runtime.session, state: 'idle' }
        this.emit(runtime.session.id, { type: 'state', state: 'idle' })
      } else {
        const error = `Connection closed (${code}${reason ? `: ${reason}` : ''}). Reconnect is explicit and safe.`
        runtime.session = { ...runtime.session, state: 'failed', lastError: error }
        this.emit(runtime.session.id, { type: 'state', state: 'failed', error })
      }
    })
    runtime.socket = socket
    // Resolves only after the ready frame validated against the ticket.
    await socket.connect()
  }

  async connect(sessionId: string, dimensions?: { columns?: number; rows?: number }): Promise<TerminalSession> {
    const runtime = this.requireSession(sessionId)
    if (runtime.session.state === 'ended') {
      throw new ClientError('http', 'Session has ended — create a new session', { status: 409 })
    }
    if (runtime.session.state === 'connected' && runtime.socket?.ready) return runtime.session
    const columns = dimensions?.columns ?? 80
    const rows = dimensions?.rows ?? 24
    runtime.session = { ...runtime.session, state: 'connecting' }
    this.emit(sessionId, { type: 'state', state: 'connecting' })
    try {
      const ticketPayload = await this.transport.request(endpoints.terminalPrepare(runtime.session.instanceId), {
        method: 'POST',
        body: { expectedInstanceId: runtime.session.instanceId, columns, rows },
        schema: unknownPayload,
      })
      const ticket = mapTerminalTicket(ticketPayload)
      runtime.intentionalClose = false
      await this.openSocket(runtime, ticket, columns, rows)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Connection failed'
      runtime.session = { ...runtime.session, state: 'failed', lastError: message }
      this.emit(sessionId, { type: 'state', state: 'failed', error: message })
      throw err instanceof ClientError
        ? err
        : new ClientError('network', 'Terminal connection failed', { detail: message })
    }
    runtime.session = { ...runtime.session, state: 'connected', lastError: undefined }
    this.emit(sessionId, { type: 'state', state: 'connected' })
    return runtime.session
  }

  async disconnect(sessionId: string): Promise<TerminalSession> {
    const runtime = this.requireSession(sessionId)
    runtime.intentionalClose = true
    runtime.socket?.close()
    runtime.socket = null
    if (runtime.session.state !== 'ended') {
      runtime.session = { ...runtime.session, state: 'idle' }
      this.emit(sessionId, { type: 'state', state: 'idle' })
    }
    return runtime.session
  }

  /** Explicit reconnect: fresh prepare + socket against the SAME origin. */
  async reconnect(sessionId: string): Promise<TerminalSession> {
    const runtime = this.requireSession(sessionId)
    if (runtime.session.state === 'ended') {
      throw new ClientError('http', 'Session has ended — create a new session', { status: 409 })
    }
    runtime.intentionalClose = true
    runtime.socket?.close()
    runtime.socket = null
    runtime.session = { ...runtime.session, state: 'reconnecting' }
    this.emit(sessionId, { type: 'state', state: 'reconnecting' })
    return this.connect(sessionId)
  }

  async endSession(sessionId: string): Promise<TerminalSession> {
    const runtime = this.requireSession(sessionId)
    runtime.intentionalClose = true
    runtime.socket?.end()
    runtime.socket = null
    runtime.session = { ...runtime.session, state: 'ended' }
    this.emit(sessionId, { type: 'state', state: 'ended' })
    this.emit(sessionId, { type: 'exit', code: 0 })
    return runtime.session
  }

  /**
   * A raw PTY has no request/response command path — the mock's line
   * discipline is a mock feature. Use `sendInput` (the raw channel) instead.
   */
  runCommand(sessionId: string, command: string): Promise<CommandResult> {
    void sessionId
    void command
    return Promise.reject(
      new ClientError('unavailable', 'Command-style execution is not available on the production terminal', {
        detail: 'The production terminal is a raw PTY; input goes through sendInput and output arrives via subscribe.',
      }),
    )
  }

  /** Raw input channel — refuses before authentication completed. */
  sendInput(sessionId: string, data: string): void {
    const runtime = this.requireSession(sessionId)
    if (!runtime.socket || !runtime.socket.ready) {
      throw new ClientError('unavailable', 'Terminal is not connected — input was not sent', {
        detail: 'Input is never sent before the ready frame validates (contract §15).',
      })
    }
    runtime.socket.send(data)
  }

  resize(sessionId: string, columns: number, rows: number): void {
    this.requireSession(sessionId).socket?.resize(columns, rows)
  }

  subscribe(sessionId: string, listener: (event: TerminalSessionEvent) => void): () => void {
    let set = this.listeners.get(sessionId)
    if (!set) {
      set = new Set()
      this.listeners.set(sessionId, set)
    }
    set.add(listener)
    return () => {
      set.delete(listener)
    }
  }
}
