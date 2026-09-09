/**
 * Terminal protocol contract tests (binding doc §15): prepare → WebSocket →
 * authenticate frame first → ready validation → raw I/O; the one-use token
 * never appears in the URL; input is refused before ready.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ClientError } from '../../types'
import { HttpTransport } from '../transport'
import { TerminalSocket } from '../terminalSocket'
import { HttpTerminalClient } from '../terminal'
import {
  FakeWebSocket,
  jsonResponse,
  makeFakeFetch,
  TERMINAL_TICKET,
  TERMINAL_TICKET_WIRE,
} from './helpers'

const ORIGIN = 'https://stateport.test'

function readyFrame(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    formatVersion: 'stateport.terminal-socket/v1',
    type: 'ready',
    sessionId: TERMINAL_TICKET.sessionId,
    purpose: TERMINAL_TICKET.purpose,
    targetClass: TERMINAL_TICKET.targetClass,
    reconnect: true,
    ...overrides,
  })
}

describe('TerminalSocket', () => {
  beforeEach(() => FakeWebSocket.reset())

  function makeSocket() {
    const socket = new TerminalSocket({
      ticket: { ...TERMINAL_TICKET },
      instanceId: 'ins_1',
      columns: 120,
      rows: 30,
      webSocketFactory: FakeWebSocket.factory(),
      origin: ORIGIN,
    })
    return socket
  }

  it('connects same-origin with the ticket subprotocol and authenticates FIRST', async () => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    // Same-origin ws URL derived from the ticket path; subprotocol honored.
    expect(ws.url).toBe('wss://stateport.test/v1/terminal/socket')
    expect(ws.protocols).toBe('stateport.terminal.v1')
    // The token NEVER appears in the URL.
    expect(ws.url).not.toContain(TERMINAL_TICKET.oneUseToken)

    ws.serverOpen()
    // The first (and only, so far) frame is the authenticate message.
    expect(ws.sent).toHaveLength(1)
    const auth = JSON.parse(ws.sent[0] as string) as Record<string, unknown>
    expect(auth).toEqual({
      formatVersion: 'stateport.terminal-socket/v1',
      type: 'authenticate',
      instanceId: 'ins_1',
      sessionId: 'tsess_1',
      purpose: 'create',
      oneUseToken: 'secret-one-use-token',
      columns: 120,
      rows: 30,
    })

    ws.serverSend(readyFrame())
    await expect(promise).resolves.toBeUndefined()
    expect(socket.ready).toBe(true)
  })

  it('refuses input before the ready frame validates', async () => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    expect(() => socket.send('ls\n')).toThrow(ClientError)
    ws.serverSend(readyFrame())
    await promise
    expect(() => socket.send('ls\n')).not.toThrow()
    expect(new TextDecoder().decode(ws.sent[1] as ArrayBufferView)).toBe('ls\n')
  })

  it('rejects a ready frame with a mismatched sessionId', async () => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame({ sessionId: 'tsess_OTHER' }))
    const err = await promise.catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
    expect((err as ClientError).message).toMatch(/did not match the prepared ticket/)
  })

  it.each([
    ['formatVersion', { formatVersion: 'stateport.terminal-socket/v2' }],
    ['purpose', { purpose: 'attach' }],
    ['targetClass', { targetClass: 'container' }],
    ['reconnect', { reconnect: false }],
  ])('rejects a ready frame with a mismatched %s', async (_label, override) => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame(override))
    await expect(promise).rejects.toBeInstanceOf(ClientError)
  })

  it.each([
    ['a missing reconnect field', { reconnect: undefined }],
    ['an extra field', { diagnostic: 'unexpected' }],
  ])('rejects a ready frame with %s', async (_label, override) => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    const frame = JSON.parse(readyFrame(override)) as Record<string, unknown>
    if ('reconnect' in override && override.reconnect === undefined) delete frame.reconnect
    ws.serverSend(JSON.stringify(frame))
    const error = await promise.catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).message).toMatch(/unexpected shape/)
  })

  it('rejects a pre-ready frame that is not ready (e.g. an error frame)', async () => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(JSON.stringify({ type: 'error', message: 'bad token' }))
    const err = await promise.catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).message).toBe('bad token')
  })

  it('rejects when the socket closes before authentication completes', async () => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverClose(1006, 'gone')
    const err = await promise.catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('network')
  })

  it('streams raw output after ready and reports close events', async () => {
    const socket = makeSocket()
    const promise = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    await promise

    const data: string[] = []
    const closes: { code: number }[] = []
    socket.onData((text) => data.push(text))
    socket.onClose((event) => closes.push(event))
    ws.serverSend('$ echo ok\r\nok\r\n')
    expect(data).toEqual(['$ echo ok\r\nok\r\n'])
    ws.serverClose(1000)
    expect(closes).toEqual([{ code: 1000, reason: '' }])
  })

  it('waits for the cleanup-ordered close acknowledgement', async () => {
    const socket = makeSocket()
    const connecting = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    await connecting

    let settled = false
    const closing = socket.closeAndWait().finally(() => { settled = true })
    await Promise.resolve()
    expect(settled).toBe(false)
    ws.serverClose(1000, 'transport_detached')
    await expect(closing).resolves.toBeUndefined()
  })

  it('rejects an abnormal close acknowledgement', async () => {
    const socket = makeSocket()
    const connecting = socket.connect()
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    await connecting

    const closing = socket.closeAndWait()
    ws.serverClose(1011, 'terminal_cleanup_unverified')
    await expect(closing).rejects.toThrow('close was not acknowledged')
  })

  it('rejects when cleanup acknowledgement times out', async () => {
    vi.useFakeTimers()
    try {
      const socket = makeSocket()
      const connecting = socket.connect()
      const ws = FakeWebSocket.instances[0]
      ws.serverOpen()
      ws.serverSend(readyFrame())
      await connecting

      const closing = socket.closeAndWait()
      void closing.catch(() => undefined)
      await vi.advanceTimersByTimeAsync(5_000)
      await expect(closing).rejects.toThrow('cleanup acknowledgement timed out')
    } finally {
      vi.useRealTimers()
    }
  })

  it('refuses a socket path that resolves cross-origin', async () => {
    const socket = new TerminalSocket({
      ticket: { ...TERMINAL_TICKET, socketPath: 'https://evil.example/v1/terminal/socket' },
      instanceId: 'ins_1',
      columns: 80,
      rows: 24,
      webSocketFactory: FakeWebSocket.factory(),
      origin: ORIGIN,
    })
    await expect(socket.connect()).rejects.toBeInstanceOf(ClientError)
    expect(FakeWebSocket.instances).toHaveLength(0)
  })
})

describe('HttpTerminalClient — prepare + explicit connect', () => {
  beforeEach(() => FakeWebSocket.reset())

  function makeTerminal(ticketPayload: unknown = TERMINAL_TICKET_WIRE) {
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/ins_1/terminal/prepare', jsonResponse({ ok: true, result: ticketPayload })],
    ])
    const client = new HttpTerminalClient(new HttpTransport({ fetchFn: fake.fetchFn }), {
      webSocketFactory: FakeWebSocket.factory(),
      origin: ORIGIN,
    })
    return { fake, client }
  }

  it('creating a session does NOT connect; explicit connect prepares + authenticates', async () => {
    const { fake, client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    expect(session.state).toBe('idle')
    expect(fake.callsTo('/terminal/prepare')).toHaveLength(0)
    expect(FakeWebSocket.instances).toHaveLength(0)

    const connecting = client.connect(session.id, { columns: 100, rows: 40 })
    await vi.waitFor(() => expect(fake.callsTo('/terminal/prepare')).toHaveLength(1))
    const prepare = fake.callsTo('/terminal/prepare')[0]
    expect(prepare.body).toEqual({ expectedInstanceId: 'ins_1', columns: 100, rows: 40 })
    expect(prepare.headers['x-stateport-csrf']).toBe('test-csrf')

    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    const connected = await connecting
    expect(connected.state).toBe('connected')

    client.sendInput(session.id, 'pwd\n')
    expect(new TextDecoder().decode(ws.sent[1] as ArrayBufferView)).toBe('pwd\n')
  })

  it('does not prepare an explicit reconnect before cleanup is acknowledged', async () => {
    const secondTicket = { ...TERMINAL_TICKET_WIRE, sessionId: 'tsess_2', oneUseToken: 'secret-two' }
    let preparationCount = 0
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/ins_1/terminal/prepare', () => jsonResponse({ ok: true, result: preparationCount++ === 0 ? TERMINAL_TICKET_WIRE : secondTicket })],
    ])
    const client = new HttpTerminalClient(new HttpTransport({ fetchFn: fake.fetchFn }), {
      webSocketFactory: FakeWebSocket.factory(),
      origin: ORIGIN,
    })
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const events: string[] = []
    client.subscribe(session.id, (event) => {
      if (event.type === 'state') events.push(event.state)
    })
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const first = FakeWebSocket.instances[0]
    first.serverOpen()
    first.serverSend(readyFrame())
    await connecting

    const reconnecting = client.reconnect(session.id)
    await Promise.resolve()
    expect(fake.callsTo('/terminal/prepare')).toHaveLength(1)
    first.serverClose(1000, 'transport_detached')
    await vi.waitFor(() => expect(fake.callsTo('/terminal/prepare')).toHaveLength(2))
    const second = FakeWebSocket.instances[1]
    second.serverOpen()
    second.serverSend(readyFrame({ sessionId: secondTicket.sessionId }))
    await expect(reconnecting).resolves.toMatchObject({ state: 'connected', preparedTarget: expect.objectContaining({ sessionId: secondTicket.sessionId }) })
    expect(events).toEqual(['connecting', 'connected', 'reconnecting', 'connecting', 'connected'])
    expect((await client.listSessions('ins_1'))[0].lastError).toBeUndefined()
  })

  it('does not install a second close waiter for overlapping reconnects', async () => {
    const { fake, client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const first = FakeWebSocket.instances[0]
    first.serverOpen()
    first.serverSend(readyFrame())
    await connecting

    const reconnecting = client.reconnect(session.id)
    await Promise.resolve()
    await expect(client.reconnect(session.id)).rejects.toMatchObject({ status: 409 })
    expect(fake.callsTo('/terminal/prepare')).toHaveLength(1)
    first.serverClose(1000, 'transport_detached')
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2))
    const second = FakeWebSocket.instances[1]
    second.serverOpen()
    second.serverSend(readyFrame())
    await expect(reconnecting).resolves.toMatchObject({ state: 'connected' })
  })

  it('preserves a rename made while reconnect cleanup is pending', async () => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const first = FakeWebSocket.instances[0]
    first.serverOpen()
    first.serverSend(readyFrame())
    await connecting

    const reconnecting = client.reconnect(session.id)
    await Promise.resolve()
    await expect(client.renameSession(session.id, 'renamed during reconnect')).resolves.toMatchObject({ name: 'renamed during reconnect', state: 'reconnecting' })
    first.serverClose(1000, 'transport_detached')
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2))
    const second = FakeWebSocket.instances[1]
    second.serverOpen()
    second.serverSend(readyFrame())
    await expect(reconnecting).resolves.toMatchObject({ name: 'renamed during reconnect', state: 'connected' })
  })

  it.each(['end', 'disconnect'] as const)('preserves %s while reconnect cleanup is pending', async (action) => {
    try {
      const { fake, client } = makeTerminal()
      const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
      const connecting = client.connect(session.id)
      await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
      const ws = FakeWebSocket.instances[0]
      ws.serverOpen()
      ws.serverSend(readyFrame())
      await connecting

      vi.useFakeTimers()
      const reconnecting = client.reconnect(session.id)
      await Promise.resolve()
      const cancelled = action === 'end' ? client.endSession(session.id) : client.disconnect(session.id)
      await expect(cancelled).resolves.toMatchObject({ state: action === 'end' ? 'ended' : 'idle' })
      await vi.advanceTimersByTimeAsync(5_000)
      await expect(reconnecting).resolves.toMatchObject({ state: action === 'end' ? 'ended' : 'idle' })
      expect(fake.callsTo('/terminal/prepare')).toHaveLength(1)
      expect((await client.listSessions('ins_1'))[0].state).toBe(action === 'end' ? 'ended' : 'idle')
    } finally {
      vi.useRealTimers()
    }
  })

  it.each([
    ['abnormal close', (ws: FakeWebSocket) => ws.serverClose(1011, 'terminal_cleanup_unverified')],
    ['cleanup timeout', undefined],
  ])('does not prepare after %s during explicit reconnect', async (_name, close) => {
    try {
      const { fake, client } = makeTerminal()
      const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
      const events: string[] = []
      client.subscribe(session.id, (event) => {
        if (event.type === 'state') events.push(event.state)
      })
      const connecting = client.connect(session.id)
      await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
      const ws = FakeWebSocket.instances[0]
      ws.serverOpen()
      ws.serverSend(readyFrame())
      await connecting

      if (!close) vi.useFakeTimers()
      const reconnecting = client.reconnect(session.id)
      void reconnecting.catch(() => undefined)
      await Promise.resolve()
      expect(fake.callsTo('/terminal/prepare')).toHaveLength(1)
      if (close) close(ws)
      else await vi.advanceTimersByTimeAsync(5_000)
      await expect(reconnecting).rejects.toBeInstanceOf(ClientError)
      expect(fake.callsTo('/terminal/prepare')).toHaveLength(1)
      expect(events).toEqual(['connecting', 'connected', 'reconnecting', 'failed'])
      expect((await client.listSessions('ins_1'))[0]).toMatchObject({ state: 'failed', lastError: expect.any(String) })
    } finally {
      if (!close) vi.useRealTimers()
    }
  })

  it('retains the authenticated capsule target and server session identity', async () => {
    const { client } = makeTerminal({ ...TERMINAL_TICKET_WIRE, target: { ...TERMINAL_TICKET_WIRE.target, targetClass: 'capsule', targetId: 'workspace-reviewed', displayName: 'Application workspace terminal' } })
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    expect(session.preparedTarget).toBeUndefined()
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame({ targetClass: 'capsule', reconnect: false }))
    const connected = await connecting
    expect(connected.preparedTarget).toEqual({ targetId: 'workspace-reviewed', targetClass: 'capsule', displayName: 'Application workspace terminal', sessionId: TERMINAL_TICKET.sessionId })
    expect(JSON.stringify(connected)).not.toContain(TERMINAL_TICKET.oneUseToken)
  })

  it.each(['before connect resolves', 'after connect resolves'])('normal authenticated process exit ends session %s', async (ordering) => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const events: Array<{ type: string; state?: string; text?: string }> = []
    client.subscribe(session.id, event => events.push(event))
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    if (ordering === 'after connect resolves') await connecting
    ws.serverSend(new TextEncoder().encode('final process output'))
    ws.serverClose(1000, 'process_exit')
    await connecting
    expect((await client.listSessions('ins_1'))[0]).toMatchObject({ state: 'ended', lastError: undefined })
    expect(events.filter(event => event.type === 'state').at(-1)?.state).toBe('ended')
    expect(events.some(event => event.text === 'final process output')).toBe(true)
    expect(events.some(event => event.type === 'exit')).toBe(false)
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(() => client.sendInput(session.id, 'must not send')).toThrow(ClientError)
  })

  it.each([[1006, 'dropped'], [1011, 'terminal_output_refused'], [1008, 'access_denied'], [1000, 'unknown_reason']])('preserves abnormal authenticated close %s/%s as failed', async (code, reason) => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    ws.serverClose(Number(code), String(reason))
    await connecting
    expect((await client.listSessions('ins_1'))[0].state).toBe('failed')
  })

  it('does not accept process_exit before the authenticated ready frame', async () => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const connecting = client.connect(session.id).catch(error => error)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverClose(1000, 'process_exit')
    expect(await connecting).toBeInstanceOf(ClientError)
    expect((await client.listSessions('ins_1'))[0].state).toBe('failed')
  })

  it('sendInput before connect fails closed', async () => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    expect(() => client.sendInput(session.id, 'x')).toThrow(ClientError)
  })

  it('rejects the obsolete token field instead of weakening the exact one-use-token contract', async () => {
    const withoutOneUseToken = Object.fromEntries(
      Object.entries(TERMINAL_TICKET_WIRE).filter(
        ([field]) => field !== 'oneUseToken',
      ),
    )
    const { client } = makeTerminal({ ...withoutOneUseToken, token: 'legacy-token' })
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')

    const error = await client.connect(session.id).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
    expect(FakeWebSocket.instances).toHaveLength(0)
  })

  it('rejects a different same-origin socket path before opening a WebSocket', async () => {
    const { client } = makeTerminal({
      ...TERMINAL_TICKET_WIRE,
      socketPath: '/v1/terminal/other',
    })
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')

    const error = await client.connect(session.id).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
    expect(FakeWebSocket.instances).toHaveLength(0)
  })

  it('a server close without intent marks the session failed honestly', async () => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]
    ws.serverOpen()
    ws.serverSend(readyFrame())
    await connecting
    ws.serverClose(1006, 'dropped')
    const states = (await client.listSessions('ins_1'))[0]
    expect(states.state).toBe('failed')
    expect(states.lastError).toContain('1006')
  })

  it('runCommand is honestly unavailable on the raw PTY transport', async () => {
    const { client } = makeTerminal()
    const session = await client.createSession('ins_1', 'tgt_ins_1_pty')
    const err = await client.runCommand(session.id, 'ls').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('unavailable')
  })
})

describe('platform workspace terminal scope', () => {
  beforeEach(() => FakeWebSocket.reset())
  it('uses verified capsule target and exact platform prepare without application experience', async () => {
    const target = { ...TERMINAL_TICKET_WIRE.target, targetClass: 'capsule', targetId: 'terminal.workspace.checked', displayName: 'Application workspace terminal', availability: 'available' }
    const fake = makeFakeFetch([
      ['GET', '/v1/execution-host/workspaces/ins_1/terminal/target', jsonResponse({ ok: true, result: { target } })],
      ['POST', '/v1/execution-host/workspaces/ins_1/terminal/prepare', jsonResponse({ ok: true, result: { ...TERMINAL_TICKET_WIRE, target } })],
    ])
    const client = new HttpTerminalClient(new HttpTransport({ fetchFn: fake.fetchFn }), { webSocketFactory: FakeWebSocket.factory(), origin: ORIGIN })
    const targets = await client.listTargets('ins_1', 'workspace')
    expect(targets[0].kind).toBe('capsule')
    const session = await client.createSession('ins_1', targets[0].id)
    const connecting = client.connect(session.id)
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    expect(fake.callsTo('/terminal/prepare')[0].body).toEqual({ expectedInstanceId: 'ins_1', expectedTargetId: target.targetId, columns: 80, rows: 24 })
    FakeWebSocket.instances[0].serverOpen()
    FakeWebSocket.instances[0].serverSend(readyFrame({ targetClass: 'capsule', reconnect: false }))
    expect((await connecting).state).toBe('connected')
    expect(fake.callsTo('/experience')).toHaveLength(0)
    expect(fake.callsTo('/v1/instances/')).toHaveLength(0)
  })
  it.each(['local_pty', 'changed-capsule'])('refuses a %s prepare target before any socket', async changed => {
    const target = { ...TERMINAL_TICKET_WIRE.target, targetClass: changed === 'local_pty' ? 'local_pty' : 'capsule', targetId: changed === 'local_pty' ? 'terminal.workspace.checked' : 'foreign-capsule' }
    const fake = makeFakeFetch([['POST', '/v1/execution-host/workspaces/ins_1/terminal/prepare', jsonResponse({ ok: true, result: { ...TERMINAL_TICKET_WIRE, target } })]])
    const client = new HttpTerminalClient(new HttpTransport({ fetchFn: fake.fetchFn }), { webSocketFactory: FakeWebSocket.factory(), origin: ORIGIN })
    const session = await client.createSession('ins_1', 'workspace-terminal:terminal.workspace.checked')
    await expect(client.connect(session.id)).rejects.toThrow('Workspace terminal target changed')
    expect(FakeWebSocket.instances).toHaveLength(0)
  })
})
