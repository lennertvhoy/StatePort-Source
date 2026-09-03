/**
 * Shared test plumbing for the HTTP adapter contract tests: a fake fetch
 * with path routing, automatic /session CSRF priming, and call recording.
 */

export interface RecordedCall {
  url: string
  method: string
  headers: Record<string, string>
  body?: unknown
}

export type RouteHandler = (call: RecordedCall) => Response

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export interface FakeFetch {
  fetchFn: typeof fetch
  calls: RecordedCall[]
  /** Calls matching a path substring. */
  callsTo(match: string): RecordedCall[]
}

/**
 * Routes: `[method, pathSubstring, handler | response]`. The `/session` GET
 * is answered automatically (CSRF header `test-csrf`) unless a route matches
 * first.
 */
export function makeFakeFetch(
  routes: [string, string, Response | RouteHandler][],
  options: { csrfToken?: string } = {},
): FakeFetch {
  const calls: RecordedCall[] = []
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const headers: Record<string, string> = {}
    new Headers(init?.headers).forEach((value, key) => {
      headers[key] = value
    })
    let body: unknown
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body)
      } catch {
        body = init.body
      }
    }
    const call: RecordedCall = { url, method, headers, body }
    calls.push(call)

    const path = new URL(url, 'http://stateport.test').pathname
    for (const [routeMethod, match, handler] of routes) {
      if (method === routeMethod && path === match) {
        // Static responses are cloned per call (a Response body is single-use).
        const res = typeof handler === 'function' ? handler(call) : handler.clone()
        if (method === 'GET' && path === '/session' && res.ok) {
          const merged = new Headers(res.headers)
          merged.set('X-StatePort-CSRF', options.csrfToken ?? 'test-csrf')
          return new Response(res.body, { status: res.status, headers: merged })
        }
        return res
      }
    }
    if (method === 'GET' && url.endsWith('/session')) {
      return withCsrf(
        jsonResponse({ authenticated: true, user: { id: 'u_1', displayName: 'Test User' } }),
        options.csrfToken ?? 'test-csrf',
      )
    }
    return jsonResponse({ ok: false, error: { code: 'not_found', message: `No fake route for ${method} ${url}` } }, 404)
  }) as typeof fetch

  return {
    fetchFn,
    calls,
    callsTo: (match) => calls.filter((c) => c.url.includes(match)),
  }
}

function withCsrf(res: Response, token: string): Response {
  const headers = new Headers(res.headers)
  headers.set('X-StatePort-CSRF', token)
  return new Response(res.body, { status: res.status, headers })
}

/** Minimal fake WebSocket for the terminal protocol tests. */
export class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  readonly url: string
  readonly protocols: string | string[]
  readyState = 0 // CONNECTING
  sent: (string | ArrayBuffer | ArrayBufferView)[] = []
  onopen: ((event: unknown) => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onclose: ((event: { code: number; reason: string }) => void) | null = null
  onerror: ((event: unknown) => void) | null = null

  constructor(url: string, protocols: string | string[]) {
    this.url = url
    this.protocols = protocols
    FakeWebSocket.instances.push(this)
  }

  send(data: string | ArrayBuffer | ArrayBufferView): void {
    this.sent.push(data)
  }

  close(): void {
    this.readyState = 3
  }

  // ── test drivers ──────────────────────────────────────────────────────────
  serverOpen(): void {
    this.readyState = 1
    this.onopen?.({})
  }

  serverSend(data: unknown): void {
    this.onmessage?.({ data })
  }

  serverClose(code = 1000, reason = ''): void {
    this.readyState = 3
    this.onclose?.({ code, reason })
  }

  serverError(): void {
    this.onerror?.({})
  }

  static factory(): (url: string, protocols: string | string[]) => FakeWebSocket {
    return (url, protocols) => new FakeWebSocket(url, protocols)
  }

  static reset(): void {
    FakeWebSocket.instances = []
  }
}

export const TERMINAL_TICKET: import('../mappers').TerminalTicket = {
  formatVersion: 'stateport.terminal-socket/v1',
  socketPath: '/v1/terminal/socket',
  subprotocol: 'stateport.terminal.v1',
  sessionId: 'tsess_1',
  oneUseToken: 'secret-one-use-token',
  purpose: 'create',
  targetClass: 'local_pty',
}

/** Exact service response before the mapper normalizes the nested target. */
export const TERMINAL_TICKET_WIRE = {
  formatVersion: TERMINAL_TICKET.formatVersion,
  socketPath: TERMINAL_TICKET.socketPath,
  subprotocol: TERMINAL_TICKET.subprotocol,
  sessionId: TERMINAL_TICKET.sessionId,
  oneUseToken: TERMINAL_TICKET.oneUseToken,
  purpose: TERMINAL_TICKET.purpose,
  expiresAt: '2026-07-19T00:30:00.000Z',
  target: {
    targetId: 'local-project',
    targetClass: TERMINAL_TICKET.targetClass,
    displayName: 'Local project terminal',
    availability: 'available',
  },
} as const
