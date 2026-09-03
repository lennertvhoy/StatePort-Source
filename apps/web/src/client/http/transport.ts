/**
 * HttpTransport — the REAL same-origin transport for the StatePort service.
 *
 * Contract (binding doc §13):
 * - Same-origin requests with `credentials: 'same-origin'`.
 * - The local browser session is primed from `GET /session` before reads or
 *   mutations; its CSRF token is sent as `X-StatePort-CSRF` on mutations.
 * - A 401 refreshes `/session` ONCE and retries the original request ONCE.
 * - JSON payloads are envelope-unwrapped and zod-validated.
 * - SSE uses the same session boundary and returns the verified response body
 *   to a domain-specific parser; it never places session credentials in URLs.
 * - The transport NEVER falls back to mock data.
 */
import { z } from 'zod'

import { ClientError } from '../types'
import { endpoints } from './endpoints'

export interface HttpTransportOptions {
  /** Same-origin by default; injectable for tests. */
  baseUrl?: string
  /** Injectable for tests; defaults to global fetch. */
  fetchFn?: typeof fetch
  /** Session endpoint used for CSRF priming and the single 401 refresh. */
  sessionPath?: string
}

export interface RequestOptions<T> {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  /** Schema the (unwrapped) response payload is validated against. */
  schema: z.ZodType<T>
  /** Mark true for state-changing requests (adds the CSRF header). */
  mutation?: boolean
  /** Internal: tracks the single 401 retry. */
  _retried?: boolean
}

export interface StreamRequestOptions {
  signal?: AbortSignal
  lastEventId?: string
  /** Internal: tracks the single 401 retry. */
  _retried?: boolean
}

/** Schema for endpoints whose success carries no payload (HTTP 204). */
export const voidSchema: z.ZodType<unknown> = z.unknown()

interface ErrorEnvelope {
  code?: string
  message: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Unwrap the response envelope. Returns the direct payload for
 * `{ ok: true, result }` and bare results; returns the error envelope otherwise.
 */
export function unwrapEnvelope(body: unknown): { ok: true; payload: unknown } | { ok: false; error: ErrorEnvelope } {
  if (isRecord(body)) {
    if (body.ok === false) {
      const raw = isRecord(body.error) ? body.error : {}
      return {
        ok: false,
        error: {
          code: typeof raw.code === 'string' ? raw.code : undefined,
          message: typeof raw.message === 'string' ? raw.message : 'The service reported an error',
        },
      }
    }
    if (body.ok === true && 'result' in body) {
      return { ok: true, payload: body.result }
    }
  }
  return { ok: true, payload: body }
}

export class HttpTransport {
  private baseUrl: string
  private fetchFn: typeof fetch
  private sessionPath: string
  private csrfToken: string | null = null
  private sessionRefresh: Promise<void> | null = null

  constructor(options: HttpTransportOptions = {}) {
    this.baseUrl = options.baseUrl ?? ''
    this.fetchFn = options.fetchFn ?? ((...args) => fetch(...args))
    this.sessionPath = options.sessionPath ?? endpoints.session
  }

  /** Drop the primed CSRF token so the next mutation re-primes /session. */
  invalidateSession(): void {
    this.csrfToken = null
  }

  /** Prime the CSRF token from the session endpoint (deduplicated). */
  async ensureSession(): Promise<void> {
    if (this.csrfToken) return
    if (!this.sessionRefresh) {
      this.sessionRefresh = this.refreshSession().finally(() => {
        this.sessionRefresh = null
      })
    }
    return this.sessionRefresh
  }

  private async refreshSession(): Promise<void> {
    let res: Response
    try {
      res = await this.rawFetch(this.sessionPath, { method: 'GET' })
    } catch (cause) {
      throw new ClientError('network', 'Could not reach the local StatePort service', {
        detail: cause instanceof Error ? cause.message : String(cause),
      })
    }
    if (!res.ok) {
      throw new ClientError('unavailable', 'Local service session could not be established', {
        status: res.status,
      })
    }
    const headerToken = res.headers.get('X-StatePort-CSRF')
    if (headerToken) {
      this.csrfToken = headerToken
      return
    }
    try {
      const body: unknown = await res.json()
      const unwrapped = unwrapEnvelope(body)
      const payload = unwrapped.ok ? unwrapped.payload : undefined
      if (isRecord(payload) && typeof payload.csrfToken === 'string') {
        this.csrfToken = payload.csrfToken
      }
    } catch {
      // Mutations fail closed if the service supplied no usable CSRF token.
    }
  }

  private rawFetch(path: string, init: RequestInit): Promise<Response> {
    return this.fetchFn(`${this.baseUrl}${path}`, {
      credentials: 'same-origin',
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(init.headers ?? {}),
      },
    })
  }

  async stream(path: string, options: StreamRequestOptions = {}): Promise<Response> {
    await this.ensureSession()
    let res: Response
    try {
      res = await this.rawFetch(path, {
        method: 'GET',
        signal: options.signal,
        headers: {
          Accept: 'text/event-stream',
          ...(options.lastEventId ? { 'Last-Event-ID': options.lastEventId } : {}),
        },
      })
    } catch (cause) {
      if (options.signal?.aborted) throw cause
      throw new ClientError('network', 'Could not reach the assistant event stream', {
        detail: cause instanceof Error ? cause.message : String(cause),
      })
    }
    if (res.status === 401 && !options._retried) {
      this.csrfToken = null
      await this.ensureSession()
      return this.stream(path, { ...options, _retried: true })
    }
    if (!res.ok) {
      let detail: string | undefined
      try {
        const body: unknown = await res.json()
        const envelope = unwrapEnvelope(body)
        detail = envelope.ok
          ? JSON.stringify(envelope.payload)
          : `${envelope.error.code ?? 'request_failed'}: ${envelope.error.message}`
      } catch {
        detail = undefined
      }
      throw new ClientError(
        res.status === 503 ? 'unavailable' : 'http',
        `Assistant event stream failed: GET ${path} → ${res.status}`,
        { status: res.status, detail },
      )
    }
    const contentType = res.headers.get('Content-Type') ?? ''
    if (!contentType.toLowerCase().startsWith('text/event-stream')) {
      throw new ClientError('validation', 'Assistant event stream returned an invalid content type', {
        detail: contentType || 'missing Content-Type',
      })
    }
    if (!res.body) {
      throw new ClientError('validation', 'Assistant event stream returned no response body')
    }
    return res
  }

  async request<T>(path: string, options: RequestOptions<T>): Promise<T> {
    const method = options.method ?? 'GET'
    const mutation = options.mutation ?? method !== 'GET'
    await this.ensureSession()

    let res: Response
    try {
      res = await this.rawFetch(path, {
        method,
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
        headers: mutation && this.csrfToken ? { 'X-StatePort-CSRF': this.csrfToken } : {},
      })
    } catch (cause) {
      throw new ClientError('network', 'Could not reach the local StatePort service', {
        detail: cause instanceof Error ? cause.message : String(cause),
      })
    }

    if (res.status === 401 && !options._retried) {
      this.csrfToken = null
      await this.ensureSession()
      return this.request(path, { ...options, _retried: true })
    }

    if (res.status === 204) {
      const parsed = options.schema.safeParse(undefined)
      if (!parsed.success) {
        throw new ClientError('validation', `Response failed validation: ${method} ${path}`, {
          detail: parsed.error.issues
            .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
            .join(String.fromCharCode(10)),
        })
      }
      return parsed.data
    }

    let body: unknown
    try {
      body = await res.json()
    } catch {
      if (!res.ok) {
        throw new ClientError('http', `Request failed: ${method} ${path} → ${res.status}`, {
          status: res.status,
        })
      }
      throw new ClientError('validation', `Response was not JSON: ${method} ${path}`)
    }

    const envelope = unwrapEnvelope(body)
    if (!envelope.ok) {
      throw new ClientError('http', envelope.error.message, {
        status: res.ok ? undefined : res.status,
        code: envelope.error.code,
        detail: `Error envelope from ${method} ${path}`,
      })
    }

    if (!res.ok) {
      throw new ClientError('http', `Request failed: ${method} ${path} → ${res.status}`, {
        status: res.status,
        detail: isRecord(envelope.payload) ? JSON.stringify(envelope.payload) : undefined,
      })
    }

    const parsed = options.schema.safeParse(envelope.payload)
    if (!parsed.success) {
      throw new ClientError('validation', `Response failed validation: ${method} ${path}`, {
        detail: parsed.error.issues
          .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
          .join(String.fromCharCode(10)),
      })
    }
    return parsed.data
  }
}
