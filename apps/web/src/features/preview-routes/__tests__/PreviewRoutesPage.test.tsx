/**
 * PreviewRoutesPage — containment UX contract: when the service reports
 * same-origin previews disabled, the page shows the typed, actionable
 * unavailable state and hides every control that would register or proxy
 * preview content. When enabled, the registry and register form render.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests, type PreviewRoute, type PreviewRouteIndex } from '@/client'

import PreviewRoutesPage from '../PreviewRoutesPage'

const ROUTE: PreviewRoute = {
  schema: 'stateport.preview-route/v1',
  routeId: 'route_1',
  capsuleId: 'capsule:demo-classdd:001',
  serviceId: 'web',
  revisionDigest: `sha256:${'a'.repeat(64)}`,
  upstream: { host: '127.0.0.1', port: 4173 },
  createdAt: '2026-08-03T12:00:00Z',
  expiresAt: '2026-08-03T13:00:00Z',
  revokedAt: null,
  revocationReason: null,
  routeDigest: `sha256:${'c'.repeat(64)}`,
  status: 'active',
}

const DISABLED: PreviewRouteIndex = {
  routes: [],
  availability: {
    status: 'disabled',
    code: 'preview_disabled_same_origin',
    message:
      'Preview execution is disabled for security: preview content is served from the StatePort origin, where hostile preview JavaScript could reach the operator session, cookies, storage, and the /v1 control API.',
    nextAction:
      'No operator action enables previews. Wait for a StatePort release that serves previews from a credential-isolated origin.',
  },
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/preview-routes']}>
      <Routes>
        <Route path="/preview-routes" element={<PreviewRoutesPage />} />
        <Route path="/deployments" element={<div>Deployments</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('PreviewRoutesPage — disabled containment state', () => {
  it('shows the typed unavailable state and hides registration when previews are disabled', async () => {
    const client = getClient()
    const list = vi.spyOn(client.previewRoutes, 'list').mockResolvedValue(DISABLED)

    renderPage()

    const notice = await screen.findByTestId('preview-routes-disabled')
    expect(notice.textContent).toContain('disabled for security')
    expect(notice.textContent).toContain('credential-isolated origin')
    // No register form, no route table, no proxy-plumbing description while
    // the surface is contained.
    expect(screen.queryByTestId('preview-route-register-start')).toBeNull()
    expect(screen.queryByText(/demo-classdd/)).toBeNull()
    expect(screen.queryByText(/Set-Cookie values are rewritten/)).toBeNull()
    expect(list).toHaveBeenCalledTimes(1)
  })

  it('renders the registry and register form when previews are enabled', async () => {
    const client = getClient()
    vi.spyOn(client.previewRoutes, 'list').mockResolvedValue({
      routes: [ROUTE],
      availability: { status: 'enabled' },
    })

    renderPage()

    expect(await screen.findByText(/demo-classdd/)).toBeTruthy()
    expect(screen.getByTestId('preview-route-register-start')).toBeTruthy()
    expect(screen.queryByTestId('preview-routes-disabled')).toBeNull()
  })
})


it('submits the reviewed digest and exposes the returned receipt and gateway path', async () => {
  const client = getClient()
  const previewPath = '/preview/capsule%3Ademo-classdd%3A001/web/'
  vi.spyOn(client.previewRoutes, 'list').mockResolvedValue({ routes: [{ ...ROUTE, previewPath }], availability: { status: 'enabled' } })
  const receipt = { schema: 'stateport.preview-route-receipt/v1' as const, receiptId: 'receipt_' + 'd'.repeat(24), routeId: ROUTE.routeId, sequence: 2, event: 'rewritten' as const, actor: 'operator', createdAt: '2026-09-06T00:00:00Z', data: {}, previousReceiptDigest: ROUTE.routeDigest, receiptDigest: ROUTE.routeDigest }
  const rewrite = vi.spyOn(client.previewRoutes, 'rewrite').mockResolvedValue({ ...ROUTE, receipt })
  renderPage()
  expect((await screen.findByText('Open preview')).getAttribute('href')).toBe(previewPath)
  fireEvent.click(screen.getByTestId(`preview-route-rewrite-start-${ROUTE.routeId}`))
  fireEvent.change(screen.getByLabelText('New revision digest'), { target: { value: ROUTE.revisionDigest } })
  fireEvent.change(screen.getByLabelText('New upstream port'), { target: { value: '8080' } })
  fireEvent.click(screen.getByTestId(`preview-route-rewrite-confirm-${ROUTE.routeId}`))
  await waitFor(() => expect(rewrite).toHaveBeenCalledWith(ROUTE.routeId, { revisionDigest: ROUTE.revisionDigest, upstreamPort: 8080, expectedRouteDigest: ROUTE.routeDigest }))
  expect((await screen.findByTestId('preview-route-receipt')).textContent).toContain(receipt.receiptId)
})
