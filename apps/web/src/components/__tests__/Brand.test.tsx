import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { BrandLockup, BrandMark } from '../Brand'

afterEach(cleanup)

describe('StatePort mascot mark', () => {
  it('renders the favicon inside the centered 24px compact-rail mark', () => {
    render(
      <div className="inline-flex h-10 w-10 items-center justify-center overflow-hidden" data-testid="rail-control">
        <BrandMark size={24} title="StatePort" />
      </div>,
    )
    const mark = screen.getByRole('img', { name: 'StatePort' })
    const rail = screen.getByTestId('rail-control')
    expect(mark.querySelectorAll('[data-brand-asset]')).toHaveLength(1)
    expect(mark.querySelector('[data-brand-asset="compact"]')?.classList.contains('brand-mascot-compact')).toBe(true)
    expect(mark.querySelector('[data-brand-asset="compact"]')?.classList.contains('object-contain')).toBe(true)
    expect(mark.classList.contains('brand-mark')).toBe(true)
    expect(mark.classList.contains('items-center')).toBe(true)
    expect(mark.classList.contains('justify-center')).toBe(true)
    expect(mark.classList.contains('overflow-hidden')).toBe(false)
    expect(mark.querySelector('.brand-art-frame')).toBeTruthy()
    expect(mark.getAttribute('style')).toContain('width: 24px')
    expect(mark.getAttribute('style')).toContain('height: 24px')
    expect(mark.dataset.brandSize).toBe('24')
    expect(rail.classList.contains('h-10')).toBe(true)
    expect(rail.classList.contains('w-10')).toBe(true)
    expect(rail.classList.contains('items-center')).toBe(true)
    expect(rail.classList.contains('justify-center')).toBe(true)
    expect(rail.classList.contains('overflow-hidden')).toBe(true)
  })

  it('uses the compact favicon at every compact size and the detailed pair from 40px', () => {
    for (const size of [16, 20, 24, 32] as const) {
      const { unmount } = render(<BrandMark size={size} />)
      const mark = screen.getByTestId('brand-mark')
      expect(mark.dataset.brandSize).toBe(String(size))
      expect(mark.querySelectorAll('[data-brand-asset]')).toHaveLength(1)
      expect(mark.querySelector('.brand-art-frame')).toBeTruthy()
      expect(mark.querySelector('[data-brand-asset="compact"]')).toBeTruthy()
      unmount()
    }

    const { unmount } = render(<BrandMark size={40} />)
    const detailed = screen.getByTestId('brand-mark')
    expect(detailed.querySelectorAll('[data-brand-asset]')).toHaveLength(1)
    expect(detailed.querySelector('.brand-art-frame')).toBeTruthy()
    expect(detailed.querySelector('[data-brand-asset="light"]')).toBeTruthy()
    expect(detailed.querySelector('[data-brand-asset="dark"]')).toBeNull()
    unmount()
  })

  it('keeps 40px lockups stable for narrow and scaled shells', () => {
    for (const width of [320, 390]) {
      window.innerWidth = width
      document.documentElement.style.setProperty('--font-scale', '1.25')
      const { unmount } = render(<BrandLockup />)
      const lockup = screen.getByTestId('brand-lockup')
      const mark = within(lockup).getByTestId('brand-mark')
      expect(lockup.classList.contains('brand-lockup')).toBe(true)
      expect(lockup.classList.contains('whitespace-nowrap')).toBe(true)
      expect(mark.getAttribute('style')).toContain('width: 40px')
      expect(mark.getAttribute('style')).toContain('height: 40px')
      unmount()
    }
  })

  it('keeps the light detailed asset active across light and dark themes', () => {
    render(<BrandMark size={40} />)
    const mark = screen.getByTestId('brand-mark')
    const light = mark.querySelector('[data-brand-asset="light"]')
    expect(light).toBeTruthy()

    for (const theme of ['light', 'dark', 'hc-light', 'hc-dark']) {
      document.documentElement.dataset.theme = theme
      expect(light?.classList.contains('brand-mascot-light')).toBe(true)
      expect(mark.querySelector('[data-brand-asset="dark"]')).toBeNull()
    }
  })

  it('keeps the mascot decorative beside the visible wordmark', () => {
    render(<BrandLockup />)
    const lockup = screen.getByTestId('brand-lockup')
    expect(lockup.textContent).toBe('StatePort')
    expect(lockup.querySelector('[data-testid="brand-mark"]')?.getAttribute('aria-hidden')).toBe('true')
    expect(screen.queryByRole('img')).toBeNull()
  })

  it('provides a named role only when a label is supplied', () => {
    const { rerender } = render(<BrandMark title="StatePort" />)
    expect(screen.getByRole('img', { name: 'StatePort' })).toBeTruthy()
    rerender(<BrandMark />)
    expect(screen.queryByRole('img')).toBeNull()
    expect(screen.getByTestId('brand-mark').getAttribute('aria-hidden')).toBe('true')
  })

  it('keeps every semantic artwork frame smaller than its fixed mark footprint', () => {
    for (const size of [16, 20, 24, 32, 40] as const) {
      const { unmount } = render(<BrandMark size={size} />)
      const mark = screen.getByTestId('brand-mark')
      const frame = mark.querySelector<HTMLElement>('.brand-art-frame')
      expect(frame).toBeTruthy()
      expect(frame?.classList.contains('shrink-0')).toBe(true)
      expect(mark.classList.contains('overflow-hidden')).toBe(false)
      unmount()
    }
  })
})
