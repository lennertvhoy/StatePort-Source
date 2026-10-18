/**
 * PanelGroup — strips the library-emitted aria-orientation from the role-less
 * group div (axe aria-allowed-attr), while Separator keeps its valid
 * role="separator" + aria-orientation pair.
 */
import { cleanup, render } from '@testing-library/react'
import { Panel, Separator } from 'react-resizable-panels'
import { afterEach, describe, expect, it } from 'vitest'

import { PanelGroup } from '../resizable'

afterEach(cleanup)

describe('PanelGroup', () => {
  it('renders the group div without aria-orientation', () => {
    const { container } = render(
      <PanelGroup orientation="horizontal">
        <Panel id="a">A</Panel>
        <Separator />
        <Panel id="b">B</Panel>
      </PanelGroup>,
    )
    const group = container.querySelector('[data-group]')
    expect(group).not.toBeNull()
    expect(group?.getAttribute('aria-orientation')).toBeNull()
  })

  it('keeps role="separator" + aria-orientation on the resize handle', () => {
    const { container } = render(
      <PanelGroup orientation="vertical">
        <Panel id="a">A</Panel>
        <Separator />
        <Panel id="b">B</Panel>
      </PanelGroup>,
    )
    const separator = container.querySelector('[role="separator"]')
    expect(separator).not.toBeNull()
    expect(separator?.getAttribute('aria-orientation')).toMatch(/^(horizontal|vertical)$/)
  })
})
