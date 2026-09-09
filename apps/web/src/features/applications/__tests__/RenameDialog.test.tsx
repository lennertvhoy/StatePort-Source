import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'

import { RenameDialog } from '../components/RenameDialog'

afterEach(cleanup)

it('keeps the reviewed input visible when rename fails, then allows an explicit retry', async () => {
  const submit = vi.fn().mockRejectedValueOnce(new Error('Name changed; reload before renaming')).mockResolvedValueOnce(undefined)
  const close = vi.fn()
  render(<RenameDialog open currentName="First" onSubmit={submit} onOpenChange={close} />)
  const input = screen.getByRole('textbox') as HTMLInputElement
  fireEvent.change(input, { target: { value: 'Renamed' } })
  fireEvent.click(screen.getByRole('button', { name: 'Rename' }))
  await screen.findByText('Name changed; reload before renaming')
  expect(input.value).toBe('Renamed')
  expect(close).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Rename' }))
  await waitFor(() => expect(close).toHaveBeenCalledWith(false))
  expect(submit).toHaveBeenCalledTimes(2)
})
