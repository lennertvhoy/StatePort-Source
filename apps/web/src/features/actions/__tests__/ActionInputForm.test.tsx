/** The generated input form: labels, required marks, maxLength, dates and integers. */
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { actionInputFields, type ActionInputField } from '../actionsModel'
import { ActionInputForm } from '../ActionInputForm'

const FIELDS: ActionInputField[] = [
  { name: 'project', label: 'Project name', type: 'string', required: true, maxLength: 20 },
  { name: 'outcome', label: 'Outcome', type: 'text', required: true, maxLength: 600, description: 'What the work is for.' },
  { name: 'firstSlice', label: 'First slice', type: 'string', required: false, maxLength: 200 },
  { name: 'deadline', label: 'Deadline', type: 'date', required: false },
  { name: 'hoursPerWeek', label: 'Hours per week', type: 'integer', required: false, minimum: 1, maximum: 80 },
]

afterEach(cleanup)

function renderForm(fields: ActionInputField[] = FIELDS, onSubmit = vi.fn()) {
  render(<ActionInputForm actionId="act" fields={fields} onSubmit={onSubmit} onCancel={vi.fn()} />)
  return { onSubmit }
}

describe('action input form', () => {
  it('labels every field, marks the required ones and enforces maxLength', () => {
    renderForm()
    const form = screen.getByTestId('action-form-act')
    expect(within(form).getByLabelText(/Project name/).getAttribute('maxlength')).toBe('20')
    expect(within(form).getByLabelText(/Outcome/).tagName).toBe('TEXTAREA')
    expect(within(form).getByLabelText(/Deadline/).getAttribute('type')).toBe('date')
    expect(within(form).getByLabelText(/Hours per week/).getAttribute('type')).toBe('number')
    expect(within(form).getAllByText('(required)')).toHaveLength(2)
    expect(within(form).getAllByText('(optional)')).toHaveLength(3)
    expect(within(form).getByText('What the work is for.')).toBeTruthy()
  })

  it('refuses to submit while a required field is empty and says which one', async () => {
    const { onSubmit } = renderForm()
    const form = screen.getByTestId('action-form-act')
    await userEvent.click(within(form).getByTestId('action-form-review-act'))
    expect(within(form).getByText('Project name is required.')).toBeTruthy()
    expect(within(form).getByText('Outcome is required.')).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('the field itself stops a value that is too long, and the form refuses a value that is not a whole number', async () => {
    const { onSubmit } = renderForm()
    const form = screen.getByTestId('action-form-act')
    const project = within(form).getByLabelText(/Project name/)
    await userEvent.type(project, 'x'.repeat(25))
    // The field carries the limit, so the value can never exceed it.
    expect((project as HTMLInputElement).value).toHaveLength(20)

    await userEvent.type(within(form).getByLabelText(/Outcome/), 'Ship it')
    await userEvent.type(within(form).getByLabelText(/Hours per week/), '2.5')
    await userEvent.click(within(form).getByTestId('action-form-review-act'))
    expect(within(form).getByText('Hours per week must be a whole number.')).toBeTruthy()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('reads a date the way the schema declares it', async () => {
    const { onSubmit } = renderForm()
    const form = screen.getByTestId('action-form-act')
    fireEvent.change(within(form).getByLabelText(/Deadline/), { target: { value: '2026-10-30' } })
    await userEvent.type(within(form).getByLabelText(/Project name/), 'StatePort')
    await userEvent.type(within(form).getByLabelText(/Outcome/), 'Ship it')
    await userEvent.click(within(form).getByTestId('action-form-review-act'))
    expect(onSubmit).toHaveBeenCalledWith(
      { project: 'StatePort', outcome: 'Ship it', deadline: '2026-10-30' },
      expect.objectContaining({ deadline: '2026-10-30' }),
    )
  })

  it('submits the parsed values and the entered ones', async () => {
    const { onSubmit } = renderForm()
    const form = screen.getByTestId('action-form-act')
    await userEvent.type(within(form).getByLabelText(/Project name/), ' StatePort ')
    await userEvent.type(within(form).getByLabelText(/Outcome/), 'Ship Alpha.26')
    await userEvent.type(within(form).getByLabelText(/Hours per week/), '6')
    await userEvent.click(within(form).getByTestId('action-form-review-act'))
    expect(onSubmit).toHaveBeenCalledWith(
      { project: 'StatePort', outcome: 'Ship Alpha.26', hoursPerWeek: 6 },
      { project: ' StatePort ', outcome: 'Ship Alpha.26', firstSlice: '', deadline: '', hoursPerWeek: '6' },
    )
  })

  it('an action without inputs has nothing to fill in', () => {
    renderForm([])
    const form = screen.getByTestId('action-form-act')
    expect(within(form).queryAllByRole('textbox')).toHaveLength(0)
  })

  it('derives the fields from the action schema', () => {
    const fields = actionInputFields({
      id: 'act', instanceId: 'ins_1', title: 'Act', engineIds: [],
      inputSchema: {
        type: 'object',
        required: ['project'],
        properties: { project: { type: 'string', maxLength: 20 }, firstSlice: { type: 'string' } },
      },
    })
    expect(fields.map((field) => [field.name, field.label, field.required, field.maxLength])).toEqual([
      ['project', 'Project', true, 20],
      ['firstSlice', 'First slice', false, undefined],
    ])
  })
})
