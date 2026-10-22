/**
 * A small form generated from an action's `inputSchema`: labels from the
 * property `title` (or its name), required fields marked, `maxLength`
 * enforced by the field and by validation. Submitting only validates; the
 * values are shown in the confirmation before anything is prepared.
 */
import { useState, type FormEvent } from 'react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

import {
  initialInputValues,
  parseActionInputs,
  type ActionInputField,
  type ActionInputValues,
} from './actionsModel'

export function ActionInputForm({
  actionId,
  fields,
  initialValues,
  onSubmit,
  onCancel,
}: {
  actionId: string
  fields: ActionInputField[]
  initialValues?: ActionInputValues
  onSubmit: (inputs: Record<string, unknown>, values: ActionInputValues) => void
  onCancel: () => void
}) {
  const [values, setValues] = useState<ActionInputValues>(() => initialValues ?? initialInputValues(fields))
  const [errors, setErrors] = useState<Record<string, string>>({})

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const parsed = parseActionInputs(fields, values)
    if (!parsed.ok) {
      setErrors(parsed.errors)
      return
    }
    setErrors({})
    onSubmit(parsed.value, values)
  }

  const set = (name: string, value: string | boolean) => setValues((current) => ({ ...current, [name]: value }))

  return (
    <form
      onSubmit={submit}
      noValidate
      className="flex flex-col gap-3 rounded-sm border border-border bg-surface-2 p-3"
      aria-label="Action inputs"
      data-testid={`action-form-${actionId}`}
    >
      {fields.map((field) => {
        const id = `action-${actionId}-${field.name}`
        const error = errors[field.name]
        const describedBy = [field.description ? `${id}-help` : null, error ? `${id}-error` : null].filter(Boolean).join(' ') || undefined
        const raw = values[field.name]
        const text = typeof raw === 'string' ? raw : ''
        return (
          <div key={field.name} className="flex flex-col gap-1">
            {field.type === 'boolean' ? (
              <label htmlFor={id} className="flex items-center gap-2 text-sm text-foreground">
                <input
                  id={id}
                  type="checkbox"
                  checked={Boolean(raw)}
                  onChange={(event) => set(field.name, event.target.checked)}
                  aria-describedby={describedBy}
                />
                {field.label}
              </label>
            ) : (
              <>
                <label htmlFor={id} className="text-sm font-medium text-foreground">
                  {field.label}
                  {field.required ? <span className="ml-1 text-xs font-normal text-foreground-tertiary">(required)</span> : (
                    <span className="ml-1 text-xs font-normal text-foreground-tertiary">(optional)</span>
                  )}
                </label>
                {field.enumValues ? (
                  <select
                    id={id}
                    value={text}
                    onChange={(event) => set(field.name, event.target.value)}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={describedBy}
                    required={field.required}
                    className="h-9 w-full rounded-md border border-input bg-surface px-2 text-sm text-foreground"
                  >
                    <option value="">{field.required ? 'Choose…' : 'Not set'}</option>
                    {field.enumValues.map((option) => (
                      <option key={option} value={option}>{option}</option>
                    ))}
                  </select>
                ) : field.type === 'text' ? (
                  <Textarea
                    id={id}
                    value={text}
                    rows={3}
                    maxLength={field.maxLength}
                    onChange={(event) => set(field.name, event.target.value)}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={describedBy}
                    required={field.required}
                  />
                ) : (
                  <Input
                    id={id}
                    value={text}
                    type={field.type === 'date' ? 'date' : field.type === 'integer' || field.type === 'number' ? 'number' : 'text'}
                    inputMode={field.type === 'integer' ? 'numeric' : field.type === 'number' ? 'decimal' : undefined}
                    step={field.type === 'integer' ? 1 : undefined}
                    min={field.minimum}
                    max={field.maximum}
                    maxLength={field.maxLength}
                    onChange={(event) => set(field.name, event.target.value)}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={describedBy}
                    required={field.required}
                    autoComplete="off"
                  />
                )}
              </>
            )}
            <div className="flex items-start justify-between gap-2">
              {field.description ? (
                <p id={`${id}-help`} className="text-xs text-foreground-tertiary">{field.description}</p>
              ) : <span />}
              {field.maxLength !== undefined && field.type !== 'boolean' ? (
                <span className="tnum shrink-0 text-xs text-foreground-tertiary">{text.length}/{field.maxLength}</span>
              ) : null}
            </div>
            {error ? (
              <p id={`${id}-error`} role="alert" className="text-xs text-status-danger">{error}</p>
            ) : null}
          </div>
        )
      })}
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" size="sm" data-testid={`action-form-review-${actionId}`}>Review</Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  )
}
