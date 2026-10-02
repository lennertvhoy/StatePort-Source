import { AlertTriangle, Check, Cpu, LockKeyhole, Network, Shield, Timer } from 'lucide-react'
import { useMemo, useState } from 'react'

import type { ExecutionEngine, GovernedAction } from '@/client'
import { InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'

import {
  defaultEngineFor,
  defaultSchemaInputValues,
  enginesForAction,
  parseSchemaInputs,
  schemaInputFields,
  type SchemaInputValues,
} from './runsModel'

function PolicyValue({ value }: { value: unknown }) {
  if (value === undefined || value === null) {
    return <span className="text-foreground-tertiary">Not declared</span>
  }
  if (typeof value === 'string' || typeof value === 'number') {
    return <span>{String(value)}</span>
  }
  return (
    <code className="whitespace-pre-wrap break-words font-mono text-xs">
      {JSON.stringify(value)}
    </code>
  )
}

function BoundaryFact({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Shield
  label: string
  value: unknown
}) {
  return (
    <div className="grid gap-1 py-2 sm:grid-cols-[10rem_1fr]">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-foreground-secondary">
        <Icon className="size-3.5" aria-hidden="true" />
        {label}
      </dt>
      <dd className="min-w-0 text-xs text-foreground">
        <PolicyValue value={value} />
      </dd>
    </div>
  )
}

function SchemaField({
  field,
  value,
  invalid,
  onChange,
}: {
  field: ReturnType<typeof schemaInputFields>[number]
  value: string | boolean
  invalid: boolean
  onChange: (value: string | boolean) => void
}) {
  const id = `run-input-${field.name}`
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-xs font-medium text-foreground">
        {field.label}
        {field.required ? <span className="ml-1 text-status-danger" aria-label="required">*</span> : null}
      </label>
      {field.type === 'boolean' ? (
        <label
          htmlFor={id}
          className="flex min-h-9 items-center gap-2 rounded-sm border border-border px-3 text-sm text-foreground"
        >
          <input
            id={id}
            type="checkbox"
            checked={Boolean(value)}
            onChange={(event) => onChange(event.currentTarget.checked)}
            className="size-4 accent-[var(--accent)]"
          />
          Enabled
        </label>
      ) : field.enumValues ? (
        <select
          id={id}
          value={String(value)}
          onChange={(event) => onChange(event.currentTarget.value)}
          aria-invalid={invalid}
          className="h-9 rounded-md border border-input bg-surface px-3 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <option value="">Select a declared value</option>
          {field.enumValues.map((option) => (
            <option key={String(option)} value={String(option)}>
              {String(option)}
            </option>
          ))}
        </select>
      ) : field.type === 'object' || field.type === 'array' ? (
        <Textarea
          id={id}
          value={String(value)}
          onChange={(event) => onChange(event.currentTarget.value)}
          aria-invalid={invalid}
          spellCheck={false}
          placeholder={field.type === 'array' ? '[]' : '{}'}
          className="min-h-24 font-mono text-xs"
        />
      ) : (
        <Input
          id={id}
          type={field.type === 'number' || field.type === 'integer' ? 'number' : 'text'}
          step={field.type === 'integer' ? 1 : field.type === 'number' ? 'any' : undefined}
          value={String(value)}
          onChange={(event) => onChange(event.currentTarget.value)}
          aria-invalid={invalid}
        />
      )}
      {field.description ? (
        <p className="text-xs text-foreground-tertiary">{field.description}</p>
      ) : null}
    </div>
  )
}

export function RunPreparation({
  action,
  engines,
  busy,
  onPrepare,
}: {
  action: GovernedAction
  engines: ExecutionEngine[]
  busy: boolean
  onPrepare: (input: {
    actionId: string
    engineId: string
    inputs: Record<string, unknown>
  }) => Promise<unknown>
}) {
  const allowedEngines = useMemo(() => enginesForAction(action, engines), [action, engines])
  const initialEngine = defaultEngineFor(action, engines)
  const [engineId, setEngineId] = useState(initialEngine?.id ?? '')
  const [values, setValues] = useState<SchemaInputValues>(() =>
    defaultSchemaInputValues(action.inputSchema),
  )
  const [formError, setFormError] = useState<{ field?: string; message: string } | null>(null)
  const fields = schemaInputFields(action.inputSchema)
  const selectedEngine = allowedEngines.find((engine) => engine.id === engineId)

  const prepare = async () => {
    const parsed = parseSchemaInputs(action.inputSchema, values)
    if (!parsed.ok) {
      setFormError({ field: parsed.field, message: parsed.error })
      return
    }
    if (!selectedEngine || selectedEngine.availability !== 'available') {
      setFormError({ message: 'Choose an available execution engine.' })
      return
    }
    setFormError(null)
    await onPrepare({ actionId: action.id, engineId: selectedEngine.id, inputs: parsed.value })
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 px-4 py-5 md:px-6" data-testid="run-preparation">
      <header className="border-b border-border pb-4">
        <p className="tnum font-mono text-xs text-foreground-tertiary">{action.id}</p>
        <h2 className="mt-1 text-2xl font-semibold tracking-tight text-foreground">{action.title}</h2>
        {action.description ? (
          <p className="mt-1 max-w-2xl text-sm text-foreground-secondary">{action.description}</p>
        ) : null}
      </header>

      <section aria-labelledby="run-inputs-heading">
        <h3 id="run-inputs-heading" className="text-sm font-semibold text-foreground">Declared inputs</h3>
        <p className="mt-0.5 text-xs text-foreground-tertiary">
          Inputs are compiled into the exact run specification before approval.
        </p>
        {fields.length === 0 ? (
          <p className="mt-3 border-y border-border py-3 text-sm text-foreground-secondary" data-testid="run-inputs-empty">
            This action declares no named inputs.
          </p>
        ) : (
          <div className="mt-3 grid gap-4 sm:grid-cols-2" data-testid="run-schema-inputs">
            {fields.map((field) => (
              <SchemaField
                key={field.name}
                field={field}
                value={values[field.name] ?? (field.type === 'boolean' ? false : '')}
                invalid={formError?.field === field.name}
                onChange={(value) => {
                  setFormError(null)
                  setValues((current) => ({ ...current, [field.name]: value }))
                }}
              />
            ))}
          </div>
        )}
      </section>

      <section aria-labelledby="run-engine-heading">
        <h3 id="run-engine-heading" className="text-sm font-semibold text-foreground">Execution engine</h3>
        <p className="mt-0.5 text-xs text-foreground-tertiary">
          Unavailable engines remain visible for diagnosis but cannot be selected.
        </p>
        {allowedEngines.length === 0 ? (
          <InlineNotice tone="blocked" title="No declared engine is available">
            This action’s engine allow-list does not match any engine returned by the service.
          </InlineNotice>
        ) : (
          <div className="mt-3 divide-y divide-border border-y border-border" data-testid="run-engines">
            {allowedEngines.map((engine) => {
              const selectable = engine.availability === 'available'
              const selected = engine.id === engineId
              return (
                <label
                  key={engine.id}
                  className={cn(
                    'flex items-start gap-3 py-3',
                    selectable ? 'cursor-pointer' : 'cursor-not-allowed opacity-65',
                  )}
                  data-testid={`run-engine-${engine.id}`}
                >
                  <input
                    type="radio"
                    name="run-engine"
                    value={engine.id}
                    checked={selected}
                    disabled={!selectable}
                    onChange={() => {
                      setFormError(null)
                      setEngineId(engine.id)
                    }}
                    className="mt-1 size-4 accent-[var(--accent)]"
                  />
                  <Cpu className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-foreground">{engine.label}</span>
                      <span className="rounded-sm bg-sunken px-1.5 py-0.5 text-xs text-foreground-secondary">
                        {engine.availability.replaceAll('_', ' ')}
                      </span>
                      {selected ? <Check className="size-3.5 text-accent" aria-hidden="true" /> : null}
                    </span>
                    <span className="tnum mt-0.5 block font-mono text-xs text-foreground-tertiary">
                      {engine.adapterId ?? engine.kind}
                      {engine.adapterVersion ? ` · ${engine.adapterVersion}` : ''}
                    </span>
                    {engine.unavailableReason ? (
                      <span className="mt-1 block text-xs text-foreground-secondary">{engine.unavailableReason}</span>
                    ) : null}
                    {engine.limitations?.length ? (
                      <span className="mt-1 block text-xs text-status-attention">
                        {engine.limitations.join(' ')}
                      </span>
                    ) : null}
                  </span>
                </label>
              )
            })}
          </div>
        )}
      </section>

      <section aria-labelledby="run-boundary-heading">
        <h3 id="run-boundary-heading" className="text-sm font-semibold text-foreground">Execution boundary</h3>
        <p className="mt-0.5 text-xs text-foreground-tertiary">
          These declarations constrain preparation; effective capability is still negotiated by the service.
        </p>
        <dl className="mt-3 divide-y divide-border border-y border-border">
          <BoundaryFact
            icon={Shield}
            label="Required capabilities"
            value={action.requiredCapabilities?.length ? action.requiredCapabilities.join(', ') : 'None declared'}
          />
          <BoundaryFact
            icon={Shield}
            label="Optional capabilities"
            value={action.optionalCapabilities?.length ? action.optionalCapabilities.join(', ') : 'None declared'}
          />
          <BoundaryFact icon={LockKeyhole} label="Mutation policy" value={action.mutationPolicy} />
          <BoundaryFact icon={Network} label="Network policy" value={action.networkPolicy} />
          <BoundaryFact icon={Timer} label="Budget defaults" value={action.budgetDefaults} />
          <BoundaryFact icon={Cpu} label="Context policy" value={action.contextPolicy} />
          <BoundaryFact icon={Check} label="Validation policy" value={action.validationPolicy} />
        </dl>
      </section>

      {selectedEngine?.productionEligible === false ? (
        <InlineNotice tone="attention" icon={AlertTriangle} title="Production-ineligible engine">
          The selected engine is available for this environment but is not declared production eligible.
        </InlineNotice>
      ) : null}

      {formError ? (
        <InlineNotice tone="danger" title="Run could not be prepared">
          {formError.message}
        </InlineNotice>
      ) : null}

      <footer className="flex flex-col items-start justify-between gap-3 border-t border-border pt-4 sm:flex-row sm:items-center">
        <p className="max-w-xl text-xs text-foreground-tertiary">
          Prepare compiles an exact run for review. It does not approve, execute, apply, or validate anything.
        </p>
        <Button
          type="button"
          onClick={() => void prepare()}
          disabled={busy || !selectedEngine || selectedEngine.availability !== 'available'}
          data-testid="run-prepare"
        >
          Prepare exact run
        </Button>
      </footer>
    </div>
  )
}
