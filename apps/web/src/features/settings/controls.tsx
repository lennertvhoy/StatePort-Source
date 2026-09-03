/**
 * Settings controls — the row/section primitives every group is built from.
 *
 * - Fieldset/legend semantics for subsections; every control is labeled.
 * - Rows are min 44 px, hairline separated, label + wrapping description with
 *   the control right-aligned (full width on narrow screens) — not a grid.
 * - Read-only effective values render as wrapping text + CopyButton, never
 *   as disabled inputs.
 */
import { Check } from 'lucide-react'
import type { ReactElement, ReactNode } from 'react'
import { cloneElement, useId } from 'react'
import * as RadioGroupPrimitive from '@radix-ui/react-radio-group'

import { CopyButton } from '@/components'
import { Switch } from '@/components/ui/switch'
import { cn } from '@/lib/utils'

// ─────────────────────────────────────────────────────────────────────────────
// Section / rows
// ─────────────────────────────────────────────────────────────────────────────

/** A labeled subsection (fieldset/legend) clustering 2–4 related settings. */
export function SettingSubsection({
  title,
  description,
  children,
  className,
}: {
  title: string
  description?: string
  children: ReactNode
  className?: string
}) {
  return (
    <fieldset className={cn('border-t border-border pt-4 first:border-t-0 first:pt-0', className)}>
      <legend className="sr-only">{title}</legend>
      <div aria-hidden="true">
        <h3 className="text-sm font-medium text-foreground">{title}</h3>
        {description ? <p className="mt-0.5 text-xs text-foreground-secondary">{description}</p> : null}
      </div>
      <div className="mt-1 flex flex-col">{children}</div>
    </fieldset>
  )
}

export interface SettingRowProps {
  /** Stable anchor id for search jumps. */
  anchor: string
  label: string
  description?: ReactNode
  /** Control; wired to the label via aria-labelledby unless it takes htmlFor. */
  children: ReactNode
  className?: string
}

/**
 * One setting row: label (13 px 500) + wrapping description (12 px secondary)
 * with the control right-aligned; stacks full-width on narrow screens.
 */
export function SettingRow({ anchor, label, description, children, className }: SettingRowProps) {
  const labelId = useId()
  return (
    <div
      id={`setting-${anchor}`}
      data-setting-anchor={anchor}
      className={cn(
        'flex min-h-11 scroll-mt-24 flex-wrap items-center justify-between gap-x-6 gap-y-2 border-b border-border/60 py-2.5 last:border-b-0',
        className,
      )}
    >
      <div className="min-w-0 flex-1 basis-52">
        <span id={labelId} className="block text-sm font-medium text-foreground">
          {label}
        </span>
        {description ? <span className="mt-0.5 block text-xs text-foreground-secondary">{description}</span> : null}
      </div>
      <div className="flex shrink-0 items-center gap-2 max-sm:w-full max-sm:justify-start">
        {/* Controls receive `aria-labelledby={labelId}` via clone in the typed rows below. */}
        {injectLabel(children, labelId)}
      </div>
    </div>
  )
}

/** Clone a single control element adding aria-labelledby when absent. */
function injectLabel(children: ReactNode, labelId: string): ReactNode {
  if (children && typeof children === 'object' && !Array.isArray(children) && 'props' in (children as object)) {
    const element = children as ReactElement<Record<string, unknown>>
    if (!element.props['aria-labelledby'] && !element.props['aria-label']) {
      return cloneElement(element, { 'aria-labelledby': labelId })
    }
  }
  return children
}

// ─────────────────────────────────────────────────────────────────────────────
// Controls
// ─────────────────────────────────────────────────────────────────────────────

export function ToggleControl({
  checked,
  onChange,
  disabled,
  'aria-labelledby': ariaLabelledby,
  'aria-label': ariaLabel,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  disabled?: boolean
  'aria-labelledby'?: string
  'aria-label'?: string
}) {
  return (
    <Switch
      checked={checked}
      onCheckedChange={onChange}
      disabled={disabled}
      aria-labelledby={ariaLabelledby}
      aria-label={ariaLabel}
    />
  )
}

export interface SelectOption {
  value: string
  label: string
}

/** Native select — honest, keyboard/IME safe, native-feeling on mobile. */
export function SelectControl({
  value,
  options,
  onChange,
  disabled,
  className,
  'aria-labelledby': ariaLabelledby,
  'aria-label': ariaLabel,
}: {
  value: string
  options: readonly SelectOption[]
  onChange: (value: string) => void
  disabled?: boolean
  className?: string
  'aria-labelledby'?: string
  'aria-label'?: string
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      aria-labelledby={ariaLabelledby}
      aria-label={ariaLabel}
      className={cn(
        'h-control max-w-full rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none transition-colors duration-instant',
        'focus-visible:border-focus disabled:cursor-not-allowed disabled:opacity-60 max-sm:flex-1',
        className,
      )}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  )
}

/** Segmented radio control (e.g. theme) — radiogroup semantics, instant pick. */
export function SegmentedControl({
  value,
  options,
  onChange,
  'aria-labelledby': ariaLabelledby,
  'aria-label': ariaLabel,
}: {
  value: string
  options: readonly SelectOption[]
  onChange: (value: string) => void
  'aria-labelledby'?: string
  'aria-label'?: string
}) {
  return (
    <RadioGroupPrimitive.Root
      value={value}
      onValueChange={onChange}
      aria-labelledby={ariaLabelledby}
      aria-label={ariaLabel}
      className="flex flex-wrap items-center gap-0.5 rounded-sm border border-border bg-surface-2 p-0.5"
    >
      {options.map((option) => (
        <RadioGroupPrimitive.Item
          key={option.value}
          value={option.value}
          className={cn(
            'flex min-h-control-sm items-center gap-1 rounded-xs px-2 text-sm outline-none transition-colors duration-instant',
            'focus-visible:ring-2 focus-visible:ring-focus',
            'data-[state=checked]:bg-surface data-[state=checked]:text-foreground data-[state=checked]:shadow-1',
            'data-[state=unchecked]:text-foreground-secondary data-[state=unchecked]:hover:text-foreground',
          )}
        >
          <RadioGroupPrimitive.Indicator>
            <Check className="size-3.5 text-accent" aria-hidden="true" />
          </RadioGroupPrimitive.Indicator>
          {option.label}
        </RadioGroupPrimitive.Item>
      ))}
    </RadioGroupPrimitive.Root>
  )
}

export function NumberControl({
  value,
  onChange,
  min,
  max,
  step = 1,
  unit,
  'aria-labelledby': ariaLabelledby,
  'aria-label': ariaLabel,
}: {
  value: number
  onChange: (value: number) => void
  min?: number
  max?: number
  step?: number
  unit?: string
  'aria-labelledby'?: string
  'aria-label'?: string
}) {
  return (
    <span className="flex items-center gap-1.5">
      <input
        type="number"
        value={Number.isFinite(value) ? value : ''}
        min={min}
        max={max}
        step={step}
        aria-labelledby={ariaLabelledby}
        aria-label={ariaLabel}
        onChange={(e) => {
          const next = e.target.valueAsNumber
          if (!Number.isFinite(next)) return
          const clamped = Math.min(max ?? Number.POSITIVE_INFINITY, Math.max(min ?? Number.NEGATIVE_INFINITY, next))
          onChange(clamped)
        }}
        className="h-control w-24 rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none focus-visible:border-focus"
      />
      {unit ? <span className="text-xs text-foreground-secondary">{unit}</span> : null}
    </span>
  )
}

export function TextControl({
  value,
  onChange,
  placeholder,
  type = 'text',
  mono,
  className,
  'aria-labelledby': ariaLabelledby,
  'aria-label': ariaLabel,
}: {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  type?: 'text' | 'time' | 'url'
  mono?: boolean
  className?: string
  'aria-labelledby'?: string
  'aria-label'?: string
}) {
  return (
    <input
      type={type}
      value={value}
      placeholder={placeholder}
      aria-labelledby={ariaLabelledby}
      aria-label={ariaLabel}
      onChange={(e) => onChange(e.target.value)}
      spellCheck={false}
      autoComplete="off"
      className={cn(
        'h-control rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none focus-visible:border-focus',
        mono ? 'w-56 font-mono' : 'w-48',
        'max-sm:flex-1',
        className,
      )}
    />
  )
}

/**
 * Read-only effective value — wrapping text with a CopyButton. Never a
 * disabled input (settings.md “Do NOT show”).
 */
export function ReadOnlyValue({
  value,
  copyValue,
  mono = true,
  className,
}: {
  value: ReactNode
  copyValue?: string
  mono?: boolean
  className?: string
}) {
  return (
    <span className={cn('flex min-w-0 max-w-md items-start gap-1', className)} data-testid="read-only-value">
      <span
        className={cn(
          'min-w-0 whitespace-pre-wrap break-words text-sm text-foreground-secondary',
          mono && 'font-mono text-code',
        )}
      >
        {value}
      </span>
      {copyValue ? <CopyButton text={copyValue} label="Copy value" className="shrink-0" /> : null}
    </span>
  )
}

/** Checkbox row used for multi-select context-chip settings. */
export function CheckboxChips<T extends string>({
  values,
  options,
  onToggle,
  ariaLabel,
}: {
  values: readonly T[]
  options: readonly { value: T; label: string }[]
  onToggle: (value: T, next: boolean) => void
  ariaLabel?: string
}) {
  return (
    <div role="group" aria-label={ariaLabel} className="flex max-w-md flex-wrap gap-1.5">
      {options.map((option) => {
        const checked = values.includes(option.value)
        return (
          <label
            key={option.value}
            className={cn(
              'flex min-h-control-sm cursor-pointer items-center gap-1.5 rounded-sm border px-2 text-sm transition-colors duration-instant',
              checked
                ? 'border-accent bg-accent-soft text-accent-soft-text'
                : 'border-border bg-surface text-foreground-secondary hover:text-foreground',
            )}
          >
            <input
              type="checkbox"
              className="size-3.5 accent-[var(--accent)]"
              checked={checked}
              onChange={(e) => onToggle(option.value, e.target.checked)}
            />
            {option.label}
          </label>
        )
      })}
    </div>
  )
}

