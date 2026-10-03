'use client'

import type { ReactNode } from 'react'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  constraintHint,
  enumKey,
  type EnumValue,
  type FieldSpec,
  type FormValue,
} from '@/lib/tool-schema'

const selectClass =
  'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring'

const enumLabel = (value: EnumValue) => (typeof value === 'string' ? value : String(value))

function defaultText(f: FieldSpec): string | undefined {
  if (!f.hasDefault || f.default === null || f.default === undefined) return undefined
  return typeof f.default === 'string' ? f.default : JSON.stringify(f.default)
}

/** One input generated from one property of the tool's input schema. */
export function ToolFormField({
  field,
  value,
  error,
  onChange,
}: {
  field: FieldSpec
  value: FormValue
  error?: string
  onChange: (value: FormValue) => void
}) {
  const id = `tool-field-${field.name}`
  const helpId = `${id}-help`
  const errorId = `${id}-error`
  const describedBy = [helpId, error ? errorId : undefined].filter(Boolean).join(' ')
  const hint = constraintHint(field)
  const shownDefault = defaultText(field)
  const common = {
    id,
    'aria-describedby': describedBy,
    'aria-invalid': error ? true : undefined,
    'aria-required': field.required || undefined,
    'data-testid': `field-${field.name}`,
  }
  const text = typeof value === 'string' ? value : ''

  let control: ReactNode
  switch (field.kind) {
    case 'boolean':
      control = (
        <input
          {...common}
          type="checkbox"
          className="h-4 w-4"
          checked={value === true}
          onChange={e => onChange(e.target.checked)}
        />
      )
      break
    case 'enum':
      control = (
        <select
          {...common}
          className={selectClass}
          value={text}
          onChange={e => onChange(e.target.value)}
        >
          {(!field.required || text === '') && <option value="">(not set)</option>}
          {field.enumValues?.map(option => (
            <option key={enumKey(option)} value={enumKey(option)}>
              {enumLabel(option)}
            </option>
          ))}
        </select>
      )
      break
    case 'integer':
    case 'number':
      control = (
        <Input
          {...common}
          type="number"
          inputMode={field.kind === 'integer' ? 'numeric' : 'decimal'}
          step={field.kind === 'integer' ? 1 : 'any'}
          min={field.minimum ?? field.exclusiveMinimum}
          max={field.maximum ?? field.exclusiveMaximum}
          placeholder={field.placeholder}
          value={text}
          onChange={e => onChange(e.target.value)}
        />
      )
      break
    case 'array':
      if (field.items?.kind === 'enum') {
        const checked = Array.isArray(value) ? value : []
        control = (
          <div
            {...common}
            role="group"
            aria-labelledby={`${id}-label`}
            className="flex flex-wrap gap-3"
          >
            {field.items.enumValues?.map(option => {
              const key = enumKey(option)
              return (
                <label key={key} className="flex items-center gap-1 text-sm">
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={checked.includes(key)}
                    onChange={e =>
                      onChange(
                        e.target.checked ? [...checked, key] : checked.filter(k => k !== key)
                      )
                    }
                  />
                  {enumLabel(option)}
                </label>
              )
            })}
          </div>
        )
      } else {
        control = (
          <Textarea
            {...common}
            rows={4}
            className="font-mono"
            placeholder={field.placeholder ?? 'One value per line'}
            value={text}
            onChange={e => onChange(e.target.value)}
          />
        )
      }
      break
    case 'json':
      control = (
        <Textarea
          {...common}
          rows={4}
          className="font-mono"
          placeholder={field.placeholder ?? 'JSON value'}
          value={text}
          onChange={e => onChange(e.target.value)}
        />
      )
      break
    default:
      control = (
        <Input
          {...common}
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={field.placeholder}
          value={text}
          onChange={e => onChange(e.target.value)}
        />
      )
  }

  const isCheckbox = field.kind === 'boolean'
  return (
    <div className="space-y-1">
      <div className={isCheckbox ? 'flex items-center gap-2' : undefined}>
        {isCheckbox && control}
        <label id={`${id}-label`} htmlFor={id} className="text-sm font-medium">
          {field.label}
          {field.required && (
            <span className="text-red-600" aria-hidden="true">
              {' '}
              *
            </span>
          )}
        </label>
        <code className="ml-2 text-xs text-muted-foreground">{field.name}</code>
      </div>
      {!isCheckbox && control}
      <p id={helpId} className="text-xs text-muted-foreground">
        {[
          field.description,
          field.kind === 'array' && field.items?.kind !== 'enum'
            ? 'One value per line.'
            : undefined,
          field.kind === 'json' ? 'A JSON value.' : undefined,
          hint ? `Allowed: ${hint}.` : undefined,
          shownDefault !== undefined ? `Default: ${shownDefault}.` : undefined,
          field.required ? 'Required.' : undefined,
        ]
          .filter(Boolean)
          .join(' ')}
      </p>
      {error && (
        <p id={errorId} className="text-xs text-red-600" data-testid={`field-error-${field.name}`}>
          {error}
        </p>
      )}
    </div>
  )
}
