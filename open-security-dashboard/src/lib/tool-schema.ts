/**
 * The form for running a tool, derived from the tool's input schema (#585).
 *
 * The tools service publishes each tool's input model as Pydantic JSON Schema
 * at GET /api/v1/tools/<name>/info. This module turns that schema into a list
 * of fields, the form's initial values, and a validator that applies the
 * schema's own constraints and produces the JSON body the tool endpoint
 * accepts. It holds no React, so it can be tested on its own.
 *
 * What a schema can say and what the form does with it:
 *   string                  text input (minLength, maxLength, pattern)
 *   integer / number        number input (minimum, maximum, exclusive bounds)
 *   enum, or a $ref to one  select
 *   boolean                 checkbox; a nullable boolean without a true/false
 *                           default is a select with "not set", so "not sent"
 *                           stays possible
 *   array of primitives     one item per line, each item checked as above; an
 *                           array of enum items is a group of checkboxes
 *   anything else           a JSON text area, parsed before sending
 *
 * `anyOf: [X, {type: null}]` (Pydantic's Optional[X]) is X, not required.
 * An empty optional field is left out of the body, so the service applies its
 * own default instead of the form inventing one.
 */
import { z } from 'zod'

export type JsonSchema = {
  type?: string | string[]
  title?: string
  description?: string
  default?: unknown
  example?: unknown
  examples?: unknown[]
  enum?: unknown[]
  const?: unknown
  format?: string
  minimum?: number
  maximum?: number
  exclusiveMinimum?: number
  exclusiveMaximum?: number
  minLength?: number
  maxLength?: number
  pattern?: string
  minItems?: number
  maxItems?: number
  items?: JsonSchema
  properties?: Record<string, JsonSchema>
  additionalProperties?: JsonSchema | boolean
  required?: string[]
  anyOf?: JsonSchema[]
  oneOf?: JsonSchema[]
  allOf?: JsonSchema[]
  $ref?: string
  $defs?: Record<string, JsonSchema>
  definitions?: Record<string, JsonSchema>
}

export type EnumValue = string | number | boolean

/** The scalar kinds an input, or an array item, can hold. */
export type ScalarKind = 'string' | 'integer' | 'number' | 'boolean' | 'enum'

export interface Constraints {
  minimum?: number
  maximum?: number
  exclusiveMinimum?: number
  exclusiveMaximum?: number
  minLength?: number
  maxLength?: number
  pattern?: string
}

export interface ItemSpec extends Constraints {
  kind: ScalarKind
  enumValues?: EnumValue[]
}

export interface FieldSpec extends Constraints {
  name: string
  label: string
  kind: ScalarKind | 'array' | 'json'
  required: boolean
  description?: string
  /** An example from the schema, shown as the input's placeholder. */
  placeholder?: string
  hasDefault: boolean
  default?: unknown
  enumValues?: EnumValue[]
  items?: ItemSpec
  minItems?: number
  maxItems?: number
  format?: string
}

/** A field's value while it is edited: text, a checkbox, or checked items. */
export type FormValue = string | boolean | string[]
export type FormValues = Record<string, FormValue>

const MAX_REF_DEPTH = 20

/** Follows local `#/$defs/...` (or `#/definitions/...`) references. */
export function resolveRef(schema: JsonSchema, root: JsonSchema): JsonSchema {
  let current = schema
  for (let depth = 0; current.$ref && depth < MAX_REF_DEPTH; depth++) {
    const match = /^#\/(\$defs|definitions)\/(.+)$/.exec(current.$ref)
    const defs = match?.[1] === '$defs' ? root.$defs : root.definitions
    const target = match && defs ? defs[decodeURIComponent(match[2])] : undefined
    if (!target) return {}
    // Keywords beside $ref (a description on the field) win over the target's.
    const { $ref: _ref, ...beside } = current
    void _ref
    current = { ...target, ...beside }
  }
  return current
}

const isNullSchema = (s: JsonSchema) => s.type === 'null' || (s.const === null && !s.type)

/**
 * Unwraps Pydantic's Optional[X] (`anyOf: [X, {type: null}]`) and single-item
 * `allOf` wrappers, and resolves references. `nullable` is true when null was
 * one of the alternatives.
 */
export function normalize(
  schema: JsonSchema,
  root: JsonSchema
): { schema: JsonSchema; nullable: boolean } {
  let s = resolveRef(schema, root)
  let nullable = false
  const alternatives = s.anyOf ?? s.oneOf
  if (alternatives) {
    const nonNull = alternatives.filter(alt => !isNullSchema(resolveRef(alt, root)))
    nullable = nonNull.length < alternatives.length
    if (nonNull.length === 1) {
      const { anyOf: _a, oneOf: _o, ...outer } = s
      void _a
      void _o
      s = { ...resolveRef(nonNull[0], root), ...outer }
    }
  }
  if (s.allOf && s.allOf.length === 1) {
    const { allOf, ...outer } = s
    s = { ...resolveRef(allOf[0], root), ...outer }
  }
  if (Array.isArray(s.type)) {
    const types = s.type.filter(t => t !== 'null')
    nullable = nullable || types.length < s.type.length
    s = { ...s, type: types.length === 1 ? types[0] : types }
  }
  return { schema: s, nullable }
}

function isEnumValue(value: unknown): value is EnumValue {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

function constraintsOf(s: JsonSchema): Constraints {
  const c: Constraints = {}
  if (typeof s.minimum === 'number') c.minimum = s.minimum
  if (typeof s.maximum === 'number') c.maximum = s.maximum
  if (typeof s.exclusiveMinimum === 'number') c.exclusiveMinimum = s.exclusiveMinimum
  if (typeof s.exclusiveMaximum === 'number') c.exclusiveMaximum = s.exclusiveMaximum
  if (typeof s.minLength === 'number') c.minLength = s.minLength
  if (typeof s.maxLength === 'number') c.maxLength = s.maxLength
  if (typeof s.pattern === 'string') c.pattern = s.pattern
  return c
}

/** The scalar kind of a (normalized) schema, or undefined when it is not a scalar. */
function scalarOf(s: JsonSchema, nullable: boolean): ItemSpec | undefined {
  const values = s.enum ?? (s.const !== undefined && s.const !== null ? [s.const] : undefined)
  if (values) {
    const enumValues = values.filter(isEnumValue)
    if (enumValues.length === 0) return undefined
    return { kind: 'enum', enumValues }
  }
  switch (s.type) {
    case 'string':
      return { kind: 'string', ...constraintsOf(s) }
    case 'integer':
      return { kind: 'integer', ...constraintsOf(s) }
    case 'number':
      return { kind: 'number', ...constraintsOf(s) }
    case 'boolean':
      // A checkbox has two states; an optional boolean with no value yet has
      // three. A select keeps "not set" possible.
      return nullable ? { kind: 'enum', enumValues: [true, false] } : { kind: 'boolean' }
    default:
      return undefined
  }
}

function exampleOf(s: JsonSchema): string | undefined {
  const example = s.example !== undefined ? s.example : s.examples?.[0]
  if (example === undefined || example === null) return undefined
  return typeof example === 'string' ? example : JSON.stringify(example)
}

/** "max_retries" -> "Max Retries", as Pydantic titles a field. */
const humanize = (name: string) =>
  name
    .split('_')
    .filter(Boolean)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')

/** One form field per property of the input schema, in the schema's order. */
export function fieldsFromSchema(input: JsonSchema | null | undefined): FieldSpec[] {
  if (!input) return []
  const root = resolveRef(input, input)
  const required = new Set(root.required ?? [])
  return Object.keys(root.properties ?? {}).map(name => {
    const raw = (root.properties ?? {})[name]
    const { schema: s, nullable } = normalize(raw, input)
    const field: FieldSpec = {
      name,
      // The property's own title; a $ref'd property has none, and the target's
      // is the name of a type, not of the field.
      label: raw.title || humanize(name),
      kind: 'json',
      required: required.has(name),
      description: s.description,
      placeholder: exampleOf(s),
      hasDefault: Object.prototype.hasOwnProperty.call(s, 'default'),
      default: s.default,
      format: s.format,
    }
    // Optional[bool] = None: null is the default, and a checkbox cannot hold it.
    const scalar = scalarOf(s, nullable && (field.default === null || !field.hasDefault))
    if (scalar) return { ...field, ...scalar }
    if (s.type === 'array' && s.items) {
      const item = normalize(s.items, input)
      const itemSpec = scalarOf(item.schema, false)
      if (itemSpec) {
        return {
          ...field,
          kind: 'array',
          items: { ...itemSpec, ...constraintsOf(item.schema) },
          minItems: s.minItems,
          maxItems: s.maxItems,
        }
      }
    }
    return field
  })
}

/** The option value of an enum member in a <select> or checkbox. */
export const enumKey = (value: EnumValue): string => JSON.stringify(value)

const fromEnumKey = (values: EnumValue[] | undefined, key: string): EnumValue | undefined =>
  values?.find(v => enumKey(v) === key)

function textOf(value: unknown): string {
  if (value === undefined || value === null) return ''
  return typeof value === 'string' ? value : String(value)
}

/** The form's starting values: each field's schema default, or empty. */
export function initialValues(fields: FieldSpec[]): FormValues {
  const values: FormValues = {}
  for (const f of fields) {
    const d = f.hasDefault ? f.default : undefined
    switch (f.kind) {
      case 'boolean':
        values[f.name] = d === true
        break
      case 'enum':
        values[f.name] = isEnumValue(d) && fromEnumKey(f.enumValues, enumKey(d)) ? enumKey(d) : ''
        break
      case 'array':
        if (f.items?.kind === 'enum') {
          values[f.name] = Array.isArray(d) ? d.filter(isEnumValue).map(enumKey) : ([] as string[])
        } else {
          values[f.name] = Array.isArray(d) ? d.map(textOf).join('\n') : ''
        }
        break
      case 'json':
        values[f.name] = d === undefined || d === null ? '' : JSON.stringify(d, null, 2)
        break
      default:
        values[f.name] = textOf(d)
    }
  }
  return values
}

function describeBound(c: Constraints): string | undefined {
  const parts: string[] = []
  if (c.minimum !== undefined) parts.push(`>= ${c.minimum}`)
  if (c.exclusiveMinimum !== undefined) parts.push(`> ${c.exclusiveMinimum}`)
  if (c.maximum !== undefined) parts.push(`<= ${c.maximum}`)
  if (c.exclusiveMaximum !== undefined) parts.push(`< ${c.exclusiveMaximum}`)
  return parts.length ? parts.join(', ') : undefined
}

/** The schema's constraints in words, shown next to a field. */
export function constraintHint(f: FieldSpec): string | undefined {
  const spec: Constraints = f.kind === 'array' && f.items ? f.items : f
  const hints: string[] = []
  const bound = describeBound(spec)
  if (bound) hints.push(bound)
  if (spec.minLength !== undefined) hints.push(`at least ${spec.minLength} characters`)
  if (spec.maxLength !== undefined) hints.push(`at most ${spec.maxLength} characters`)
  if (spec.pattern !== undefined) hints.push(`pattern ${spec.pattern}`)
  if (f.kind === 'array') {
    if (f.minItems !== undefined) hints.push(`at least ${f.minItems} items`)
    if (f.maxItems !== undefined) hints.push(`at most ${f.maxItems} items`)
  }
  return hints.length ? hints.join('; ') : undefined
}

/** zod schema for one typed scalar, carrying the JSON Schema's constraints. */
function scalarValidator(spec: ItemSpec): z.ZodTypeAny {
  if (spec.kind === 'integer' || spec.kind === 'number') {
    let n = z.number({ invalid_type_error: 'Enter a number' }).finite('Enter a number')
    if (spec.kind === 'integer') n = n.int('Enter a whole number')
    if (spec.minimum !== undefined) n = n.gte(spec.minimum, `Must be at least ${spec.minimum}`)
    if (spec.maximum !== undefined) n = n.lte(spec.maximum, `Must be at most ${spec.maximum}`)
    if (spec.exclusiveMinimum !== undefined)
      n = n.gt(spec.exclusiveMinimum, `Must be greater than ${spec.exclusiveMinimum}`)
    if (spec.exclusiveMaximum !== undefined)
      n = n.lt(spec.exclusiveMaximum, `Must be less than ${spec.exclusiveMaximum}`)
    return n
  }
  if (spec.kind === 'string') {
    let s = z.string()
    if (spec.minLength !== undefined)
      s = s.min(spec.minLength, `Must be at least ${spec.minLength} characters`)
    if (spec.maxLength !== undefined)
      s = s.max(spec.maxLength, `Must be at most ${spec.maxLength} characters`)
    if (spec.pattern !== undefined) {
      const pattern = toRegExp(spec.pattern)
      // A Python pattern JavaScript cannot compile is left to the service.
      if (pattern) s = s.regex(pattern, `Must match ${spec.pattern}`)
    }
    return s
  }
  return z.any()
}

function toRegExp(pattern: string): RegExp | undefined {
  try {
    return new RegExp(pattern)
  } catch {
    return undefined
  }
}

const OMIT = Symbol('omit')
type Converted = { value: unknown } | { error: string } | typeof OMIT

/** Text to the scalar's type, then the schema's constraints. */
function convertScalar(spec: ItemSpec, text: string): { value: unknown } | { error: string } {
  let candidate: unknown = text
  if (spec.kind === 'integer' || spec.kind === 'number') {
    candidate = text.trim() === '' ? NaN : Number(text.trim())
    if (Number.isNaN(candidate)) return { error: 'Enter a number' }
  } else if (spec.kind === 'enum') {
    const value = fromEnumKey(spec.enumValues, text)
    return value === undefined ? { error: 'Choose one of the listed values' } : { value }
  } else if (spec.kind === 'boolean') {
    if (text !== 'true' && text !== 'false') return { error: 'Enter true or false' }
    return { value: text === 'true' }
  }
  const checked = scalarValidator(spec).safeParse(candidate)
  return checked.success ? { value: checked.data } : { error: checked.error.issues[0].message }
}

/** An array field's items: the checked ones, or the non-empty lines of its text. */
function arrayItems(raw: FormValue | undefined): string[] {
  if (Array.isArray(raw)) return raw
  if (typeof raw !== 'string') return []
  return raw
    .split('\n')
    .map(line => line.trim())
    .filter(line => line !== '')
}

function convertField(f: FieldSpec, raw: FormValue | undefined): Converted {
  if (f.kind === 'boolean') return { value: raw === true }

  if (f.kind === 'array') {
    const items = arrayItems(raw)
    if (items.length === 0) return f.required ? { error: 'Required' } : OMIT
    const values: unknown[] = []
    for (let i = 0; i < items.length; i++) {
      const converted = convertScalar(f.items as ItemSpec, items[i])
      if ('error' in converted) return { error: `Item ${i + 1} (${items[i]}): ${converted.error}` }
      values.push(converted.value)
    }
    if (f.minItems !== undefined && values.length < f.minItems)
      return { error: `At least ${f.minItems} items` }
    if (f.maxItems !== undefined && values.length > f.maxItems)
      return { error: `At most ${f.maxItems} items` }
    return { value: values }
  }

  const text = typeof raw === 'string' ? raw : ''
  if (text.trim() === '') return f.required ? { error: 'Required' } : OMIT

  if (f.kind === 'json') {
    try {
      return { value: JSON.parse(text) }
    } catch {
      return { error: 'Enter valid JSON' }
    }
  }
  return convertScalar(f as ItemSpec, text)
}

export type BuildResult =
  { ok: true; body: Record<string, unknown> } | { ok: false; errors: Record<string, string> }

/**
 * Validates the form against the schema and builds the request body.
 * Empty optional fields are left out; the service applies its defaults.
 */
export function buildRequestBody(fields: FieldSpec[], values: FormValues): BuildResult {
  const body: Record<string, unknown> = {}
  const errors: Record<string, string> = {}
  for (const f of fields) {
    const converted = convertField(f, values[f.name])
    if (converted === OMIT) continue
    if ('error' in converted) errors[f.name] = converted.error
    else body[f.name] = converted.value
  }
  return Object.keys(errors).length ? { ok: false, errors } : { ok: true, body }
}

export interface ServerFieldErrors {
  /** Messages for fields of the form, by field name. */
  fields: Record<string, string>
  /** Messages the form has no field for. */
  other: string[]
}

interface ValidationItem {
  loc?: unknown[]
  msg?: unknown
}

/**
 * The field errors in an error body, if it has any.
 *
 * Two shapes carry them: FastAPI's request validation (`error.details` is
 * the list of `{loc, msg}`, `loc` starting with "body"), and the tool
 * endpoint's input validation (`error.details.errors`, `loc` starting with
 * the field).
 */
export function serverFieldErrors(body: unknown, fieldNames: string[]): ServerFieldErrors {
  const result: ServerFieldErrors = { fields: {}, other: [] }
  const details = (body as { error?: { details?: unknown } } | undefined)?.error?.details
  const list: unknown = Array.isArray(details)
    ? details
    : (details as { errors?: unknown } | undefined)?.errors
  if (!Array.isArray(list)) return result
  const known = new Set(fieldNames)
  for (const entry of list as ValidationItem[]) {
    if (!entry || typeof entry.msg !== 'string') continue
    const loc = Array.isArray(entry.loc) ? entry.loc : []
    const path = loc[0] === 'body' ? loc.slice(1) : loc
    const field = typeof path[0] === 'string' && known.has(path[0]) ? path[0] : undefined
    if (field && !result.fields[field]) {
      const rest = path.slice(1)
      result.fields[field] = rest.length ? `${rest.join('.')}: ${entry.msg}` : entry.msg
    } else {
      result.other.push(path.length ? `${path.join('.')}: ${entry.msg}` : entry.msg)
    }
  }
  return result
}
