import { expect, test } from '@playwright/test'
import {
  buildRequestBody,
  enumKey,
  fieldsFromSchema,
  initialValues,
  serverFieldErrors,
  type FieldSpec,
  type JsonSchema,
} from '../../src/lib/tool-schema'

/**
 * The schema-to-form mapping of /toolbox/<name> (#585), without a browser or
 * a backend: these tests use no page, so Playwright starts none.
 *
 * Both schemas are Pydantic's own output (model_json_schema()): the first is
 * hash_generator's input model as the tools service serves it, the second a
 * model written to hold every construct the mapping handles.
 */

const HASH_GENERATOR: JsonSchema = {
  description: 'Input schema for hash generation',
  properties: {
    target: {
      anyOf: [{ type: 'string' }, { type: 'null' }],
      default: null,
      description: 'Primary target (URL, IP, domain, etc.)',
      title: 'Target',
    },
    timeout: {
      default: 30,
      description: 'Execution timeout in seconds',
      maximum: 300,
      minimum: 1,
      title: 'Timeout',
      type: 'integer',
    },
    verify_ssl: {
      default: true,
      description: 'Verify SSL certificates',
      title: 'Verify Ssl',
      type: 'boolean',
    },
    input_text: { description: 'Text to generate hashes for', title: 'Input Text', type: 'string' },
    hash_types: {
      default: ['md5', 'sha1', 'sha256', 'sha512'],
      description: 'List of hash types to generate',
      items: { type: 'string' },
      title: 'Hash Types',
      type: 'array',
    },
    include_salted: {
      default: false,
      description: 'Include salted hashes',
      title: 'Include Salted',
      type: 'boolean',
    },
    iterations: {
      default: 1,
      maximum: 1000000,
      minimum: 1,
      title: 'Iterations',
      type: 'integer',
    },
  },
  required: ['input_text'],
  title: 'HashGeneratorInput',
  type: 'object',
}

const EVERYTHING: JsonSchema = {
  $defs: {
    Inner: {
      properties: { a: { title: 'A', type: 'integer' } },
      required: ['a'],
      title: 'Inner',
      type: 'object',
    },
    ScanMode: { enum: ['fast', 'full'], title: 'ScanMode', type: 'string' },
  },
  properties: {
    level: { enum: [1, 2, 3], title: 'Level', type: 'integer' },
    ratio: { exclusiveMaximum: 1.0, exclusiveMinimum: 0.0, title: 'Ratio', type: 'number' },
    mode: { $ref: '#/$defs/ScanMode', default: 'fast' },
    opt_mode: { anyOf: [{ $ref: '#/$defs/ScanMode' }, { type: 'null' }], default: null },
    flag: { anyOf: [{ type: 'boolean' }, { type: 'null' }], default: null, title: 'Flag' },
    ports: { items: { type: 'integer' }, maxItems: 3, title: 'Ports', type: 'array' },
    kinds: {
      default: ['fast'],
      items: { $ref: '#/$defs/ScanMode' },
      title: 'Kinds',
      type: 'array',
    },
    headers: {
      anyOf: [{ additionalProperties: { type: 'string' }, type: 'object' }, { type: 'null' }],
      default: null,
      examples: [{ 'X-A': '1' }],
      title: 'Headers',
    },
    code: {
      default: 'AB',
      maxLength: 4,
      minLength: 2,
      pattern: '^[A-Z]+$',
      title: 'Code',
      type: 'string',
    },
    nested: { anyOf: [{ $ref: '#/$defs/Inner' }, { type: 'null' }], default: null },
    url: { example: 'https://example.com', title: 'Url', type: 'string' },
  },
  required: ['level', 'ratio', 'url'],
  title: 'M',
  type: 'object',
}

const byName = (fields: FieldSpec[]) => Object.fromEntries(fields.map(f => [f.name, f]))

/** The form's initial values with some fields changed. */
function valuesWith(fields: FieldSpec[], changes: Record<string, string | boolean | string[]>) {
  return { ...initialValues(fields), ...changes }
}

test.describe('tool schema to form', () => {
  test('maps each property to a field, in order, with its constraints', () => {
    const fields = fieldsFromSchema(HASH_GENERATOR)
    expect(fields.map(f => f.name)).toEqual([
      'target',
      'timeout',
      'verify_ssl',
      'input_text',
      'hash_types',
      'include_salted',
      'iterations',
    ])
    const f = byName(fields)
    expect(f.target).toMatchObject({ kind: 'string', required: false, label: 'Target' })
    expect(f.timeout).toMatchObject({ kind: 'integer', minimum: 1, maximum: 300, default: 30 })
    expect(f.verify_ssl).toMatchObject({ kind: 'boolean', default: true })
    expect(f.input_text).toMatchObject({ kind: 'string', required: true, hasDefault: false })
    expect(f.input_text.description).toBe('Text to generate hashes for')
    expect(f.hash_types).toMatchObject({ kind: 'array', items: { kind: 'string' } })
    expect(f.iterations).toMatchObject({ kind: 'integer', minimum: 1, maximum: 1000000 })
  })

  test('resolves $ref, unwraps Optional, and falls back to JSON for objects', () => {
    const f = byName(fieldsFromSchema(EVERYTHING))
    expect(f.level).toMatchObject({ kind: 'enum', enumValues: [1, 2, 3], required: true })
    expect(f.ratio).toMatchObject({ kind: 'number', exclusiveMinimum: 0, exclusiveMaximum: 1 })
    expect(f.mode).toMatchObject({ kind: 'enum', enumValues: ['fast', 'full'], label: 'Mode' })
    expect(f.opt_mode).toMatchObject({ kind: 'enum', required: false, label: 'Opt Mode' })
    // Optional[bool] = None cannot be a checkbox: "not set" is a third state.
    expect(f.flag).toMatchObject({ kind: 'enum', enumValues: [true, false] })
    expect(f.ports).toMatchObject({ kind: 'array', items: { kind: 'integer' }, maxItems: 3 })
    expect(f.kinds).toMatchObject({ kind: 'array', items: { kind: 'enum' } })
    expect(f.headers).toMatchObject({ kind: 'json', placeholder: '{"X-A":"1"}' })
    expect(f.code).toMatchObject({
      kind: 'string',
      minLength: 2,
      maxLength: 4,
      pattern: '^[A-Z]+$',
    })
    expect(f.nested).toMatchObject({ kind: 'json', required: false })
    expect(f.url).toMatchObject({ kind: 'string', placeholder: 'https://example.com' })
  })

  test('a tool without an input schema has no fields', () => {
    expect(fieldsFromSchema(null)).toEqual([])
    expect(buildRequestBody([], {})).toEqual({ ok: true, body: {} })
  })

  test('starts from the schema defaults, and empty where there is none', () => {
    const values = initialValues(fieldsFromSchema(HASH_GENERATOR))
    expect(values).toEqual({
      target: '',
      timeout: '30',
      verify_ssl: true,
      input_text: '',
      hash_types: 'md5\nsha1\nsha256\nsha512',
      include_salted: false,
      iterations: '1',
    })
    const everything = initialValues(fieldsFromSchema(EVERYTHING))
    expect(everything.mode).toBe(enumKey('fast'))
    expect(everything.opt_mode).toBe('')
    expect(everything.kinds).toEqual([enumKey('fast')])
    expect(everything.code).toBe('AB')
  })

  test('builds the typed body and leaves empty optional fields out', () => {
    const fields = fieldsFromSchema(HASH_GENERATOR)
    const result = buildRequestBody(
      fields,
      valuesWith(fields, { input_text: 'wildbox', hash_types: ' sha256 \n\n md5 ' })
    )
    expect(result).toEqual({
      ok: true,
      body: {
        timeout: 30,
        verify_ssl: true,
        input_text: 'wildbox',
        hash_types: ['sha256', 'md5'],
        include_salted: false,
        iterations: 1,
      },
    })
  })

  test('a missing required field blocks the body', () => {
    const fields = fieldsFromSchema(HASH_GENERATOR)
    expect(buildRequestBody(fields, initialValues(fields))).toEqual({
      ok: false,
      errors: { input_text: 'Required' },
    })
    expect(buildRequestBody(fields, valuesWith(fields, { input_text: '   ' }))).toMatchObject({
      ok: false,
      errors: { input_text: 'Required' },
    })
  })

  test('applies the numeric constraints', () => {
    const fields = fieldsFromSchema(HASH_GENERATOR)
    const errorsFor = (iterations: string) => {
      const result = buildRequestBody(fields, valuesWith(fields, { input_text: 'x', iterations }))
      return result.ok ? undefined : result.errors.iterations
    }
    expect(errorsFor('0')).toBe('Must be at least 1')
    expect(errorsFor('1000001')).toBe('Must be at most 1000000')
    expect(errorsFor('2.5')).toBe('Enter a whole number')
    expect(errorsFor('abc')).toBe('Enter a number')
    expect(errorsFor('1')).toBeUndefined()
    expect(errorsFor('1000000')).toBeUndefined()

    const everything = fieldsFromSchema(EVERYTHING)
    const ratio = (value: string) => {
      const result = buildRequestBody(
        everything,
        valuesWith(everything, { level: enumKey(1), url: 'u', ratio: value })
      )
      return result.ok ? result.body.ratio : result.errors.ratio
    }
    expect(ratio('0')).toBe('Must be greater than 0')
    expect(ratio('1')).toBe('Must be less than 1')
    expect(ratio('0.5')).toBe(0.5)
  })

  test('applies the string constraints', () => {
    const fields = fieldsFromSchema(EVERYTHING)
    const code = (value: string) => {
      const result = buildRequestBody(
        fields,
        valuesWith(fields, { level: enumKey(2), ratio: '0.1', url: 'u', code: value })
      )
      return result.ok ? result.body.code : result.errors.code
    }
    expect(code('A')).toBe('Must be at least 2 characters')
    expect(code('ABCDE')).toBe('Must be at most 4 characters')
    expect(code('ab')).toBe('Must match ^[A-Z]+$')
    expect(code('ABC')).toBe('ABC')
  })

  test('sends enum members, arrays and JSON as their own types', () => {
    const fields = fieldsFromSchema(EVERYTHING)
    const result = buildRequestBody(
      fields,
      valuesWith(fields, {
        level: enumKey(3),
        ratio: '0.25',
        url: 'https://example.com',
        opt_mode: enumKey('full'),
        flag: enumKey(false),
        ports: '22\n443',
        kinds: [enumKey('fast'), enumKey('full')],
        headers: '{"X-A": "1"}',
      })
    )
    expect(result).toEqual({
      ok: true,
      body: {
        level: 3,
        ratio: 0.25,
        mode: 'fast',
        opt_mode: 'full',
        flag: false,
        ports: [22, 443],
        kinds: ['fast', 'full'],
        headers: { 'X-A': '1' },
        code: 'AB',
        url: 'https://example.com',
      },
    })
  })

  test('checks array items and lengths, and JSON syntax', () => {
    const fields = fieldsFromSchema(EVERYTHING)
    const base = { level: enumKey(1), ratio: '0.5', url: 'u' }
    const errors = (changes: Record<string, string>) => {
      const result = buildRequestBody(fields, valuesWith(fields, { ...base, ...changes }))
      return result.ok ? {} : result.errors
    }
    expect(errors({ ports: '22\nhttp' }).ports).toBe('Item 2 (http): Enter a number')
    expect(errors({ ports: '1\n2\n3\n4' }).ports).toBe('At most 3 items')
    expect(errors({ headers: '{not json' }).headers).toBe('Enter valid JSON')
  })

  test('reads field errors from both validation error shapes', () => {
    const names = ['input_text', 'iterations']
    // The tool endpoint's input validation (open-security-tools router).
    const tool = {
      error: {
        code: 422,
        message: 'Input validation failed',
        details: {
          reason: 'Input validation failed',
          errors: [
            { loc: ['input_text'], msg: 'Field required', type: 'missing' },
            { loc: ['iterations'], msg: 'Input should be >= 1', type: 'greater_than_equal' },
            { loc: ['unknown_field', 0], msg: 'Extra', type: 'x' },
          ],
        },
      },
    }
    expect(serverFieldErrors(tool, names)).toEqual({
      fields: { input_text: 'Field required', iterations: 'Input should be >= 1' },
      other: ['unknown_field.0: Extra'],
    })
    // FastAPI's request validation: the location starts with "body".
    const request = {
      error: {
        message: 'Request validation failed',
        details: [{ loc: ['body', 'iterations'], msg: 'bad', type: 't' }],
      },
    }
    expect(serverFieldErrors(request, names)).toEqual({
      fields: { iterations: 'bad' },
      other: [],
    })
    expect(serverFieldErrors({ error: { message: 'x' } }, names)).toEqual({ fields: {}, other: [] })
    expect(serverFieldErrors(undefined, names)).toEqual({ fields: {}, other: [] })
  })
})
