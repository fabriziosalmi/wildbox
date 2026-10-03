'use client'

import { useMemo, useRef, useState, type FormEvent } from 'react'
import { Loader2, Play, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { CopyButton } from '@/components/json-view'
import { RunError, RunOutput, StatusBadge, seconds } from '@/components/toolbox/run-result'
import { TaskPanel } from '@/components/toolbox/task-panel'
import { ToolFormField } from '@/components/toolbox/tool-form-field'
import type { ApiError } from '@/lib/api-client'
import {
  buildRequestBody,
  fieldsFromSchema,
  initialValues,
  serverFieldErrors,
  type FormValue,
  type FormValues,
} from '@/lib/tool-schema'
import {
  GATEWAY_SYNC_LIMIT_S,
  curlCommand,
  runToolSync,
  submitToolAsync,
  toolRoute,
  type ToolInfo,
} from '@/lib/tools-api'

type Mode = 'sync' | 'async'

type Run =
  | { kind: 'idle' }
  | { kind: 'running'; mode: Mode }
  | { kind: 'done'; result: unknown; roundTripMs: number }
  | { kind: 'task'; taskId: string }
  | { kind: 'error'; error: ApiError; other: string[] }

const asApiError = (err: unknown): ApiError =>
  err && typeof err === 'object' && 'status' in err && 'message' in err
    ? (err as ApiError)
    : { status: 0, message: err instanceof Error ? err.message : String(err) }

/** The form built from the tool's input schema, the run, and its result. */
export function ToolRunner({ tool }: { tool: ToolInfo }) {
  const fields = useMemo(() => fieldsFromSchema(tool.input_schema), [tool.input_schema])
  const [values, setValues] = useState<FormValues>(() => initialValues(fields))
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [mode, setMode] = useState<Mode>('sync')
  const [run, setRun] = useState<Run>({ kind: 'idle' })
  // Only the latest run may write its outcome: an earlier one that answers
  // late must not replace it.
  const runId = useRef(0)
  const formRef = useRef<HTMLFormElement>(null)

  const preview = buildRequestBody(fields, values)
  const timeoutValue = Number(values.timeout)
  const longerThanGateway =
    mode === 'sync' &&
    fields.some(f => f.name === 'timeout') &&
    Number.isFinite(timeoutValue) &&
    timeoutValue > GATEWAY_SYNC_LIMIT_S

  const setValue = (name: string, value: FormValue) => {
    setValues(current => ({ ...current, [name]: value }))
    setErrors(current => {
      if (!(name in current)) return current
      const next = { ...current }
      delete next[name]
      return next
    })
  }

  const focusFirstError = (names: string[]) => {
    const first = fields.find(f => names.includes(f.name))
    if (first) formRef.current?.querySelector<HTMLElement>(`#tool-field-${first.name}`)?.focus()
  }

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault()
    const built = buildRequestBody(fields, values)
    if (!built.ok) {
      setErrors(built.errors)
      focusFirstError(Object.keys(built.errors))
      return
    }
    setErrors({})
    const id = ++runId.current
    const runMode = mode
    setRun({ kind: 'running', mode: runMode })
    const started = performance.now()
    try {
      if (runMode === 'sync') {
        const result = await runToolSync(tool.name, built.body)
        if (id === runId.current)
          setRun({ kind: 'done', result, roundTripMs: performance.now() - started })
      } else {
        const submitted = await submitToolAsync(tool.name, built.body)
        if (id === runId.current) setRun({ kind: 'task', taskId: submitted.task_id })
      }
    } catch (err) {
      if (id !== runId.current) return
      const error = asApiError(err)
      const found = serverFieldErrors(
        error.details,
        fields.map(f => f.name)
      )
      setErrors(found.fields)
      setRun({ kind: 'error', error, other: found.other })
    }
  }

  const reset = () => {
    setValues(initialValues(fields))
    setErrors({})
  }

  const running = run.kind === 'running'
  const origin = typeof window === 'undefined' ? '' : window.location.origin

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Input</CardTitle>
          <CardDescription>
            Generated from the tool&apos;s input schema. Fields marked * are required; an empty
            optional field is not sent, so the service applies its own default.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!tool.input_schema && (
            <p className="mb-4 text-sm text-muted-foreground" data-testid="no-input-schema">
              The tools service publishes no input schema for this tool; it is run with an empty
              body.
            </p>
          )}
          <form
            ref={formRef}
            noValidate
            onSubmit={onSubmit}
            className="space-y-5"
            data-testid="tool-form"
          >
            {fields.map(field => (
              <ToolFormField
                key={field.name}
                field={field}
                value={values[field.name]}
                error={errors[field.name]}
                onChange={value => setValue(field.name, value)}
              />
            ))}

            <fieldset className="space-y-2 rounded border border-border p-3">
              <legend className="px-1 text-sm font-medium">Run mode</legend>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="run-mode"
                  value="sync"
                  checked={mode === 'sync'}
                  onChange={() => setMode('sync')}
                  data-testid="mode-sync"
                />
                Wait for the result (<code>POST {toolRoute(tool.name, false)}</code>)
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="run-mode"
                  value="async"
                  checked={mode === 'async'}
                  onChange={() => setMode('async')}
                  data-testid="mode-async"
                />
                Run as a background task (<code>POST {toolRoute(tool.name, true)}</code>), then
                follow it
              </label>
              <p className="text-xs text-muted-foreground">
                The gateway waits up to {GATEWAY_SYNC_LIMIT_S} s for a synchronous run. A run that
                may take longer belongs in a background task, which can also be cancelled.
              </p>
              {longerThanGateway && (
                <p className="text-xs text-amber-700" data-testid="sync-timeout-hint">
                  The timeout asked for ({timeoutValue} s) is longer than the gateway waits for a
                  synchronous run.
                </p>
              )}
            </fieldset>

            {Object.keys(errors).length > 0 && (
              <p className="text-sm text-red-600" role="alert" data-testid="form-errors">
                Correct the highlighted fields to run the tool.
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={running} data-testid="run-tool">
                {running ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Play className="mr-2 h-4 w-4" />
                )}
                {running ? 'Running...' : 'Run'}
              </Button>
              <Button type="button" variant="outline" onClick={reset} disabled={running}>
                <RotateCcw className="mr-2 h-4 w-4" />
                Reset to defaults
              </Button>
              {preview.ok && (
                <CopyButton
                  text={curlCommand(origin, tool.name, mode === 'async', preview.body)}
                  label="Copy as cURL"
                />
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      {run.kind === 'running' && (
        <p className="text-sm text-muted-foreground" data-testid="run-pending">
          {run.mode === 'sync' ? 'Waiting for the tool...' : 'Submitting the task...'}
        </p>
      )}

      {run.kind === 'error' && <RunError error={run.error} other={run.other} />}

      {run.kind === 'task' && (
        <TaskPanel key={run.taskId} taskId={run.taskId} toolName={tool.name} />
      )}

      {run.kind === 'done' && (
        <Card data-testid="run-result">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              Result <StatusBadge status="completed" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <RunOutput
              value={run.result}
              toolName={tool.name}
              facts={syncFacts(run.result, run.roundTripMs)}
            />
          </CardContent>
        </Card>
      )}
    </div>
  )
}

/** What is known about a synchronous run: the service's own timing, if it sent one. */
function syncFacts(result: unknown, roundTripMs: number): [string, string][] {
  const facts: [string, string][] = []
  const reported =
    result && typeof result === 'object'
      ? (result as Record<string, unknown>).execution_time
      : undefined
  if (typeof reported === 'number') facts.push(['Execution time', seconds(reported)])
  facts.push(['Round trip', seconds(roundTripMs / 1000)])
  return facts
}
