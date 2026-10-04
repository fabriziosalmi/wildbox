'use client'

import { AlertCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { CopyButton, DownloadJsonButton, RawJson, ValueView } from '@/components/json-view'
import type { ApiError } from '@/lib/api-client'

const STATUS_STYLE: Record<string, string> = {
  completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
  pending: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
  running: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
  retrying: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100',
  cancelled: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
}
const FAILED_STYLE = 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100'

export function StatusBadge({ status }: { status: string }) {
  return (
    <Badge data-testid="result-status" className={STATUS_STYLE[status] ?? FAILED_STYLE}>
      {status}
    </Badge>
  )
}

export const seconds = (value: number) => `${value.toFixed(value < 10 ? 3 : 1)} s`

/** A finished run's output: tables and lists, the raw JSON, copy and download. */
export function RunOutput({
  value,
  toolName,
  facts,
}: {
  value: unknown
  toolName: string
  /** Label/value lines about the run, each from the API or measured here. */
  facts: [string, string][]
}) {
  const reportedFailure =
    value !== null &&
    typeof value === 'object' &&
    (value as Record<string, unknown>).success === false
  return (
    <div className="space-y-4" data-testid="run-output">
      {facts.length > 0 && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          {facts.map(([label, text]) => (
            <div key={label} className="contents">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="font-mono">{text}</dd>
            </div>
          ))}
        </dl>
      )}
      {reportedFailure && (
        <p className="text-sm text-red-700" data-testid="tool-reported-failure">
          The tool answered with <code>success: false</code>; its own fields below say why.
        </p>
      )}
      <div className="overflow-x-auto rounded border border-border p-3">
        <ValueView value={value} />
      </div>
      <div className="flex flex-wrap gap-2">
        <CopyButton text={JSON.stringify(value, null, 2)} label="Copy JSON" />
        <DownloadJsonButton value={value} filename={`${toolName}-result.json`} />
      </div>
      <RawJson value={value} />
    </div>
  )
}

function errorTitle(error: ApiError): string {
  if (error.code === 'timeout') return 'No answer in time'
  switch (error.status) {
    case 0:
      return 'The request did not reach the server'
    case 400:
      return 'Refused by the tools service'
    case 401:
      return 'Not signed in'
    case 403:
      return 'Not authorized'
    case 404:
      return 'Not found'
    case 408:
      return 'The tool timed out'
    case 422:
      return 'Input rejected'
    case 429:
      return 'Rate limited'
    case 503:
      return 'Service unavailable'
    case 504:
      return 'The gateway stopped waiting'
    default:
      return 'The run failed'
  }
}

/** An error answer, as the server gave it. */
export function RunError({
  error,
  other = [],
  hint,
}: {
  error: ApiError
  /** Field errors the form has no field for. */
  other?: string[]
  hint?: string
}) {
  return (
    <Card role="alert" data-testid="run-error" className="border-red-300">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base text-red-700">
          <AlertCircle className="h-4 w-4" />
          {errorTitle(error)}
          {error.status > 0 && (
            <span className="font-mono text-xs font-normal">HTTP {error.status}</span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p data-testid="run-error-message" className="wrap-break-word whitespace-pre-wrap">
          {error.message}
        </p>
        {other.length > 0 && (
          <ul className="list-inside list-disc">
            {other.map(message => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        )}
        {hint && <p className="text-muted-foreground">{hint}</p>}
        {error.requestId && (
          <p className="text-xs text-muted-foreground">
            Request id: <code>{error.requestId}</code>
          </p>
        )}
      </CardContent>
    </Card>
  )
}
