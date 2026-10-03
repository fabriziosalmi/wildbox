'use client'

import { Suspense, useMemo, useSyncExternalStore } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  Ban,
  CheckCircle,
  Clock,
  Info,
  Loader2,
  PlayCircle,
  RefreshCw,
  XCircle,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  EXECUTION_HISTORY_KEY,
  formatDuration,
  getStatusColor,
  useExecutionStatus,
  type ExecutionHistoryItem,
  type ExecutionStatus,
} from '@/hooks/use-execution-status'

/*
 * The responder has no endpoint that lists runs: it answers GET /v1/runs/{id}
 * for a run the caller's team owns, and nothing else. This page used to call
 * GET /v1/runs (through a path that resolved to /v1/v1/runs), so it could only
 * ever fail -- and its error state then claimed to be "showing demo data".
 *
 * What it can show truthfully: the runs started from this browser (the
 * playbooks page records each run ID it gets back) and a run named in the
 * URL, each with the status the responder reports for it.
 */

function subscribeToStorage(onChange: () => void) {
  window.addEventListener('storage', onChange)
  return () => window.removeEventListener('storage', onChange)
}

function readStoredHistory(): string | null {
  try {
    return localStorage.getItem(EXECUTION_HISTORY_KEY)
  } catch {
    return null
  }
}

function parseHistory(raw: string | null): ExecutionHistoryItem[] {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? (parsed as ExecutionHistoryItem[]) : []
  } catch {
    return []
  }
}

function StatusIcon({ status }: { status: ExecutionStatus }) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="h-5 w-5 text-green-500" />
    case 'running':
      return <Loader2 className="h-5 w-5 animate-spin text-blue-500" />
    case 'failed':
      return <XCircle className="h-5 w-5 text-red-500" />
    case 'cancelled':
      return <Ban className="h-5 w-5 text-orange-500" />
    default:
      return <Clock className="h-5 w-5 text-gray-500" />
  }
}

function RunCard({ runId, label }: { runId: string; label?: string }) {
  const { data, isLoading, error, refetch } = useExecutionStatus(runId)

  return (
    <Card data-testid="run-card" data-run-id={runId}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 space-y-1">
            <CardTitle className="truncate text-lg font-semibold">
              {data?.playbook_name ?? label ?? 'Playbook run'}
            </CardTitle>
            <CardDescription className="break-all text-sm">Run ID: {runId}</CardDescription>
          </div>
          {data && (
            <div className="flex shrink-0 items-center gap-2">
              <StatusIcon status={data.status} />
              <Badge className={getStatusColor(data.status)} data-testid="run-status">
                {data.status}
              </Badge>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3 pt-0 text-sm">
        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading status...
          </div>
        ) : error ? (
          <div className="flex items-center justify-between gap-2 text-red-700">
            <span>The responder did not return this run: {error.message}</span>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              Retry
            </Button>
          </div>
        ) : data ? (
          <>
            <div className="grid grid-cols-2 gap-2 text-muted-foreground">
              <span>Started: {new Date(data.start_time).toLocaleString()}</span>
              <span>Duration: {formatDuration(data.duration_seconds)}</span>
            </div>
            {data.error && (
              <div className="rounded-md border border-red-200 bg-red-50 p-3 text-red-800">
                {data.error}
              </div>
            )}
            {data.step_results.length > 0 && (
              <ul className="space-y-1">
                {data.step_results.map(step => (
                  <li key={step.step_name} className="flex items-center justify-between gap-2">
                    <span className="truncate">{step.step_name}</span>
                    <Badge className={getStatusColor(step.status)}>{step.status}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}

function RunsContent() {
  const searchParams = useSearchParams()
  const requestedRun = searchParams.get('run_id')
  const raw = useSyncExternalStore(subscribeToStorage, readStoredHistory, () => null)
  const history = useMemo(() => parseHistory(raw), [raw])

  const runs = useMemo(() => {
    const items: { runId: string; label?: string }[] = []
    if (requestedRun) {
      const known = history.find(item => item.run_id === requestedRun)
      items.push({ runId: requestedRun, label: known?.playbook_name })
    }
    for (const item of history) {
      if (item.run_id !== requestedRun) {
        items.push({ runId: item.run_id, label: item.playbook_name })
      }
    }
    return items
  }, [history, requestedRun])

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Playbook Runs</h1>
          <p className="text-muted-foreground">Status of the playbook runs started here</p>
        </div>
        <Button onClick={() => window.location.reload()} variant="outline" size="sm">
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      <Card data-testid="run-history-unavailable">
        <CardContent className="flex items-start gap-3 p-4 text-sm">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
          <p>
            Run history is not available: the responder does not list runs. This page shows the runs
            started from this browser, with the status the responder reports for each.
          </p>
        </CardContent>
      </Card>

      {runs.length > 0 ? (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {runs.map(run => (
            <RunCard key={run.runId} runId={run.runId} label={run.label} />
          ))}
        </div>
      ) : (
        <div className="flex min-h-[240px] flex-col items-center justify-center text-center">
          <PlayCircle className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-semibold">No runs started from this browser</h3>
          <p className="mb-4 text-muted-foreground">
            Run a playbook and its status will appear here.
          </p>
          <Link href="/response/playbooks">
            <Button>Open playbooks</Button>
          </Link>
        </div>
      )}
    </div>
  )
}

export default function RunsPage() {
  // useSearchParams needs a Suspense boundary for the static render.
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[300px] items-center justify-center gap-2">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span>Loading runs...</span>
        </div>
      }
    >
      <RunsContent />
    </Suspense>
  )
}
