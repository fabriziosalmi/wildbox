'use client'

import { useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, Bot, Info, Loader2, Send, X } from 'lucide-react'
import { useAuth } from '@/components/auth-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useSubmittedAnalyses, type SubmittedAnalysis } from '@/hooks/use-submitted-analyses'
import {
  IOC_TYPES,
  getAgentsStats,
  getAnalysis,
  isAnalysisFinished,
  isReport,
  submitAnalysis,
  type AgentsStats,
  type AnalysisAnswer,
  type AnalysisReport,
  type AnalysisTask,
  type Ioc,
  type IocType,
} from '@/lib/agents-api'
import type { ApiError } from '@/lib/api-client'
import { serverFieldErrors } from '@/lib/tool-schema'

/*
 * AI analysis of an indicator, by the agents service (#727).
 *
 * The service runs an analysis as a task: POST answers with a task id, GET
 * answers the task's status and, once it has completed, its report. It lists
 * no tasks and keeps each for a limited time, so this page shows the
 * analyses submitted from this browser by this account, each with what the
 * service answers for it. Nothing here is computed in the browser: a status,
 * a reason for a failure, a verdict are the service's, or they are not shown.
 */

/** How often an unfinished analysis is read again. */
const POLL_MS = 2000

/* What the service accepts for each type (IOC_REGEX_PATTERNS in its
   schemas). A hint for the field; the service is what validates. */
const IOC_HINT: Record<IocType, string> = {
  ipv4: 'An IPv4 address, for example 203.0.113.10',
  ipv6: 'An IPv6 address, for example 2001:db8::1',
  domain: 'A domain name, for example example.com',
  url: 'An http, https or ftp URL',
  md5: '32 hexadecimal digits, in lowercase',
  sha1: '40 hexadecimal digits, in lowercase',
  sha256: '64 hexadecimal digits, in lowercase',
  email: 'An email address',
}

const selectClass =
  'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-ring'

const STATUS_STYLE: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
  running: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
  completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
  failed: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
  revoked: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
}

const VERDICT_STYLE: Record<AnalysisReport['verdict'], string> = {
  Malicious: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
  Suspicious: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100',
  Benign: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
  Informational: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
}

const noticeClass = 'flex items-start gap-3 p-4 text-sm'
const errorBoxClass =
  'rounded-md border border-red-300 bg-red-50 p-3 text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200'

const when = (iso: string) => new Date(iso).toLocaleString()

/** The service's own message for a refused indicator, if the answer has one. */
function refusedValue(error: ApiError): string | undefined {
  const message = serverFieldErrors(error.details, ['ioc']).fields.ioc
  return message?.replace(/^value: (Value error, )?/, '')
}

function SubmitForm({ onSubmitted }: { onSubmitted: (item: SubmittedAnalysis) => void }) {
  const [type, setType] = useState<IocType>('ipv4')
  const [value, setValue] = useState('')
  const [fieldError, setFieldError] = useState<string | null>(null)
  const [submitted, setSubmitted] = useState<string | null>(null)
  const valueRef = useRef<HTMLInputElement>(null)

  const submit = useMutation<AnalysisTask, ApiError, Ioc>({
    mutationFn: submitAnalysis,
    onSuccess: (task, ioc) => {
      onSubmitted({ task_id: task.task_id, ioc, submitted_at: task.created_at })
      setSubmitted(ioc.value)
      setValue('')
    },
    onError: error => {
      const refused = error.status === 422 ? refusedValue(error) : undefined
      if (refused) {
        setFieldError(refused)
        valueRef.current?.focus()
      }
    },
  })

  // An answer to what was submitted says nothing about what is typed next.
  const clearErrors = () => {
    setFieldError(null)
    if (submit.isError) submit.reset()
  }

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (submit.isPending) return
    setSubmitted(null)
    const trimmed = value.trim()
    if (!trimmed) {
      submit.reset()
      setFieldError('Enter the indicator to analyze.')
      valueRef.current?.focus()
      return
    }
    setFieldError(null)
    submit.mutate({ type, value: trimmed })
  }

  // A refused value is shown at the field; any other error, below the form.
  const requestError = submit.isError && !fieldError ? submit.error : null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Analyze an indicator</CardTitle>
        <CardDescription>
          The agent looks the indicator up with the security tools and writes a report with a
          verdict. An analysis can take several minutes.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form noValidate onSubmit={onSubmit} className="space-y-4" data-testid="analysis-form">
          <div className="grid gap-4 md:grid-cols-[12rem_1fr]">
            <div className="space-y-2">
              <Label htmlFor="ioc-type">Indicator type</Label>
              <select
                id="ioc-type"
                name="type"
                className={selectClass}
                value={type}
                onChange={event => {
                  setType(event.target.value as IocType)
                  clearErrors()
                }}
              >
                {IOC_TYPES.map(option => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="ioc-value">Indicator</Label>
              <Input
                ref={valueRef}
                id="ioc-value"
                name="value"
                autoComplete="off"
                spellCheck={false}
                value={value}
                onChange={event => {
                  setValue(event.target.value)
                  clearErrors()
                }}
                aria-required="true"
                aria-invalid={fieldError ? true : undefined}
                aria-describedby={fieldError ? 'ioc-value-help ioc-value-error' : 'ioc-value-help'}
              />
              <p id="ioc-value-help" className="text-xs text-muted-foreground">
                {IOC_HINT[type]}
              </p>
              {fieldError && (
                <p
                  id="ioc-value-error"
                  role="alert"
                  className="text-sm text-red-700 dark:text-red-300"
                  data-testid="ioc-value-error"
                >
                  {fieldError}
                </p>
              )}
            </div>
          </div>

          {/* aria-disabled, not disabled: a disabled button drops the focus it
              holds, and whoever submitted with the keyboard is left on the
              page's body. A second submission is refused in onSubmit. */}
          <Button
            type="submit"
            aria-disabled={submit.isPending}
            className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
            data-testid="submit-analysis"
          >
            {submit.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Send className="mr-2 h-4 w-4" aria-hidden="true" />
            )}
            {submit.isPending ? 'Submitting...' : 'Analyze'}
          </Button>
        </form>

        {requestError && (
          <div role="alert" className={`mt-4 text-sm ${errorBoxClass}`} data-testid="submit-error">
            <p className="font-medium">
              The analysis was not submitted
              {requestError.status > 0 && (
                <span className="ml-2 font-mono text-xs font-normal">
                  HTTP {requestError.status}
                </span>
              )}
            </p>
            <p className="wrap-break-word whitespace-pre-wrap">{requestError.message}</p>
            {requestError.requestId && (
              <p className="text-xs">
                Request id: <code>{requestError.requestId}</code>
              </p>
            )}
          </div>
        )}
        <p
          role="status"
          className={`text-sm text-muted-foreground ${submitted ? 'mt-4' : ''}`}
          data-testid="submit-status"
        >
          {submitted && `Submitted ${submitted}. Its status is first in the list below.`}
        </p>
      </CardContent>
    </Card>
  )
}

function Report({ report }: { report: AnalysisReport }) {
  return (
    <div className="space-y-4" data-testid="analysis-report">
      <dl className="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-1">
        <dt className="text-muted-foreground">Verdict</dt>
        <dd>
          <Badge className={VERDICT_STYLE[report.verdict]} data-testid="analysis-verdict">
            {report.verdict}
          </Badge>
        </dd>
        <dt className="text-muted-foreground">Confidence</dt>
        <dd data-testid="analysis-confidence">{Math.round(report.confidence * 100)}%</dd>
        {typeof report.analysis_duration === 'number' && (
          <>
            <dt className="text-muted-foreground">Duration</dt>
            <dd>{report.analysis_duration.toFixed(1)} s</dd>
          </>
        )}
        <dt className="text-muted-foreground">Tools used</dt>
        <dd className="font-mono text-xs">
          {report.tools_used.length > 0 ? report.tools_used.join(', ') : 'none'}
        </dd>
      </dl>

      <p>{report.executive_summary}</p>

      <div>
        <h4 className="mb-1 font-medium">Evidence</h4>
        {report.evidence.length > 0 ? (
          <ul className="space-y-2">
            {report.evidence.map((item, index) => (
              <li key={index} className="rounded border border-border p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs">{item.source}</span>
                  <Badge variant="outline">{item.severity}</Badge>
                </div>
                <p className="mt-1">{item.finding}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-muted-foreground">The report lists no evidence.</p>
        )}
      </div>

      {report.recommended_actions.length > 0 && (
        <div>
          <h4 className="mb-1 font-medium">Recommended actions</h4>
          <ul className="list-inside list-disc space-y-1">
            {report.recommended_actions.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ul>
        </div>
      )}

      <details>
        <summary className="cursor-pointer font-medium">Full report</summary>
        <pre
          className="mt-2 overflow-x-auto rounded border border-border p-3 text-xs whitespace-pre-wrap"
          data-testid="analysis-full-report"
        >
          {report.full_report}
        </pre>
      </details>
    </div>
  )
}

function AnalysisCard({ item, onRemove }: { item: SubmittedAnalysis; onRemove: () => void }) {
  const analysis = useQuery<AnalysisAnswer, ApiError>({
    queryKey: ['ai-analysis', item.task_id],
    queryFn: () => getAnalysis(item.task_id),
    refetchInterval: query =>
      query.state.status === 'error' || isAnalysisFinished(query.state.data) ? false : POLL_MS,
    // A 404 is an answer: the task has expired. Anything else is tried once more.
    retry: (failures, error) => error.status !== 404 && failures < 1,
    refetchOnWindowFocus: false,
  })
  const answer = analysis.data
  const status = answer ? (isReport(answer) ? 'completed' : answer.status) : undefined
  const task = answer && !isReport(answer) ? answer : undefined

  return (
    <li>
      <Card data-testid="analysis-card" data-task-id={item.task_id}>
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0 space-y-1">
              <CardTitle className="text-base font-semibold break-all">{item.ioc.value}</CardTitle>
              <CardDescription>
                {item.ioc.type}, submitted {when(item.submitted_at)}
              </CardDescription>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {status && (
                <Badge className={STATUS_STYLE[status]} data-testid="analysis-status">
                  {status}
                </Badge>
              )}
              {analysis.isSuccess && !isAnalysisFinished(answer) && (
                <Loader2
                  className="h-4 w-4 animate-spin text-muted-foreground"
                  aria-hidden="true"
                />
              )}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={onRemove}
                aria-label={`Remove ${item.ioc.value} from this list`}
                data-testid="remove-analysis"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 pt-0 text-sm" aria-live="polite">
          {analysis.isLoading && <p className="text-muted-foreground">Reading the status...</p>}

          {analysis.isError &&
            (analysis.error.status === 404 ? (
              <p className="text-muted-foreground" data-testid="analysis-gone">
                The service no longer has this analysis. It keeps an analysis for a limited time,
                one hour by default.
              </p>
            ) : (
              <div className={errorBoxClass} data-testid="analysis-read-error">
                <p>The agents service did not return this analysis: {analysis.error.message}</p>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={() => analysis.refetch()}
                >
                  Read it again
                </Button>
              </div>
            ))}

          {task?.status === 'pending' && (
            <p className="text-muted-foreground">Queued: no worker has started it yet.</p>
          )}
          {task?.status === 'running' && (
            <p className="text-muted-foreground" data-testid="analysis-progress">
              {task.progress ?? 'Running.'}
              {task.started_at && ` Started ${when(task.started_at)}.`}
            </p>
          )}
          {task?.status === 'failed' && (
            <div className={errorBoxClass} data-testid="analysis-error">
              <p className="font-medium">The analysis failed. There is no report.</p>
              <p>{task.error ?? 'The service gave no reason.'}</p>
            </div>
          )}
          {task?.status === 'revoked' && (
            <p className="text-muted-foreground">The analysis was canceled. There is no report.</p>
          )}

          {answer && isReport(answer) && <Report report={answer} />}
        </CardContent>
      </Card>
    </li>
  )
}

export default function AiAnalysisPage() {
  const { user } = useAuth()
  const { items, add, remove } = useSubmittedAnalyses(user?.id)
  const listHeading = useRef<HTMLHeadingElement>(null)
  // The button that removes a card goes with the card. Without somewhere to
  // go, the focus it held falls to the page's body, and a keyboard user
  // starts again from the top of the page.
  const removeFromList = (taskId: string) => {
    remove(taskId)
    listHeading.current?.focus()
  }
  // Asked once: whether analyses can run at all on this server. When the
  // question itself fails the page says nothing about it either way.
  const stats = useQuery<AgentsStats, ApiError>({
    queryKey: ['agents-stats'],
    queryFn: getAgentsStats,
    retry: 1,
    refetchOnWindowFocus: false,
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">AI Analysis</h1>
        <p className="text-muted-foreground">
          Have an indicator of compromise investigated by the AI agent
        </p>
      </div>

      {stats.data?.model_configured === false && (
        <Card
          role="alert"
          className="border-amber-300 dark:border-amber-700"
          data-testid="model-not-configured"
        >
          <CardContent className={noticeClass}>
            <AlertTriangle
              className="mt-0.5 h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400"
              aria-hidden="true"
            />
            <p>
              AI analysis is not configured on this server: no model API key is set. An analysis
              submitted now fails. An administrator sets <code>ANTHROPIC_API_KEY</code> for the
              agents service to enable it.
            </p>
          </CardContent>
        </Card>
      )}

      <SubmitForm onSubmitted={add} />

      <section aria-labelledby="analyses-heading" className="space-y-4">
        <h2 id="analyses-heading" ref={listHeading} tabIndex={-1} className="text-xl font-semibold">
          Submitted analyses
        </h2>
        <Card data-testid="analysis-list-scope">
          <CardContent className={noticeClass}>
            <Info className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" aria-hidden="true" />
            <p>
              The agents service does not list analyses, and keeps each one for a limited time. This
              page shows the analyses submitted from this browser by this account, with the status
              the service reports for each.
            </p>
          </CardContent>
        </Card>

        {items.length > 0 ? (
          <ul className="space-y-4" data-testid="analysis-list">
            {items.map(item => (
              <AnalysisCard
                key={item.task_id}
                item={item}
                onRemove={() => removeFromList(item.task_id)}
              />
            ))}
          </ul>
        ) : (
          <div
            className="flex min-h-[160px] flex-col items-center justify-center text-center"
            data-testid="no-analyses"
          >
            <Bot className="mb-4 h-12 w-12 text-muted-foreground" aria-hidden="true" />
            <h3 className="mb-2 text-lg font-semibold">No analysis submitted from this browser</h3>
            <p className="text-muted-foreground">
              Submit an indicator above and its analysis will appear here.
            </p>
          </div>
        )}
      </section>
    </div>
  )
}
