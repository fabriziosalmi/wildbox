'use client'

import { useMutation, useQuery } from '@tanstack/react-query'
import { Loader2, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { RunError, RunOutput, StatusBadge, seconds } from '@/components/toolbox/run-result'
import type { ApiError } from '@/lib/api-client'
import { cancelTask, getTask, isTaskFinished, type TaskStatus } from '@/lib/tools-api'

/** How often an unfinished task is read again. */
const POLL_MS = 1000

/** An asynchronous run: its task, read until it finishes, and a way to cancel it. */
export function TaskPanel({ taskId, toolName }: { taskId: string; toolName: string }) {
  const task = useQuery<TaskStatus, ApiError>({
    queryKey: ['tool-task', taskId],
    queryFn: () => getTask(taskId),
    refetchInterval: query =>
      query.state.status === 'error' || isTaskFinished(query.state.data?.status) ? false : POLL_MS,
    retry: 1,
    refetchOnWindowFocus: false,
  })
  const cancel = useMutation<unknown, ApiError>({
    mutationFn: () => cancelTask(taskId),
    onSettled: () => task.refetch(),
  })

  const status = task.data?.status
  const finished = isTaskFinished(status)
  const facts: [string, string][] = [['Task', taskId]]
  if (task.data?.submitted_at) facts.push(['Submitted', task.data.submitted_at])
  if (task.data?.completed_at) facts.push(['Completed', task.data.completed_at])
  if (typeof task.data?.duration === 'number')
    facts.push(['Execution time', seconds(task.data.duration)])

  return (
    <Card data-testid="task-panel">
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          Background task
          {status && <StatusBadge status={status} />}
          {!finished && !task.isError && (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-hidden="true" />
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!finished && (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="text-muted-foreground" data-testid="task-message">
              {task.data?.message ?? 'Reading the task status...'}
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => cancel.mutate()}
              disabled={cancel.isPending || !task.data}
              data-testid="cancel-task"
            >
              <XCircle className="mr-1 h-3 w-3" />
              {cancel.isPending ? 'Cancelling...' : 'Cancel task'}
            </Button>
          </div>
        )}
        {cancel.isError && <RunError error={cancel.error} />}
        {task.isError && (
          <div className="space-y-2">
            <RunError error={task.error} />
            <Button type="button" variant="outline" size="sm" onClick={() => task.refetch()}>
              Read the task again
            </Button>
          </div>
        )}
        {finished && status === 'completed' && (
          <RunOutput value={task.data?.result} toolName={toolName} facts={facts} />
        )}
        {finished && status !== 'completed' && (
          <div className="space-y-2 text-sm" data-testid="task-outcome">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
              {facts.map(([label, text]) => (
                <div key={label} className="contents">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="font-mono">{text}</dd>
                </div>
              ))}
            </dl>
            {task.data?.error && (
              <p className="whitespace-pre-wrap break-words text-red-700" data-testid="task-error">
                {task.data.error}
              </p>
            )}
            {task.data?.message && <p className="text-muted-foreground">{task.data.message}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
