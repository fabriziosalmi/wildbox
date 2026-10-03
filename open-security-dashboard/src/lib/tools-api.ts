/**
 * The tools service's API as the dashboard calls it, through the gateway
 * with the session's Bearer token (apiClient is mounted on /api/v1).
 *
 *   GET    /api/v1/tools/<name>/info    the tool and its input/output schema
 *   POST   /api/v1/tools/<name>         run it and wait for the result
 *   POST   /api/v1/tools/<name>/async   queue it; answers with a task id
 *   GET    /api/v1/tasks/<id>           the task's status and result (#580)
 *   DELETE /api/v1/tasks/<id>           cancel a task that has not finished
 *
 * Tasks are the caller's own: another user's task id answers 404.
 */
import { apiClient } from '@/lib/api-client'
import type { JsonSchema } from '@/lib/tool-schema'

export interface ToolInfo {
  name: string
  display_name?: string
  description?: string
  version?: string
  author?: string
  category?: string
  input_schema: JsonSchema | null
  output_schema: JsonSchema | null
}

export interface TaskSubmission {
  task_id: string
  status: string
  tool_name?: string
  status_url?: string
}

/** GET /api/v1/tasks/<id>; which fields are present depends on the status. */
export interface TaskStatus {
  task_id: string
  state?: string
  status: string
  message?: string
  tool_name?: string
  submitted_at?: string | null
  completed_at?: string | null
  duration?: number | null
  error?: string | null
  result?: unknown
}

/**
 * How long a synchronous run is waited for. The gateway gives an upstream 60 s
 * to answer (proxy_read_timeout in open-security-gateway/nginx/includes/
 * proxy_params.conf) and then answers 504 itself; waiting a little longer
 * lets that answer, not a client-side timeout, be what the page shows.
 */
export const SYNC_WAIT_MS = 75_000

/** The gateway's own limit on a synchronous run, in seconds, for the form's hint. */
export const GATEWAY_SYNC_LIMIT_S = 60

/** Statuses after which a task changes no more. */
const UNFINISHED_STATUSES = new Set(['pending', 'running', 'retrying'])
export const isTaskFinished = (status: string | undefined) =>
  status !== undefined && !UNFINISHED_STATUSES.has(status)

const toolPath = (name: string) => `/tools/${encodeURIComponent(name)}`
const taskPath = (id: string) => `/tasks/${encodeURIComponent(id)}`

export const getToolInfo = (name: string) => apiClient.get<ToolInfo>(`${toolPath(name)}/info`)

export const runToolSync = (name: string, body: Record<string, unknown>) =>
  apiClient.post<unknown>(toolPath(name), body, { timeout: SYNC_WAIT_MS })

export const submitToolAsync = (name: string, body: Record<string, unknown>) =>
  apiClient.post<TaskSubmission>(`${toolPath(name)}/async`, body)

export const getTask = (id: string) => apiClient.get<TaskStatus>(taskPath(id))

export const cancelTask = (id: string) =>
  apiClient.delete<{ task_id: string; status: string; message?: string }>(taskPath(id))

/** The public route a run goes to, for the page and for "copy as cURL". */
export const toolRoute = (name: string, async: boolean) =>
  `/api/v1${toolPath(name)}${async ? '/async' : ''}`

/** Single-quotes a value for a POSIX shell. */
const shellQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`

/**
 * The run as a curl command, with the body the form would send. The session
 * token is not copied: the command reads it from $WILDBOX_TOKEN.
 */
export function curlCommand(origin: string, name: string, async: boolean, body: unknown): string {
  return [
    `curl -X POST ${shellQuote(origin + toolRoute(name, async))}`,
    `  -H 'Content-Type: application/json'`,
    `  -H "Authorization: Bearer $WILDBOX_TOKEN"`,
    `  --data ${shellQuote(JSON.stringify(body))}`,
  ].join(' \\\n')
}
