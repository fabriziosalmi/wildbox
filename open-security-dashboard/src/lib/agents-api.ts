/**
 * The agents service's API as the dashboard calls it, through the gateway
 * with the session's Bearer token (agentsClient is mounted on
 * /api/v1/agents).
 *
 *   POST /api/v1/agents/analyze        submit an indicator; answers with a task
 *   GET  /api/v1/agents/analyze/<id>   the task's status, or its report
 *   GET  /api/v1/agents/stats          whether a model API key is set
 *
 * A task is its submitter's own: another user's task id answers 404. The
 * service has no route that lists tasks, and it keeps a task for a limited
 * time (an hour by default), after which the task answers 404 as well.
 */
import { agentsClient, getAgentsPath } from '@/lib/api-client'

/** The indicator types the service accepts (IOCType in its schemas). */
export const IOC_TYPES = [
  'ipv4',
  'ipv6',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256',
  'email',
] as const
export type IocType = (typeof IOC_TYPES)[number]

export interface Ioc {
  type: IocType
  value: string
}

/** A task that has no report: queued, running, failed or canceled. */
export interface AnalysisTask {
  task_id: string
  status: 'pending' | 'running' | 'failed' | 'revoked'
  created_at: string
  started_at: string | null
  completed_at: string | null
  progress: string | null
  /** Why a failed task failed, in the service's own words. */
  error: string | null
}

export interface AnalysisEvidence {
  source: string
  finding: string
  severity: string
}

/** A completed analysis. The service answers it without a `status` field. */
export interface AnalysisReport {
  task_id: string
  ioc: Ioc
  verdict: 'Malicious' | 'Suspicious' | 'Benign' | 'Informational'
  confidence: number
  executive_summary: string
  evidence: AnalysisEvidence[]
  recommended_actions: string[]
  full_report: string
  analysis_duration: number | null
  tools_used: string[]
}

export type AnalysisAnswer = AnalysisTask | AnalysisReport

export const isReport = (answer: AnalysisAnswer): answer is AnalysisReport => 'verdict' in answer

/** Whether the task will change no more, so reading it again is pointless. */
export const isAnalysisFinished = (answer: AnalysisAnswer | undefined): boolean =>
  !!answer && (isReport(answer) || answer.status === 'failed' || answer.status === 'revoked')

export const submitAnalysis = (ioc: Ioc) =>
  agentsClient.post<AnalysisTask>(getAgentsPath('/api/v1/analyze'), { ioc })

export const getAnalysis = (taskId: string) =>
  agentsClient.get<AnalysisAnswer>(getAgentsPath(`/api/v1/analyze/${encodeURIComponent(taskId)}`))

/** The one statistic the dashboard reads; the answer has more. */
export interface AgentsStats {
  model_configured: boolean
}

export const getAgentsStats = () => agentsClient.get<AgentsStats>(getAgentsPath('/api/v1/stats'))
