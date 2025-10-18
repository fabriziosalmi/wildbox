/**
 * Custom hook for Responder SOAR execution status monitoring
 * 
 * Provides real-time polling of playbook execution status with automatic
 * stop conditions when execution completes.
 * 
 * Features:
 * - Automatic 2-second polling for active executions
 * - Stops polling when execution reaches terminal state
 * - TypeScript interfaces matching backend schemas
 * - Step-level execution details
 */

import { useQuery, UseQueryResult } from '@tanstack/react-query'
import axios from 'axios'

// ============================================================================
// TypeScript Interfaces (matching backend Pydantic schemas)
// ============================================================================

export type ExecutionStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

/**
 * Individual step execution result
 */
export interface StepExecutionResult {
  step_name: string
  status: ExecutionStatus
  start_time: string | null
  end_time: string | null
  duration_seconds: number | null
  output: any
  error: string | null
}

/**
 * Complete playbook execution result
 */
export interface PlaybookExecutionResult {
  run_id: string
  playbook_id: string
  playbook_name: string
  status: ExecutionStatus
  start_time: string
  end_time: string | null
  duration_seconds: number | null
  step_results: StepExecutionResult[]
  trigger_data: Record<string, any>
  context: Record<string, any>
  error: string | null
}

// ============================================================================
// API Client Configuration
// ============================================================================

const RESPONDER_BASE_URL = process.env.NEXT_PUBLIC_RESPONDER_URL || 'http://localhost:8018'

const responderClient = axios.create({
  baseURL: RESPONDER_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// ============================================================================
// API Functions
// ============================================================================

/**
 * Fetch execution status by run_id
 */
async function fetchExecutionStatus(runId: string): Promise<PlaybookExecutionResult> {
  const response = await responderClient.get(`/v1/runs/${encodeURIComponent(runId)}`)
  return response.data
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Check if execution status is terminal (polling should stop)
 */
export function isTerminalStatus(status: ExecutionStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled'
}

/**
 * Calculate polling interval based on status
 * - Active executions: 2 seconds
 * - Terminal states: No polling
 */
function getPollingInterval(data: PlaybookExecutionResult | undefined): number | false {
  if (!data) return 2000 // Poll if no data yet
  
  return isTerminalStatus(data.status) ? false : 2000
}

// ============================================================================
// Main Hook: Execution Status with Polling
// ============================================================================

export interface UseExecutionStatusOptions {
  /**
   * Whether to enable polling (default: true)
   */
  enabled?: boolean
  
  /**
   * Custom polling interval in ms (default: 2000)
   */
  pollingInterval?: number
}

export interface UseExecutionStatusResult {
  /**
   * Execution result data
   */
  data: PlaybookExecutionResult | undefined
  
  /**
   * Whether query is loading
   */
  isLoading: boolean
  
  /**
   * Error object if query failed
   */
  error: Error | null
  
  /**
   * Whether execution is found and loaded
   */
  isSuccess: boolean
  
  /**
   * Whether execution is currently active (running/pending)
   */
  isActive: boolean
  
  /**
   * Whether execution has completed successfully
   */
  isCompleted: boolean
  
  /**
   * Whether execution has failed
   */
  isFailed: boolean
  
  /**
   * Whether execution was cancelled
   */
  isCancelled: boolean
  
  /**
   * Refetch function to manually reload status
   */
  refetch: () => void
}

/**
 * Hook to monitor playbook execution status with automatic polling
 * 
 * Automatically polls every 2 seconds while execution is active,
 * then stops when execution reaches a terminal state.
 * 
 * @param runId - The execution run_id to monitor
 * @param options - Optional configuration
 * 
 * @example
 * ```tsx
 * const { data, isLoading, isActive, isCompleted } = useExecutionStatus(runId)
 * 
 * if (isLoading) return <Spinner />
 * if (isCompleted) return <SuccessBadge />
 * if (isActive) return <ProgressIndicator steps={data.step_results} />
 * ```
 */
export function useExecutionStatus(
  runId: string | null | undefined,
  options: UseExecutionStatusOptions = {}
): UseExecutionStatusResult {
  const { enabled = true, pollingInterval = 2000 } = options
  
  const query = useQuery<PlaybookExecutionResult, Error>({
    queryKey: ['responder-execution', runId],
    queryFn: () => fetchExecutionStatus(runId!),
    enabled: enabled && !!runId,
    refetchInterval: (query) => {
      // Stop polling if terminal status reached
      if (query.state.data && isTerminalStatus(query.state.data.status)) {
        return false
      }
      return pollingInterval
    },
    staleTime: 0, // Always fetch fresh data
    gcTime: 5 * 60 * 1000, // Keep in cache for 5 minutes after unmount
  })
  
  const status = query.data?.status
  
  return {
    data: query.data,
    isLoading: query.isLoading,
    error: query.error,
    isSuccess: query.isSuccess,
    isActive: status === 'pending' || status === 'running',
    isCompleted: status === 'completed',
    isFailed: status === 'failed',
    isCancelled: status === 'cancelled',
    refetch: query.refetch,
  }
}

// ============================================================================
// Helper Hook: List Executions
// ============================================================================

/**
 * Simple in-memory execution tracking
 * 
 * Note: Backend doesn't provide a list endpoint, so we maintain
 * client-side history of initiated executions.
 */
export interface ExecutionHistoryItem {
  run_id: string
  playbook_id: string
  playbook_name: string
  started_at: string
}

const STORAGE_KEY = 'responder_execution_history'

/**
 * Get execution history from localStorage
 */
export function getExecutionHistory(): ExecutionHistoryItem[] {
  if (typeof window === 'undefined') return []
  
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return stored ? JSON.parse(stored) : []
  } catch {
    return []
  }
}

/**
 * Add execution to history
 */
export function addExecutionToHistory(item: ExecutionHistoryItem): void {
  if (typeof window === 'undefined') return
  
  try {
    const history = getExecutionHistory()
    
    // Add to front, limit to 50 items
    const updated = [item, ...history].slice(0, 50)
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  } catch (error) {
    console.error('Failed to save execution history:', error)
  }
}

/**
 * Clear execution history
 */
export function clearExecutionHistory(): void {
  if (typeof window === 'undefined') return
  
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch (error) {
    console.error('Failed to clear execution history:', error)
  }
}

// ============================================================================
// UI Helper Functions
// ============================================================================

/**
 * Get color class for execution status
 */
export function getStatusColor(status: ExecutionStatus): string {
  const colors: Record<ExecutionStatus, string> = {
    pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100',
    running: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
    completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
    failed: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
    cancelled: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
  }
  return colors[status]
}

/**
 * Get icon name for execution status (Lucide icons)
 */
export function getStatusIcon(status: ExecutionStatus): string {
  const icons: Record<ExecutionStatus, string> = {
    pending: 'Clock',
    running: 'Play',
    completed: 'CheckCircle',
    failed: 'XCircle',
    cancelled: 'Ban',
  }
  return icons[status]
}

/**
 * Format duration in human-readable format
 */
export function formatDuration(seconds: number | null): string {
  if (seconds === null) return 'N/A'
  
  if (seconds < 60) {
    return `${Math.round(seconds)}s`
  }
  
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = Math.round(seconds % 60)
  
  return `${minutes}m ${remainingSeconds}s`
}

/**
 * Calculate execution progress percentage
 */
export function calculateProgress(result: PlaybookExecutionResult): number {
  if (!result.step_results.length) return 0
  
  const completedSteps = result.step_results.filter(
    (step) => isTerminalStatus(step.status)
  ).length
  
  return Math.round((completedSteps / result.step_results.length) * 100)
}

/**
 * Get currently executing step
 */
export function getCurrentStep(
  result: PlaybookExecutionResult
): StepExecutionResult | null {
  return (
    result.step_results.find((step) => step.status === 'running') || null
  )
}

/**
 * Get failed steps
 */
export function getFailedSteps(
  result: PlaybookExecutionResult
): StepExecutionResult[] {
  return result.step_results.filter((step) => step.status === 'failed')
}
