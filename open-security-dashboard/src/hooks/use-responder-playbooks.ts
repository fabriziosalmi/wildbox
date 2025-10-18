/**
 * Custom hook for Responder SOAR playbook management
 * 
 * Provides type-safe access to the Responder service playbook APIs:
 * - GET /v1/playbooks - List all available playbooks
 * - POST /v1/playbooks/{id}/execute - Execute a playbook
 * 
 * Features:
 * - Automatic playbook listing with caching
 * - Playbook execution with mutation tracking
 * - TypeScript interfaces matching backend schemas
 * - Error handling with user-friendly messages
 */

import { useQuery, useMutation, useQueryClient, UseQueryResult } from '@tanstack/react-query'
import axios from 'axios'

// ============================================================================
// TypeScript Interfaces (matching backend Pydantic schemas)
// ============================================================================

export type TriggerType = 'api' | 'webhook' | 'schedule'

/**
 * Playbook summary from list endpoint
 */
export interface PlaybookSummary {
  playbook_id: string
  name: string
  description: string
  version: string
  author: string
  tags: string[]
  steps_count: number
  trigger_type: TriggerType
}

/**
 * Response from list playbooks endpoint
 */
export interface PlaybookListResponse {
  playbooks: PlaybookSummary[]
  total: number
}

/**
 * Request for playbook execution
 */
export interface PlaybookExecutionRequest {
  trigger_data?: Record<string, any>
  context?: Record<string, any>
}

/**
 * Response from execute playbook endpoint
 */
export interface PlaybookExecutionResponse {
  run_id: string
  playbook_id: string
  playbook_name: string
  status: string
  status_url: string
  message: string
}

// ============================================================================
// API Client Configuration
// ============================================================================

const RESPONDER_BASE_URL = process.env.NEXT_PUBLIC_RESPONDER_URL || 'http://localhost:8018'

// Create axios instance for Responder service
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
 * Fetch all available playbooks
 */
async function fetchPlaybooks(): Promise<PlaybookListResponse> {
  const response = await responderClient.get('/v1/playbooks')
  return response.data
}

/**
 * Execute a playbook
 */
async function executePlaybook(
  playbookId: string,
  request: PlaybookExecutionRequest = {}
): Promise<PlaybookExecutionResponse> {
  const response = await responderClient.post(
    `/v1/playbooks/${encodeURIComponent(playbookId)}/execute`,
    request
  )
  return response.data
}

// ============================================================================
// Main Hook: List Playbooks
// ============================================================================

export interface UseResponderPlaybooksResult {
  /**
   * List of available playbooks
   */
  playbooks: PlaybookSummary[]
  
  /**
   * Total number of playbooks
   */
  total: number
  
  /**
   * Whether the query is currently loading
   */
  isLoading: boolean
  
  /**
   * Error object if query failed
   */
  error: Error | null
  
  /**
   * Whether query has succeeded
   */
  isSuccess: boolean
  
  /**
   * Refetch function to manually reload playbooks
   */
  refetch: () => void
}

/**
 * Hook to fetch and manage SOAR playbooks
 * 
 * @example
 * ```tsx
 * const { playbooks, total, isLoading } = useResponderPlaybooks()
 * 
 * return (
 *   <div>
 *     <h1>Playbooks ({total})</h1>
 *     {playbooks.map(pb => (
 *       <PlaybookCard key={pb.playbook_id} playbook={pb} />
 *     ))}
 *   </div>
 * )
 * ```
 */
export function useResponderPlaybooks(): UseResponderPlaybooksResult {
  const query = useQuery<PlaybookListResponse, Error>({
    queryKey: ['responder-playbooks'],
    queryFn: fetchPlaybooks,
    staleTime: 5 * 60 * 1000, // 5 minutes - playbooks don't change often
    gcTime: 10 * 60 * 1000, // 10 minutes cache retention
  })
  
  return {
    playbooks: query.data?.playbooks || [],
    total: query.data?.total || 0,
    isLoading: query.isLoading,
    error: query.error,
    isSuccess: query.isSuccess,
    refetch: query.refetch,
  }
}

// ============================================================================
// Main Hook: Execute Playbook
// ============================================================================

export interface UsePlaybookExecutionOptions {
  /**
   * Callback fired when execution starts successfully
   */
  onSuccess?: (response: PlaybookExecutionResponse) => void
  
  /**
   * Callback fired when execution fails
   */
  onError?: (error: Error) => void
}

export interface UsePlaybookExecutionResult {
  /**
   * Mutation function to execute a playbook
   */
  execute: (playbookId: string, request?: PlaybookExecutionRequest) => void
  
  /**
   * Latest execution response (includes run_id)
   */
  data: PlaybookExecutionResponse | undefined
  
  /**
   * Whether execution is in progress
   */
  isLoading: boolean
  
  /**
   * Error if execution failed
   */
  error: Error | null
  
  /**
   * Whether execution succeeded
   */
  isSuccess: boolean
  
  /**
   * Reset mutation state
   */
  reset: () => void
}

/**
 * Hook to execute SOAR playbooks with mutation tracking
 * 
 * @example
 * ```tsx
 * const { execute, data, isLoading } = usePlaybookExecution({
 *   onSuccess: (response) => {
 *     console.log('Execution started:', response.run_id)
 *     // Navigate to runs page or show status
 *   }
 * })
 * 
 * const handleExecute = () => {
 *   execute('triage_ip', {
 *     trigger_data: { ip: '8.8.8.8' }
 *   })
 * }
 * ```
 */
export function usePlaybookExecution(
  options: UsePlaybookExecutionOptions = {}
): UsePlaybookExecutionResult {
  const queryClient = useQueryClient()
  
  const mutation = useMutation<
    PlaybookExecutionResponse,
    Error,
    { playbookId: string; request: PlaybookExecutionRequest }
  >({
    mutationFn: ({ playbookId, request }) => executePlaybook(playbookId, request),
    onSuccess: (data) => {
      // Invalidate runs list if it exists
      queryClient.invalidateQueries({ queryKey: ['responder-runs'] })
      
      // Call user callback
      if (options.onSuccess) {
        options.onSuccess(data)
      }
    },
    onError: (error) => {
      if (options.onError) {
        options.onError(error)
      }
    },
  })
  
  return {
    execute: (playbookId: string, request: PlaybookExecutionRequest = {}) => {
      mutation.mutate({ playbookId, request })
    },
    data: mutation.data,
    isLoading: mutation.isPending,
    error: mutation.error,
    isSuccess: mutation.isSuccess,
    reset: mutation.reset,
  }
}

// ============================================================================
// Helper Functions for UI
// ============================================================================

/**
 * Get color class for playbook tag
 */
export function getTagColor(tag: string): string {
  const colorMap: Record<string, string> = {
    test: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100',
    triage: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
    security: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
    network: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
    malware: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100',
    phishing: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100',
    notification: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-100',
  }
  
  return colorMap[tag.toLowerCase()] || 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100'
}

/**
 * Get icon for trigger type
 */
export function getTriggerTypeLabel(type: TriggerType): string {
  const labels: Record<TriggerType, string> = {
    api: 'API Trigger',
    webhook: 'Webhook',
    schedule: 'Scheduled',
  }
  return labels[type] || type
}

/**
 * Filter playbooks by search term
 */
export function filterPlaybooks(
  playbooks: PlaybookSummary[],
  searchTerm: string
): PlaybookSummary[] {
  if (!searchTerm) return playbooks
  
  const term = searchTerm.toLowerCase()
  
  return playbooks.filter(
    (pb) =>
      pb.name.toLowerCase().includes(term) ||
      pb.description.toLowerCase().includes(term) ||
      pb.playbook_id.toLowerCase().includes(term) ||
      pb.tags.some((tag) => tag.toLowerCase().includes(term))
  )
}

/**
 * Group playbooks by tag
 */
export function groupPlaybooksByTag(
  playbooks: PlaybookSummary[]
): Record<string, PlaybookSummary[]> {
  const grouped: Record<string, PlaybookSummary[]> = {}
  
  playbooks.forEach((playbook) => {
    playbook.tags.forEach((tag) => {
      if (!grouped[tag]) {
        grouped[tag] = []
      }
      grouped[tag].push(playbook)
    })
  })
  
  return grouped
}

/**
 * Get all unique tags from playbooks
 */
export function getAllTags(playbooks: PlaybookSummary[]): string[] {
  const tags = new Set<string>()
  playbooks.forEach((pb) => {
    pb.tags.forEach((tag) => tags.add(tag))
  })
  return Array.from(tags).sort()
}
