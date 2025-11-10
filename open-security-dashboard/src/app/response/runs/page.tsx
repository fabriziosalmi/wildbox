'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  PlayCircle, 
  Clock, 
  CheckCircle,
  XCircle,
  AlertCircle,
  User,
  Activity,
  Filter,
  Search,
  RefreshCw,
  Eye,
  Loader2,
  Calendar,
  Timer
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { responderClient } from '@/lib/api-client'

interface PlaybookRun {
  id: string
  playbookId: string
  playbookName: string
  status: 'running' | 'completed' | 'failed' | 'cancelled'
  startTime: string
  endTime?: string
  duration?: number
  trigger: string
  userId: string
  progress?: number
  error?: string
}

interface RunsResponse {
  runs: PlaybookRun[]
  total: number
}

// Mock data since the API endpoint might not be implemented yet
const mockRuns: PlaybookRun[] = [
  {
    id: 'run-001',
    playbookId: 'triage_ip',
    playbookName: 'IP Address Triage',
    status: 'completed',
    startTime: new Date(Date.now() - 30000).toISOString(),
    endTime: new Date(Date.now() - 15000).toISOString(),
    duration: 15,
    trigger: 'manual',
    userId: 'admin',
  },
  {
    id: 'run-002',
    playbookId: 'triage_url',
    playbookName: 'URL Analysis and Response',
    status: 'running',
    startTime: new Date(Date.now() - 45000).toISOString(),
    trigger: 'api',
    userId: 'security-team',
    progress: 65,
  },
  {
    id: 'run-003',
    playbookId: 'simple_notification',
    playbookName: 'Simple Notification Test',
    status: 'failed',
    startTime: new Date(Date.now() - 120000).toISOString(),
    endTime: new Date(Date.now() - 110000).toISOString(),
    duration: 10,
    trigger: 'manual',
    userId: 'admin',
    error: 'Connection timeout to external service',
  },
]

async function fetchRuns(): Promise<RunsResponse> {
  try {
    // Try to fetch from API, but fall back to mock data if not available
    const response = await responderClient.get('/v1/runs')
    return response
  } catch (error) {
    console.warn('API not available, using mock data:', error)
    // Return mock data for demonstration
    return {
      runs: mockRuns,
      total: mockRuns.length
    }
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="h-5 w-5 text-green-500" />
    case 'running':
      return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />
    case 'failed':
      return <XCircle className="h-5 w-5 text-red-500" />
    case 'cancelled':
      return <AlertCircle className="h-5 w-5 text-orange-500" />
    default:
      return <Clock className="h-5 w-5 text-gray-500" />
  }
}

function getStatusColor(status: string): string {
  switch (status) {
    case 'completed':
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100'
    case 'running':
      return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100'
    case 'failed':
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100'
    case 'cancelled':
      return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100'
    default:
      return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-100'
  }
}

function formatDuration(seconds?: number): string {
  if (!seconds) return 'N/A'
  
  if (seconds < 60) {
    return `${seconds}s`
  } else if (seconds < 3600) {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}m ${remainingSeconds}s`
  } else {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return `${hours}h ${minutes}m`
  }
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp)
  return date.toLocaleString()
}

function RunCard({ run, onViewDetails }: { run: PlaybookRun; onViewDetails: (run: PlaybookRun) => void }) {
  const elapsed = run.endTime 
    ? Math.floor((new Date(run.endTime).getTime() - new Date(run.startTime).getTime()) / 1000)
    : Math.floor((Date.now() - new Date(run.startTime).getTime()) / 1000)

  return (
    <Card className="group hover:shadow-lg transition-all duration-200">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <CardTitle className="text-lg font-semibold group-hover:text-blue-600 transition-colors">
              {run.playbookName}
            </CardTitle>
            <CardDescription className="text-sm">
              Run ID: {run.id}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {getStatusIcon(run.status)}
            <Badge className={getStatusColor(run.status)}>
              {run.status}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-4">
          {/* Progress bar for running tasks */}
          {run.status === 'running' && run.progress && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Progress</span>
                <span>{run.progress}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div 
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${run.progress}%` }}
                />
              </div>
            </div>
          )}

          {/* Error message */}
          {run.error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-md">
              <p className="text-sm text-red-800">{run.error}</p>
            </div>
          )}

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <User className="h-4 w-4" />
              <span>{run.userId}</span>
            </div>
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              <span>{run.trigger}</span>
            </div>
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4" />
              <span>{formatTimestamp(run.startTime)}</span>
            </div>
            <div className="flex items-center gap-2">
              <Timer className="h-4 w-4" />
              <span>{run.duration ? formatDuration(run.duration) : formatDuration(elapsed)}</span>
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-2 border-t">
            <Button
              onClick={() => onViewDetails(run)}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <Eye className="h-4 w-4 mr-2" />
              View Details
            </Button>
            {run.status === 'running' && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  // TODO: Implement cancel functionality
                  console.log('Cancel run:', run.id)
                }}
              >
                Cancel
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default function RunsPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const { data: runsData, isLoading, error, refetch } = useQuery({
    queryKey: ['playbook-runs'],
    queryFn: fetchRuns,
    refetchInterval: 5000, // Refetch every 5 seconds for real-time updates
  })

  const filteredRuns = runsData?.runs?.filter((run) => {
    const matchesSearch = run.playbookName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         run.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         run.userId.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesStatus = statusFilter === 'all' || run.status === statusFilter
    
    return matchesSearch && matchesStatus
  }) || []

  const handleViewDetails = (run: PlaybookRun) => {
    // TODO: Implement run details modal or navigation
    console.log('View run details:', run.id)
    alert(`Run Details: ${run.id}\n\nThis would show detailed execution logs and step-by-step results.`)
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
        <h3 className="text-lg font-semibold mb-2">Failed to load runs</h3>
        <p className="text-muted-foreground mb-4">
          Unable to connect to the Response service. Showing demo data.
        </p>
        <Button onClick={() => refetch()}>
          Try Again
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Playbook Runs</h1>
          <p className="text-muted-foreground">
            Monitor and manage playbook execution history
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="px-3 py-1">
            <Activity className="h-4 w-4 mr-1" />
            {runsData?.total || 0} runs
          </Badge>
          <Button onClick={() => refetch()} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search runs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-input bg-background rounded-md text-sm"
          >
            <option value="all">All statuses</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
      </div>

      {/* Runs Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center min-h-[300px]">
          <div className="flex items-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            <span>Loading runs...</span>
          </div>
        </div>
      ) : filteredRuns.length > 0 ? (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {filteredRuns.map((run) => (
            <RunCard
              key={run.id}
              run={run}
              onViewDetails={handleViewDetails}
            />
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center min-h-[300px] text-center">
          <PlayCircle className="h-12 w-12 text-muted-foreground mb-4" />
          <h3 className="text-lg font-semibold mb-2">No runs found</h3>
          <p className="text-muted-foreground">
            {searchTerm || statusFilter !== 'all' 
              ? 'Try adjusting your search or filter criteria.'
              : 'No playbook runs have been executed yet.'}
          </p>
        </div>
      )}
    </div>
  )
}
