'use client''use client'



import { useState, useEffect } from 'react'import { useState, useEffect } from 'react'

import { useSearchParams, useRouter } from 'next/navigation'import { useQuery } from '@tanstack/react-query'

import { import { 

  Clock,   PlayCircle, 

  CheckCircle,  Clock, 

  XCircle,  CheckCircle,

  AlertCircle,  XCircle,

  Activity,  AlertCircle,

  Filter,  User,

  Search,  Activity,

  Eye,  Filter,

  Loader2,  Search,

  Calendar,  RefreshCw,

  Timer,  Eye,

  Play,  Loader2,

  Ban,  Calendar,

  ChevronDown,  Timer

  ChevronUp} from 'lucide-react'

} from 'lucide-react'import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'import { Button } from '@/components/ui/button'

import { Button } from '@/components/ui/button'import { Badge } from '@/components/ui/badge'

import { Badge } from '@/components/ui/badge'import { Input } from '@/components/ui/input'

import { Input } from '@/components/ui/input'import { responderClient } from '@/lib/api-client'

import { 

  useExecutionStatus,interface PlaybookRun {

  getExecutionHistory,  id: string

  getStatusColor,  playbookId: string

  getStatusIcon,  playbookName: string

  formatDuration,  status: 'running' | 'completed' | 'failed' | 'cancelled'

  calculateProgress,  startTime: string

  getCurrentStep,  endTime?: string

  getFailedSteps,  duration?: number

  type ExecutionHistoryItem,  trigger: string

  type PlaybookExecutionResult,  userId: string

  type StepExecutionResult  progress?: number

} from '@/hooks/use-execution-status'  error?: string

}

// Icons mapping

const statusIcons = {interface RunsResponse {

  pending: Clock,  runs: PlaybookRun[]

  running: Play,  total: number

  completed: CheckCircle,}

  failed: XCircle,

  cancelled: Ban// Mock data since the API endpoint might not be implemented yet

}const mockRuns: PlaybookRun[] = [

  {

interface ExecutionRowProps {    id: 'run-001',

  item: ExecutionHistoryItem    playbookId: 'triage_ip',

  isExpanded: boolean    playbookName: 'IP Address Triage',

  onToggle: () => void    status: 'completed',

}    startTime: new Date(Date.now() - 30000).toISOString(),

    endTime: new Date(Date.now() - 15000).toISOString(),

function ExecutionRow({ item, isExpanded, onToggle }: ExecutionRowProps) {    duration: 15,

  // Poll for status    trigger: 'manual',

  const {     userId: 'admin',

    data,   },

    isLoading,   {

    isActive,     id: 'run-002',

    isCompleted,     playbookId: 'triage_url',

    isFailed,     playbookName: 'URL Analysis and Response',

    isCancelled     status: 'running',

  } = useExecutionStatus(item.run_id)    startTime: new Date(Date.now() - 45000).toISOString(),

    trigger: 'api',

  const status = data?.status || 'pending'    userId: 'security-team',

  const StatusIcon = statusIcons[status]    progress: 65,

    },

  const progress = data ? calculateProgress(data) : 0  {

  const currentStep = data ? getCurrentStep(data) : null    id: 'run-003',

  const failedSteps = data ? getFailedSteps(data) : []    playbookId: 'simple_notification',

    playbookName: 'Simple Notification Test',

  return (    status: 'failed',

    <>    startTime: new Date(Date.now() - 120000).toISOString(),

      {/* Main Row */}    endTime: new Date(Date.now() - 110000).toISOString(),

      <tr     duration: 10,

        className="border-b transition-colors hover:bg-muted/50 cursor-pointer"    trigger: 'manual',

        onClick={onToggle}    userId: 'admin',

      >    error: 'Connection timeout to external service',

        <td className="p-4">  },

          <div className="flex items-center gap-2">]

            {isExpanded ? (

              <ChevronUp className="h-4 w-4 text-muted-foreground" />async function fetchRuns(): Promise<RunsResponse> {

            ) : (  try {

              <ChevronDown className="h-4 w-4 text-muted-foreground" />    // Try to fetch from API, but fall back to mock data if not available

            )}    const response = await responderClient.get('/v1/runs')

            <code className="text-xs bg-muted px-2 py-1 rounded">    return response

              {item.run_id.slice(0, 8)}...  } catch (error) {

            </code>    console.warn('API not available, using mock data:', error)

          </div>    // Return mock data for demonstration

        </td>    return {

        <td className="p-4">      runs: mockRuns,

          <div className="font-medium">{item.playbook_name}</div>      total: mockRuns.length

          <div className="text-sm text-muted-foreground">{item.playbook_id}</div>    }

        </td>  }

        <td className="p-4">}

          <Badge className={getStatusColor(status)}>

            <StatusIcon className="h-3 w-3 mr-1" />function getStatusIcon(status: string) {

            {status.charAt(0).toUpperCase() + status.slice(1)}  switch (status) {

          </Badge>    case 'completed':

        </td>      return <CheckCircle className="h-5 w-5 text-green-500" />

        <td className="p-4">    case 'running':

          {isActive && (      return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />

            <div className="flex items-center gap-2">    case 'failed':

              <div className="w-32 h-2 bg-gray-200 rounded-full overflow-hidden">      return <XCircle className="h-5 w-5 text-red-500" />

                <div     case 'cancelled':

                  className="h-full bg-blue-500 transition-all duration-500"      return <AlertCircle className="h-5 w-5 text-orange-500" />

                  style={{ width: `${progress}%` }}    default:

                />      return <Clock className="h-5 w-5 text-gray-500" />

              </div>  }

              <span className="text-sm text-muted-foreground">{progress}%</span>}

            </div>

          )}function getStatusColor(status: string): string {

          {isCompleted && (  switch (status) {

            <span className="text-sm text-green-600">100%</span>    case 'completed':

          )}      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100'

          {isFailed && (    case 'running':

            <span className="text-sm text-red-600">Failed</span>      return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100'

          )}    case 'failed':

        </td>      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100'

        <td className="p-4 text-sm text-muted-foreground">    case 'cancelled':

          {data?.duration_seconds !== null ? formatDuration(data?.duration_seconds || 0) : 'In progress...'}      return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100'

        </td>    default:

        <td className="p-4 text-sm text-muted-foreground">      return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-100'

          {new Date(item.started_at).toLocaleString()}  }

        </td>}

      </tr>

function formatDuration(seconds?: number): string {

      {/* Expanded Details */}  if (!seconds) return 'N/A'

      {isExpanded && data && (  

        <tr className="bg-muted/30">  if (seconds < 60) {

          <td colSpan={6} className="p-6">    return `${seconds}s`

            <div className="space-y-6">  } else if (seconds < 3600) {

              {/* Execution Info */}    const minutes = Math.floor(seconds / 60)

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">    const remainingSeconds = seconds % 60

                <div>    return `${minutes}m ${remainingSeconds}s`

                  <div className="text-sm font-medium text-muted-foreground">Run ID</div>  } else {

                  <code className="text-xs bg-background px-2 py-1 rounded mt-1 inline-block">    const hours = Math.floor(seconds / 3600)

                    {data.run_id}    const minutes = Math.floor((seconds % 3600) / 60)

                  </code>    return `${hours}h ${minutes}m`

                </div>  }

                <div>}

                  <div className="text-sm font-medium text-muted-foreground">Start Time</div>

                  <div className="text-sm mt-1">function formatTimestamp(timestamp: string): string {

                    {new Date(data.start_time).toLocaleString()}  const date = new Date(timestamp)

                  </div>  return date.toLocaleString()

                </div>}

                {data.end_time && (

                  <div>function RunCard({ run, onViewDetails }: { run: PlaybookRun; onViewDetails: (run: PlaybookRun) => void }) {

                    <div className="text-sm font-medium text-muted-foreground">End Time</div>  const elapsed = run.endTime 

                    <div className="text-sm mt-1">    ? Math.floor((new Date(run.endTime).getTime() - new Date(run.startTime).getTime()) / 1000)

                      {new Date(data.end_time).toLocaleString()}    : Math.floor((Date.now() - new Date(run.startTime).getTime()) / 1000)

                    </div>

                  </div>  return (

                )}    <Card className="group hover:shadow-lg transition-all duration-200">

                <div>      <CardHeader className="pb-3">

                  <div className="text-sm font-medium text-muted-foreground">Duration</div>        <div className="flex items-start justify-between">

                  <div className="text-sm mt-1">          <div className="space-y-1">

                    {formatDuration(data.duration_seconds)}            <CardTitle className="text-lg font-semibold group-hover:text-blue-600 transition-colors">

                  </div>              {run.playbookName}

                </div>            </CardTitle>

              </div>            <CardDescription className="text-sm">

              Run ID: {run.id}

              {/* Current Step */}            </CardDescription>

              {currentStep && (          </div>

                <div className="bg-blue-50 dark:bg-blue-950 p-4 rounded-lg">          <div className="flex items-center gap-2">

                  <div className="flex items-center gap-2 mb-2">            {getStatusIcon(run.status)}

                    <Loader2 className="h-4 w-4 animate-spin text-blue-600" />            <Badge className={getStatusColor(run.status)}>

                    <span className="font-medium text-blue-900 dark:text-blue-100">              {run.status}

                      Currently executing: {currentStep.step_name}            </Badge>

                    </span>          </div>

                  </div>        </div>

                </div>      </CardHeader>

              )}      <CardContent className="pt-0">

        <div className="space-y-4">

              {/* Failed Steps */}          {/* Progress bar for running tasks */}

              {failedSteps.length > 0 && (          {run.status === 'running' && run.progress && (

                <div className="bg-red-50 dark:bg-red-950 p-4 rounded-lg">            <div className="space-y-2">

                  <div className="flex items-center gap-2 mb-2">              <div className="flex justify-between text-sm">

                    <XCircle className="h-4 w-4 text-red-600" />                <span>Progress</span>

                    <span className="font-medium text-red-900 dark:text-red-100">                <span>{run.progress}%</span>

                      Failed Steps ({failedSteps.length})              </div>

                    </span>              <div className="w-full bg-gray-200 rounded-full h-2">

                  </div>                <div 

                  <ul className="space-y-1 ml-6">                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"

                    {failedSteps.map((step, idx) => (                  style={{ width: `${run.progress}%` }}

                      <li key={idx} className="text-sm text-red-800 dark:text-red-200">                />

                        {step.step_name}: {step.error || 'Unknown error'}              </div>

                      </li>            </div>

                    ))}          )}

                  </ul>

                </div>          {/* Error message */}

              )}          {run.error && (

            <div className="p-3 bg-red-50 border border-red-200 rounded-md">

              {/* Step Results */}              <p className="text-sm text-red-800">{run.error}</p>

              <div>            </div>

                <h4 className="font-medium mb-3">Execution Steps</h4>          )}

                <div className="space-y-2">

                  {data.step_results.map((step, idx) => (          {/* Metadata */}

                    <StepResultCard key={idx} step={step} index={idx} />          <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">

                  ))}            <div className="flex items-center gap-2">

                </div>              <User className="h-4 w-4" />

              </div>              <span>{run.userId}</span>

            </div>

              {/* Trigger Data */}            <div className="flex items-center gap-2">

              {Object.keys(data.trigger_data).length > 0 && (              <Activity className="h-4 w-4" />

                <div>              <span>{run.trigger}</span>

                  <h4 className="font-medium mb-2">Trigger Data</h4>            </div>

                  <pre className="bg-background p-3 rounded-md text-xs overflow-auto">            <div className="flex items-center gap-2">

                    {JSON.stringify(data.trigger_data, null, 2)}              <Calendar className="h-4 w-4" />

                  </pre>              <span>{formatTimestamp(run.startTime)}</span>

                </div>            </div>

              )}            <div className="flex items-center gap-2">

            </div>              <Timer className="h-4 w-4" />

          </td>              <span>{run.duration ? formatDuration(run.duration) : formatDuration(elapsed)}</span>

        </tr>            </div>

      )}          </div>

    </>

  )          {/* Actions */}

}          <div className="flex gap-2 pt-2 border-t">

            <Button

interface StepResultCardProps {              onClick={() => onViewDetails(run)}

  step: StepExecutionResult              variant="outline"

  index: number              size="sm"

}              className="flex-1"

            >

function StepResultCard({ step, index }: StepResultCardProps) {              <Eye className="h-4 w-4 mr-2" />

  const StatusIcon = statusIcons[step.status]              View Details

              </Button>

  return (            {run.status === 'running' && (

    <div className="flex items-start gap-3 p-3 bg-background rounded-md border">              <Button

      <div className="flex items-center justify-center w-6 h-6 rounded-full bg-muted text-xs font-medium">                variant="outline"

        {index + 1}                size="sm"

      </div>                onClick={() => {

      <div className="flex-1 min-w-0">                  // TODO: Implement cancel functionality

        <div className="flex items-center gap-2 mb-1">                  console.log('Cancel run:', run.id)

          <span className="font-medium">{step.step_name}</span>                }}

          <Badge className={getStatusColor(step.status)}>              >

            <StatusIcon className="h-3 w-3 mr-1" />                Cancel

            {step.status}              </Button>

          </Badge>            )}

        </div>          </div>

        {step.duration_seconds !== null && (        </div>

          <div className="text-xs text-muted-foreground">      </CardContent>

            Duration: {formatDuration(step.duration_seconds)}    </Card>

          </div>  )

        )}}

        {step.error && (

          <div className="text-xs text-red-600 mt-1">export default function RunsPage() {

            Error: {step.error}  const [searchTerm, setSearchTerm] = useState('')

          </div>  const [statusFilter, setStatusFilter] = useState<string>('all')

        )}

      </div>  const { data: runsData, isLoading, error, refetch } = useQuery({

    </div>    queryKey: ['playbook-runs'],

  )    queryFn: fetchRuns,

}    refetchInterval: 5000, // Refetch every 5 seconds for real-time updates

  })

export default function RunsPage() {

  const router = useRouter()  const filteredRuns = runsData?.runs?.filter((run) => {

  const searchParams = useSearchParams()    const matchesSearch = run.playbookName.toLowerCase().includes(searchTerm.toLowerCase()) ||

  const highlightRunId = searchParams.get('run_id')                         run.id.toLowerCase().includes(searchTerm.toLowerCase()) ||

                           run.userId.toLowerCase().includes(searchTerm.toLowerCase())

  const [searchTerm, setSearchTerm] = useState('')    

  const [statusFilter, setStatusFilter] = useState<string>('all')    const matchesStatus = statusFilter === 'all' || run.status === statusFilter

  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())    

  const [history, setHistory] = useState<ExecutionHistoryItem[]>([])    return matchesSearch && matchesStatus

  }) || []

  // Load history on mount

  useEffect(() => {  const handleViewDetails = (run: PlaybookRun) => {

    const loaded = getExecutionHistory()    // TODO: Implement run details modal or navigation

    setHistory(loaded)    console.log('View run details:', run.id)

        alert(`Run Details: ${run.id}\n\nThis would show detailed execution logs and step-by-step results.`)

    // Auto-expand highlighted run  }

    if (highlightRunId) {

      setExpandedRows(new Set([highlightRunId]))  if (error) {

    }    return (

  }, [highlightRunId])      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">

        <AlertCircle className="h-12 w-12 text-red-500 mb-4" />

  // Auto-refresh history every 5 seconds        <h3 className="text-lg font-semibold mb-2">Failed to load runs</h3>

  useEffect(() => {        <p className="text-muted-foreground mb-4">

    const interval = setInterval(() => {          Unable to connect to the Response service. Showing demo data.

      const updated = getExecutionHistory()        </p>

      setHistory(updated)        <Button onClick={() => refetch()}>

    }, 5000)          Try Again

            </Button>

    return () => clearInterval(interval)      </div>

  }, [])    )

  }

  const toggleRow = (runId: string) => {

    setExpandedRows(prev => {  return (

      const next = new Set(prev)    <div className="space-y-6">

      if (next.has(runId)) {        {/* Header */}

        next.delete(runId)        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">

      } else {          <div>

        next.add(runId)            <h1 className="text-3xl font-bold tracking-tight">Playbook Runs</h1>

      }            <p className="text-muted-foreground">

      return next              Monitor and manage playbook execution history

    })            </p>

  }          </div>

          <div className="flex items-center gap-2">

  // Filter history            <Badge variant="outline" className="px-3 py-1">

  const filteredHistory = history.filter(item => {              <Activity className="h-4 w-4 mr-1" />

    const matchesSearch =               {runsData?.total || 0} runs

      item.playbook_name.toLowerCase().includes(searchTerm.toLowerCase()) ||            </Badge>

      item.playbook_id.toLowerCase().includes(searchTerm.toLowerCase()) ||            <Button onClick={() => refetch()} variant="outline" size="sm">

      item.run_id.toLowerCase().includes(searchTerm.toLowerCase())              <RefreshCw className="h-4 w-4 mr-2" />

                  Refresh

    // Status filter requires querying each execution (expensive, skip for now)            </Button>

    // For now, just filter by search term          </div>

    return matchesSearch        </div>

  })

        {/* Search and Filter */}

  if (history.length === 0) {        <div className="flex flex-col sm:flex-row gap-4">

    return (          <div className="relative flex-1">

      <div className="space-y-6">            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />

        <div>            <Input

          <h1 className="text-3xl font-bold tracking-tight">Playbook Runs</h1>              placeholder="Search runs..."

          <p className="text-muted-foreground">              value={searchTerm}

            Monitor and review playbook execution history              onChange={(e) => setSearchTerm(e.target.value)}

          </p>              className="pl-10"

        </div>            />

          </div>

        <Card>          <div className="flex items-center gap-2">

          <CardContent className="flex flex-col items-center justify-center py-16">            <Filter className="h-4 w-4 text-muted-foreground" />

            <Activity className="h-12 w-12 text-muted-foreground mb-4" />            <select

            <h3 className="text-lg font-semibold mb-2">No executions yet</h3>              value={statusFilter}

            <p className="text-muted-foreground text-center mb-6">              onChange={(e) => setStatusFilter(e.target.value)}

              Playbook executions will appear here once you start running playbooks.              className="px-3 py-2 border border-input bg-background rounded-md text-sm"

            </p>            >

            <Button onClick={() => router.push('/response/playbooks')}>              <option value="all">All statuses</option>

              <Play className="h-4 w-4 mr-2" />              <option value="running">Running</option>

              Go to Playbooks              <option value="completed">Completed</option>

            </Button>              <option value="failed">Failed</option>

          </CardContent>              <option value="cancelled">Cancelled</option>

        </Card>            </select>

      </div>          </div>

    )        </div>

  }

        {/* Runs Grid */}

  return (        {isLoading ? (

    <div className="space-y-6">          <div className="flex items-center justify-center min-h-[300px]">

      {/* Header */}            <div className="flex items-center gap-2">

      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">              <Loader2 className="h-5 w-5 animate-spin" />

        <div>              <span>Loading runs...</span>

          <h1 className="text-3xl font-bold tracking-tight">Playbook Runs</h1>            </div>

          <p className="text-muted-foreground">          </div>

            Monitor and review playbook execution history        ) : filteredRuns.length > 0 ? (

          </p>          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">

        </div>            {filteredRuns.map((run) => (

        <div className="flex items-center gap-2">              <RunCard

          <Badge variant="outline" className="px-3 py-1">                key={run.id}

            <Activity className="h-4 w-4 mr-1" />                run={run}

            {history.length} executions                onViewDetails={handleViewDetails}

          </Badge>              />

          <Button onClick={() => router.push('/response/playbooks')} size="sm">            ))}

            <Play className="h-4 w-4 mr-2" />          </div>

            New Run        ) : (

          </Button>          <div className="flex flex-col items-center justify-center min-h-[300px] text-center">

        </div>            <PlayCircle className="h-12 w-12 text-muted-foreground mb-4" />

      </div>            <h3 className="text-lg font-semibold mb-2">No runs found</h3>

            <p className="text-muted-foreground">

      {/* Search */}              {searchTerm || statusFilter !== 'all' 

      <div className="flex flex-col sm:flex-row gap-4">                ? 'Try adjusting your search or filter criteria.'

        <div className="relative flex-1">                : 'No playbook runs have been executed yet.'}

          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />            </p>

          <Input          </div>

            placeholder="Search by playbook name, ID, or run ID..."        )}

            value={searchTerm}      </div>

            onChange={(e) => setSearchTerm(e.target.value)}  )

            className="pl-10"}

          />
        </div>
      </div>

      {/* Executions Table */}
      <Card>
        <CardHeader>
          <CardTitle>Execution History</CardTitle>
          <CardDescription>
            Click any row to view detailed step execution and results
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-sm text-muted-foreground">
                  <th className="p-4 text-left font-medium">Run ID</th>
                  <th className="p-4 text-left font-medium">Playbook</th>
                  <th className="p-4 text-left font-medium">Status</th>
                  <th className="p-4 text-left font-medium">Progress</th>
                  <th className="p-4 text-left font-medium">Duration</th>
                  <th className="p-4 text-left font-medium">Started</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map((item) => (
                  <ExecutionRow
                    key={item.run_id}
                    item={item}
                    isExpanded={expandedRows.has(item.run_id)}
                    onToggle={() => toggleRow(item.run_id)}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {filteredHistory.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16">
              <Search className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">No matching executions</h3>
              <p className="text-muted-foreground">
                Try adjusting your search criteria
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
