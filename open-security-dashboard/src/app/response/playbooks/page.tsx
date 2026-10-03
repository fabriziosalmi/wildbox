'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Book,
  Clock,
  User,
  Settings,
  AlertCircle,
  Loader2,
  Play,
  Search,
  Filter,
  XCircle,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  useResponderPlaybooks,
  usePlaybookExecution,
  filterPlaybooks,
  getAllTags,
  getTagColor,
  getTriggerTypeLabel,
  type PlaybookSummary,
} from '@/hooks/use-responder-playbooks'
import { addExecutionToHistory } from '@/hooks/use-execution-status'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'

function PlaybookCard({
  playbook,
  onExecute,
}: {
  playbook: PlaybookSummary
  onExecute: (playbook: PlaybookSummary) => void
}) {
  return (
    <Card
      className="group border-l-4 border-l-blue-500 transition-all duration-200 hover:shadow-lg"
      data-testid="playbook-card"
      data-playbook-id={playbook.playbook_id}
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <CardTitle className="text-lg font-semibold transition-colors group-hover:text-blue-600">
              {playbook.name}
            </CardTitle>
            <CardDescription className="text-sm">{playbook.description}</CardDescription>
          </div>
          <Badge variant="outline" className="ml-2 shrink-0">
            v{playbook.version}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-4">
          {/* Tags */}
          <div className="flex flex-wrap gap-1.5">
            {playbook.tags.map((tag: string) => (
              <Badge key={tag} variant="secondary" className={`text-xs ${getTagColor(tag)}`}>
                {tag}
              </Badge>
            ))}
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <User className="h-4 w-4" />
              <span>{playbook.author}</span>
            </div>
            <div className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span>{playbook.steps_count} steps</span>
            </div>
          </div>

          {/* Trigger info */}
          <div className="flex items-center gap-2 text-sm">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Clock className="h-4 w-4" />
              <span>Trigger: {getTriggerTypeLabel(playbook.trigger_type)}</span>
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-2 border-t pt-2">
            <Button
              onClick={() => onExecute(playbook)}
              className="flex-1 bg-blue-600 hover:bg-blue-700"
              size="sm"
            >
              <Play className="mr-2 h-4 w-4" />
              Execute
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

interface ExecutionDialogProps {
  playbook: PlaybookSummary | null
  isOpen: boolean
  onClose: () => void
  onExecute: (triggerData: string) => void
  isLoading: boolean
}

function ExecutionDialog({
  playbook,
  isOpen,
  onClose,
  onExecute,
  isLoading,
}: ExecutionDialogProps) {
  const [triggerData, setTriggerData] = useState('{}')
  const [error, setError] = useState<string | null>(null)

  const handleExecute = () => {
    try {
      // Validate JSON
      JSON.parse(triggerData)
      setError(null)
      onExecute(triggerData)
    } catch {
      setError('Invalid JSON format')
    }
  }

  const getExampleData = (playbookId: string): string => {
    const examples: Record<string, string> = {
      simple_notification: JSON.stringify({ message: 'Test notification' }, null, 2),
      triage_ip: JSON.stringify({ ip: '8.8.8.8' }, null, 2),
      triage_url: JSON.stringify({ url: 'https://example.com' }, null, 2),
    }
    return examples[playbookId] || '{}'
  }

  if (!playbook) return null

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[550px]">
        <DialogHeader>
          <DialogTitle>Execute Playbook: {playbook.name}</DialogTitle>
          <DialogDescription>{playbook.description}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="trigger-data">Trigger Data (JSON)</Label>
            <Textarea
              id="trigger-data"
              value={triggerData}
              onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                setTriggerData(e.target.value)
              }
              placeholder={getExampleData(playbook.playbook_id)}
              className="min-h-[150px] font-mono text-sm"
            />
            {error && (
              <div className="flex items-center gap-2 text-sm text-red-600">
                <XCircle className="h-4 w-4" />
                {error}
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 rounded-md bg-blue-50 p-3 text-sm text-muted-foreground dark:bg-blue-950">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>
              Execution will start asynchronously. You&apos;ll be redirected to the runs page to
              monitor progress.
            </span>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isLoading}>
            Cancel
          </Button>
          <Button onClick={handleExecute} disabled={isLoading}>
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Starting...
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" />
                Execute
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function PlaybooksPage() {
  const router = useRouter()
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedTag, setSelectedTag] = useState<string>('all')
  const [executionDialog, setExecutionDialog] = useState<{
    isOpen: boolean
    playbook: PlaybookSummary | null
  }>({
    isOpen: false,
    playbook: null,
  })

  // Use custom hooks
  const { playbooks, total, isLoading, error, refetch } = useResponderPlaybooks()

  const { execute, isLoading: isExecuting } = usePlaybookExecution({
    onSuccess: response => {
      // Save to history
      addExecutionToHistory({
        run_id: response.run_id,
        playbook_id: response.playbook_id,
        playbook_name: response.playbook_name,
        started_at: new Date().toISOString(),
      })

      // Close dialog
      setExecutionDialog({ isOpen: false, playbook: null })

      // Redirect to runs page
      router.push(`/response/runs?run_id=${response.run_id}`)
    },
    onError: error => {
      alert(`Failed to execute playbook: ${error.message}`)
    },
  })

  // Filter playbooks
  const filteredList = filterPlaybooks(
    selectedTag === 'all' ? playbooks : playbooks.filter(p => p.tags.includes(selectedTag)),
    searchTerm
  )

  // Get all unique tags
  const allTags = getAllTags(playbooks)

  const handleExecutePlaybook = (playbook: PlaybookSummary) => {
    setExecutionDialog({
      isOpen: true,
      playbook,
    })
  }

  const handleConfirmExecution = (triggerDataJson: string) => {
    if (!executionDialog.playbook) return

    try {
      const triggerData = JSON.parse(triggerDataJson)
      execute(executionDialog.playbook.playbook_id, { trigger_data: triggerData })
    } catch (e) {
      console.error('Invalid JSON:', e)
    }
  }

  if (error) {
    return (
      <div className="flex min-h-[400px] flex-col items-center justify-center text-center">
        <AlertCircle className="mb-4 h-12 w-12 text-red-500" />
        <h3 className="mb-2 text-lg font-semibold">Failed to load playbooks</h3>
        <p className="mb-4 text-muted-foreground">
          Unable to connect to the Response service. Please check if the service is running.
        </p>
        <Button onClick={() => refetch()}>Try Again</Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Response Playbooks</h1>
          <p className="text-muted-foreground">
            Automated security response workflows and orchestration
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="px-3 py-1">
            <Book className="mr-1 h-4 w-4" />
            {total} playbooks
          </Badge>
          <Button onClick={() => refetch()} variant="outline" size="sm">
            Refresh
          </Button>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="flex flex-col gap-4 sm:flex-row">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
          <Input
            placeholder="Search playbooks..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <select
            value={selectedTag}
            onChange={e => setSelectedTag(e.target.value)}
            className="rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            <option value="all">All tags</option>
            {allTags.map(tag => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Playbooks Grid */}
      {isLoading ? (
        <div className="flex min-h-[300px] items-center justify-center">
          <div className="flex items-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            <span>Loading playbooks...</span>
          </div>
        </div>
      ) : filteredList.length > 0 ? (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {filteredList.map(playbook => (
            <PlaybookCard
              key={playbook.playbook_id}
              playbook={playbook}
              onExecute={handleExecutePlaybook}
            />
          ))}
        </div>
      ) : (
        <div className="flex min-h-[300px] flex-col items-center justify-center text-center">
          <Book className="mb-4 h-12 w-12 text-muted-foreground" />
          <h3 className="mb-2 text-lg font-semibold">No playbooks found</h3>
          <p className="text-muted-foreground">
            {searchTerm || selectedTag !== 'all'
              ? 'Try adjusting your search or filter criteria.'
              : 'No playbooks are currently available.'}
          </p>
        </div>
      )}

      {/* Execution Dialog */}
      <ExecutionDialog
        playbook={executionDialog.playbook}
        isOpen={executionDialog.isOpen}
        onClose={() => setExecutionDialog({ isOpen: false, playbook: null })}
        onExecute={handleConfirmExecution}
        isLoading={isExecuting}
      />
    </div>
  )
}
