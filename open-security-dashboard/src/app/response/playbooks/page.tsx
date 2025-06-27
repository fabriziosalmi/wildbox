'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  PlayCircle, 
  Book, 
  Clock, 
  User,
  Tag,
  Settings,
  ChevronRight,
  AlertCircle,
  CheckCircle,
  Loader2,
  Play,
  Search,
  Filter
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { responderClient } from '@/lib/api-client'

interface Playbook {
  playbook_id: string
  name: string
  description: string
  version: string
  author: string
  tags: string[]
  steps_count: number
  trigger_type: string
}

interface PlaybooksResponse {
  playbooks: Playbook[]
  total: number
}

async function fetchPlaybooks(): Promise<PlaybooksResponse> {
  try {
    const response = await responderClient.get('/v1/playbooks')
    return response
  } catch (error) {
    console.error('Failed to fetch playbooks:', error)
    throw error
  }
}

function getCategoryColor(tag: string): string {
  const colors: Record<string, string> = {
    'test': 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-100',
    'notification': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
    'triage': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100',
    'url': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
    'malware': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
    'blacklist': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100',
    'ip': 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-100',
    'network': 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-100',
    'security': 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100',
  }
  return colors[tag] || 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-100'
}

function PlaybookCard({ playbook, onExecute }: { playbook: Playbook; onExecute: (playbook: Playbook) => void }) {
  return (
    <Card className="group hover:shadow-lg transition-all duration-200 border-l-4 border-l-blue-500">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <CardTitle className="text-lg font-semibold group-hover:text-blue-600 transition-colors">
              {playbook.name}
            </CardTitle>
            <CardDescription className="text-sm">
              {playbook.description}
            </CardDescription>
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
            {playbook.tags.map((tag) => (
              <Badge
                key={tag}
                variant="secondary"
                className={`text-xs ${getCategoryColor(tag)}`}
              >
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
              <span>Trigger: {playbook.trigger_type}</span>
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-2 border-t">
            <Button
              onClick={() => onExecute(playbook)}
              className="flex-1 bg-blue-600 hover:bg-blue-700"
              size="sm"
            >
              <Play className="h-4 w-4 mr-2" />
              Execute
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                // TODO: Implement view details
                console.log('View details:', playbook.playbook_id)
              }}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default function PlaybooksPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedTag, setSelectedTag] = useState<string>('all')

  const { data: playbooksData, isLoading, error, refetch } = useQuery({
    queryKey: ['playbooks'],
    queryFn: fetchPlaybooks,
    refetchInterval: 30000, // Refetch every 30 seconds
  })

  const filteredPlaybooks = playbooksData?.playbooks?.filter((playbook) => {
    const matchesSearch = playbook.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         playbook.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         playbook.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
    
    const matchesTag = selectedTag === 'all' || playbook.tags.includes(selectedTag)
    
    return matchesSearch && matchesTag
  }) || []

  const allTags = Array.from(
    new Set(playbooksData?.playbooks?.flatMap(p => p.tags) || [])
  ).sort()

  const handleExecutePlaybook = async (playbook: Playbook) => {
    try {
      // TODO: Implement playbook execution with parameters dialog
      console.log('Execute playbook:', playbook.playbook_id)
      alert(`Executing playbook: ${playbook.name}\n\nThis would open a parameters dialog and start execution.`)
    } catch (error) {
      console.error('Failed to execute playbook:', error)
      alert('Failed to execute playbook. Please try again.')
    }
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] text-center">
        <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
        <h3 className="text-lg font-semibold mb-2">Failed to load playbooks</h3>
        <p className="text-muted-foreground mb-4">
          Unable to connect to the Response service. Please check if the service is running.
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
            <h1 className="text-3xl font-bold tracking-tight">Response Playbooks</h1>
            <p className="text-muted-foreground">
              Automated security response workflows and orchestration
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="px-3 py-1">
              <Book className="h-4 w-4 mr-1" />
              {playbooksData?.total || 0} playbooks
            </Badge>
            <Button onClick={() => refetch()} variant="outline" size="sm">
              Refresh
            </Button>
          </div>
        </div>

        {/* Search and Filter */}
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search playbooks..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <select
              value={selectedTag}
              onChange={(e) => setSelectedTag(e.target.value)}
              className="px-3 py-2 border border-input bg-background rounded-md text-sm"
            >
              <option value="all">All tags</option>
              {allTags.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Playbooks Grid */}
        {isLoading ? (
          <div className="flex items-center justify-center min-h-[300px]">
            <div className="flex items-center gap-2">
              <Loader2 className="h-5 w-5 animate-spin" />
              <span>Loading playbooks...</span>
            </div>
          </div>
        ) : filteredPlaybooks.length > 0 ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {filteredPlaybooks.map((playbook) => (
              <PlaybookCard
                key={playbook.playbook_id}
                playbook={playbook}
                onExecute={handleExecutePlaybook}
              />
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center min-h-[300px] text-center">
            <Book className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No playbooks found</h3>
            <p className="text-muted-foreground">
              {searchTerm || selectedTag !== 'all' 
                ? 'Try adjusting your search or filter criteria.'
                : 'No playbooks are currently available.'}
            </p>
          </div>
        )}
      </div>
  )
}
