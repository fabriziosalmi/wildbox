'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Search,
  Play,
  Settings,
  Clock,
  CheckCircle,
  AlertCircle,
  ExternalLink,
  Book,
  Filter,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MainLayout } from '@/components/main-layout'
import { apiClient, gatewayBaseUrl } from '@/lib/api-client'

// A tool's own page in the tools service, through the gateway's /tools/
// route, which accepts the dashboard's session cookie. These links used
// NEXT_PUBLIC_API_BASE_URL, which no build set (it fell back to the tools
// service's port on the browser's machine, http://localhost:8000) and which
// docker-compose.yml pointed at a path that does not exist (#559).
const toolPageUrl = (name: string) => `${gatewayBaseUrl}/tools/${encodeURIComponent(name)}`

// The tools service's own /docs is not routed through the gateway; the
// dashboard's API documentation page is.
const API_DOCS_PATH = '/api-docs'

const openInNewTab = (url: string) => window.open(url, '_blank', 'noopener,noreferrer')

interface SecurityTool {
  name: string
  display_name: string
  description: string
  version: string
  author: string
  category: string
  endpoint: string
}

/**
 * A tool opened from this page. The tool runs in its own tab, in the tools
 * service's page, so this page never learns whether or when it finished: it
 * records only that it was opened. It used to mark each entry "completed"
 * after three seconds with a random duration of 5-34 s (#559).
 */
interface OpenedTool {
  id: string
  tool: string
  openedAt: string
}

async function fetchSecurityTools(): Promise<SecurityTool[]> {
  try {
    // Use the gateway-aware API client
    // apiClient base URL is http://localhost:80/api/v1 (when using gateway)
    // Calling /tools results in full path: /api/v1/tools
    const response = await apiClient.get<SecurityTool[]>('/tools')
    return response
  } catch (error) {
    console.error('Failed to fetch security tools:', error)
    return []
  }
}

function getCategoryColor(category: string): string {
  const colors: Record<string, string> = {
    network_security: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
    web_security: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
    reconnaissance: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-100',
    cryptography: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100',
    vulnerability_assessment: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
    security_analysis: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-100',
    osint: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-100',
    general: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-100',
  }
  return colors[category] || colors['general']
}

function formatCategoryName(category: string): string {
  return category
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

function ToolCard({
  tool,
  onExecute,
}: {
  tool: SecurityTool
  onExecute: (tool: SecurityTool) => void
}) {
  return (
    <Card className="group cursor-pointer transition-shadow hover:shadow-md">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <CardTitle className="text-lg transition-colors group-hover:text-primary">
              {tool.display_name}
            </CardTitle>
            <CardDescription className="mt-1">{tool.description}</CardDescription>
          </div>
          <Badge className={getCategoryColor(tool.category)}>
            {formatCategoryName(tool.category)}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>v{tool.version}</span>
            <span>by {tool.author}</span>
          </div>

          <div className="flex items-center gap-2">
            <Button onClick={() => onExecute(tool)} className="flex-1" size="sm">
              <Play className="mr-2 h-4 w-4" />
              Execute Tool
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => openInNewTab(toolPageUrl(tool.name))}
              aria-label={`Open ${tool.display_name} in the tools service`}
            >
              <Settings className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => openInNewTab(API_DOCS_PATH)}
              aria-label="API documentation"
            >
              <Book className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function OpenedToolsPanel({ opened }: { opened: OpenedTool[] }) {
  if (opened.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recently Opened</CardTitle>
          <CardDescription>Tools you open will be listed here</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="py-8 text-center text-muted-foreground">
            <Clock className="mx-auto mb-4 h-12 w-12 opacity-50" />
            <p>No tools opened yet</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Recently Opened</CardTitle>
        <CardDescription>
          Each tool runs in its own tab; its results are shown there
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {opened.map(entry => (
            <div
              key={entry.id}
              className="flex items-center justify-between rounded-lg bg-muted/50 p-3"
            >
              <div className="flex items-center gap-3">
                <ExternalLink className="h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="font-medium">{entry.tool}</p>
                  <p className="text-sm text-muted-foreground">
                    {new Date(entry.openedAt).toLocaleTimeString()}
                  </p>
                </div>
              </div>

              <Badge variant="secondary">opened</Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export default function ToolboxPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [opened, setOpened] = useState<OpenedTool[]>([])

  const {
    data: tools = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: ['security-tools'],
    queryFn: fetchSecurityTools,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Get unique categories
  const categories = ['all', ...Array.from(new Set(tools.map(tool => tool.category)))]

  // Filter tools based on search and category
  const filteredTools = tools.filter(tool => {
    const matchesSearch =
      tool.display_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tool.category.toLowerCase().includes(searchTerm.toLowerCase())

    const matchesCategory = selectedCategory === 'all' || tool.category === selectedCategory

    return matchesSearch && matchesCategory
  })

  const handleExecuteTool = (tool: SecurityTool) => {
    setOpened(prev => [
      {
        id: `${tool.name}-${Date.now()}`,
        tool: tool.display_name,
        openedAt: new Date().toISOString(),
      },
      ...prev.slice(0, 9), // Keep last 10
    ])

    openInNewTab(toolPageUrl(tool.name))
  }

  if (isLoading) {
    return (
      <MainLayout>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold">Security Toolbox</h1>
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {[...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="mb-2 h-4 rounded bg-muted" />
                  <div className="h-3 w-3/4 rounded bg-muted" />
                </CardHeader>
                <CardContent>
                  <div className="h-8 rounded bg-muted" />
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </MainLayout>
    )
  }

  if (error) {
    return (
      <MainLayout>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold">Security Toolbox</h1>
          </div>
          <Card>
            <CardContent className="pt-6">
              <div className="py-8 text-center">
                <AlertCircle className="mx-auto mb-4 h-12 w-12 text-red-500" />
                <h3 className="mb-2 text-lg font-semibold">Failed to Load Tools</h3>
                <p className="mb-4 text-muted-foreground">
                  Unable to connect to the security API service.
                </p>
                <Button onClick={() => window.location.reload()} variant="outline">
                  Try Again
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </MainLayout>
    )
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Security Toolbox</h1>
            <p className="text-muted-foreground">Execute security tools and analyze results</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => openInNewTab(API_DOCS_PATH)}>
              <Book className="mr-2 h-4 w-4" />
              API Docs
            </Button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded bg-primary/10">
                  <Settings className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Total Tools</p>
                  <p className="text-xl font-bold">{tools.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded bg-green-100">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Available</p>
                  <p className="text-xl font-bold">{tools.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded bg-blue-100">
                  <Filter className="h-4 w-4 text-blue-600" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Categories</p>
                  <p className="text-xl font-bold">{categories.length - 1}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded bg-orange-100">
                  <Clock className="h-4 w-4 text-orange-600" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Recently Opened</p>
                  <p className="text-xl font-bold">{opened.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Search and Filters */}
        <Card>
          <CardContent className="p-6">
            <div className="flex flex-col gap-4 md:flex-row">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
                  <Input
                    placeholder="Search tools by name, description, or category..."
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>
              <div className="md:w-48">
                <select
                  value={selectedCategory}
                  onChange={e => setSelectedCategory(e.target.value)}
                  className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  {categories.map(category => (
                    <option key={category} value={category}>
                      {category === 'all' ? 'All Categories' : formatCategoryName(category)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Main Content */}
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Tools Grid */}
          <div className="lg:col-span-2">
            <div className="space-y-4">
              <h2 className="text-xl font-semibold">Available Tools ({filteredTools.length})</h2>

              {filteredTools.length === 0 ? (
                <Card>
                  <CardContent className="pt-6">
                    <div className="py-8 text-center">
                      <Search className="mx-auto mb-4 h-12 w-12 opacity-50" />
                      <h3 className="mb-2 text-lg font-semibold">No Tools Found</h3>
                      <p className="text-muted-foreground">
                        Try adjusting your search or filter criteria.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  {filteredTools.map(tool => (
                    <ToolCard key={tool.name} tool={tool} onExecute={handleExecuteTool} />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Execution Panel */}
          <div>
            <OpenedToolsPanel opened={opened} />
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
