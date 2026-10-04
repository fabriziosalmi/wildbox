'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { Search, Settings, CheckCircle, AlertCircle, Book, Filter, Play } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MainLayout } from '@/components/main-layout'
import { apiClient, type ApiError } from '@/lib/api-client'

// The route that runs a tool, as the gateway exposes it. Each card used to
// open the tools service's own page for the tool at /tools/<name>; that
// standalone UI is removed (#581). The card names the API call, and opens
// the dashboard's own page for the tool, which runs it (#585).
const toolApiPath = (name: string) => `/api/v1/tools/${encodeURIComponent(name)}`

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

// apiClient is mounted on the gateway's /api/v1, so this is GET /api/v1/tools.
// A failure is left to reach the error state: it used to be turned into an
// empty list, which read as a toolbox with 0 tools (#572).
function fetchSecurityTools(): Promise<SecurityTool[]> {
  return apiClient.get<SecurityTool[]>('/tools')
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

function ToolCard({ tool }: { tool: SecurityTool }) {
  return (
    <Card className="group transition-shadow hover:shadow-md">
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
            <code className="flex-1 truncate rounded bg-muted px-2 py-1 text-xs">
              POST {toolApiPath(tool.name)}
            </code>
            <Button asChild size="sm" data-testid={`open-tool-${tool.name}`}>
              <Link href={`/toolbox/${encodeURIComponent(tool.name)}`}>
                <Play className="mr-1 h-4 w-4" />
                Run
              </Link>
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

export default function ToolboxPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')

  const {
    data: tools = [],
    isLoading,
    error,
    refetch,
    isFetching,
  } = useQuery<SecurityTool[], ApiError>({
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
          <Card data-testid="toolbox-error" role="alert">
            <CardContent className="pt-6">
              <div className="py-8 text-center">
                <AlertCircle className="mx-auto mb-4 h-12 w-12 text-red-500" />
                <h3 className="mb-2 text-lg font-semibold">Failed to Load Tools</h3>
                <p className="mb-4 text-muted-foreground">
                  {error.message || 'Unable to connect to the security API service.'}
                </p>
                <Button onClick={() => refetch()} variant="outline" disabled={isFetching}>
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
            <p className="text-muted-foreground">
              Browse the security tools and run them here or through the API
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => openInNewTab(API_DOCS_PATH)}>
              <Book className="mr-2 h-4 w-4" />
              API Docs
            </Button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded bg-primary/10">
                  <Settings className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Total Tools</p>
                  <p className="text-xl font-bold" data-testid="toolbox-total">
                    {tools.length}
                  </p>
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
        </div>

        {/* Search and Filters */}
        <Card>
          <CardContent className="p-6">
            <div className="flex flex-col gap-4 md:flex-row">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 transform text-muted-foreground" />
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

        {/* Tools Grid */}
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
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {filteredTools.map(tool => (
                <ToolCard key={tool.name} tool={tool} />
              ))}
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}
