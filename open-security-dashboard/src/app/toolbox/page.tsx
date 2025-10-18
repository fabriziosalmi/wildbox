'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  Search, 
  Play, 
  Settings, 
  Clock, 
  CheckCircle,
  AlertCircle,
  Loader2,
  ExternalLink,
  Book,
  Filter
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MainLayout } from '@/components/main-layout'
import { apiClient } from '@/lib/api-client'

interface SecurityTool {
  name: string
  display_name: string
  description: string
  version: string
  author: string
  category: string
  endpoint: string
}

interface ToolExecution {
  id: string
  tool: string
  status: 'running' | 'completed' | 'failed'
  startTime: string
  duration?: number
  result?: any
}

async function fetchSecurityTools(): Promise<SecurityTool[]> {
  try {
    // Use the gateway-aware API client
    // apiClient base URL is already http://localhost:80/api/v1/tools (when using gateway)
    // so we just need to append the path without /api prefix
    const response = await apiClient.get('/tools')
    return response
  } catch (error) {
    console.error('Failed to fetch security tools:', error)
    return []
  }
}

function getCategoryColor(category: string): string {
  const colors: Record<string, string> = {
    'network_security': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100',
    'web_security': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100',
    'reconnaissance': 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-100',
    'cryptography': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100',
    'vulnerability_assessment': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100',
    'security_analysis': 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-100',
    'osint': 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-100',
    'general': 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-100'
  }
  return colors[category] || colors['general']
}

function formatCategoryName(category: string): string {
  return category.split('_').map(word => 
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ')
}

function ToolCard({ tool, onExecute }: { tool: SecurityTool; onExecute: (tool: SecurityTool) => void }) {
  return (
    <Card className="hover:shadow-md transition-shadow cursor-pointer group">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <CardTitle className="text-lg group-hover:text-primary transition-colors">
              {tool.display_name}
            </CardTitle>
            <CardDescription className="mt-1">
              {tool.description}
            </CardDescription>
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
            <Button 
              onClick={() => onExecute(tool)}
              className="flex-1"
              size="sm"
            >
              <Play className="h-4 w-4 mr-2" />
              Execute Tool
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => window.open(`${process.env.NEXT_PUBLIC_API_BASE_URL}/tools/${tool.name}`, '_blank')}
            >
              <Settings className="h-4 w-4" />
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => window.open(`${process.env.NEXT_PUBLIC_API_BASE_URL}/docs#/Security%20Tools/execute_${tool.name}_api_tools__tool_name__post`, '_blank')}
            >
              <Book className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function ExecutionPanel({ executions }: { executions: ToolExecution[] }) {
  if (executions.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recent Executions</CardTitle>
          <CardDescription>
            Tool execution history will appear here
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No recent executions</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Recent Executions</CardTitle>
        <CardDescription>
          Latest tool execution results
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {executions.map((execution) => (
            <div key={execution.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
              <div className="flex items-center gap-3">
                {execution.status === 'running' && <Loader2 className="h-4 w-4 animate-spin text-blue-500" />}
                {execution.status === 'completed' && <CheckCircle className="h-4 w-4 text-green-500" />}
                {execution.status === 'failed' && <AlertCircle className="h-4 w-4 text-red-500" />}
                
                <div>
                  <p className="font-medium">{execution.tool}</p>
                  <p className="text-sm text-muted-foreground">
                    {new Date(execution.startTime).toLocaleTimeString()}
                    {execution.duration && ` • ${execution.duration}s`}
                  </p>
                </div>
              </div>
              
              <Badge variant={
                execution.status === 'completed' ? 'default' :
                execution.status === 'running' ? 'secondary' : 'destructive'
              }>
                {execution.status}
              </Badge>
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
  const [executions, setExecutions] = useState<ToolExecution[]>([])

  const { data: tools = [], isLoading, error } = useQuery({
    queryKey: ['security-tools'],
    queryFn: fetchSecurityTools,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Get unique categories
  const categories = ['all', ...Array.from(new Set(tools.map(tool => tool.category)))]

  // Filter tools based on search and category
  const filteredTools = tools.filter(tool => {
    const matchesSearch = tool.display_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         tool.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         tool.category.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesCategory = selectedCategory === 'all' || tool.category === selectedCategory
    
    return matchesSearch && matchesCategory
  })

  const handleExecuteTool = (tool: SecurityTool) => {
    // Create a new execution entry
    const execution: ToolExecution = {
      id: Date.now().toString(),
      tool: tool.display_name,
      status: 'running',
      startTime: new Date().toISOString()
    }
    
    setExecutions(prev => [execution, ...prev.slice(0, 9)]) // Keep last 10
    
    // Open the tool execution page in the API service
    const toolUrl = `${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}/tools/${tool.name}`
    window.open(toolUrl, '_blank')
    
    // Simulate completion (in reality, this would be handled by the API)
    setTimeout(() => {
      setExecutions(prev => prev.map(exec => 
        exec.id === execution.id 
          ? { ...exec, status: 'completed' as const, duration: Math.floor(Math.random() * 30) + 5 }
          : exec
      ))
    }, 3000)
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
                  <div className="h-4 bg-muted rounded mb-2" />
                  <div className="h-3 bg-muted rounded w-3/4" />
                </CardHeader>
                <CardContent>
                  <div className="h-8 bg-muted rounded" />
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
              <div className="text-center py-8">
                <AlertCircle className="h-12 w-12 mx-auto mb-4 text-red-500" />
                <h3 className="text-lg font-semibold mb-2">Failed to Load Tools</h3>
                <p className="text-muted-foreground mb-4">
                  Unable to connect to the security API service.
                </p>
                <Button 
                  onClick={() => window.location.reload()}
                  variant="outline"
                >
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
              Execute security tools and analyze results
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button 
              variant="outline"
              onClick={() => window.open(`${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}/docs`, '_blank')}
            >
              <Book className="h-4 w-4 mr-2" />
              API Docs
            </Button>
            <Button 
              variant="outline"
              onClick={() => window.open(`${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}`, '_blank')}
            >
              <ExternalLink className="h-4 w-4 mr-2" />
              Web Interface
            </Button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-2">
                <div className="h-8 w-8 bg-primary/10 rounded flex items-center justify-center">
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
                <div className="h-8 w-8 bg-green-100 rounded flex items-center justify-center">
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
                <div className="h-8 w-8 bg-blue-100 rounded flex items-center justify-center">
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
                <div className="h-8 w-8 bg-orange-100 rounded flex items-center justify-center">
                  <Clock className="h-4 w-4 text-orange-600" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Recent Runs</p>
                  <p className="text-xl font-bold">{executions.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Search and Filters */}
        <Card>
          <CardContent className="p-6">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search tools by name, description, or category..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>
              <div className="md:w-48">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="w-full h-10 px-3 border border-input bg-background rounded-md text-sm"
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
              <h2 className="text-xl font-semibold">
                Available Tools ({filteredTools.length})
              </h2>
              
              {filteredTools.length === 0 ? (
                <Card>
                  <CardContent className="pt-6">
                    <div className="text-center py-8">
                      <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <h3 className="text-lg font-semibold mb-2">No Tools Found</h3>
                      <p className="text-muted-foreground">
                        Try adjusting your search or filter criteria.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  {filteredTools.map((tool) => (
                    <ToolCard
                      key={tool.name}
                      tool={tool}
                      onExecute={handleExecuteTool}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Execution Panel */}
          <div>
            <ExecutionPanel executions={executions} />
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
