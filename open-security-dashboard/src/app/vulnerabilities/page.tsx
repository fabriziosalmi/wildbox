'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  Search, 
  Filter, 
  Download, 
  Bug, 
  AlertTriangle, 
  Shield, 
  Clock,
  User,
  Calendar,
  ChevronDown,
  Eye,
  Edit,
  Trash2,
  RefreshCw
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { MainLayout } from '@/components/main-layout'
import { guardianClient, getGuardianPath } from '@/lib/api-client'
import { formatRelativeTime } from '@/lib/utils'
import { GuardianVulnerability } from '@/types'
import { useAuth } from '@/components/auth-provider'

interface VulnerabilityListResponse {
  count: number
  next?: string
  previous?: string
  results: GuardianVulnerability[]
}

interface VulnerabilityStats {
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  open_count: number
  in_progress_count: number
  resolved_count: number
  overdue_count: number
  due_today_count: number
  due_this_week_count: number
  avg_risk_score: number
  avg_resolution_time_days: number
}

const severityColors = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white'
}

const statusColors = {
  open: 'bg-red-100 text-red-800',
  in_progress: 'bg-blue-100 text-blue-800',
  resolved: 'bg-green-100 text-green-800',
  accepted: 'bg-gray-100 text-gray-800',
  false_positive: 'bg-purple-100 text-purple-800',
  duplicate: 'bg-yellow-100 text-yellow-800'
}

export default function VulnerabilitiesPage() {
  const { isAuthenticated, isLoading: authLoading, user } = useAuth()
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [pageSize] = useState(25)
  const [mounted, setMounted] = useState(false)

  // Track when component is mounted to prevent hydration mismatches
  useEffect(() => {
    setMounted(true)
  }, [])

  // Debug authentication state
  useEffect(() => {
    if (mounted) {
      console.log('🔍 VulnerabilitiesPage Auth State:', {
        isAuthenticated,
        authLoading,
        user: user?.email,
        mounted,
        canRunQueries: isAuthenticated && !authLoading && mounted
      })
    }
  }, [isAuthenticated, authLoading, user, mounted])

  // Query for vulnerability statistics
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery<VulnerabilityStats>({
    queryKey: ['vulnerability-stats'],
    queryFn: async (): Promise<VulnerabilityStats> => {
      console.log('🔍 Starting stats query...')
      console.log('🔍 Auth state:', { isAuthenticated, authLoading, user: user?.email })
      
      try {
        const originalPath = '/api/v1/vulnerabilities/vulnerabilities/stats/'
        const path = getGuardianPath(originalPath)
        console.log('🔍 Original path:', originalPath)
        console.log('🔍 Transformed path:', path)
        
        const response = await guardianClient.get(path)
        console.log('✅ Stats API Response:', response)
        
        // Ensure we always return a valid object with the correct structure
        const data: VulnerabilityStats = {
          total_vulnerabilities: response.total_vulnerabilities || 0,
          critical_count: response.critical_count || 0,
          high_count: response.high_count || 0,
          medium_count: response.medium_count || 0,
          low_count: response.low_count || 0,
          info_count: response.info_count || 0,
          open_count: response.open_count || 0,
          in_progress_count: response.in_progress_count || 0,
          resolved_count: response.resolved_count || 0,
          overdue_count: response.overdue_count || 0,
          due_today_count: response.due_today_count || 0,
          due_this_week_count: response.due_this_week_count || 0,
          avg_risk_score: response.avg_risk_score || 0,
          avg_resolution_time_days: response.avg_resolution_time_days || 0
        }
        
        console.log('✅ Returning stats data:', data)
        return data
      } catch (error: any) {
        console.error('❌ Stats API Error:', error)
        console.error('❌ Error details:', {
          message: error?.message,
          status: error?.status,
          response: error?.response?.data
        })
        
        // Return default data instead of throwing to prevent undefined
        const fallbackData: VulnerabilityStats = {
          total_vulnerabilities: 0,
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
          info_count: 0,
          open_count: 0,
          in_progress_count: 0,
          resolved_count: 0,
          overdue_count: 0,
          due_today_count: 0,
          due_this_week_count: 0,
          avg_risk_score: 0,
          avg_resolution_time_days: 0
        }
        console.log('🔄 Returning fallback stats data:', fallbackData)
        return fallbackData
      }
    },
    enabled: mounted && isAuthenticated && !authLoading,
    retry: false, // Disable retry to prevent loops
    staleTime: 30000, // 30 seconds
    gcTime: 300000, // 5 minutes
    refetchOnWindowFocus: false
  })

  // Query for vulnerabilities list
  const { data: vulnerabilities, isLoading: vulnsLoading, error: vulnsError, refetch } = useQuery<VulnerabilityListResponse>({
    queryKey: ['vulnerabilities', search, severityFilter, statusFilter, page],
    queryFn: async (): Promise<VulnerabilityListResponse> => {
      console.log('🔍 Starting vulnerabilities query...')
      console.log('🔍 Auth state:', { isAuthenticated, authLoading, user: user?.email })
      console.log('🔍 Query params:', { search, severityFilter, statusFilter, page })
      
      try {
        let originalPath = '/api/v1/vulnerabilities/vulnerabilities/'
        const params = new URLSearchParams()
        
        params.append('page', page.toString())
        params.append('page_size', pageSize.toString())
        
        if (search.trim()) {
          params.append('search', search.trim())
        }
        
        if (severityFilter !== 'all') {
          params.append('severity', severityFilter)
        }
        
        if (statusFilter !== 'all') {
          params.append('status', statusFilter)
        }
        
        if (params.toString()) {
          originalPath += '?' + params.toString()
        }
        
        const path = getGuardianPath(originalPath)
        console.log('🔍 Original path:', originalPath)
        console.log('🔍 Transformed path:', path)
        
        const response = await guardianClient.get(path)
        console.log('✅ Vulnerabilities API Response:', response)
        
        // Ensure we always return a valid object with the correct structure
        const data: VulnerabilityListResponse = {
          count: response.count || 0,
          next: response.next || undefined,
          previous: response.previous || undefined,
          results: Array.isArray(response.results) ? response.results : []
        }
        
        console.log('✅ Returning vulnerabilities data:', data)
        return data
      } catch (error: any) {
        console.error('❌ Vulnerabilities API Error:', error)
        console.error('❌ Error details:', {
          message: error?.message,
          status: error?.status,
          response: error?.response?.data
        })
        
        // Return default data instead of throwing to prevent undefined
        const fallbackData: VulnerabilityListResponse = {
          count: 0,
          results: []
        }
        console.log('🔄 Returning fallback vulnerabilities data:', fallbackData)
        return fallbackData
      }
    },
    enabled: mounted && isAuthenticated && !authLoading,
    retry: false, // Disable retry to prevent loops  
    staleTime: 30000, // 30 seconds
    gcTime: 300000, // 5 minutes
    refetchOnWindowFocus: false
  })
      
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setPage(1)
    refetch()
  }

  const totalPages = vulnerabilities ? Math.ceil(vulnerabilities.count / pageSize) : 0

  // Show loading state while authentication is in progress
  if (!mounted || authLoading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center min-h-[400px]">
          <div className="text-center">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4" />
            <p className="text-muted-foreground">Loading...</p>
          </div>
        </div>
      </MainLayout>
    )
  }

  // Show login prompt if not authenticated
  if (!isAuthenticated) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center min-h-[400px]">
          <div className="text-center">
            <Shield className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
            <h2 className="text-xl font-semibold mb-2">Authentication Required</h2>
            <p className="text-muted-foreground mb-4">Please log in to view vulnerabilities.</p>
            <Button asChild>
              <a href="/auth/login">Go to Login</a>
            </Button>
          </div>
        </div>
      </MainLayout>
    )
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Vulnerabilities</h1>
            <p className="text-muted-foreground">
              Manage and track security vulnerabilities across your infrastructure
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button onClick={() => refetch()} variant="outline" size="sm">
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Statistics Cards */}
        {statsError ? (
          <Card>
            <CardContent className="pt-6">
              <div className="text-center py-4">
                <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-2" />
                <p className="text-red-600 font-medium">Failed to load statistics</p>
                <p className="text-sm text-muted-foreground">{statsError.message}</p>
              </div>
            </CardContent>
          </Card>
        ) : statsLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <Card key={i}>
                <CardContent className="pt-6">
                  <div className="animate-pulse">
                    <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                    <div className="h-8 bg-gray-200 rounded w-1/2"></div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
                <Bug className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats.total_vulnerabilities || 0}</div>
                <p className="text-xs text-muted-foreground">
                  {stats.due_today_count || 0} due today
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Critical & High</CardTitle>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">
                  {(stats.critical_count || 0) + (stats.high_count || 0)}
                </div>
                <p className="text-xs text-muted-foreground">
                  {stats.critical_count || 0} critical, {stats.high_count || 0} high
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">In Progress</CardTitle>
                <Clock className="h-4 w-4 text-yellow-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-yellow-600">
                  {stats.in_progress_count || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  {stats.overdue_count || 0} overdue
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Resolved</CardTitle>
                <Shield className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">
                  {stats.resolved_count || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  Avg {(stats.avg_resolution_time_days || 0).toFixed(1)} days to resolve
                </p>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Filters */}
        <Card>
          <CardContent className="pt-6">
            <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search vulnerabilities..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full"
                />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="open">Open</SelectItem>
                  <SelectItem value="in_progress">In Progress</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                  <SelectItem value="accepted">Accepted</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="duplicate">Duplicate</SelectItem>
                </SelectContent>
              </Select>
              <Button type="submit">
                <Search className="w-4 h-4 mr-2" />
                Search
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Vulnerabilities List */}
        <Card>
          <CardHeader>
            <CardTitle>Vulnerabilities</CardTitle>
            <CardDescription>
              {vulnerabilities ? `${vulnerabilities.count} total vulnerabilities` : 'Loading...'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {vulnsError ? (
              <div className="text-center py-8">
                <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
                <p className="text-red-600 font-medium mb-2">Failed to load vulnerabilities</p>
                <p className="text-sm text-muted-foreground mb-4">{vulnsError.message}</p>
                <Button onClick={() => refetch()} variant="outline">
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Try Again
                </Button>
              </div>
            ) : vulnsLoading ? (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="w-6 h-6 animate-spin" />
                <span className="ml-2">Loading vulnerabilities...</span>
              </div>
            ) : vulnerabilities?.results?.length === 0 ? (
              <div className="text-center py-8">
                <Bug className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No vulnerabilities found</p>
              </div>
            ) : (
              <div className="space-y-4">
                {vulnerabilities?.results?.map((vuln) => (
                  <div key={vuln.id} className="border rounded-lg p-4 hover:bg-muted/50 transition-colors">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 space-y-2">
                        <div className="flex items-center gap-3">
                          <h3 className="font-semibold text-lg">{vuln.title}</h3>
                          <Badge className={severityColors[vuln.severity]}>
                            {vuln.severity.toUpperCase()}
                          </Badge>
                          <Badge variant="outline" className={statusColors[vuln.status]}>
                            {vuln.status.replace('_', ' ').toUpperCase()}
                          </Badge>
                          {vuln.cve_id && (
                            <Badge variant="outline">
                              {vuln.cve_id}
                            </Badge>
                          )}
                        </div>
                        
                        <p className="text-muted-foreground">{vuln.description}</p>
                        
                        <div className="flex items-center gap-6 text-sm text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <Shield className="w-4 h-4" />
                            <span>CVSS: {vuln.cvss_v3_score?.toFixed(1) || 'N/A'}</span>
                          </div>
                          {vuln.asset_name && (
                            <div className="flex items-center gap-1">
                              <User className="w-4 h-4" />
                              <span>Asset: {vuln.asset_name}</span>
                            </div>
                          )}
                          <div className="flex items-center gap-1">
                            <Calendar className="w-4 h-4" />
                            <span>Created: {formatRelativeTime(new Date(vuln.created_at))}</span>
                          </div>
                          {vuln.due_date && (
                            <div className="flex items-center gap-1">
                              <Clock className="w-4 h-4" />
                              <span>Due: {formatRelativeTime(new Date(vuln.due_date))}</span>
                            </div>
                          )}
                        </div>
                        
                        {vuln.asset_name && (
                          <div className="flex items-center gap-2">
                            <span className="text-sm text-muted-foreground">Asset:</span>
                            <Badge variant="secondary" className="text-xs">
                              {vuln.asset_name} ({vuln.asset_type})
                            </Badge>
                          </div>
                        )}
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <Button variant="ghost" size="sm">
                          <Eye className="w-4 h-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Edit className="w-4 h-4" />
                        </Button>
                        <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive">
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-6">
                <div className="text-sm text-muted-foreground">
                  Showing {((page - 1) * pageSize) + 1} to {Math.min(page * pageSize, vulnerabilities?.count || 0)} of {vulnerabilities?.count || 0} results
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(page - 1)}
                    disabled={page === 1}
                  >
                    Previous
                  </Button>
                  <div className="flex items-center gap-1">
                    {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                      const pageNum = Math.max(1, Math.min(totalPages - 4, page - 2)) + i
                      return (
                        <Button
                          key={pageNum}
                          variant={pageNum === page ? "default" : "outline"}
                          size="sm"
                          onClick={() => setPage(pageNum)}
                          className="w-8 h-8 p-0"
                        >
                          {pageNum}
                        </Button>
                      )
                    })}
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(page + 1)}
                    disabled={page === totalPages}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  )
}
