'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import Link from 'next/link'
import { 
  PlayCircle, 
  Book, 
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
  ChevronRight,
  Zap,
  AlertTriangle,
  TrendingUp
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MainLayout } from '@/components/main-layout'
import { responderClient } from '@/lib/api-client'

interface DashboardStats {
  totalPlaybooks: number
  totalRuns: number
  runningNow: number
  successRate: number
  recentRuns: Array<{
    id: string
    playbookName: string
    status: string
    startTime: string
  }>
}

// Mock data for demonstration
const mockStats: DashboardStats = {
  totalPlaybooks: 3,
  totalRuns: 45,
  runningNow: 2,
  successRate: 87,
  recentRuns: [
    {
      id: 'run-001',
      playbookName: 'IP Address Triage',
      status: 'completed',
      startTime: new Date(Date.now() - 30000).toISOString(),
    },
    {
      id: 'run-002',
      playbookName: 'URL Analysis and Response',
      status: 'running',
      startTime: new Date(Date.now() - 45000).toISOString(),
    },
    {
      id: 'run-003',
      playbookName: 'Simple Notification Test',
      status: 'failed',
      startTime: new Date(Date.now() - 120000).toISOString(),
    },
  ]
}

async function fetchDashboardStats(): Promise<DashboardStats> {
  try {
    // Try to fetch real data from multiple endpoints
    const [playbooksResponse] = await Promise.allSettled([
      responderClient.get('/v1/playbooks')
    ])

    let totalPlaybooks = 0
    if (playbooksResponse.status === 'fulfilled') {
      totalPlaybooks = playbooksResponse.value?.total || 0
    }

    // For now, return mock data with real playbook count
    return {
      ...mockStats,
      totalPlaybooks
    }
  } catch (error) {
    console.warn('API not available, using mock data:', error)
    return mockStats
  }
}

function getStatusIcon(status: string, size = 'h-4 w-4') {
  switch (status) {
    case 'completed':
      return <CheckCircle className={`${size} text-green-500`} />
    case 'running':
      return <Loader2 className={`${size} text-blue-500 animate-spin`} />
    case 'failed':
      return <XCircle className={`${size} text-red-500`} />
    default:
      return <Clock className={`${size} text-gray-500`} />
  }
}

function formatTimeAgo(timestamp: string): string {
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000)
  
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export default function ResponsePage() {
  const { data: stats, isLoading, error, refetch } = useQuery({
    queryKey: ['response-dashboard'],
    queryFn: fetchDashboardStats,
    refetchInterval: 30000,
  })

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Response & Automation</h1>
            <p className="text-muted-foreground">
              Incident response playbooks and automated security workflows
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button onClick={() => refetch()} variant="outline" size="sm">
              Refresh
            </Button>
          </div>
        </div>

        {/* Quick Stats */}
        {isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {[...Array(4)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                  <div className="h-4 w-4 bg-gray-200 rounded"></div>
                </CardHeader>
                <CardContent>
                  <div className="h-8 bg-gray-200 rounded w-1/3 mb-1"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Playbooks</CardTitle>
                <Book className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.totalPlaybooks || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Available security workflows
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Runs</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats?.totalRuns || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Executions this month
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Running Now</CardTitle>
                <Zap className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-600">{stats?.runningNow || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Active executions
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">{stats?.successRate || 0}%</div>
                <p className="text-xs text-muted-foreground">
                  Last 30 days
                </p>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Quick Actions */}
        <div className="grid gap-6 md:grid-cols-2">
          <Card className="group hover:shadow-lg transition-all duration-200">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Book className="h-5 w-5 text-blue-600" />
                Playbooks
              </CardTitle>
              <CardDescription>
                View and execute automated response workflows
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex justify-between items-center text-sm">
                  <span>Available playbooks</span>
                  <Badge variant="outline">{stats?.totalPlaybooks || 0}</Badge>
                </div>
                <Link href="/response/playbooks">
                  <Button className="w-full group-hover:bg-blue-700">
                    Manage Playbooks
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>

          <Card className="group hover:shadow-lg transition-all duration-200">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-green-600" />
                Execution History
              </CardTitle>
              <CardDescription>
                Monitor and review playbook run history
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex justify-between items-center text-sm">
                  <span>Total runs</span>
                  <Badge variant="outline">{stats?.totalRuns || 0}</Badge>
                </div>
                <Link href="/response/runs">
                  <Button className="w-full group-hover:bg-green-700" variant="default">
                    View Run History
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Recent Activity
            </CardTitle>
            <CardDescription>
              Latest playbook executions and their status
            </CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.recentRuns && stats.recentRuns.length > 0 ? (
              <div className="space-y-3">
                {stats.recentRuns.map((run) => (
                  <div key={run.id} className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(run.status)}
                      <div>
                        <p className="font-medium">{run.playbookName}</p>
                        <p className="text-sm text-muted-foreground">ID: {run.id}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge className={
                        run.status === 'completed' ? 'bg-green-100 text-green-800' :
                        run.status === 'running' ? 'bg-blue-100 text-blue-800' :
                        'bg-red-100 text-red-800'
                      }>
                        {run.status}
                      </Badge>
                      <p className="text-sm text-muted-foreground mt-1">
                        {formatTimeAgo(run.startTime)}
                      </p>
                    </div>
                  </div>
                ))}
                <div className="pt-2 border-t">
                  <Link href="/response/runs">
                    <Button variant="outline" className="w-full">
                      View All Runs
                      <ChevronRight className="ml-2 h-4 w-4" />
                    </Button>
                  </Link>
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">No recent activity</h3>
                <p className="text-muted-foreground">
                  No playbook runs have been executed recently.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  )
}
