'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Radio, Shield, Activity, Clock, Database, ExternalLink, RefreshCw, AlertCircle, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { MainLayout } from '@/components/main-layout'
import { dataClient, getDataPath } from '@/lib/api-client'
import { formatRelativeTime } from '@/lib/utils'

interface Feed {
  id: string
  name: string
  description: string
  source_type: string
  url: string
  enabled: boolean
  status: string
  last_collection: string | null
  collection_count: number
  error_count: number
  created_at: string
  updated_at: string
}

interface FeedStats {
  total_feeds: number
  active_feeds: number
  last_updated: string
  new_indicators: number
  trends_change: number
}

async function fetchFeeds(): Promise<Feed[]> {
  try {
    const response = await dataClient.get(getDataPath('/api/v1/sources?enabled_only=false'))
    return response
  } catch (error) {
    console.error('Failed to fetch feeds:', error)
    throw error
  }
}

async function fetchFeedStats(): Promise<FeedStats> {
  try {
    const response = await dataClient.get(getDataPath('/api/v1/dashboard/threat-intel'))
    return response
  } catch (error) {
    console.error('Failed to fetch feed stats:', error)
    throw error
  }
}

function FeedStatusBadge({ status, enabled }: { status: string; enabled: boolean }) {
  if (!enabled) {
    return (
      <Badge variant="outline" className="bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">
        <XCircle className="w-3 h-3 mr-1" />
        Disabled
      </Badge>
    )
  }

  switch (status) {
    case 'active':
    case 'healthy':
    case 'online':
      return (
        <Badge className="bg-green-500 text-white">
          <CheckCircle2 className="w-3 h-3 mr-1" />
          Active
        </Badge>
      )
    case 'collecting':
      return (
        <Badge className="bg-blue-500 text-white">
          <Loader2 className="w-3 h-3 mr-1 animate-spin" />
          Collecting
        </Badge>
      )
    case 'error':
    case 'failed':
      return (
        <Badge className="bg-red-500 text-white">
          <AlertCircle className="w-3 h-3 mr-1" />
          Error
        </Badge>
      )
    case 'idle':
    case 'waiting':
      return (
        <Badge variant="outline" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100">
          <Clock className="w-3 h-3 mr-1" />
          Idle
        </Badge>
      )
    default:
      return (
        <Badge variant="outline">
          {status}
        </Badge>
      )
  }
}

export default function ThreatIntelFeedsPage() {
  const { data: feeds = [], isLoading: feedsLoading, error: feedsError, refetch: refetchFeeds } = useQuery({
    queryKey: ['threat-intel-feeds'],
    queryFn: fetchFeeds,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['threat-intel-feed-stats'],
    queryFn: fetchFeedStats,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const handleRefresh = () => {
    refetchFeeds()
    refetchStats()
  }

  const activeFeeds = feeds.filter(f => f.enabled)
  const inactiveFeeds = feeds.filter(f => !f.enabled)

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Threat Intelligence Feeds</h1>
            <p className="text-muted-foreground mt-2">
              Real-time threat intelligence from multiple trusted sources
            </p>
          </div>
          <Button onClick={handleRefresh} disabled={feedsLoading || statsLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${(feedsLoading || statsLoading) ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>

        {/* Statistics Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Feeds</CardTitle>
              <Database className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {statsLoading ? '...' : stats?.total_feeds || feeds.length}
              </div>
              <p className="text-xs text-muted-foreground">
                Configured sources
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Feeds</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {statsLoading ? '...' : stats?.active_feeds || activeFeeds.length}
              </div>
              <p className="text-xs text-muted-foreground">
                Currently enabled
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">New Indicators</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {statsLoading ? '...' : (stats?.new_indicators || 0).toLocaleString()}
              </div>
              <p className="text-xs text-muted-foreground">
                Last 24 hours
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Last Updated</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {statsLoading ? '...' : stats?.last_updated ? formatRelativeTime(new Date(stats.last_updated)) : 'Never'}
              </div>
              <p className="text-xs text-muted-foreground">
                {stats?.trends_change !== undefined && (
                  <span className={stats.trends_change >= 0 ? 'text-green-600' : 'text-red-600'}>
                    {stats.trends_change >= 0 ? '+' : ''}{stats.trends_change}% vs previous period
                  </span>
                )}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Error State */}
        {feedsError && (
          <Card className="border-red-200 dark:border-red-800">
            <CardContent className="pt-6">
              <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
                <AlertCircle className="w-5 h-5" />
                <span>Error loading threat intelligence feeds</span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Active Feeds */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radio className="w-5 h-5 text-green-500" />
              Active Feeds
            </CardTitle>
            <CardDescription>
              Currently enabled threat intelligence sources ({activeFeeds.length})
            </CardDescription>
          </CardHeader>
          <CardContent>
            {feedsLoading ? (
              <div className="text-center py-8 text-muted-foreground">
                <Loader2 className="w-8 h-8 mx-auto mb-2 animate-spin" />
                Loading feeds...
              </div>
            ) : activeFeeds.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No active feeds configured
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {activeFeeds.map((feed) => (
                  <div key={feed.id} className="border rounded-lg p-4 hover:bg-accent/50 transition-colors">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-semibold">{feed.name}</h4>
                          <FeedStatusBadge status={feed.status} enabled={feed.enabled} />
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">
                          {feed.description || 'No description available'}
                        </p>
                      </div>
                    </div>

                    <div className="space-y-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Type:</span>
                        <Badge variant="outline" className="capitalize">
                          {feed.source_type.replace('_', ' ')}
                        </Badge>
                      </div>

                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Collections:</span>
                        <span className="font-medium">{feed.collection_count.toLocaleString()}</span>
                      </div>

                      {feed.error_count > 0 && (
                        <div className="flex items-center justify-between text-red-600">
                          <span>Errors:</span>
                          <span className="font-medium">{feed.error_count}</span>
                        </div>
                      )}

                      {feed.last_collection && (
                        <div className="flex items-center justify-between">
                          <span className="text-muted-foreground">Last Collection:</span>
                          <span className="font-medium">
                            {formatRelativeTime(new Date(feed.last_collection))}
                          </span>
                        </div>
                      )}

                      {feed.url && (
                        <div className="flex items-center gap-2 mt-3 pt-3 border-t">
                          <ExternalLink className="w-3 h-3 text-muted-foreground" />
                          <a
                            href={feed.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-blue-600 hover:underline truncate"
                          >
                            {feed.url}
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Inactive Feeds */}
        {inactiveFeeds.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <XCircle className="w-5 h-5 text-gray-500" />
                Inactive Feeds
              </CardTitle>
              <CardDescription>
                Disabled threat intelligence sources ({inactiveFeeds.length})
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {inactiveFeeds.map((feed) => (
                  <div key={feed.id} className="border rounded-lg p-4 opacity-60">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-semibold">{feed.name}</h4>
                          <FeedStatusBadge status={feed.status} enabled={feed.enabled} />
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {feed.description || 'No description available'}
                        </p>
                      </div>
                    </div>

                    <div className="space-y-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Type:</span>
                        <Badge variant="outline" className="capitalize">
                          {feed.source_type.replace('_', ' ')}
                        </Badge>
                      </div>

                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Total Collections:</span>
                        <span className="font-medium">{feed.collection_count.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </MainLayout>
  )
}
