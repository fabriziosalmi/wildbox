'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Database, Activity, TrendingUp, AlertTriangle, Shield, Globe, Hash, Mail, Server, Eye, Filter, Download, RefreshCcw } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MainLayout } from '@/components/main-layout'
import { dataClient, getDataPath } from '@/lib/api-client'
import { formatRelativeTime } from '@/lib/utils'

interface Indicator {
  id: string
  indicator_type: string
  value: string
  normalized_value: string
  threat_types: string[]
  confidence: string
  severity: number
  description?: string
  tags: string[]
  first_seen?: string
  last_seen?: string
  expires_at?: string
  active: boolean
  source_id: string
  indicator_metadata: Record<string, any>
  created_at: string
  updated_at: string
}

interface IndicatorSearchResponse {
  indicators: Indicator[]
  total: number
  limit: number
  offset: number
  query_time: string
}

interface SystemStats {
  total_indicators: number
  indicator_types: Record<string, number>
  total_sources: number
  active_sources: number
  recent_collections: number
  timestamp: string
}

interface SourceInfo {
  id: string
  name: string
  description?: string
  source_type: string
  enabled: boolean
  status: string
  last_collection?: string
  collection_count: number
  error_count: number
}

async function fetchSystemStats(): Promise<SystemStats> {
  try {
    const response = await dataClient.get(getDataPath('/api/v1/stats'))
    return response
  } catch (error) {
    console.error('Failed to fetch system stats:', error)
    throw error
  }
}

async function fetchSources(): Promise<SourceInfo[]> {
  try {
    const response = await dataClient.get(getDataPath('/api/v1/sources'))
    return response
  } catch (error) {
    console.error('Failed to fetch sources:', error)
    throw error
  }
}

async function searchIndicators(params: {
  q?: string
  indicator_type?: string
  threat_types?: string[]
  confidence?: string
  min_severity?: number
  max_severity?: number
  source_id?: string
  since?: string
  active_only?: boolean
  limit?: number
  offset?: number
}): Promise<IndicatorSearchResponse> {
  try {
    const searchParams = new URLSearchParams()
    
    if (params.q) searchParams.append('q', params.q)
    if (params.indicator_type) searchParams.append('indicator_type', params.indicator_type)
    if (params.threat_types) params.threat_types.forEach(t => searchParams.append('threat_types', t))
    if (params.confidence) searchParams.append('confidence', params.confidence)
    if (params.min_severity) searchParams.append('min_severity', params.min_severity.toString())
    if (params.max_severity) searchParams.append('max_severity', params.max_severity.toString())
    if (params.source_id) searchParams.append('source_id', params.source_id)
    if (params.since) searchParams.append('since', params.since)
    if (params.active_only !== undefined) searchParams.append('active_only', params.active_only.toString())
    if (params.limit) searchParams.append('limit', params.limit.toString())
    if (params.offset) searchParams.append('offset', params.offset.toString())

    const response = await dataClient.get(getDataPath(`/api/v1/indicators/search?${searchParams.toString()}`))
    return response
  } catch (error) {
    console.error('Failed to search indicators:', error)
    throw error
  }
}

export default function ThreatIntelligenceData() {
  const [searchTerm, setSearchTerm] = useState('')
  const [indicatorType, setIndicatorType] = useState<string>('all')
  const [confidence, setConfidence] = useState<string>('all')
  const [severityRange, setSeverityRange] = useState<{ min: number; max: number }>({ min: 1, max: 10 })
  const [selectedSource, setSelectedSource] = useState<string>('all')
  const [activeOnly, setActiveOnly] = useState(true)
  const [offset, setOffset] = useState(0)
  const limit = 50

  // Fetch system statistics
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['threat-intel-stats'],
    queryFn: fetchSystemStats,
    refetchInterval: 60000, // Refresh every minute
  })

  // Fetch data sources
  const { data: sources = [], isLoading: sourcesLoading } = useQuery({
    queryKey: ['threat-intel-sources'],
    queryFn: fetchSources,
    refetchInterval: 300000, // Refresh every 5 minutes
  })

  // Search indicators
  const { data: searchResults, isLoading: searchLoading, refetch } = useQuery({
    queryKey: ['threat-intel-search', searchTerm, indicatorType, confidence, severityRange, selectedSource, activeOnly, offset],
    queryFn: () => searchIndicators({
      q: searchTerm || undefined,
      indicator_type: indicatorType !== 'all' ? indicatorType : undefined,
      confidence: confidence !== 'all' ? confidence : undefined,
      min_severity: severityRange.min,
      max_severity: severityRange.max,
      source_id: selectedSource !== 'all' ? selectedSource : undefined,
      active_only: activeOnly,
      limit,
      offset
    }),
    enabled: true, // Always enabled to show initial data
  })

  const indicators = searchResults?.indicators || []
  const totalResults = searchResults?.total || 0

  const getIndicatorIcon = (type: string) => {
    switch (type) {
      case 'ip_address': return <Globe className="h-4 w-4" />
      case 'domain': return <Server className="h-4 w-4" />
      case 'url': return <Globe className="h-4 w-4" />
      case 'file_hash': return <Hash className="h-4 w-4" />
      case 'email': return <Mail className="h-4 w-4" />
      default: return <Shield className="h-4 w-4" />
    }
  }

  const getSeverityColor = (severity: number) => {
    if (severity >= 8) return 'bg-red-500'
    if (severity >= 6) return 'bg-orange-500'
    if (severity >= 4) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'verified': return 'bg-green-500'
      case 'high': return 'bg-blue-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-orange-500'
      default: return 'bg-gray-500'
    }
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold">Threat Intelligence Data</h1>
          <p className="text-muted-foreground mt-2">
            Browse and search the threat intelligence database with live indicators from multiple sources
          </p>
        </div>

        {/* Statistics Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Indicators</CardTitle>
              <Database className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {statsLoading ? '...' : stats?.total_indicators.toLocaleString() || '0'}
              </div>
              <p className="text-xs text-muted-foreground">
                Active threat indicators
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Data Sources</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {sourcesLoading ? '...' : `${stats?.active_sources || 0}/${stats?.total_sources || 0}`}
              </div>
              <p className="text-xs text-muted-foreground">
                Active sources
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Recent Collections</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {statsLoading ? '...' : stats?.recent_collections || '0'}
              </div>
              <p className="text-xs text-muted-foreground">
                Last 24 hours
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Search Results</CardTitle>
              <Eye className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {searchLoading ? '...' : totalResults.toLocaleString()}
              </div>
              <p className="text-xs text-muted-foreground">
                Matching indicators
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Indicator Type Distribution */}
        {stats?.indicator_types && (
          <Card>
            <CardHeader>
              <CardTitle>Indicator Types Distribution</CardTitle>
              <CardDescription>Breakdown of indicators by type</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                {Object.entries(stats.indicator_types).map(([type, count]) => (
                  <div key={type} className="text-center">
                    <div className="flex items-center justify-center mb-2">
                      {getIndicatorIcon(type)}
                    </div>
                    <div className="text-lg font-semibold">{count.toLocaleString()}</div>
                    <div className="text-xs text-muted-foreground capitalize">
                      {type.replace('_', ' ')}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Search and Filters */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Filter className="h-5 w-5" />
              Search & Filter
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Search Input */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search indicators (IP, domain, hash, email, etc.)"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>

            {/* Filters Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Indicator Type Filter */}
              <div>
                <label className="text-sm font-medium">Type</label>
                <select 
                  value={indicatorType} 
                  onChange={(e) => setIndicatorType(e.target.value)}
                  className="w-full mt-1 p-2 border rounded-md"
                >
                  <option value="all">All Types</option>
                  <option value="ip_address">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="file_hash">File Hash</option>
                  <option value="email">Email</option>
                  <option value="certificate">Certificate</option>
                  <option value="asn">ASN</option>
                  <option value="vulnerability">Vulnerability</option>
                </select>
              </div>

              {/* Confidence Filter */}
              <div>
                <label className="text-sm font-medium">Confidence</label>
                <select 
                  value={confidence} 
                  onChange={(e) => setConfidence(e.target.value)}
                  className="w-full mt-1 p-2 border rounded-md"
                >
                  <option value="all">All Levels</option>
                  <option value="verified">Verified</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              {/* Source Filter */}
              <div>
                <label className="text-sm font-medium">Source</label>
                <select 
                  value={selectedSource} 
                  onChange={(e) => setSelectedSource(e.target.value)}
                  className="w-full mt-1 p-2 border rounded-md"
                >
                  <option value="all">All Sources</option>
                  {sources.map((source) => (
                    <option key={source.id} value={source.id}>
                      {source.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Active Only Filter */}
              <div className="flex flex-col justify-end">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={activeOnly}
                    onChange={(e) => setActiveOnly(e.target.checked)}
                    className="rounded"
                  />
                  <span className="text-sm font-medium">Active Only</span>
                </label>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-2">
              <Button onClick={() => refetch()} disabled={searchLoading}>
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button variant="outline">
                <Download className="h-4 w-4 mr-2" />
                Export Results
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        <Card>
          <CardHeader>
            <CardTitle>Search Results</CardTitle>
            <CardDescription>
              Showing {indicators.length} of {totalResults.toLocaleString()} indicators
            </CardDescription>
          </CardHeader>
          <CardContent>
            {searchLoading ? (
              <div className="text-center py-8">Loading indicators...</div>
            ) : indicators.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No indicators found matching your criteria.
              </div>
            ) : (
              <div className="space-y-3">
                {indicators.map((indicator) => (
                  <div key={indicator.id} className="border rounded-lg p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3 flex-1">
                        <div className="mt-1">
                          {getIndicatorIcon(indicator.indicator_type)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded">
                              {indicator.value}
                            </code>
                            <Badge variant="outline" className="capitalize">
                              {indicator.indicator_type.replace('_', ' ')}
                            </Badge>
                            <Badge className={`text-white ${getConfidenceColor(indicator.confidence)}`}>
                              {indicator.confidence}
                            </Badge>
                            <div className="flex items-center gap-1">
                              <div className={`w-2 h-2 rounded-full ${getSeverityColor(indicator.severity)}`} />
                              <span className="text-xs text-muted-foreground">
                                Severity {indicator.severity}
                              </span>
                            </div>
                          </div>
                          
                          {indicator.description && (
                            <p className="text-sm text-muted-foreground mt-1">
                              {indicator.description}
                            </p>
                          )}
                          
                          {indicator.threat_types.length > 0 && (
                            <div className="flex gap-1 mt-2 flex-wrap">
                              {indicator.threat_types.map((threat) => (
                                <Badge key={threat} variant="secondary" className="text-xs">
                                  {threat}
                                </Badge>
                              ))}
                            </div>
                          )}

                          {indicator.tags.length > 0 && (
                            <div className="flex gap-1 mt-2 flex-wrap">
                              {indicator.tags.slice(0, 5).map((tag) => (
                                <Badge key={tag} variant="outline" className="text-xs">
                                  {tag}
                                </Badge>
                              ))}
                              {indicator.tags.length > 5 && (
                                <Badge variant="outline" className="text-xs">
                                  +{indicator.tags.length - 5} more
                                </Badge>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="text-right text-xs text-muted-foreground">
                        {indicator.last_seen && (
                          <div>Last seen: {formatRelativeTime(new Date(indicator.last_seen))}</div>
                        )}
                        {indicator.first_seen && (
                          <div>First seen: {formatRelativeTime(new Date(indicator.first_seen))}</div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Pagination */}
            {totalResults > limit && (
              <div className="flex justify-between items-center mt-6">
                <Button
                  variant="outline"
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                >
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  Page {Math.floor(offset / limit) + 1} of {Math.ceil(totalResults / limit)}
                </span>
                <Button
                  variant="outline"
                  onClick={() => setOffset(offset + limit)}
                  disabled={offset + limit >= totalResults}
                >
                  Next
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Data Sources */}
        {sources.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Data Sources</CardTitle>
              <CardDescription>Active threat intelligence feeds</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {sources.map((source) => (
                  <div key={source.id} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold">{source.name}</h4>
                      <Badge 
                        variant={source.enabled ? "default" : "secondary"}
                        className={source.enabled ? "bg-green-500" : ""}
                      >
                        {source.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </div>
                    {source.description && (
                      <p className="text-sm text-muted-foreground mb-2">
                        {source.description}
                      </p>
                    )}
                    <div className="text-xs space-y-1">
                      <div>Type: {source.source_type}</div>
                      <div>Collections: {source.collection_count.toLocaleString()}</div>
                      {source.error_count > 0 && (
                        <div className="text-red-500">
                          Errors: {source.error_count}
                        </div>
                      )}
                      {source.last_collection && (
                        <div>
                          Last collection: {formatRelativeTime(new Date(source.last_collection))}
                        </div>
                      )}
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
