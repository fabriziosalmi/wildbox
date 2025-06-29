'use client'

import { useQuery } from '@tanstack/react-query'
import { 
  TrendingUp, 
  TrendingDown, 
  Shield, 
  AlertTriangle, 
  Activity,
  Server,
  Users,
  Zap,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { MainLayout } from '@/components/main-layout'
import { apiClient, dataClient, guardianClient, responderClient, cspmClient, sensorClient, getSensorPath, getGuardianPath, getResponderPath, getCSPMPath } from '@/lib/api-client'
import { formatNumber, formatRelativeTime } from '@/lib/utils'

interface DashboardMetrics {
  threatIntel: {
    totalFeeds: number
    activeFeeds: number
    lastUpdated: string
    newIndicators: number
    trendsChange: number
  }
  cloudSecurity: {
    totalAccounts: number
    complianceScore: number
    criticalFindings: number
    lastScan: string
    trendsChange: number
  }
  endpoints: {
    totalEndpoints: number
    onlineEndpoints: number
    alerts: number
    lastActivity: string
    trendsChange: number
  }
  vulnerabilities: {
    totalVulns: number
    criticalVulns: number
    highVulns: number
    resolved: number
    trendsChange: number
  }
  response: {
    totalPlaybooks: number
    activeRuns: number
    successRate: number
    lastExecution: string
  }
  systemHealth: {
    status: 'operational' | 'degraded' | 'down'
    uptime: number
    responseTime: number
    errorRate: number
  }
}

interface RecentActivity {
  id: string
  type: 'threat' | 'scan' | 'alert' | 'playbook' | 'vulnerability'
  title: string
  description: string
  timestamp: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'completed' | 'failed' | 'running' | 'pending'
}

async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  try {
    // Fetch real data from Guardian (the only service with confirmed working APIs)
    const [
      guardianVulnsRes,
      guardianAssetsRes
    ] = await Promise.allSettled([
      // Get actual vulnerabilities from Guardian
      guardianClient.get(getGuardianPath('/api/v1/vulnerabilities/vulnerabilities/?page_size=100')),
      // Get actual assets from Guardian  
      guardianClient.get(getGuardianPath('/api/v1/assets/assets/?page_size=100'))
    ])

    // Process Guardian vulnerabilities data
    let vulnerabilities = {
      totalVulns: 0,
      criticalVulns: 0,
      highVulns: 0,
      resolved: 0,
      trendsChange: 5.2
    }

    if (guardianVulnsRes.status === 'fulfilled') {
      const vulnData = guardianVulnsRes.value as any
      if (vulnData?.results) {
        vulnerabilities.totalVulns = vulnData.count || vulnData.results.length
        vulnerabilities.criticalVulns = vulnData.results.filter((v: any) => v.severity === 'critical').length
        vulnerabilities.highVulns = vulnData.results.filter((v: any) => v.severity === 'high').length
        vulnerabilities.resolved = vulnData.results.filter((v: any) => v.status === 'resolved').length
      }
    }

    // Process Guardian assets data for endpoints
    let endpoints = {
      totalEndpoints: 0,
      onlineEndpoints: 0,
      alerts: 3,
      lastActivity: new Date().toISOString(),
      trendsChange: 2.1
    }

    if (guardianAssetsRes.status === 'fulfilled') {
      const assetData = guardianAssetsRes.value as any
      if (assetData?.results) {
        endpoints.totalEndpoints = assetData.count || assetData.results.length
        endpoints.onlineEndpoints = assetData.results.filter((a: any) => a.status === 'active').length
        // Update last activity to most recent asset activity
        const lastSeen = assetData.results.reduce((latest: string, asset: any) => {
          return new Date(asset.last_seen || asset.updated_at) > new Date(latest) ? 
            (asset.last_seen || asset.updated_at) : latest
        }, new Date(0).toISOString())
        if (lastSeen !== new Date(0).toISOString()) {
          endpoints.lastActivity = lastSeen
        }
      }
    }

    // Mock data for services that don't have working APIs yet
    const threatIntel = {
      totalFeeds: 47,
      activeFeeds: 45,
      lastUpdated: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      newIndicators: 1247,
      trendsChange: 8.2
    }

    const cloudSecurity = {
      totalAccounts: 12,
      complianceScore: 87,
      criticalFindings: 5,
      lastScan: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      trendsChange: 3.1
    }

    const response = {
      totalPlaybooks: 28,
      activeRuns: 3,
      successRate: 94.5,
      lastExecution: new Date(Date.now() - 1000 * 60 * 45).toISOString()
    }

    const systemHealth = {
      status: 'operational' as const,
      uptime: 99.97,
      responseTime: 142,
      errorRate: 0.03
    }

    return {
      threatIntel,
      cloudSecurity,
      endpoints,
      vulnerabilities,
      response,
      systemHealth
    }

  } catch (error) {
    console.error('Failed to fetch dashboard metrics:', error)
    // Return fallback data if APIs are unavailable
    return {
      threatIntel: {
        totalFeeds: 0,
        activeFeeds: 0,
        lastUpdated: new Date().toISOString(),
        newIndicators: 0,
        trendsChange: 0
      },
      cloudSecurity: {
        totalAccounts: 0,
        complianceScore: 0,
        criticalFindings: 0,
        lastScan: new Date().toISOString(),
        trendsChange: 0
      },
      endpoints: {
        totalEndpoints: 0,
        onlineEndpoints: 0,
        alerts: 0,
        lastActivity: new Date().toISOString(),
        trendsChange: 0
      },
      vulnerabilities: {
        totalVulns: 0,
        criticalVulns: 0,
        highVulns: 0,
        resolved: 0,
        trendsChange: 0
      },
      response: {
        totalPlaybooks: 0,
        activeRuns: 0,
        successRate: 0,
        lastExecution: new Date().toISOString()
      },
      systemHealth: {
        status: 'down',
        uptime: 0,
        responseTime: 0,
        errorRate: 100
      }
    }
  }
}

async function fetchRecentActivity(): Promise<RecentActivity[]> {
  try {
    // Fetch recent activity from multiple services
    const [threatIntelRes, scanResultsRes, alertsRes] = await Promise.allSettled([
      // Fetch recent IOCs from data service
      dataClient.get('/api/v1/indicators/search?limit=5&sort=-created_at'),
      // Fetch recent scan results from CSMP
      cspmClient.get('/api/v1/scans?limit=3&sort=-created_at'),
      // Fetch recent alerts from Guardian
      guardianClient.get(getGuardianPath('/api/v1/vulnerabilities/?limit=3&severity=critical,high&ordering=-created_at'))
    ])

    const activities: RecentActivity[] = []

    // Process threat intel data
    if (threatIntelRes.status === 'fulfilled') {
      const threatData = threatIntelRes.value as any
      const indicators = threatData.results || threatData.indicators || []
      indicators.slice(0, 2).forEach((indicator: any, index: number) => {
        activities.push({
          id: `threat-${index}`,
          type: 'threat',
          title: 'New IOC detected',
          description: `${indicator.type?.toUpperCase()} ${indicator.value} added to threat intelligence`,
          timestamp: indicator.created_at || new Date(Date.now() - 1000 * 60 * (10 + index * 5)).toISOString(),
          severity: indicator.severity || 'high',
          status: 'completed'
        })
      })
    }

    // Process CSPM scan results
    if (scanResultsRes.status === 'fulfilled') {
      const scanData = scanResultsRes.value as any
      const scans = scanData.results || scanData.scans || []
      scans.slice(0, 2).forEach((scan: any, index: number) => {
        const criticalCount = scan.summary?.critical_findings || scan.critical_findings || 0
        activities.push({
          id: `scan-${index}`,
          type: 'scan',
          title: `${scan.provider?.toUpperCase() || 'Cloud'} compliance scan completed`,
          description: `${scan.account_name || scan.account_id || 'Account'} scan found ${criticalCount} critical findings`,
          timestamp: scan.completed_at || scan.created_at || new Date(Date.now() - 1000 * 60 * (30 + index * 15)).toISOString(),
          severity: criticalCount > 0 ? 'critical' : 'medium',
          status: scan.status || 'completed'
        })
      })
    }

    // Process Guardian vulnerability alerts
    if (alertsRes.status === 'fulfilled') {
      const alertData = alertsRes.value as any
      const vulnerabilities = alertData.results || alertData.vulnerabilities || []
      vulnerabilities.slice(0, 2).forEach((vuln: any, index: number) => {
        activities.push({
          id: `vuln-${index}`,
          type: vuln.status === 'remediated' ? 'vulnerability' : 'alert',
          title: vuln.status === 'remediated' ? 'Critical vulnerability patched' : 'Vulnerability alert triggered',
          description: `${vuln.cve_id || vuln.title || 'Vulnerability'} ${vuln.status === 'remediated' ? 'remediated' : 'detected'} on ${vuln.asset?.hostname || 'system'}`,
          timestamp: vuln.updated_at || vuln.created_at || new Date(Date.now() - 1000 * 60 * (60 + index * 30)).toISOString(),
          severity: vuln.severity || 'high',
          status: vuln.status === 'remediated' ? 'completed' : 'pending'
        })
      })
    }

    // If no real data is available, return fallback data
    if (activities.length === 0) {
      return [
        {
          id: '1',
          type: 'threat',
          title: 'New IOC detected',
          description: 'Malicious IP 192.168.1.100 added to threat intelligence',
          timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
          severity: 'high',
          status: 'completed'
        },
        {
          id: '2',
          type: 'scan',
          title: 'AWS compliance scan completed',
          description: 'Production account scan found 3 new critical findings',
          timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          severity: 'critical',
          status: 'completed'
        },
        {
          id: '3',
          type: 'alert',
          title: 'Endpoint alert triggered',
          description: 'Suspicious process detected on WORKSTATION-01',
          timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
          severity: 'high',
          status: 'pending'
        }
      ]
    }

    // Sort by timestamp (most recent first) and return up to 5 activities
    return activities
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 5)

  } catch (error) {
    console.error('Failed to fetch recent activity:', error)
    // Return fallback data on error
    return [
      {
        id: '1',
        type: 'threat',
        title: 'New IOC detected',
        description: 'Malicious IP 192.168.1.100 added to threat intelligence',
        timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
        severity: 'high',
        status: 'completed'
      },
      {
        id: '2',
        type: 'scan',
        title: 'AWS compliance scan completed',
        description: 'Production account scan found 3 new critical findings',
        timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        severity: 'critical',
        status: 'completed'
      }
    ]
  }
}

function MetricCard({ 
  title, 
  value, 
  description, 
  icon: Icon, 
  trend, 
  trendValue 
}: {
  title: string
  value: string | number
  description: string
  icon: any
  trend?: 'up' | 'down'
  trendValue?: number
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>{description}</span>
          {trend && trendValue && (
            <div className={`flex items-center gap-1 ${
              trend === 'up' ? 'text-green-600' : 'text-red-600'
            }`}>
              {trend === 'up' ? (
                <TrendingUp className="h-3 w-3" />
              ) : (
                <TrendingDown className="h-3 w-3" />
              )}
              <span>{Math.abs(trendValue)}%</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function ActivityItem({ activity }: { activity: RecentActivity }) {
  const getIcon = () => {
    switch (activity.type) {
      case 'threat': return <Shield className="h-4 w-4" />
      case 'scan': return <Activity className="h-4 w-4" />
      case 'alert': return <AlertTriangle className="h-4 w-4" />
      case 'playbook': return <Zap className="h-4 w-4" />
      case 'vulnerability': return <AlertCircle className="h-4 w-4" />
      default: return <Activity className="h-4 w-4" />
    }
  }

  const getStatusIcon = () => {
    switch (activity.status) {
      case 'completed': return <CheckCircle className="h-3 w-3 text-green-500" />
      case 'failed': return <XCircle className="h-3 w-3 text-red-500" />
      case 'running': return <Activity className="h-3 w-3 text-blue-500 animate-pulse" />
      case 'pending': return <Clock className="h-3 w-3 text-yellow-500" />
      default: return null
    }
  }

  const getSeverityColor = () => {
    switch (activity.severity) {
      case 'critical': return 'border-l-red-500'
      case 'high': return 'border-l-orange-500'
      case 'medium': return 'border-l-yellow-500'
      case 'low': return 'border-l-green-500'
      default: return 'border-l-gray-500'
    }
  }

  return (
    <div className={`border-l-4 pl-4 py-3 ${getSeverityColor()}`}>
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-muted rounded-lg">
            {getIcon()}
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-medium">{activity.title}</h4>
              {getStatusIcon()}
            </div>
            <p className="text-sm text-muted-foreground">{activity.description}</p>
            <p className="text-xs text-muted-foreground">
              {formatRelativeTime(new Date(activity.timestamp))}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: fetchDashboardMetrics,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: activities, isLoading: activitiesLoading } = useQuery({
    queryKey: ['recent-activity'],
    queryFn: fetchRecentActivity,
    refetchInterval: 60000, // Refresh every minute
  })

  if (metricsLoading || !metrics) {
    return (
      <MainLayout>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold">Dashboard</h1>
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {[...Array(8)].map((_, i) => (
              <Card key={i}>
                <CardHeader className="skeleton h-4 mb-2" />
                <CardContent>
                  <div className="skeleton h-8 mb-2" />
                  <div className="skeleton h-4" />
                </CardContent>
              </Card>
            ))}
          </div>
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
            <h1 className="text-3xl font-bold">Security Dashboard</h1>
            <p className="text-muted-foreground">
              Overview of your security posture and recent activities
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="text-right text-sm">
              <div className="font-medium">Last updated</div>
              <div className="text-muted-foreground">
                {formatRelativeTime(new Date())}
              </div>
            </div>
          </div>
        </div>

        {/* System Health */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              System Health
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {metrics.systemHealth.uptime}%
                </div>
                <div className="text-sm text-muted-foreground">Uptime</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">
                  {metrics.systemHealth.responseTime}ms
                </div>
                <div className="text-sm text-muted-foreground">Response Time</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {metrics.systemHealth.errorRate}%
                </div>
                <div className="text-sm text-muted-foreground">Error Rate</div>
              </div>
              <div className="text-center">
                <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${
                  metrics.systemHealth.status === 'operational' 
                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100'
                    : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100'
                }`}>
                  <div className={`w-2 h-2 rounded-full ${
                    metrics.systemHealth.status === 'operational' ? 'bg-green-500' : 'bg-red-500'
                  }`} />
                  {metrics.systemHealth.status}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Metrics Grid */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            title="Threat Intelligence"
            value={`${metrics.threatIntel.activeFeeds}/${metrics.threatIntel.totalFeeds}`}
            description="Active feeds"
            icon={Shield}
            trend="up"
            trendValue={metrics.threatIntel.trendsChange}
          />
          <MetricCard
            title="Cloud Compliance"
            value={`${metrics.cloudSecurity.complianceScore}%`}
            description="Overall score"
            icon={Activity}
            trend="down"
            trendValue={Math.abs(metrics.cloudSecurity.trendsChange)}
          />
          <MetricCard
            title="Endpoints"
            value={`${metrics.endpoints.onlineEndpoints}/${metrics.endpoints.totalEndpoints}`}
            description="Online endpoints"
            icon={Server}
            trend="up"
            trendValue={metrics.endpoints.trendsChange}
          />
          <MetricCard
            title="Vulnerabilities"
            value={metrics.vulnerabilities.criticalVulns}
            description="Critical findings"
            icon={AlertTriangle}
            trend="down"
            trendValue={Math.abs(metrics.vulnerabilities.trendsChange)}
          />
        </div>

        {/* Secondary Metrics */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            title="New IOCs"
            value={formatNumber(metrics.threatIntel.newIndicators)}
            description="Last 24 hours"
            icon={Shield}
          />
          <MetricCard
            title="Critical Findings"
            value={metrics.cloudSecurity.criticalFindings}
            description="Require attention"
            icon={AlertCircle}
          />
          <MetricCard
            title="Active Alerts"
            value={metrics.endpoints.alerts}
            description="Pending review"
            icon={AlertTriangle}
          />
          <MetricCard
            title="Playbook Success"
            value={`${metrics.response.successRate}%`}
            description="Automation rate"
            icon={Zap}
          />
        </div>

        {/* Recent Activity */}
        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>
                Latest security events and system activities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {activitiesLoading ? (
                [...Array(5)].map((_, i) => (
                  <div key={i} className="space-y-2">
                    <div className="skeleton h-4 w-3/4" />
                    <div className="skeleton h-3 w-1/2" />
                  </div>
                ))
              ) : (
                activities?.map((activity) => (
                  <ActivityItem key={activity.id} activity={activity} />
                ))
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
              <CardDescription>
                Common security operations and tools
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3">
                <button className="flex items-center gap-3 p-3 text-left rounded-lg border hover:bg-accent transition-colors">
                  <Shield className="h-5 w-5 text-blue-500" />
                  <div>
                    <div className="font-medium">IOC Lookup</div>
                    <div className="text-sm text-muted-foreground">
                      Analyze indicators of compromise
                    </div>
                  </div>
                </button>
                <button className="flex items-center gap-3 p-3 text-left rounded-lg border hover:bg-accent transition-colors">
                  <Activity className="h-5 w-5 text-green-500" />
                  <div>
                    <div className="font-medium">Run Cloud Scan</div>
                    <div className="text-sm text-muted-foreground">
                      Start compliance assessment
                    </div>
                  </div>
                </button>
                <button className="flex items-center gap-3 p-3 text-left rounded-lg border hover:bg-accent transition-colors">
                  <Zap className="h-5 w-5 text-purple-500" />
                  <div>
                    <div className="font-medium">Execute Playbook</div>
                    <div className="text-sm text-muted-foreground">
                      Automated response workflow
                    </div>
                  </div>
                </button>
                <button className="flex items-center gap-3 p-3 text-left rounded-lg border hover:bg-accent transition-colors">
                  <Users className="h-5 w-5 text-orange-500" />
                  <div>
                    <div className="font-medium">AI Analysis</div>
                    <div className="text-sm text-muted-foreground">
                      Intelligent threat hunting
                    </div>
                  </div>
                </button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  )
}
