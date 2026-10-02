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
  CheckCircle,
  Clock,
  AlertCircle,
  ListChecks,
  type LucideIcon,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { MainLayout } from '@/components/main-layout'
import {
  dataClient,
  guardianClient,
  responderClient,
  cspmClient,
  getCSPMPath,
  getDataPath,
  getGuardianPath,
  getResponderPath,
} from '@/lib/api-client'
import { formatNumber, formatRelativeTime } from '@/lib/utils'
import { useVulnerabilityStats } from '@/hooks/use-vulnerability-stats'

/*
 * Every number on this page comes from a service response. A card whose
 * source did not answer says "Unavailable"; one whose source answered with
 * nothing yet says so. The page used to fill both cases with sample values
 * -- "87%" compliance, "5" critical findings, "4/4" feeds, "3" alerts and an
 * IOC 192.168.1.100 -- which an empty stack displayed as real (#559).
 */

interface ThreatIntelSummary {
  total_feeds: number
  active_feeds: number
  new_indicators: number
  trends_change: number
}

interface CloudSummary {
  total_scans: number
  total_findings: number
  compliance_score: number
}

interface AssetCounts {
  total: number
  active: number
}

interface DashboardMetrics {
  threatIntel: ThreatIntelSummary | null
  cloud: CloudSummary | null
  assets: AssetCounts | null
  playbooks: number | null
  /** Sources that answered, out of those asked. */
  reachable: number
  probed: number
}

interface RecentActivity {
  id: string
  type: 'indicator' | 'vulnerability'
  title: string
  description: string
  timestamp: string
  severity: 'low' | 'medium' | 'high' | 'critical'
}

interface ActivityFeed {
  items: RecentActivity[]
  /** False when no activity source answered at all. */
  available: boolean
}

interface IndicatorItem {
  id: string
  indicator_type: string
  value: string
  severity: number
  last_seen?: string | null
  created_at?: string | null
}

interface VulnerabilityItem {
  id: string
  title?: string
  cve_id?: string | null
  severity?: string
  status?: string
  asset_name?: string
  created_at?: string
}

const settled = <T,>(result: PromiseSettledResult<T>): T | null =>
  result.status === 'fulfilled' ? result.value : null

async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  const results = await Promise.allSettled([
    dataClient.get<ThreatIntelSummary>(getDataPath('/api/v1/dashboard/threat-intel')),
    cspmClient.get<CloudSummary>(getCSPMPath('/api/v1/dashboard/summary')),
    guardianClient.get<{ count: number }>(getGuardianPath('/api/v1/assets/assets/?page_size=1')),
    guardianClient.get<{ count: number }>(
      getGuardianPath('/api/v1/assets/assets/?status=active&page_size=1')
    ),
    responderClient.get<{ total: number }>(getResponderPath('/api/v1/playbooks')),
  ])
  const [threatIntel, cloud, allAssets, activeAssets, playbooks] = results

  const assetTotal = settled(allAssets)
  const assetActive = settled(activeAssets)

  return {
    threatIntel: settled(threatIntel),
    cloud: settled(cloud),
    assets:
      assetTotal && assetActive ? { total: assetTotal.count, active: assetActive.count } : null,
    playbooks: settled(playbooks)?.total ?? null,
    reachable: results.filter(r => r.status === 'fulfilled').length,
    probed: results.length,
  }
}

function indicatorSeverity(score: number): RecentActivity['severity'] {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

function vulnerabilitySeverity(severity: string | undefined): RecentActivity['severity'] {
  return severity === 'critical' || severity === 'high' || severity === 'medium' ? severity : 'low'
}

async function fetchRecentActivity(): Promise<ActivityFeed> {
  const [indicatorsRes, vulnerabilitiesRes] = await Promise.allSettled([
    dataClient.get<{ indicators: IndicatorItem[] }>(getDataPath('/api/v1/indicators/search'), {
      limit: 3,
    }),
    guardianClient.get<{ results?: VulnerabilityItem[] }>(
      getGuardianPath('/api/v1/vulnerabilities/?ordering=-created_at&page_size=3')
    ),
  ])

  const items: RecentActivity[] = []

  // An entry without a timestamp is left out rather than given one.
  for (const indicator of settled(indicatorsRes)?.indicators ?? []) {
    const timestamp = indicator.last_seen || indicator.created_at
    if (!timestamp) continue
    items.push({
      id: `indicator-${indicator.id}`,
      type: 'indicator',
      title: 'Threat indicator seen',
      description: `${indicator.indicator_type.toUpperCase()} ${indicator.value}`,
      timestamp,
      severity: indicatorSeverity(indicator.severity),
    })
  }

  for (const vuln of settled(vulnerabilitiesRes)?.results ?? []) {
    if (!vuln.created_at) continue
    const name = vuln.cve_id || vuln.title || 'Vulnerability'
    items.push({
      id: `vulnerability-${vuln.id}`,
      type: 'vulnerability',
      title: vuln.status === 'resolved' ? 'Vulnerability resolved' : 'Vulnerability recorded',
      description: vuln.asset_name ? `${name} on ${vuln.asset_name}` : name,
      timestamp: vuln.created_at,
      severity: vulnerabilitySeverity(vuln.severity),
    })
  }

  return {
    items: items
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 5),
    available: indicatorsRes.status === 'fulfilled' || vulnerabilitiesRes.status === 'fulfilled',
  }
}

const UNAVAILABLE = 'Unavailable'

function MetricCard({
  title,
  value,
  description,
  icon: Icon,
  trendValue,
  testId,
}: {
  title: string
  value: string | number
  description: string
  icon: LucideIcon
  /** A signed percentage from the service; omitted when it has none. */
  trendValue?: number
  testId?: string
}) {
  const unavailable = value === UNAVAILABLE
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div
          className={`text-2xl font-bold ${unavailable ? 'text-muted-foreground' : ''}`}
          data-testid={testId ? `${testId}-value` : undefined}
        >
          {value}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>{description}</span>
          {!unavailable && trendValue !== undefined && trendValue !== 0 && (
            <div
              className={`flex items-center gap-1 ${
                trendValue > 0 ? 'text-green-600' : 'text-red-600'
              }`}
            >
              {trendValue > 0 ? (
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
  const severityColor = {
    critical: 'border-l-red-500',
    high: 'border-l-orange-500',
    medium: 'border-l-yellow-500',
    low: 'border-l-green-500',
  }[activity.severity]

  return (
    <div className={`border-l-4 py-3 pl-4 ${severityColor}`}>
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-muted p-2">
          {activity.type === 'indicator' ? (
            <Shield className="h-4 w-4" />
          ) : (
            <AlertCircle className="h-4 w-4" />
          )}
        </div>
        <div className="space-y-1">
          <h4 className="text-sm font-medium">{activity.title}</h4>
          <p className="text-sm text-muted-foreground">{activity.description}</p>
          <p className="text-xs text-muted-foreground">
            {formatRelativeTime(new Date(activity.timestamp))}
          </p>
        </div>
      </div>
    </div>
  )
}

function ServiceStatus({ reachable, probed }: { reachable: number; probed: number }) {
  const all = reachable === probed
  const none = reachable === 0
  const [label, color, icon] = all
    ? ['All services responding', 'bg-green-500', CheckCircle]
    : none
      ? ['No service responding', 'bg-red-500', AlertTriangle]
      : ['Some services not responding', 'bg-yellow-500', Clock]
  const Icon = icon
  return (
    <div className="flex items-center gap-3" data-testid="service-status">
      <div className={`h-2 w-2 rounded-full ${color}`} />
      <Icon className="h-4 w-4 text-muted-foreground" />
      <span className="text-sm font-medium">{label}</span>
      <span className="text-sm text-muted-foreground">
        ({reachable}/{probed} sources answered)
      </span>
    </div>
  )
}

export default function DashboardPage() {
  const vulnStats = useVulnerabilityStats()

  const {
    data: metrics,
    isLoading: metricsLoading,
    dataUpdatedAt,
  } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: fetchDashboardMetrics,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: activity, isLoading: activitiesLoading } = useQuery({
    queryKey: ['recent-activity'],
    queryFn: fetchRecentActivity,
    refetchInterval: 60000, // Refresh every minute
  })

  // The stats hook shows zeros as placeholder data while it loads; those are
  // not counts, so the page waits for the real ones and never displays them.
  const vulnStatsPending =
    vulnStats.isLoading || (vulnStats.isPlaceholderData && vulnStats.isFetching)

  if (metricsLoading || vulnStatsPending || !metrics) {
    return (
      <MainLayout>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold">Dashboard</h1>
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {[...Array(8)].map((_, i) => (
              <Card key={i}>
                <CardHeader className="skeleton mb-2 h-4" />
                <CardContent>
                  <div className="skeleton mb-2 h-8" />
                  <div className="skeleton h-4" />
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </MainLayout>
    )
  }

  const { threatIntel, cloud, assets, playbooks } = metrics
  const vulns = vulnStats.isPlaceholderData || vulnStats.isError ? null : (vulnStats.data ?? null)
  const hasScans = cloud !== null && cloud.total_scans > 0

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
          <div className="text-right text-sm">
            <div className="font-medium">Last updated</div>
            <div className="text-muted-foreground">
              {formatRelativeTime(new Date(dataUpdatedAt))}
            </div>
          </div>
        </div>

        {/* Service status: which of the sources below answered. Uptime,
            response times and error rates need the Prometheus integration
            and are not shown until they exist. */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              Data Sources
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ServiceStatus reachable={metrics.reachable} probed={metrics.probed} />
          </CardContent>
        </Card>

        {/* Metrics Grid */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            title="Threat Intelligence"
            value={
              threatIntel ? `${threatIntel.active_feeds}/${threatIntel.total_feeds}` : UNAVAILABLE
            }
            description="Active feeds"
            icon={Shield}
            testId="metric-threat-feeds"
          />
          <MetricCard
            title="Cloud Compliance"
            value={
              cloud === null
                ? UNAVAILABLE
                : hasScans
                  ? `${Math.round(cloud.compliance_score)}%`
                  : 'No scans'
            }
            description={hasScans ? 'Score across completed scans' : 'Run a scan to get a score'}
            icon={Activity}
            testId="metric-cloud-compliance"
          />
          <MetricCard
            title="Assets"
            value={assets ? `${assets.active}/${assets.total}` : UNAVAILABLE}
            description="Active assets"
            icon={Server}
            testId="metric-assets"
          />
          <MetricCard
            title="Vulnerabilities"
            value={vulns ? vulns.critical_count : UNAVAILABLE}
            description="Critical vulnerabilities"
            icon={AlertTriangle}
            testId="metric-critical-vulns"
          />
        </div>

        {/* Secondary Metrics */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            title="New IOCs"
            value={threatIntel ? formatNumber(threatIntel.new_indicators) : UNAVAILABLE}
            description="Last 24 hours"
            icon={Shield}
            trendValue={threatIntel?.trends_change}
            testId="metric-new-iocs"
          />
          <MetricCard
            title="Failed Cloud Checks"
            value={cloud ? cloud.total_findings : UNAVAILABLE}
            description="Across all scans"
            icon={ListChecks}
            testId="metric-failed-checks"
          />
          <MetricCard
            title="Open Vulnerabilities"
            value={vulns ? vulns.open_count : UNAVAILABLE}
            description="Pending remediation"
            icon={AlertCircle}
            testId="metric-open-vulns"
          />
          <MetricCard
            title="Playbooks"
            value={playbooks ?? UNAVAILABLE}
            description="Available for response"
            icon={Zap}
            testId="metric-playbooks"
          />
        </div>

        {/* Recent Activity */}
        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>
                Latest threat indicators and vulnerabilities recorded
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4" data-testid="recent-activity">
              {activitiesLoading ? (
                [...Array(3)].map((_, i) => (
                  <div key={i} className="space-y-2">
                    <div className="skeleton h-4 w-3/4" />
                    <div className="skeleton h-3 w-1/2" />
                  </div>
                ))
              ) : activity && activity.items.length > 0 ? (
                activity.items.map(item => <ActivityItem key={item.id} activity={item} />)
              ) : (
                <div className="py-6 text-center text-sm text-muted-foreground">
                  {activity?.available === false
                    ? 'Activity sources are unavailable'
                    : 'No recent activity'}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
              <CardDescription>Common security operations and tools</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3">
                <button className="flex items-center gap-3 rounded-lg border p-3 text-left transition-colors hover:bg-accent">
                  <Shield className="h-5 w-5 text-blue-500" />
                  <div>
                    <div className="font-medium">IOC Lookup</div>
                    <div className="text-sm text-muted-foreground">
                      Analyze indicators of compromise
                    </div>
                  </div>
                </button>
                <button className="flex items-center gap-3 rounded-lg border p-3 text-left transition-colors hover:bg-accent">
                  <Activity className="h-5 w-5 text-green-500" />
                  <div>
                    <div className="font-medium">Run Cloud Scan</div>
                    <div className="text-sm text-muted-foreground">Start compliance assessment</div>
                  </div>
                </button>
                <button className="flex items-center gap-3 rounded-lg border p-3 text-left transition-colors hover:bg-accent">
                  <Zap className="h-5 w-5 text-purple-500" />
                  <div>
                    <div className="font-medium">Execute Playbook</div>
                    <div className="text-sm text-muted-foreground">Automated response workflow</div>
                  </div>
                </button>
                <button className="flex items-center gap-3 rounded-lg border p-3 text-left transition-colors hover:bg-accent">
                  <Users className="h-5 w-5 text-orange-500" />
                  <div>
                    <div className="font-medium">AI Analysis</div>
                    <div className="text-sm text-muted-foreground">Intelligent threat hunting</div>
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
