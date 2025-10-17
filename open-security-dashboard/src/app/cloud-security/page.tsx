'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cspmClient, getCSPMPath } from '@/lib/api-client'
import { useToast } from '@/hooks/use-toast'
import { 
  Cloud, 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Clock,
  TrendingUp,
  TrendingDown,
  Construction
} from 'lucide-react'
import Link from 'next/link'

interface DashboardSummary {
  total_scans: number
  active_scans: number
  completed_scans: number
  failed_scans: number
  total_accounts: number
  total_checks_run: number
  compliance_score: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  last_scan_time?: string
}

interface ExecutiveSummary {
  security_posture: {
    overall_score: number
    risk_level: string
    trend: string
  }
  compliance: {
    frameworks: Array<{
      name: string
      score: number
      controls_passed: number
      controls_total: number
    }>
  }
  findings: {
    by_severity: {
      critical: number
      high: number
      medium: number
      low: number
    }
    trending: {
      direction: string
      percentage: number
    }
  }
}

export default function CloudSecurityPage() {
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null)
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummary | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const { toast } = useToast()

  useEffect(() => {
    fetchDashboardData()
  }, [])

  const fetchDashboardData = async () => {
    try {
      setIsLoading(true)
      
      const [dashboardResponse, executiveResponse] = await Promise.allSettled([
        cspmClient.get(getCSPMPath('/api/v1/dashboard/summary')),
        cspmClient.get(getCSPMPath('/api/v1/dashboard/executive-summary'))
      ])

      if (dashboardResponse.status === 'fulfilled') {
        setDashboardSummary(dashboardResponse.value)
      }

      if (executiveResponse.status === 'fulfilled') {
        setExecutiveSummary(executiveResponse.value)
      }

    } catch (error: any) {
      console.error('Error fetching dashboard data:', error)
      toast({
        title: 'Error',
        description: 'Failed to fetch cloud security data. Please try again.',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const formatLastScan = (timestamp?: string) => {
    if (!timestamp) return 'Never'
    return new Date(timestamp).toLocaleString()
  }

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel?.toLowerCase()) {
      case 'low': return 'text-green-600 bg-green-50'
      case 'medium': return 'text-yellow-600 bg-yellow-50'
      case 'high': return 'text-orange-600 bg-orange-50'
      case 'critical': return 'text-red-600 bg-red-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud Security</h1>
          <p className="text-muted-foreground">
            Monitor and manage your cloud security posture across all environments
          </p>
        </div>
        
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  <div className="h-4 bg-gray-200 rounded animate-pulse" />
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-8 bg-gray-200 rounded animate-pulse mb-2" />
                <div className="h-4 bg-gray-200 rounded animate-pulse" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* v1.0 Roadmap Future Notice */}
      <Card className="border-amber-500 bg-amber-50 dark:bg-amber-900/20">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Construction className="w-6 h-6 text-amber-600" />
            <div>
              <CardTitle className="text-amber-900 dark:text-amber-100">
                Coming in Future Release
              </CardTitle>
              <CardDescription className="text-amber-700 dark:text-amber-200">
                Cloud Security (CSPM) module is planned for post-v1.0 release. This feature will include comprehensive cloud security posture management across AWS, Azure, and GCP.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud Security</h1>
          <p className="text-muted-foreground">
            Monitor and manage your cloud security posture across all environments
          </p>
        </div>
        <Button asChild>
          <Link href="/cloud-security/scans">
            <Cloud className="mr-2 h-4 w-4" />
            View All Scans
          </Link>
        </Button>
      </div>

      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{dashboardSummary?.total_scans || 0}</div>
            <p className="text-xs text-muted-foreground">
              {dashboardSummary?.active_scans || 0} active
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{dashboardSummary?.compliance_score || 0}%</div>
            <p className="text-xs text-muted-foreground">
              Across all frameworks
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {dashboardSummary?.critical_findings || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Requires immediate attention
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Cloud Accounts</CardTitle>
            <Cloud className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{dashboardSummary?.total_accounts || 0}</div>
            <p className="text-xs text-muted-foreground">
              Under management
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Executive Summary */}
      {executiveSummary && (
        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Security Posture</CardTitle>
              <CardDescription>
                Overall security posture across all cloud environments
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Overall Score</span>
                <span className="text-2xl font-bold">
                  {executiveSummary.security_posture?.overall_score || 0}%
                </span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Risk Level</span>
                <Badge className={getRiskLevelColor(executiveSummary.security_posture?.risk_level || '')}>
                  {executiveSummary.security_posture?.risk_level || 'Unknown'}
                </Badge>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Trend</span>
                <div className="flex items-center space-x-1">
                  {executiveSummary.security_posture?.trend === 'improving' ? (
                    <TrendingUp className="h-4 w-4 text-green-600" />
                  ) : (
                    <TrendingDown className="h-4 w-4 text-red-600" />
                  )}
                  <span className="text-sm capitalize">
                    {executiveSummary.security_posture?.trend || 'stable'}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Findings Distribution</CardTitle>
              <CardDescription>
                Security findings by severity level
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-red-600">Critical</span>
                  <span className="font-bold">{executiveSummary.findings?.by_severity?.critical || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-orange-600">High</span>
                  <span className="font-bold">{executiveSummary.findings?.by_severity?.high || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-yellow-600">Medium</span>
                  <span className="font-bold">{executiveSummary.findings?.by_severity?.medium || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-blue-600">Low</span>
                  <span className="font-bold">{executiveSummary.findings?.by_severity?.low || 0}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Quick Actions */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-6">
          <div className="flex items-center space-x-4">
            <Cloud className="h-8 w-8 text-blue-600" />
            <div>
              <h3 className="font-semibold">Cloud Scans</h3>
              <p className="text-sm text-muted-foreground">
                View and manage security scans
              </p>
            </div>
          </div>
          <Button asChild className="w-full mt-4" variant="outline">
            <Link href="/cloud-security/scans">Manage Scans</Link>
          </Button>
        </Card>

        <Card className="p-6">
          <div className="flex items-center space-x-4">
            <CheckCircle2 className="h-8 w-8 text-green-600" />
            <div>
              <h3 className="font-semibold">Compliance</h3>
              <p className="text-sm text-muted-foreground">
                Monitor compliance frameworks
              </p>
            </div>
          </div>
          <Button asChild className="w-full mt-4" variant="outline">
            <Link href="/cloud-security/compliance">View Compliance</Link>
          </Button>
        </Card>

        <Card className="p-6">
          <div className="flex items-center space-x-4">
            <Clock className="h-8 w-8 text-orange-600" />
            <div>
              <h3 className="font-semibold">Last Scan</h3>
              <p className="text-sm text-muted-foreground">
                {formatLastScan(dashboardSummary?.last_scan_time)}
              </p>
            </div>
          </div>
          <Button className="w-full mt-4" onClick={fetchDashboardData}>
            Refresh Data
          </Button>
        </Card>
      </div>
    </div>
  )
}
