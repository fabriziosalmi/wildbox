'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { cspmClient, getCSPMPath } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/utils'
import { Cloud, Shield, AlertTriangle, CheckCircle2, Clock, Info, RefreshCw } from 'lucide-react'

/**
 * GET /api/v1/cspm/dashboard/summary, field for field. The scan count is
 * every scan the team started that cspm still keeps; the other figures come
 * from the newest completed scan of each account in the period.
 */
interface DashboardSummary {
  total_scans: number
  last_scan_at: string | null
  summary_period_days: number
  accounts_assessed: number
  compliance_score: number | null
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  info_findings: number
  unknown_severity_findings: number
}

type SeverityKey =
  'critical_findings' | 'high_findings' | 'medium_findings' | 'low_findings' | 'info_findings'

const SEVERITY_ROWS: { key: SeverityKey; label: string; className: string }[] = [
  { key: 'critical_findings', label: 'Critical', className: 'text-red-600' },
  { key: 'high_findings', label: 'High', className: 'text-orange-600' },
  { key: 'medium_findings', label: 'Medium', className: 'text-yellow-600' },
  { key: 'low_findings', label: 'Low', className: 'text-blue-600' },
  { key: 'info_findings', label: 'Info', className: 'text-muted-foreground' },
]

/** cspm sends naive UTC timestamps; without a zone Date() would read local time. */
function utcDate(timestamp: string): Date {
  return new Date(/(Z|[+-]\d\d:\d\d)$/.test(timestamp) ? timestamp : `${timestamp}Z`)
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}

export default function CloudSecurityPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const fetchSummary = useCallback(async () => {
    setIsLoading(true)
    setLoadError(null)
    try {
      setSummary(await cspmClient.get<DashboardSummary>(getCSPMPath('/api/v1/dashboard/summary')))
    } catch (error) {
      // A failed request is not an account with nothing in it: no figure is
      // shown in its place, not even a stale one.
      setSummary(null)
      setLoadError(getErrorMessage(error, 'The CSPM service did not answer.'))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSummary()
  }, [fetchSummary])

  const period = summary ? `in the last ${summary.summary_period_days} days` : ''

  return (
    <div className="space-y-8">
      {/* v1.0 Roadmap Future Notice */}
      <Card className="border-amber-500 bg-amber-50 dark:bg-amber-900/20">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Info className="h-6 w-6 text-amber-600" />
            <div>
              <CardTitle className="text-amber-900 dark:text-amber-100">AWS only</CardTitle>
              <CardDescription className="text-amber-700 dark:text-amber-200">
                The CSPM service scans AWS accounts only. Azure and Google Cloud are not supported,
                and the service refuses scans of them.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud Security</h1>
          <p className="text-muted-foreground">
            Scans and the results of the newest completed scan of each cloud account
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchSummary} variant="outline" disabled={isLoading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button asChild>
            <Link href="/cloud-security/scans">
              <Cloud className="mr-2 h-4 w-4" />
              View All Scans
            </Link>
          </Button>
        </div>
      </div>

      {isLoading && !summary && !loadError && (
        <div
          className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
          data-testid="cloud-overview-loading"
        >
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardHeader className="pb-2">
                <div className="h-4 rounded bg-muted" />
              </CardHeader>
              <CardContent>
                <div className="mb-2 h-8 rounded bg-muted" />
                <div className="h-4 rounded bg-muted" />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {loadError && (
        <Card data-testid="cloud-overview-error" role="alert">
          <CardContent className="py-8 text-center">
            <AlertTriangle className="mx-auto mb-4 h-12 w-12 text-red-500" />
            <p className="mb-2 font-medium text-red-600">Cloud security data could not be loaded</p>
            <p className="mb-4 text-sm text-muted-foreground">{loadError}</p>
            <Button onClick={fetchSummary} variant="outline" disabled={isLoading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Try again
            </Button>
          </CardContent>
        </Card>
      )}

      {summary && (
        <>
          <div
            className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
            data-testid="cloud-overview-summary"
          >
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold" data-testid="cloud-total-scans">
                  {summary.total_scans}
                </div>
                <p className="text-xs text-muted-foreground">started in the last 30 days</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
                <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold" data-testid="cloud-compliance-score">
                  {summary.compliance_score === null
                    ? 'Not assessed'
                    : `${summary.compliance_score}%`}
                </div>
                <p className="text-xs text-muted-foreground">passed share of checks {period}</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Critical Findings</CardTitle>
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div
                  className="text-2xl font-bold text-red-600"
                  data-testid="cloud-critical-findings"
                >
                  {summary.critical_findings}
                </div>
                <p className="text-xs text-muted-foreground">failed checks of critical severity</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Accounts Assessed</CardTitle>
                <Cloud className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold" data-testid="cloud-accounts-assessed">
                  {summary.accounts_assessed}
                </div>
                <p className="text-xs text-muted-foreground">with a completed scan {period}</p>
              </CardContent>
            </Card>
          </div>

          {summary.total_scans === 0 && (
            <Card data-testid="cloud-no-scans">
              <CardContent className="flex items-start gap-3 p-6 text-sm">
                <Info className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
                <div className="space-y-2">
                  <p className="font-medium">No scans yet</p>
                  <p className="text-muted-foreground">
                    The figures above come from cloud scan results. Start a scan to see them.
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <Link href="/cloud-security/scans">Go to scans</Link>
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          <Card data-testid="cloud-findings-by-severity">
            <CardHeader>
              <CardTitle>Failed Checks by Severity</CardTitle>
              <CardDescription>
                {plural(summary.total_findings, 'failed check')} in the newest completed scan of{' '}
                {plural(summary.accounts_assessed, 'account')} {period}. The severity is the one
                each check declares.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {SEVERITY_ROWS.map(row => (
                  <div key={row.key} className="flex items-center justify-between">
                    <span className={`text-sm font-medium ${row.className}`}>{row.label}</span>
                    <span className="font-bold" data-testid={`cloud-severity-${row.key}`}>
                      {summary[row.key]}
                    </span>
                  </div>
                ))}
                {summary.unknown_severity_findings > 0 && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-muted-foreground">
                      Unknown (check no longer in the catalog)
                    </span>
                    <span
                      className="font-bold"
                      data-testid="cloud-severity-unknown_severity_findings"
                    >
                      {summary.unknown_severity_findings}
                    </span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {/* Quick Actions */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-6">
          <div className="flex items-center space-x-4">
            <Cloud className="h-8 w-8 text-blue-600" />
            <div>
              <h3 className="font-semibold">Cloud Scans</h3>
              <p className="text-sm text-muted-foreground">View and manage security scans</p>
            </div>
          </div>
          <Button asChild className="mt-4 w-full" variant="outline">
            <Link href="/cloud-security/scans">Manage Scans</Link>
          </Button>
        </Card>

        <Card className="p-6">
          <div className="flex items-center space-x-4">
            <CheckCircle2 className="h-8 w-8 text-green-600" />
            <div>
              <h3 className="font-semibold">Compliance</h3>
              <p className="text-sm text-muted-foreground">Monitor compliance frameworks</p>
            </div>
          </div>
          <Button asChild className="mt-4 w-full" variant="outline">
            <Link href="/cloud-security/compliance">View Compliance</Link>
          </Button>
        </Card>

        {summary && (
          <Card className="p-6">
            <div className="flex items-center space-x-4">
              <Clock className="h-8 w-8 text-orange-600" />
              <div>
                <h3 className="font-semibold">Last Scan</h3>
                <p className="text-sm text-muted-foreground" data-testid="cloud-last-scan">
                  {summary.last_scan_at ? (
                    <time dateTime={utcDate(summary.last_scan_at).toISOString()}>
                      {utcDate(summary.last_scan_at).toLocaleString()}
                    </time>
                  ) : (
                    'No scan yet'
                  )}
                </p>
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
