'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cspmClient, getCSPMPath } from '@/lib/api-client'
import { getErrorMessage } from '@/lib/utils'
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Search,
  RefreshCw,
  Info,
  Construction,
} from 'lucide-react'

/*
 * Every figure on this page comes from the CSPM service, which aggregates the
 * newest completed scan of each of the team's cloud accounts. When a request
 * fails the page says so and offers a retry. It used to show an invented
 * account instead (1547 resources, 86.7% compliant, CIS / NIST / PCI with
 * made-up control counts and three made-up findings), which read exactly
 * like a real posture (#572).
 */

interface ComplianceFramework {
  name: string
  total_checks: number
  passed_checks: number
  failed_checks: number
  compliance_percentage: number
  last_assessment: string | null
}

interface ComplianceSummary {
  total_resources: number
  compliant_resources: number
  non_compliant_resources: number
  /** null when no check produced a verdict in the period. */
  overall_score: number | null
  frameworks: ComplianceFramework[]
  scans_considered: number
  summary_period_days: number
  last_updated: string | null
}

interface ComplianceFinding {
  finding_id: string
  scan_id: string
  check_id: string
  title: string
  frameworks: string[]
  resource_id: string
  resource_type: string
  region: string | null
  status: 'passed' | 'failed'
  severity: string | null
  description: string
  remediation: string | null
  last_checked: string | null
}

interface ComplianceFindingsResponse {
  findings: ComplianceFinding[]
  total_count: number
}

interface ComplianceData {
  summary: ComplianceSummary
  findings: ComplianceFindingsResponse
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  info: 'bg-gray-100 text-gray-800 border-gray-200',
}

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'Unknown'
}

export default function CompliancePage() {
  const [data, setData] = useState<ComplianceData | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [selectedFramework, setSelectedFramework] = useState<string>('all')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')

  const fetchComplianceData = useCallback(async () => {
    setIsLoading(true)
    setLoadError(null)
    try {
      const [summary, findings] = await Promise.all([
        cspmClient.get<ComplianceSummary>(getCSPMPath('/api/v1/compliance/summary')),
        cspmClient.get<ComplianceFindingsResponse>(getCSPMPath('/api/v1/compliance/findings')),
      ])
      setData({ summary, findings })
    } catch (error) {
      // Nothing from a half-failed load is shown: the summary and the
      // findings describe the same scans and must not disagree.
      setData(null)
      setLoadError(getErrorMessage(error, 'The CSPM service did not answer.'))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchComplianceData()
  }, [fetchComplianceData])

  const summary = data?.summary
  const findings = data?.findings.findings ?? []

  const filteredFindings = findings.filter(finding => {
    const matchesFramework =
      selectedFramework === 'all' || finding.frameworks.includes(selectedFramework)
    const matchesSeverity = selectedSeverity === 'all' || finding.severity === selectedSeverity
    const term = searchTerm.toLowerCase()
    const matchesSearch =
      term === '' ||
      finding.title.toLowerCase().includes(term) ||
      finding.check_id.toLowerCase().includes(term) ||
      finding.resource_id.toLowerCase().includes(term)
    return matchesFramework && matchesSeverity && matchesSearch
  })

  return (
    <div className="space-y-6">
      {/* v1.0 Roadmap Future Notice */}
      <Card className="border-amber-500 bg-amber-50 dark:bg-amber-900/20">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Construction className="h-6 w-6 text-amber-600" />
            <div>
              <CardTitle className="text-amber-900 dark:text-amber-100">
                Coming in Future Release
              </CardTitle>
              <CardDescription className="text-amber-700 dark:text-amber-200">
                Cloud Compliance module is planned for post-v1.0 release. Its results come from the
                AWS checks only, grouped by the frameworks each check is tagged with; they are not a
                full assessment against any framework.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Compliance</h1>
          <p className="text-muted-foreground">
            Check results from the newest completed scan of each cloud account
          </p>
        </div>
        <Button onClick={fetchComplianceData} variant="outline" size="sm" disabled={isLoading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {isLoading && !data && !loadError && (
        <div className="grid gap-6" data-testid="compliance-loading">
          {[...Array(3)].map((_, i) => (
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
      )}

      {loadError && (
        <Card data-testid="compliance-error" role="alert">
          <CardContent className="py-8 text-center">
            <AlertTriangle className="mx-auto mb-4 h-12 w-12 text-red-500" />
            <p className="mb-2 font-medium text-red-600">Compliance data could not be loaded</p>
            <p className="mb-4 text-sm text-muted-foreground">{loadError}</p>
            <Button onClick={fetchComplianceData} variant="outline" disabled={isLoading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Try again
            </Button>
          </CardContent>
        </Card>
      )}

      {summary && (
        <>
          {/* Summary Cards */}
          <div
            className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
            data-testid="compliance-summary"
          >
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Overall Score</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold" data-testid="compliance-overall-score">
                  {summary.overall_score === null ? 'Not assessed' : `${summary.overall_score}%`}
                </div>
                <p className="text-xs text-muted-foreground">
                  {summary.scans_considered === 1
                    ? 'from 1 completed scan'
                    : `from ${summary.scans_considered} completed scans`}{' '}
                  in the last {summary.summary_period_days} days
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Compliant Resources</CardTitle>
                <CheckCircle2 className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{summary.compliant_resources}</div>
                <p className="text-xs text-muted-foreground">
                  of {summary.total_resources} resources checked
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Non-Compliant</CardTitle>
                <XCircle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{summary.non_compliant_resources}</div>
                <p className="text-xs text-muted-foreground">with at least one failed check</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Frameworks</CardTitle>
                <Info className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{summary.frameworks.length}</div>
                <p className="text-xs text-muted-foreground">with check results</p>
              </CardContent>
            </Card>
          </div>

          {summary.scans_considered === 0 && (
            <Card data-testid="compliance-no-scans">
              <CardContent className="flex items-start gap-3 p-6 text-sm">
                <Info className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
                <div className="space-y-2">
                  <p className="font-medium">
                    No completed scan in the last {summary.summary_period_days} days
                  </p>
                  <p className="text-muted-foreground">
                    Compliance is computed from cloud scan results. Start a scan to see it here.
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <Link href="/cloud-security/scans">Go to scans</Link>
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Compliance Frameworks */}
          {summary.frameworks.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Compliance Frameworks</CardTitle>
                <CardDescription>
                  Passed share of the check results mapped to each framework
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {summary.frameworks.map(framework => (
                    <div key={framework.name} className="rounded-lg border p-4">
                      <div className="mb-2 flex items-center justify-between">
                        <h3 className="font-semibold">{framework.name}</h3>
                        <div className="text-right">
                          <div className="text-2xl font-bold">
                            {framework.compliance_percentage}%
                          </div>
                          <p className="text-xs text-muted-foreground">checks passed</p>
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span>
                          {framework.passed_checks} passed, {framework.failed_checks} failed
                        </span>
                        <span className="text-muted-foreground">
                          Last assessed: {formatDate(framework.last_assessment)}
                        </span>
                      </div>
                      <div className="mt-2 h-2 w-full rounded-full bg-gray-200">
                        <div
                          className="h-2 rounded-full bg-blue-600"
                          style={{ width: `${framework.compliance_percentage}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Findings */}
          <Card>
            <CardHeader>
              <CardTitle>Compliance Findings</CardTitle>
              <CardDescription>
                {data.findings.total_count === 1
                  ? '1 check result'
                  : `${data.findings.total_count} check results`}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="mb-4 flex flex-wrap gap-4">
                <div className="flex items-center gap-2">
                  <Search className="h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search checks, resources..."
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    className="w-64"
                  />
                </div>
                <Select value={selectedFramework} onValueChange={setSelectedFramework}>
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="All Frameworks" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Frameworks</SelectItem>
                    {summary.frameworks.map(framework => (
                      <SelectItem key={framework.name} value={framework.name}>
                        {framework.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                  <SelectTrigger className="w-32">
                    <SelectValue placeholder="All Severities" />
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
              </div>

              <div className="rounded-lg border">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b bg-muted/50">
                        <th className="p-3 text-left font-medium">Status</th>
                        <th className="p-3 text-left font-medium">Check</th>
                        <th className="p-3 text-left font-medium">Resource</th>
                        <th className="p-3 text-left font-medium">Severity</th>
                        <th className="p-3 text-left font-medium">Frameworks</th>
                        <th className="p-3 text-left font-medium">Last Checked</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map(finding => (
                        <tr key={finding.finding_id} className="border-b hover:bg-muted/50">
                          <td className="p-3">
                            <div className="flex items-center gap-2">
                              {finding.status === 'passed' ? (
                                <CheckCircle2 className="h-4 w-4 text-green-500" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-500" />
                              )}
                              <span className="capitalize">{finding.status}</span>
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="font-medium">{finding.title}</div>
                            <div className="text-sm text-muted-foreground">
                              {finding.description}
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="font-mono text-sm">{finding.resource_type}</div>
                            <div className="max-w-48 truncate text-xs text-muted-foreground">
                              {finding.resource_id}
                            </div>
                          </td>
                          <td className="p-3">
                            {finding.severity ? (
                              <Badge
                                className={severityColors[finding.severity] ?? severityColors.info}
                              >
                                {finding.severity.toUpperCase()}
                              </Badge>
                            ) : (
                              <span className="text-sm text-muted-foreground">Unknown</span>
                            )}
                          </td>
                          <td className="p-3">
                            <div className="flex flex-wrap gap-1">
                              {finding.frameworks.map(name => (
                                <Badge key={name} variant="outline">
                                  {name}
                                </Badge>
                              ))}
                            </div>
                          </td>
                          <td className="p-3 text-sm text-muted-foreground">
                            {formatDate(finding.last_checked)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {filteredFindings.length === 0 && (
                  <div className="py-8 text-center text-muted-foreground">
                    {findings.length === 0
                      ? 'No check results yet.'
                      : 'No check results match the current filters.'}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
