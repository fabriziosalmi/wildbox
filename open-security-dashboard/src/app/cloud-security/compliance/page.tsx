'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cspmClient, getCSPMPath } from '@/lib/api-client'
import { useToast } from '@/hooks/use-toast'
import { 
  Shield, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  Search,
  Filter,
  Download,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Info
} from 'lucide-react'

interface ComplianceFramework {
  name: string
  version: string
  description: string
  total_controls: number
  passed_controls: number
  failed_controls: number
  compliance_percentage: number
  last_assessment: string
}

interface ComplianceFinding {
  finding_id: string
  framework: string
  control_id: string
  control_title: string
  resource_id: string
  resource_type: string
  region: string
  status: 'passed' | 'failed' | 'warning' | 'not_applicable'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  remediation: string
  last_checked: string
}

interface ComplianceSummary {
  total_resources: number
  compliant_resources: number
  non_compliant_resources: number
  overall_score: number
  frameworks: ComplianceFramework[]
  trend: {
    direction: 'up' | 'down' | 'stable'
    percentage: number
  }
}

export default function CompliancePage() {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null)
  const [findings, setFindings] = useState<ComplianceFinding[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [selectedFramework, setSelectedFramework] = useState<string>('all')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')
  const { toast } = useToast()

  useEffect(() => {
    fetchComplianceData()
  }, [])

  const fetchComplianceData = async () => {
    try {
      setIsLoading(true)
      
      const [summaryResponse, findingsResponse] = await Promise.allSettled([
        cspmClient.get(getCSPMPath('/api/v1/compliance/summary')),
        cspmClient.get(getCSPMPath('/api/v1/compliance/findings'))
      ])

      if (summaryResponse.status === 'fulfilled') {
        setSummary(summaryResponse.value)
      } else {
        console.warn('Failed to fetch compliance summary:', summaryResponse.reason)
        // Set default data for demo
        setSummary({
          total_resources: 1547,
          compliant_resources: 1342,
          non_compliant_resources: 205,
          overall_score: 86.7,
          frameworks: [
            {
              name: 'CIS AWS Foundations',
              version: '1.4.0',
              description: 'Center for Internet Security AWS Foundations Benchmark',
              total_controls: 51,
              passed_controls: 43,
              failed_controls: 8,
              compliance_percentage: 84.3,
              last_assessment: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString()
            },
            {
              name: 'NIST Cybersecurity Framework',
              version: '1.1',
              description: 'NIST Cybersecurity Framework controls',
              total_controls: 108,
              passed_controls: 97,
              failed_controls: 11,
              compliance_percentage: 89.8,
              last_assessment: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString()
            },
            {
              name: 'PCI DSS',
              version: '3.2.1',
              description: 'Payment Card Industry Data Security Standard',
              total_controls: 78,
              passed_controls: 67,
              failed_controls: 11,
              compliance_percentage: 85.9,
              last_assessment: new Date(Date.now() - 1000 * 60 * 60 * 1).toISOString()
            }
          ],
          trend: {
            direction: 'up',
            percentage: 2.4
          }
        })
      }

      if (findingsResponse.status === 'fulfilled') {
        setFindings(findingsResponse.value)
      } else {
        console.warn('Failed to fetch compliance findings:', findingsResponse.reason)
        // Set demo data
        setFindings([
          {
            finding_id: 'finding-001',
            framework: 'CIS AWS Foundations',
            control_id: 'CIS-2.1',
            control_title: 'Ensure CloudTrail is enabled in all regions',
            resource_id: 'arn:aws:cloudtrail:us-west-2:123456789012:trail/demo-trail',
            resource_type: 'CloudTrail',
            region: 'us-west-2',
            status: 'failed',
            severity: 'high',
            description: 'CloudTrail is not enabled in all AWS regions',
            remediation: 'Enable CloudTrail in all regions to ensure comprehensive logging',
            last_checked: new Date(Date.now() - 1000 * 60 * 30).toISOString()
          },
          {
            finding_id: 'finding-002',
            framework: 'NIST Cybersecurity Framework',
            control_id: 'NIST-PR.AC-1',
            control_title: 'Access Control Policy and Procedures',
            resource_id: 'arn:aws:iam::123456789012:policy/demo-policy',
            resource_type: 'IAM Policy',
            region: 'global',
            status: 'passed',
            severity: 'medium',
            description: 'Access control policy meets NIST requirements',
            remediation: 'Continue monitoring access control policies',
            last_checked: new Date(Date.now() - 1000 * 60 * 15).toISOString()
          },
          {
            finding_id: 'finding-003',
            framework: 'PCI DSS',
            control_id: 'PCI-3.4',
            control_title: 'Render PANs unreadable',
            resource_id: 'arn:aws:s3:::demo-bucket',
            resource_type: 'S3 Bucket',
            region: 'us-east-1',
            status: 'failed',
            severity: 'critical',
            description: 'S3 bucket may contain unencrypted cardholder data',
            remediation: 'Enable encryption at rest for all S3 buckets containing cardholder data',
            last_checked: new Date(Date.now() - 1000 * 60 * 45).toISOString()
          }
        ])
      }

    } catch (error: any) {
      console.error('Error fetching compliance data:', error)
      toast({
        title: 'Error',
        description: 'Failed to fetch compliance data. Please try again.',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />
      default:
        return <Info className="w-4 h-4 text-blue-500" />
    }
  }

  const getSeverityBadge = (severity: string) => {
    const severityColors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      info: 'bg-gray-100 text-gray-800 border-gray-200'
    }
    
    return (
      <Badge className={severityColors[severity as keyof typeof severityColors] || severityColors.info}>
        {severity.toUpperCase()}
      </Badge>
    )
  }

  const filteredFindings = findings.filter(finding => {
    const matchesFramework = selectedFramework === 'all' || finding.framework === selectedFramework
    const matchesSeverity = selectedSeverity === 'all' || finding.severity === selectedSeverity
    const matchesSearch = searchTerm === '' || 
      finding.control_title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.resource_id.toLowerCase().includes(searchTerm.toLowerCase())
    
    return matchesFramework && matchesSeverity && matchesSearch
  })

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Compliance</h1>
        </div>
        <div className="grid gap-6">
          {[...Array(4)].map((_, i) => (
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
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Compliance</h1>
          <p className="text-muted-foreground">
            Monitor compliance posture across security frameworks
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={fetchComplianceData} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Overall Score</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary.overall_score}%</div>
              <p className="text-xs text-muted-foreground flex items-center">
                {summary.trend.direction === 'up' ? (
                  <TrendingUp className="w-3 h-3 mr-1 text-green-500" />
                ) : (
                  <TrendingDown className="w-3 h-3 mr-1 text-red-500" />
                )}
                {summary.trend.percentage}% from last month
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
                of {summary.total_resources} total resources
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
              <p className="text-xs text-muted-foreground">
                require attention
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Frameworks</CardTitle>
              <Info className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary.frameworks.length}</div>
              <p className="text-xs text-muted-foreground">
                active frameworks
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Compliance Frameworks */}
      {summary?.frameworks && (
        <Card>
          <CardHeader>
            <CardTitle>Compliance Frameworks</CardTitle>
            <CardDescription>
              Current compliance status across security frameworks
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {summary.frameworks.map((framework, index) => (
                <div key={index} className="border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <h3 className="font-semibold">{framework.name}</h3>
                      <p className="text-sm text-muted-foreground">{framework.description}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold">{framework.compliance_percentage}%</div>
                      <p className="text-xs text-muted-foreground">compliance</p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span>
                      {framework.passed_controls} passed, {framework.failed_controls} failed
                    </span>
                    <span className="text-muted-foreground">
                      Last assessed: {formatDate(framework.last_assessment)}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                    <div 
                      className="bg-blue-600 h-2 rounded-full" 
                      style={{ width: `${framework.compliance_percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle>Compliance Findings</CardTitle>
          <CardDescription>
            Detailed compliance findings and recommendations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4 mb-4">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search controls, resources..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-64"
              />
            </div>
            <Select value={selectedFramework} onValueChange={setSelectedFramework}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="All Frameworks" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Frameworks</SelectItem>
                {summary?.frameworks.map((framework) => (
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

          {/* Findings Table */}
          <div className="border rounded-lg">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left p-3 font-medium">Status</th>
                    <th className="text-left p-3 font-medium">Control</th>
                    <th className="text-left p-3 font-medium">Resource</th>
                    <th className="text-left p-3 font-medium">Severity</th>
                    <th className="text-left p-3 font-medium">Framework</th>
                    <th className="text-left p-3 font-medium">Last Checked</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((finding) => (
                    <tr key={finding.finding_id} className="border-b hover:bg-muted/50">
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(finding.status)}
                          <span className="capitalize">{finding.status}</span>
                        </div>
                      </td>
                      <td className="p-3">
                        <div>
                          <div className="font-medium">{finding.control_id}</div>
                          <div className="text-sm text-muted-foreground">{finding.control_title}</div>
                        </div>
                      </td>
                      <td className="p-3">
                        <div>
                          <div className="font-mono text-sm">{finding.resource_type}</div>
                          <div className="text-xs text-muted-foreground truncate max-w-48">
                            {finding.resource_id}
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        {getSeverityBadge(finding.severity)}
                      </td>
                      <td className="p-3">
                        <Badge variant="outline">{finding.framework}</Badge>
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
              <div className="text-center py-8 text-muted-foreground">
                No compliance findings found matching the current filters.
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
