'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { cspmClient, getCSPMPath } from '@/lib/api-client'
import { useToast } from '@/hooks/use-toast'
import { 
  Play, 
  Pause, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  AlertTriangle,
  Plus,
  Eye,
  Download,
  RefreshCw,
  Construction
} from 'lucide-react'

interface ScanStatus {
  scan_id: string
  provider: string
  account_id: string
  account_name?: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  created_at: string
  started_at?: string
  completed_at?: string
  error_message?: string
  progress?: number
  total_checks?: number
  completed_checks?: number
  findings_count?: number
}

interface NewScanRequest {
  provider: 'aws' | 'gcp' | 'azure'
  account_id: string
  account_name?: string
  regions?: string[]
  check_ids?: string[]
  credentials: {
    auth_method: string
    access_key_id?: string
    secret_access_key?: string
    role_arn?: string
    project_id?: string
    service_account_key?: string
    subscription_id?: string
    tenant_id?: string
    client_id?: string
    client_secret?: string
  }
}

export default function CloudSecurityScansPage() {
  const [scans, setScans] = useState<ScanStatus[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isCreating, setIsCreating] = useState(false)
  const [showNewScanDialog, setShowNewScanDialog] = useState(false)
  const { toast } = useToast()

  // New scan form state
  const [newScan, setNewScan] = useState<Partial<NewScanRequest>>({
    provider: 'aws',
    credentials: {
      auth_method: 'access_key'
    }
  })

  useEffect(() => {
    fetchScans()
    // Set up polling for active scans
    const interval = setInterval(fetchScans, 10000) // Poll every 10 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchScans = async () => {
    try {
      // Since we don't have a list scans endpoint, we'll create mock data
      // In a real implementation, you'd call the API
      const mockScans: ScanStatus[] = [
        {
          scan_id: 'scan-001',
          provider: 'aws',
          account_id: '123456789012',
          account_name: 'Production AWS',
          status: 'completed',
          created_at: new Date(Date.now() - 3600000).toISOString(),
          started_at: new Date(Date.now() - 3500000).toISOString(),
          completed_at: new Date(Date.now() - 600000).toISOString(),
          total_checks: 45,
          completed_checks: 45,
          findings_count: 12
        },
        {
          scan_id: 'scan-002',
          provider: 'gcp',
          account_id: 'my-project-123',
          account_name: 'GCP Production',
          status: 'running',
          created_at: new Date(Date.now() - 1800000).toISOString(),
          started_at: new Date(Date.now() - 1700000).toISOString(),
          progress: 65,
          total_checks: 38,
          completed_checks: 25
        },
        {
          scan_id: 'scan-003',
          provider: 'azure',
          account_id: 'sub-456789',
          account_name: 'Azure Development',
          status: 'failed',
          created_at: new Date(Date.now() - 7200000).toISOString(),
          started_at: new Date(Date.now() - 7100000).toISOString(),
          error_message: 'Authentication failed'
        }
      ]
      
      setScans(mockScans)
    } catch (error: any) {
      console.error('Error fetching scans:', error)
      toast({
        title: 'Error',
        description: 'Failed to fetch scans. Please try again.',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const createScan = async () => {
    try {
      setIsCreating(true)
      
      // Validate required fields
      if (!newScan.provider || !newScan.account_id) {
        toast({
          title: 'Validation Error',
          description: 'Provider and Account ID are required.',
          variant: 'destructive',
        })
        return
      }

      const response = await cspmClient.post(getCSPMPath('/api/v1/scans'), newScan)
      
      toast({
        title: 'Scan Created',
        description: `Scan ${response.scan_id} has been created and will start shortly.`,
      })

      setShowNewScanDialog(false)
      setNewScan({
        provider: 'aws',
        credentials: { auth_method: 'access_key' }
      })
      
      // Refresh the scans list
      fetchScans()
      
    } catch (error: any) {
      console.error('Error creating scan:', error)
      toast({
        title: 'Error',
        description: error.message || 'Failed to create scan. Please try again.',
        variant: 'destructive',
      })
    } finally {
      setIsCreating(false)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="h-4 w-4 text-green-600" />
      case 'running':
        return <RefreshCw className="h-4 w-4 text-blue-600 animate-spin" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-600" />
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-600" />
      default:
        return <Clock className="h-4 w-4 text-gray-600" />
    }
  }

  const getStatusBadge = (status: string) => {
    const variants = {
      completed: 'bg-green-50 text-green-700',
      running: 'bg-blue-50 text-blue-700',
      failed: 'bg-red-50 text-red-700',
      pending: 'bg-yellow-50 text-yellow-700',
      cancelled: 'bg-gray-50 text-gray-700'
    }
    
    return (
      <Badge className={variants[status as keyof typeof variants] || variants.pending}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Badge>
    )
  }

  const formatTime = (timestamp?: string) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
  }

  const getProviderColor = (provider: string) => {
    switch (provider) {
      case 'aws': return 'bg-orange-50 text-orange-700'
      case 'gcp': return 'bg-blue-50 text-blue-700'
      case 'azure': return 'bg-sky-50 text-sky-700'
      default: return 'bg-gray-50 text-gray-700'
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud Security Scans</h1>
          <p className="text-muted-foreground">
            Manage and monitor security scans across your cloud environments
          </p>
        </div>
        
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <div className="animate-pulse space-y-3">
                  <div className="h-4 bg-gray-200 rounded w-1/4" />
                  <div className="h-4 bg-gray-200 rounded w-1/2" />
                  <div className="h-4 bg-gray-200 rounded w-3/4" />
                </div>
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
                Cloud Security Scans module is planned for post-v1.0 release. This feature will enable automated security scanning across AWS, Azure, and GCP environments.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud Security Scans</h1>
          <p className="text-muted-foreground">
            Manage and monitor security scans across your cloud environments
          </p>
        </div>
        
        <div className="flex space-x-2">
          <Button variant="outline" onClick={fetchScans}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          
          <Dialog open={showNewScanDialog} onOpenChange={setShowNewScanDialog}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                New Scan
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[600px]">
              <DialogHeader>
                <DialogTitle>Create New Cloud Security Scan</DialogTitle>
                <DialogDescription>
                  Configure a new security scan for your cloud environment.
                </DialogDescription>
              </DialogHeader>
              
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="provider">Cloud Provider</Label>
                    <Select
                      value={newScan.provider}
                      onValueChange={(value: 'aws' | 'gcp' | 'azure') => setNewScan({...newScan, provider: value})}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select provider" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="aws">Amazon Web Services</SelectItem>
                        <SelectItem value="gcp">Google Cloud Platform</SelectItem>
                        <SelectItem value="azure">Microsoft Azure</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div>
                    <Label htmlFor="account_id">Account ID</Label>
                    <Input
                      id="account_id"
                      value={newScan.account_id || ''}
                      onChange={(e) => setNewScan({...newScan, account_id: e.target.value})}
                      placeholder="Enter account ID"
                    />
                  </div>
                </div>
                
                <div>
                  <Label htmlFor="account_name">Account Name (Optional)</Label>
                  <Input
                    id="account_name"
                    value={newScan.account_name || ''}
                    onChange={(e) => setNewScan({...newScan, account_name: e.target.value})}
                    placeholder="Enter account name"
                  />
                </div>

                {newScan.provider === 'aws' && (
                  <>
                    <div>
                      <Label htmlFor="access_key">Access Key ID</Label>
                      <Input
                        id="access_key"
                        type="password"
                        value={newScan.credentials?.access_key_id || ''}
                        onChange={(e) => setNewScan({
                          ...newScan,
                          credentials: {
                            ...newScan.credentials, 
                            auth_method: newScan.credentials?.auth_method || 'access_key',
                            access_key_id: e.target.value
                          }
                        })}
                        placeholder="Enter AWS Access Key ID"
                      />
                    </div>
                    <div>
                      <Label htmlFor="secret_key">Secret Access Key</Label>
                      <Input
                        id="secret_key"
                        type="password"
                        value={newScan.credentials?.secret_access_key || ''}
                        onChange={(e) => setNewScan({
                          ...newScan,
                          credentials: {
                            ...newScan.credentials,
                            auth_method: newScan.credentials?.auth_method || 'access_key',
                            secret_access_key: e.target.value
                          }
                        })}
                        placeholder="Enter AWS Secret Access Key"
                      />
                    </div>
                  </>
                )}
              </div>
              
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowNewScanDialog(false)}>
                  Cancel
                </Button>
                <Button onClick={createScan} disabled={isCreating}>
                  {isCreating ? 'Creating...' : 'Create Scan'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Scans List */}
      <div className="space-y-4">
        {scans.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <AlertTriangle className="h-12 w-12 text-gray-400 mb-4" />
              <h3 className="text-lg font-medium mb-2">No scans found</h3>
              <p className="text-muted-foreground mb-4">
                Get started by creating your first cloud security scan.
              </p>
              <Button onClick={() => setShowNewScanDialog(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Create First Scan
              </Button>
            </CardContent>
          </Card>
        ) : (
          scans.map((scan) => (
            <Card key={scan.scan_id}>
              <CardContent className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      {getStatusIcon(scan.status)}
                      <h3 className="font-semibold">
                        {scan.account_name || scan.account_id}
                      </h3>
                      <Badge className={getProviderColor(scan.provider)}>
                        {scan.provider.toUpperCase()}
                      </Badge>
                      {getStatusBadge(scan.status)}
                    </div>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-muted-foreground">
                      <div>
                        <span className="font-medium">Scan ID:</span> {scan.scan_id}
                      </div>
                      <div>
                        <span className="font-medium">Created:</span> {formatTime(scan.created_at)}
                      </div>
                      {scan.completed_at && (
                        <div>
                          <span className="font-medium">Completed:</span> {formatTime(scan.completed_at)}
                        </div>
                      )}
                      {scan.findings_count !== undefined && (
                        <div>
                          <span className="font-medium">Findings:</span> {scan.findings_count}
                        </div>
                      )}
                    </div>

                    {scan.status === 'running' && scan.progress && (
                      <div className="mt-3">
                        <div className="flex justify-between text-sm mb-1">
                          <span>Progress</span>
                          <span>{scan.progress}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {scan.completed_checks}/{scan.total_checks} checks completed
                        </div>
                      </div>
                    )}

                    {scan.error_message && (
                      <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md">
                        <p className="text-sm text-red-700">{scan.error_message}</p>
                      </div>
                    )}
                  </div>
                  
                  <div className="flex space-x-2 ml-4">
                    {scan.status === 'completed' && (
                      <>
                        <Button variant="outline" size="sm">
                          <Eye className="h-4 w-4 mr-1" />
                          View Report
                        </Button>
                        <Button variant="outline" size="sm">
                          <Download className="h-4 w-4 mr-1" />
                          Download
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  )
}
