'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { cspmClient, getCSPMPath } from '@/lib/api-client'
import { useToast } from '@/hooks/use-toast'
import { getErrorMessage } from '@/lib/utils'
import { Info, Plus, Construction } from 'lucide-react'

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
  // The ID of the last scan started here: the CSPM service answers with it,
  // and it is the only scan this page can name (see the notice below).
  const [lastScanId, setLastScanId] = useState<string | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [showNewScanDialog, setShowNewScanDialog] = useState(false)
  const { toast } = useToast()

  // New scan form state
  const [newScan, setNewScan] = useState<Partial<NewScanRequest>>({
    provider: 'aws',
    credentials: {
      auth_method: 'access_key',
    },
  })

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

      const response = await cspmClient.post<{ scan_id: string }>(
        getCSPMPath('/api/v1/scans'),
        newScan
      )

      toast({
        title: 'Scan Created',
        description: `Scan ${response.scan_id} has been created and will start shortly.`,
      })

      setLastScanId(response.scan_id)
      setShowNewScanDialog(false)
      setNewScan({
        provider: 'aws',
        credentials: { auth_method: 'access_key' },
      })
    } catch (error) {
      console.error('Error creating scan:', error)
      toast({
        title: 'Error',
        description: getErrorMessage(error, 'Failed to create scan. Please try again.'),
        variant: 'destructive',
      })
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <div className="space-y-8">
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
                Cloud Security Scans module is planned for post-v1.0 release. This feature will
                enable automated security scanning across AWS, Azure, and GCP environments.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cloud Security Scans</h1>
          <p className="text-muted-foreground">Start security scans of your cloud environments</p>
        </div>

        <div className="flex space-x-2">
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
                      onValueChange={(value: 'aws' | 'gcp' | 'azure') =>
                        setNewScan({ ...newScan, provider: value })
                      }
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
                      onChange={e => setNewScan({ ...newScan, account_id: e.target.value })}
                      placeholder="Enter account ID"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="account_name">Account Name (Optional)</Label>
                  <Input
                    id="account_name"
                    value={newScan.account_name || ''}
                    onChange={e => setNewScan({ ...newScan, account_name: e.target.value })}
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
                        onChange={e =>
                          setNewScan({
                            ...newScan,
                            credentials: {
                              ...newScan.credentials,
                              auth_method: newScan.credentials?.auth_method || 'access_key',
                              access_key_id: e.target.value,
                            },
                          })
                        }
                        placeholder="Enter AWS Access Key ID"
                      />
                    </div>
                    <div>
                      <Label htmlFor="secret_key">Secret Access Key</Label>
                      <Input
                        id="secret_key"
                        type="password"
                        value={newScan.credentials?.secret_access_key || ''}
                        onChange={e =>
                          setNewScan({
                            ...newScan,
                            credentials: {
                              ...newScan.credentials,
                              auth_method: newScan.credentials?.auth_method || 'access_key',
                              secret_access_key: e.target.value,
                            },
                          })
                        }
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

      {/* Scan history: the CSPM service has no endpoint that lists scans. This
          page used to fill the gap with three invented scans. */}
      <Card data-testid="scan-history-unavailable">
        <CardContent className="flex items-start gap-3 p-6 text-sm">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
          <div className="space-y-2">
            <p className="font-medium">Scan history is not available</p>
            <p className="text-muted-foreground">
              The CSPM service does not list scans, so this page cannot show the scans that have
              run. A scan you start here reports its ID when the service accepts it.
            </p>
            {lastScanId && (
              <p data-testid="last-scan-id">
                Last scan started: <span className="font-mono">{lastScanId}</span>
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
