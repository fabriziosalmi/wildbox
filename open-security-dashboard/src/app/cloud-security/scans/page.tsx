'use client'

import { useCallback, useEffect, useState } from 'react'
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
import { AlertTriangle, Info, Plus, RefreshCw } from 'lucide-react'

/**
 * GET /api/v1/cspm/providers: the providers the CSPM service can scan, from
 * its own registry (a session factory and implemented checks). The form
 * offers these and nothing else; it used to list GCP and Azure, whose scans
 * the service accepted and then always failed (#612).
 */
interface ScanProvider {
  provider: string
  name: string
  checks: number
}

interface ProvidersResponse {
  providers: ScanProvider[]
}

interface NewScanRequest {
  provider: string
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

  // The providers the service can scan; null until it answers.
  const [providers, setProviders] = useState<ScanProvider[] | null>(null)
  const [providersError, setProvidersError] = useState<string | null>(null)
  const [providersLoading, setProvidersLoading] = useState(true)

  // New scan form state. No provider is chosen until the service lists them.
  const [newScan, setNewScan] = useState<Partial<NewScanRequest>>({
    credentials: {
      auth_method: 'access_key',
    },
  })

  const fetchProviders = useCallback(async () => {
    setProvidersLoading(true)
    setProvidersError(null)
    try {
      const response = await cspmClient.get<ProvidersResponse>(getCSPMPath('/api/v1/providers'))
      setProviders(response.providers)
      setNewScan(current =>
        response.providers.some(entry => entry.provider === current.provider)
          ? current
          : { ...current, provider: response.providers[0]?.provider }
      )
    } catch (error) {
      // No list stands in for the missing answer: the form offers nothing.
      setProviders(null)
      setProvidersError(getErrorMessage(error, 'The CSPM service did not answer.'))
    } finally {
      setProvidersLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchProviders()
  }, [fetchProviders])

  const canCreate = !!providers && providers.length > 0 && !isCreating

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
        provider: providers?.[0]?.provider,
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
            <Info className="h-6 w-6 text-amber-600" />
            <div>
              <CardTitle className="text-amber-900 dark:text-amber-100">AWS only</CardTitle>
              <CardDescription className="text-amber-700 dark:text-amber-200">
                Scans run against AWS accounts only. Azure and Google Cloud are not supported, and
                the form offers only the providers the CSPM service lists.
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
                    {providers && providers.length > 0 ? (
                      <Select
                        value={newScan.provider}
                        onValueChange={(value: string) =>
                          setNewScan({ ...newScan, provider: value })
                        }
                      >
                        <SelectTrigger id="provider" data-testid="scan-provider-select">
                          <SelectValue placeholder="Select provider" />
                        </SelectTrigger>
                        <SelectContent>
                          {providers.map(entry => (
                            <SelectItem
                              key={entry.provider}
                              value={entry.provider}
                              data-testid={`scan-provider-option-${entry.provider}`}
                            >
                              {entry.name} ({entry.checks} {entry.checks === 1 ? 'check' : 'checks'}
                              )
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : (
                      <p
                        className="pt-2 text-sm text-muted-foreground"
                        data-testid="scan-provider-unavailable"
                      >
                        {providersLoading
                          ? 'Loading providers…'
                          : providersError
                            ? 'Not available'
                            : 'None available'}
                      </p>
                    )}
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

                {providersError && (
                  <div
                    className="flex items-start gap-3 rounded-md border border-red-300 p-4 text-sm"
                    data-testid="scan-providers-error"
                    role="alert"
                  >
                    <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" />
                    <div className="space-y-2">
                      <p className="font-medium text-red-600">
                        The providers the CSPM service can scan could not be loaded
                      </p>
                      <p className="text-muted-foreground">{providersError}</p>
                      <Button
                        onClick={fetchProviders}
                        variant="outline"
                        size="sm"
                        disabled={providersLoading}
                      >
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Try again
                      </Button>
                    </div>
                  </div>
                )}

                {providers && providers.length === 0 && (
                  <p className="text-sm text-muted-foreground" data-testid="scan-providers-empty">
                    The CSPM service reports no provider it can scan.
                  </p>
                )}

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
                <Button onClick={createScan} disabled={!canCreate}>
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
