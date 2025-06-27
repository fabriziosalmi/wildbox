'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/components/auth-provider'
import { identityClient } from '@/lib/api-client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { 
  Key, 
  Plus, 
  Trash2, 
  Copy, 
  Eye, 
  EyeOff,
  Calendar,
  AlertCircle,
  Shield,
  Activity
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { ApiKey } from '@/types'

interface CreateApiKeyRequest {
  name: string
  scopes: string[]
  expires_at?: string
}

interface ApiKeyWithSecret extends ApiKey {
  key?: string // Only returned on creation
}

const availableScopes = [
  { id: 'read', name: 'Read', description: 'Read access to resources' },
  { id: 'write', name: 'Write', description: 'Write access to resources' },
  { id: 'admin', name: 'Admin', description: 'Administrative access' },
  { id: 'tools:read', name: 'Tools Read', description: 'Read access to security tools' },
  { id: 'tools:execute', name: 'Tools Execute', description: 'Execute security tools' },
  { id: 'data:read', name: 'Data Read', description: 'Read access to data services' },
  { id: 'data:write', name: 'Data Write', description: 'Write access to data services' },
  { id: 'reports:read', name: 'Reports Read', description: 'Read access to reports' },
  { id: 'reports:write', name: 'Reports Write', description: 'Create and modify reports' },
]

export default function ApiKeysPage() {
  const { user } = useAuth()
  const { toast } = useToast()
  const [apiKeys, setApiKeys] = useState<ApiKeyWithSecret[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isCreating, setIsCreating] = useState(false)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set())
  
  const [createForm, setCreateForm] = useState({
    name: '',
    scopes: [] as string[],
    expires_at: '',
  })

  useEffect(() => {
    if (user) {
      fetchApiKeys()
    }
  }, [user])

  const fetchApiKeys = async () => {
    try {
      setIsLoading(true)
      const keys = await identityClient.get('/api/v1/users/me/api-keys')
      setApiKeys(keys)
    } catch (error: any) {
      console.error('Failed to fetch API keys:', error)
      toast({
        title: "Error",
        description: "Failed to load API keys",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!createForm.name.trim()) {
      toast({
        title: "Error",
        description: "API key name is required",
        variant: "destructive",
      })
      return
    }

    if (createForm.scopes.length === 0) {
      toast({
        title: "Error", 
        description: "At least one scope is required",
        variant: "destructive",
      })
      return
    }

    setIsCreating(true)
    try {
      const createData: CreateApiKeyRequest = {
        name: createForm.name.trim(),
        scopes: createForm.scopes,
      }

      if (createForm.expires_at) {
        createData.expires_at = createForm.expires_at
      }

      const newKey = await identityClient.post('/api/v1/users/me/api-keys', createData)
      
      setApiKeys(prev => [newKey, ...prev])
      setCreateForm({ name: '', scopes: [], expires_at: '' })
      setShowCreateForm(false)
      
      toast({
        title: "Success",
        description: "API key created successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to create API key",
        variant: "destructive",
      })
    } finally {
      setIsCreating(false)
    }
  }

  const handleDeleteApiKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to delete this API key? This action cannot be undone.')) {
      return
    }

    try {
      await identityClient.delete(`/api/v1/users/me/api-keys/${keyId}`)
      setApiKeys(prev => prev.filter(key => key.id !== keyId))
      
      toast({
        title: "Success",
        description: "API key deleted successfully",
      })
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to delete API key",
        variant: "destructive",
      })
    }
  }

  const toggleKeyVisibility = (keyId: string) => {
    setVisibleKeys(prev => {
      const newSet = new Set(prev)
      if (newSet.has(keyId)) {
        newSet.delete(keyId)
      } else {
        newSet.add(keyId)
      }
      return newSet
    })
  }

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      toast({
        title: "Copied",
        description: "API key copied to clipboard",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to copy to clipboard",
        variant: "destructive",
      })
    }
  }

  const toggleScope = (scope: string) => {
    setCreateForm(prev => ({
      ...prev,
      scopes: prev.scopes.includes(scope)
        ? prev.scopes.filter(s => s !== scope)
        : [...prev.scopes, scope]
    }))
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  const isExpired = (expiresAt?: string) => {
    if (!expiresAt) return false
    return new Date(expiresAt) < new Date()
  }

  const maskApiKey = (key: string) => {
    if (key.length <= 8) return key
    return `${key.substring(0, 4)}...${key.substring(key.length - 4)}`
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">Please log in to manage API keys</p>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">API Keys</h1>
            <p className="text-muted-foreground mt-2">
              Manage API keys for programmatic access
            </p>
          </div>
          <Button onClick={() => setShowCreateForm(true)} className="flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Create API Key
          </Button>
        </div>
      </div>

      {/* Create API Key Form */}
      {showCreateForm && (
        <Card className="p-6 mb-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Create New API Key</h3>
          
          <form onSubmit={handleCreateApiKey} className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-foreground mb-2">
                Name
              </label>
              <Input
                id="name"
                type="text"
                value={createForm.name}
                onChange={(e) => setCreateForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., Production API, Development Key"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-2">
                Scopes
              </label>
              <div className="grid grid-cols-2 gap-2">
                {availableScopes.map((scope) => (
                  <label key={scope.id} className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={createForm.scopes.includes(scope.id)}
                      onChange={() => toggleScope(scope.id)}
                      className="rounded border-gray-300"
                    />
                    <div>
                      <div className="text-sm font-medium">{scope.name}</div>
                      <div className="text-xs text-muted-foreground">{scope.description}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="expires_at" className="block text-sm font-medium text-foreground mb-2">
                Expiration Date (Optional)
              </label>
              <Input
                id="expires_at"
                type="date"
                value={createForm.expires_at}
                onChange={(e) => setCreateForm(prev => ({ ...prev, expires_at: e.target.value }))}
                min={new Date().toISOString().split('T')[0]}
              />
            </div>

            <div className="flex gap-2">
              <Button type="submit" disabled={isCreating}>
                {isCreating ? 'Creating...' : 'Create API Key'}
              </Button>
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setShowCreateForm(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* API Keys List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="text-center py-8">
            <div className="text-muted-foreground">Loading API keys...</div>
          </div>
        ) : apiKeys.length === 0 ? (
          <Card className="p-8 text-center">
            <Key className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No API Keys</h3>
            <p className="text-muted-foreground mb-4">
              You haven't created any API keys yet. Create one to get started with programmatic access.
            </p>
            <Button onClick={() => setShowCreateForm(true)} className="flex items-center gap-2">
              <Plus className="w-4 h-4" />
              Create Your First API Key
            </Button>
          </Card>
        ) : (
          apiKeys.map((apiKey) => (
            <Card key={apiKey.id} className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-green-500 to-blue-600 rounded-lg flex items-center justify-center">
                    <Key className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">{apiKey.name}</h3>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant={apiKey.is_active && !isExpired(apiKey.expires_at) ? "default" : "secondary"}>
                        {apiKey.is_active && !isExpired(apiKey.expires_at) ? "Active" : "Inactive"}
                      </Badge>
                      {isExpired(apiKey.expires_at) && (
                        <Badge variant="outline" className="text-red-600 border-red-600">
                          Expired
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
                
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleDeleteApiKey(apiKey.id)}
                  className="text-red-600 hover:text-red-700"
                >
                  <Trash2 className="w-4 h-4" />
                </Button>
              </div>

              <div className="space-y-3">
                {/* API Key */}
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1">
                    API Key
                  </label>
                  <div className="flex items-center gap-2">
                    <Input
                      type={visibleKeys.has(apiKey.id) ? "text" : "password"}
                      value={apiKey.key || `${apiKey.prefix}...`}
                      readOnly
                      className="font-mono text-sm"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleKeyVisibility(apiKey.id)}
                    >
                      {visibleKeys.has(apiKey.id) ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(apiKey.key || `${apiKey.prefix}...`)}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                {/* Scopes */}
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1">
                    Scopes
                  </label>
                  <div className="flex flex-wrap gap-1">
                    {(apiKey.scopes || ['read']).map((scope: string) => {
                      const scopeConfig = availableScopes.find(s => s.id === scope)
                      return (
                        <Badge key={scope} variant="outline" className="text-xs">
                          {scopeConfig?.name || scope}
                        </Badge>
                      )
                    })}
                  </div>
                </div>

                {/* Metadata */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-muted-foreground">Created</div>
                    <div className="font-medium flex items-center gap-1">
                      <Calendar className="w-4 h-4" />
                      {formatDate(apiKey.created_at)}
                    </div>
                  </div>
                  
                  {apiKey.expires_at && (
                    <div>
                      <div className="text-muted-foreground">Expires</div>
                      <div className="font-medium flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {formatDate(apiKey.expires_at)}
                      </div>
                    </div>
                  )}
                  
                  {apiKey.last_used_at && (
                    <div>
                      <div className="text-muted-foreground">Last Used</div>
                      <div className="font-medium flex items-center gap-1">
                        <Activity className="w-4 h-4" />
                        {formatDate(apiKey.last_used_at)}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </Card>
          ))
        )}
      </div>

      {/* API Key Usage Information */}
      <Card className="p-6 mt-6">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-8 h-8 text-blue-500" />
          <h3 className="text-lg font-semibold text-foreground">Using Your API Keys</h3>
        </div>
        
        <div className="space-y-4 text-sm">
          <div>
            <h4 className="font-medium text-foreground mb-2">Authentication</h4>
            <p className="text-muted-foreground">
              Include your API key in the request header: <code className="bg-muted px-1 rounded">X-API-Key: your-api-key</code>
            </p>
          </div>
          
          <div>
            <h4 className="font-medium text-foreground mb-2">Example Usage</h4>
            <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">
{`curl -H "X-API-Key: your-api-key" \\
     -H "Content-Type: application/json" \\
     https://api.wildbox.local/api/v1/tools/nmap`}
            </pre>
          </div>
          
          <div>
            <h4 className="font-medium text-foreground mb-2">Security Best Practices</h4>
            <ul className="text-muted-foreground space-y-1">
              <li>• Keep your API keys secure and never share them publicly</li>
              <li>• Use different keys for different environments (development, production)</li>
              <li>• Set appropriate scopes and expiration dates</li>
              <li>• Regularly rotate your API keys</li>
              <li>• Monitor API key usage and disable unused keys</li>
            </ul>
          </div>
        </div>
      </Card>
    </div>
  )
}
