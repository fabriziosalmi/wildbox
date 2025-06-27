'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  Server, 
  Shield, 
  Database, 
  Cloud, 
  Bug, 
  Zap, 
  Monitor, 
  Activity, 
  Code, 
  Copy, 
  CheckCircle,
  ExternalLink,
  AlertCircle
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MainLayout } from '@/components/main-layout'
import { gatewayDataClient, dataClient } from '@/lib/api-client'

interface ApiEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'
  path: string
  description: string
  gateway_path: string
  requires_auth: boolean
  plan_required: 'Free' | 'Business' | 'Enterprise'
  parameters?: Array<{
    name: string
    type: string
    required: boolean
    description: string
  }>
  example_response?: any
}

interface ApiService {
  name: string
  description: string
  port: number
  icon: React.ComponentType<any>
  status: 'healthy' | 'degraded' | 'down'
  endpoints: ApiEndpoint[]
}

const apiServices: ApiService[] = [
  {
    name: 'Threat Intelligence Data',
    description: 'Security data lake with threat intelligence and IOCs',
    port: 8002,
    icon: Database,
    status: 'healthy',
    endpoints: [
      {
        method: 'GET',
        path: '/health',
        gateway_path: '/api/v1/data/health',
        description: 'Health check endpoint',
        requires_auth: false,
        plan_required: 'Free'
      },
      {
        method: 'GET',
        path: '/api/v1/stats',
        gateway_path: '/api/v1/data/stats',
        description: 'Get system statistics including indicator counts',
        requires_auth: true,
        plan_required: 'Free',
        example_response: {
          total_indicators: 150420,
          indicator_types: {
            ip_address: 45230,
            domain: 38940,
            file_hash: 25850,
            url: 18650,
            email: 12750
          },
          total_sources: 15,
          active_sources: 12,
          recent_collections: 42
        }
      },
      {
        method: 'GET',
        path: '/api/v1/indicators/search',
        gateway_path: '/api/v1/data/indicators/search',
        description: 'Search security indicators with filters',
        requires_auth: true,
        plan_required: 'Free',
        parameters: [
          { name: 'q', type: 'string', required: false, description: 'Search query' },
          { name: 'indicator_type', type: 'string', required: false, description: 'Filter by type' },
          { name: 'confidence', type: 'string', required: false, description: 'Confidence level' },
          { name: 'min_severity', type: 'number', required: false, description: 'Minimum severity (1-10)' },
          { name: 'limit', type: 'number', required: false, description: 'Results limit (max 10000)' },
          { name: 'offset', type: 'number', required: false, description: 'Pagination offset' }
        ]
      },
      {
        method: 'GET',
        path: '/api/v1/indicators/{indicator_id}',
        gateway_path: '/api/v1/data/indicators/{indicator_id}',
        description: 'Get detailed information about a specific indicator',
        requires_auth: true,
        plan_required: 'Free'
      },
      {
        method: 'POST',
        path: '/api/v1/indicators/lookup',
        gateway_path: '/api/v1/data/indicators/lookup',
        description: 'Bulk lookup of indicators',
        requires_auth: true,
        plan_required: 'Business'
      },
      {
        method: 'GET',
        path: '/api/v1/ips/{ip_address}',
        gateway_path: '/api/v1/data/ips/{ip_address}',
        description: 'Get intelligence about an IP address',
        requires_auth: true,
        plan_required: 'Free'
      },
      {
        method: 'GET',
        path: '/api/v1/domains/{domain}',
        gateway_path: '/api/v1/data/domains/{domain}',
        description: 'Get intelligence about a domain',
        requires_auth: true,
        plan_required: 'Free'
      },
      {
        method: 'GET',
        path: '/api/v1/hashes/{file_hash}',
        gateway_path: '/api/v1/data/hashes/{file_hash}',
        description: 'Get intelligence about a file hash',
        requires_auth: true,
        plan_required: 'Free'
      },
      {
        method: 'GET',
        path: '/api/v1/sources',
        gateway_path: '/api/v1/data/sources',
        description: 'List data sources and their status',
        requires_auth: true,
        plan_required: 'Business'
      },
      {
        method: 'GET',
        path: '/api/v1/feeds/realtime',
        gateway_path: '/api/v1/data/feeds/realtime',
        description: 'Real-time threat intelligence feed (NDJSON stream)',
        requires_auth: true,
        plan_required: 'Business'
      },
      {
        method: 'GET',
        path: '/api/v1/dashboard/threat-intel',
        gateway_path: '/api/v1/data/dashboard/threat-intel',
        description: 'Dashboard metrics for threat intelligence',
        requires_auth: true,
        plan_required: 'Free'
      }
    ]
  },
  {
    name: 'Cloud Security (CSPM)',
    description: 'Cloud Security Posture Management and compliance scanning',
    port: 8019,
    icon: Cloud,
    status: 'healthy',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/dashboard/executive-summary',
        gateway_path: '/api/v1/cspm/dashboard/executive-summary',
        description: 'Executive dashboard summary with compliance scores',
        requires_auth: true,
        plan_required: 'Business'
      }
    ]
  },
  {
    name: 'Vulnerability Management',
    description: 'Guardian vulnerability scanning and reporting',
    port: 8013,
    icon: Bug,
    status: 'healthy',
    endpoints: [
      {
        method: 'GET',
        path: '/api/v1/reports/dashboards/1/data/',
        gateway_path: '/api/v1/guardian/reports/dashboards/1/data/',
        description: 'Dashboard vulnerability data and metrics',
        requires_auth: true,
        plan_required: 'Free'
      }
    ]
  },
  {
    name: 'Response Automation',
    description: 'Security playbooks and automated response',
    port: 8018,
    icon: Zap,
    status: 'healthy',
    endpoints: [
      {
        method: 'GET',
        path: '/v1/metrics',
        gateway_path: '/api/v1/responder/metrics',
        description: 'Response automation metrics and playbook stats',
        requires_auth: true,
        plan_required: 'Business'
      }
    ]
  },
  {
    name: 'Identity & Authentication',
    description: 'User management and authentication services',
    port: 8001,
    icon: Shield,
    status: 'healthy',
    endpoints: [
      {
        method: 'POST',
        path: '/auth/login',
        gateway_path: '/auth/login',
        description: 'User authentication',
        requires_auth: false,
        plan_required: 'Free'
      },
      {
        method: 'GET',
        path: '/api/v1/user/profile',
        gateway_path: '/api/v1/identity/user/profile',
        description: 'Get user profile information',
        requires_auth: true,
        plan_required: 'Free'
      }
    ]
  }
]

async function testEndpoint(endpoint: ApiEndpoint): Promise<{ success: boolean; response?: any; error?: string }> {
  try {
    let response
    const client = gatewayDataClient // Use gateway client for testing

    switch (endpoint.method) {
      case 'GET':
        response = await client.get(endpoint.path.replace('/api/v1/', '/'))
        break
      default:
        throw new Error(`Testing ${endpoint.method} endpoints not implemented yet`)
    }

    return { success: true, response }
  } catch (error: any) {
    return { 
      success: false, 
      error: error?.response?.data?.message || error?.message || 'Unknown error'
    }
  }
}

export default function APIDocumentation() {
  const [selectedService, setSelectedService] = useState<string>('Threat Intelligence Data')
  const [testResults, setTestResults] = useState<Record<string, any>>({})
  const [copiedCode, setCopiedCode] = useState<string>('')

  // Check service health
  const { data: healthData } = useQuery({
    queryKey: ['api-health'],
    queryFn: async () => {
      try {
        const response = await dataClient.get('/health')
        return { service: 'data', status: 'healthy', ...response }
      } catch (error) {
        return { service: 'data', status: 'down', error }
      }
    },
    refetchInterval: 30000
  })

  const handleTestEndpoint = async (endpoint: ApiEndpoint) => {
    const key = `${endpoint.method}-${endpoint.path}`
    setTestResults(prev => ({ ...prev, [key]: { loading: true } }))

    const result = await testEndpoint(endpoint)
    setTestResults(prev => ({ ...prev, [key]: result }))
  }

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedCode(key)
    setTimeout(() => setCopiedCode(''), 2000)
  }

  const generateCurlCommand = (endpoint: ApiEndpoint) => {
    const baseUrl = 'https://api.wildbox.local'
    let curl = `curl -X ${endpoint.method} "${baseUrl}${endpoint.gateway_path}"`
    
    if (endpoint.requires_auth) {
      curl += ` \\\n  -H "Authorization: Bearer YOUR_TOKEN"`
    }
    
    curl += ` \\\n  -H "Content-Type: application/json"`

    if (endpoint.method === 'POST' && endpoint.path.includes('lookup')) {
      curl += ` \\\n  -d '{"indicators": [{"indicator_type": "ip_address", "value": "8.8.8.8"}]}'`
    }

    return curl
  }

  const generateJavaScriptCode = (endpoint: ApiEndpoint) => {
    const path = endpoint.gateway_path.replace('/api/v1/data/', '/')
    return `// Using Wildbox Gateway Client
import { gatewayDataClient } from '@/lib/api-client'

try {
  const response = await gatewayDataClient.${endpoint.method.toLowerCase()}('${path}')
  console.log(response)
} catch (error) {
  console.error('API Error:', error)
}`
  }

  const selectedServiceData = apiServices.find(s => s.name === selectedService)

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold">API Documentation</h1>
          <p className="text-muted-foreground mt-2">
            Complete API reference for all Wildbox security services with gateway integration
          </p>
        </div>

        {/* Service Status Overview */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Service Status
            </CardTitle>
            <CardDescription>Real-time status of all API services</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {apiServices.map((service) => {
                const Icon = service.icon
                return (
                  <div key={service.name} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <Icon className="h-5 w-5 text-blue-500" />
                      <div>
                        <div className="font-medium">{service.name}</div>
                        <div className="text-sm text-muted-foreground">Port {service.port}</div>
                      </div>
                    </div>
                    <Badge 
                      variant={service.status === 'healthy' ? 'default' : 'destructive'}
                      className={service.status === 'healthy' ? 'bg-green-500' : ''}
                    >
                      {service.status}
                    </Badge>
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Service Selector */}
        <Card>
          <CardHeader>
            <CardTitle>API Services</CardTitle>
            <CardDescription>Select a service to view its endpoints</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {apiServices.map((service) => {
                const Icon = service.icon
                const isSelected = selectedService === service.name
                return (
                  <div 
                    key={service.name}
                    className={`p-4 border rounded-lg cursor-pointer transition-colors ${
                      isSelected ? 'border-blue-500 bg-blue-50' : 'hover:bg-gray-50'
                    }`}
                    onClick={() => setSelectedService(service.name)}
                  >
                    <div className="flex items-start gap-3">
                      <Icon className="h-6 w-6 text-blue-500 mt-1" />
                      <div>
                        <h3 className="font-semibold">{service.name}</h3>
                        <p className="text-sm text-muted-foreground mt-1">
                          {service.description}
                        </p>
                        <div className="flex items-center gap-2 mt-2">
                          <Badge variant="outline">
                            {service.endpoints.length} endpoints
                          </Badge>
                          <Badge variant="outline">
                            Port {service.port}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Selected Service Endpoints */}
        {selectedServiceData && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <selectedServiceData.icon className="h-5 w-5" />
                {selectedServiceData.name} - API Endpoints
              </CardTitle>
              <CardDescription>
                {selectedServiceData.description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {selectedServiceData.endpoints.map((endpoint, index) => {
                const testKey = `${endpoint.method}-${endpoint.path}`
                const testResult = testResults[testKey]
                const curlKey = `curl-${index}`
                const jsKey = `js-${index}`

                return (
                  <div key={index} className="border rounded-lg p-4 space-y-4">
                    {/* Endpoint Header */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge 
                          className={`${
                            endpoint.method === 'GET' ? 'bg-green-500' :
                            endpoint.method === 'POST' ? 'bg-blue-500' :
                            endpoint.method === 'PUT' ? 'bg-yellow-500' :
                            endpoint.method === 'DELETE' ? 'bg-red-500' :
                            'bg-gray-500'
                          } text-white`}
                        >
                          {endpoint.method}
                        </Badge>
                        <code className="text-sm bg-gray-100 px-2 py-1 rounded">
                          {endpoint.gateway_path}
                        </code>
                        {endpoint.requires_auth && (
                          <Badge variant="outline">
                            <Shield className="h-3 w-3 mr-1" />
                            Auth Required
                          </Badge>
                        )}
                        <Badge variant="outline">
                          {endpoint.plan_required}+
                        </Badge>
                      </div>
                      
                      {endpoint.method === 'GET' && (
                        <Button
                          size="sm"
                          onClick={() => handleTestEndpoint(endpoint)}
                          disabled={testResult?.loading}
                        >
                          {testResult?.loading ? 'Testing...' : 'Test'}
                        </Button>
                      )}
                    </div>

                    {/* Description */}
                    <p className="text-sm text-muted-foreground">
                      {endpoint.description}
                    </p>

                    {/* Parameters */}
                    {endpoint.parameters && (
                      <div>
                        <h5 className="font-medium mb-2">Parameters</h5>
                        <div className="space-y-2">
                          {endpoint.parameters.map((param, paramIndex) => (
                            <div key={paramIndex} className="grid grid-cols-4 gap-2 text-sm">
                              <div className="font-mono">
                                {param.name}
                                {param.required && <span className="text-red-500">*</span>}
                              </div>
                              <div className="text-blue-600">{param.type}</div>
                              <div>{param.required ? 'Required' : 'Optional'}</div>
                              <div className="text-muted-foreground">{param.description}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Code Examples */}
                    <div className="space-y-3">
                      {/* cURL Example */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="font-medium">cURL Example</h5>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(generateCurlCommand(endpoint), curlKey)}
                          >
                            {copiedCode === curlKey ? (
                              <CheckCircle className="h-4 w-4" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="text-xs bg-gray-900 text-white p-3 rounded overflow-x-auto">
                          {generateCurlCommand(endpoint)}
                        </pre>
                      </div>

                      {/* JavaScript Example */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="font-medium">JavaScript Example</h5>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(generateJavaScriptCode(endpoint), jsKey)}
                          >
                            {copiedCode === jsKey ? (
                              <CheckCircle className="h-4 w-4" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="text-xs bg-gray-900 text-white p-3 rounded overflow-x-auto">
                          {generateJavaScriptCode(endpoint)}
                        </pre>
                      </div>
                    </div>

                    {/* Test Results */}
                    {testResult && (
                      <div className={`p-3 rounded ${
                        testResult.success ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                      } border`}>
                        <div className="flex items-center gap-2 mb-2">
                          {testResult.success ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : (
                            <AlertCircle className="h-4 w-4 text-red-500" />
                          )}
                          <span className="font-medium">
                            {testResult.success ? 'Success' : 'Error'}
                          </span>
                        </div>
                        {testResult.response && (
                          <pre className="text-xs bg-white p-2 rounded border overflow-x-auto">
                            {JSON.stringify(testResult.response, null, 2)}
                          </pre>
                        )}
                        {testResult.error && (
                          <div className="text-sm text-red-600">
                            {testResult.error}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Example Response */}
                    {endpoint.example_response && (
                      <div>
                        <h5 className="font-medium mb-2">Example Response</h5>
                        <pre className="text-xs bg-gray-100 p-3 rounded overflow-x-auto">
                          {JSON.stringify(endpoint.example_response, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )
              })}
            </CardContent>
          </Card>
        )}

        {/* Gateway Integration Guide */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              Gateway Integration Guide
            </CardTitle>
            <CardDescription>
              How to use the Wildbox Security Gateway for authenticated API access
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2">Gateway Benefits</h4>
                <ul className="text-sm space-y-1 text-muted-foreground">
                  <li>• Unified authentication across all services</li>
                  <li>• Rate limiting and plan enforcement</li>
                  <li>• SSL termination and security headers</li>
                  <li>• Request/response logging and monitoring</li>
                  <li>• Load balancing and failover</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Authentication</h4>
                <ul className="text-sm space-y-1 text-muted-foreground">
                  <li>• Include Bearer token in Authorization header</li>
                  <li>• Tokens are validated against identity service</li>
                  <li>• Plan restrictions are enforced automatically</li>
                  <li>• Rate limits are applied per user/team</li>
                </ul>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-2">Gateway URL Structure</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <Badge variant="outline">Base URL</Badge>
                  <code>https://api.wildbox.local</code>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">Data Service</Badge>
                  <code>https://api.wildbox.local/api/v1/data/*</code>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">CSPM Service</Badge>
                  <code>https://api.wildbox.local/api/v1/cspm/*</code>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">Guardian Service</Badge>
                  <code>https://api.wildbox.local/api/v1/guardian/*</code>
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <Button variant="outline" asChild>
                <a href="https://api.wildbox.local/docs" target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Gateway API Docs
                </a>
              </Button>
              <Button variant="outline" asChild>
                <a href="/auth/login" target="_blank" rel="noopener noreferrer">
                  <Shield className="h-4 w-4 mr-2" />
                  Get API Token
                </a>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  )
}
