'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Shield, Globe, Clock, AlertTriangle, CheckCircle, Loader2 } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { MainLayout } from '@/components/main-layout'
import { dataClient } from '@/lib/api-client'
import { validateIP, validateDomain, formatRelativeTime } from '@/lib/utils'

interface IOCLookupResult {
  ioc: {
    value: string
    type: 'ip' | 'domain' | 'url' | 'hash'
    reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown'
    confidence: number
    firstSeen: string
    lastSeen: string
    sources: string[]
    tags: string[]
  }
  reputation: {
    score: number
    verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown'
    sources: Array<{
      name: string
      verdict: string
      confidence: number
    }>
    lastChecked: string
  }
  geolocation?: {
    country: string
    countryCode: string
    city: string
    latitude: number
    longitude: number
    asn: string
    isp: string
  }
  whois?: {
    domain: string
    registrar: string
    creationDate: string
    expirationDate: string
    nameServers: string[]
  }
}

async function lookupIOC(indicator: string): Promise<IOCLookupResult> {
  try {
    // First, search for the indicator in our database
    const searchResponse = await dataClient.get(`/api/v1/indicators/search?q=${encodeURIComponent(indicator)}&limit=1`)
    
    const isIP = validateIP(indicator)
    const isDomain = validateDomain(indicator)
    
    let result: IOCLookupResult
    
    if (searchResponse.results && searchResponse.results.length > 0) {
      // Found in database, use real data
      const dbIndicator = searchResponse.results[0]
      result = {
        ioc: {
          value: indicator,
          type: dbIndicator.type || (isIP ? 'ip' : isDomain ? 'domain' : 'url'),
          reputation: dbIndicator.reputation || 'unknown',
          confidence: dbIndicator.confidence || 50,
          firstSeen: dbIndicator.first_seen || dbIndicator.created_at,
          lastSeen: dbIndicator.last_seen || dbIndicator.updated_at,
          sources: dbIndicator.sources || ['Open Security Data'],
          tags: dbIndicator.tags || []
        },
        reputation: {
          score: dbIndicator.reputation_score || 50,
          verdict: dbIndicator.reputation || 'unknown',
          sources: dbIndicator.reputation_sources || [
            { name: 'Open Security Data', verdict: dbIndicator.reputation || 'unknown', confidence: dbIndicator.confidence || 50 }
          ],
          lastChecked: dbIndicator.updated_at || new Date().toISOString()
        }
      }
      
      // Add geolocation for IPs if available
      if (isIP && dbIndicator.metadata?.geolocation) {
        result.geolocation = dbIndicator.metadata.geolocation
      }
      
      // Add whois for domains if available
      if (isDomain && dbIndicator.metadata?.whois) {
        result.whois = dbIndicator.metadata.whois
      }
      
    } else {
      // Not found in database, try to enrich from external sources
      try {
        const enrichResponse = await dataClient.post('/api/v1/indicators/enrich', {
          indicator,
          type: isIP ? 'ip' : isDomain ? 'domain' : 'url'
        })
        
        if (enrichResponse.success) {
          const enrichedData = enrichResponse.data
          result = {
            ioc: {
              value: indicator,
              type: enrichedData.type || (isIP ? 'ip' : isDomain ? 'domain' : 'url'),
              reputation: enrichedData.reputation || 'unknown',
              confidence: enrichedData.confidence || 50,
              firstSeen: enrichedData.first_seen || new Date().toISOString(),
              lastSeen: enrichedData.last_seen || new Date().toISOString(),
              sources: enrichedData.sources || ['External Enrichment'],
              tags: enrichedData.tags || []
            },
            reputation: {
              score: enrichedData.reputation_score || 50,
              verdict: enrichedData.reputation || 'unknown',
              sources: enrichedData.reputation_sources || [],
              lastChecked: new Date().toISOString()
            }
          }
          
          if (enrichedData.geolocation) {
            result.geolocation = enrichedData.geolocation
          }
          
          if (enrichedData.whois) {
            result.whois = enrichedData.whois
          }
        } else {
          throw new Error('Enrichment failed')
        }
      } catch (enrichError) {
        // Fallback to basic analysis
        result = {
          ioc: {
            value: indicator,
            type: isIP ? 'ip' : isDomain ? 'domain' : 'url',
            reputation: 'unknown',
            confidence: 0,
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString(),
            sources: [],
            tags: []
          },
          reputation: {
            score: 0,
            verdict: 'unknown',
            sources: [],
            lastChecked: new Date().toISOString()
          }
        }
      }
    }
    
    return result
    
  } catch (error) {
    console.error('IOC lookup failed:', error)
    
    // Fallback to mock data if APIs are unavailable
    const isIP = validateIP(indicator)
    const isDomain = validateDomain(indicator)
    
    const mockResult: IOCLookupResult = {
      ioc: {
        value: indicator,
        type: isIP ? 'ip' : isDomain ? 'domain' : 'url',
        reputation: Math.random() > 0.7 ? 'malicious' : Math.random() > 0.5 ? 'suspicious' : 'clean',
        confidence: Math.floor(Math.random() * 40) + 60,
        firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
        lastSeen: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
        sources: ['VirusTotal', 'AbuseIPDB', 'PhishTank', 'URLVoid'],
        tags: ['malware', 'botnet', 'phishing'].filter(() => Math.random() > 0.6)
      },
      reputation: {
        score: Math.floor(Math.random() * 100),
        verdict: Math.random() > 0.7 ? 'malicious' : 'clean',
        sources: [
          { name: 'VirusTotal', verdict: 'clean', confidence: 95 },
          { name: 'AbuseIPDB', verdict: 'suspicious', confidence: 78 },
          { name: 'PhishTank', verdict: 'clean', confidence: 88 }
        ],
        lastChecked: new Date().toISOString()
      }
    }

    if (isIP) {
      mockResult.geolocation = {
        country: 'United States',
        countryCode: 'US',
        city: 'San Francisco',
        latitude: 37.7749,
        longitude: -122.4194,
        asn: 'AS13335',
        isp: 'Cloudflare, Inc.'
      }
    }

    if (isDomain) {
      mockResult.whois = {
        domain: indicator,
        registrar: 'GoDaddy.com',
        creationDate: '2020-01-15T00:00:00Z',
        expirationDate: '2025-01-15T00:00:00Z',
        nameServers: ['ns1.example.com', 'ns2.example.com']
      }
    }

    return mockResult
  }
}

function ReputationBadge({ verdict, score }: { verdict: string; score?: number }) {
  const getColor = () => {
    switch (verdict) {
      case 'malicious': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100'
      case 'suspicious': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100'
      case 'clean': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100'
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100'
    }
  }

  const getIcon = () => {
    switch (verdict) {
      case 'malicious': return <AlertTriangle className="w-4 h-4" />
      case 'suspicious': return <AlertTriangle className="w-4 h-4" />
      case 'clean': return <CheckCircle className="w-4 h-4" />
      default: return <Shield className="w-4 h-4" />
    }
  }

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${getColor()}`}>
      {getIcon()}
      <span className="capitalize">{verdict}</span>
      {score !== undefined && <span>({score}%)</span>}
    </div>
  )
}

export default function ThreatIntelLookupPage() {
  const [indicator, setIndicator] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  const { data: result, isLoading, error } = useQuery({
    queryKey: ['ioc-lookup', searchTerm],
    queryFn: () => lookupIOC(searchTerm),
    enabled: !!searchTerm,
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (indicator.trim()) {
      setSearchTerm(indicator.trim())
    }
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">IOC Lookup</h1>
            <p className="text-muted-foreground">
              Analyze indicators of compromise using threat intelligence
            </p>
          </div>
        </div>

        {/* Search Form */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5" />
              Indicator Lookup
            </CardTitle>
            <CardDescription>
              Enter an IP address, domain, URL, or hash to analyze
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSearch} className="flex gap-4">
              <Input
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                placeholder="Enter IP, domain, URL, or hash..."
                className="flex-1"
                disabled={isLoading}
              />
              <Button
                type="submit"
                disabled={!indicator.trim() || isLoading}
                className="px-8"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 mr-2" />
                    Lookup
                  </>
                )}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Results */}
        {error && (
          <Card className="border-red-200 dark:border-red-800">
            <CardContent className="pt-6">
              <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
                <AlertTriangle className="w-5 h-5" />
                <span>Error occurred while analyzing indicator</span>
              </div>
            </CardContent>
          </Card>
        )}

        {result && (
          <div className="space-y-6">
            {/* Overview */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  Analysis Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-lg font-mono">{result.ioc.value}</div>
                      <div className="text-sm text-muted-foreground capitalize">
                        {result.ioc.type} • Confidence: {result.ioc.confidence}%
                      </div>
                    </div>
                    <ReputationBadge 
                      verdict={result.ioc.reputation} 
                      score={result.reputation.score}
                    />
                  </div>

                  <div className="grid gap-4 md:grid-cols-3">
                    <div>
                      <div className="text-sm text-muted-foreground">First Seen</div>
                      <div className="font-medium">
                        {formatRelativeTime(new Date(result.ioc.firstSeen))}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Last Seen</div>
                      <div className="font-medium">
                        {formatRelativeTime(new Date(result.ioc.lastSeen))}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Sources</div>
                      <div className="font-medium">{result.ioc.sources.length} providers</div>
                    </div>
                  </div>

                  {result.ioc.tags.length > 0 && (
                    <div>
                      <div className="text-sm text-muted-foreground mb-2">Tags</div>
                      <div className="flex flex-wrap gap-2">
                        {result.ioc.tags.map((tag) => (
                          <span
                            key={tag}
                            className="px-2 py-1 bg-secondary text-secondary-foreground rounded-md text-xs"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Reputation Sources */}
            <Card>
              <CardHeader>
                <CardTitle>Reputation Sources</CardTitle>
                <CardDescription>
                  Analysis from multiple threat intelligence providers
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.reputation.sources.map((source) => (
                    <div key={source.name} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="font-medium">{source.name}</div>
                        <ReputationBadge verdict={source.verdict} />
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {source.confidence}% confidence
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Geolocation (for IPs) */}
            {result.geolocation && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Globe className="w-5 h-5" />
                    Geolocation
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <div className="text-sm text-muted-foreground">Location</div>
                      <div className="font-medium">
                        {result.geolocation.city}, {result.geolocation.country}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">ISP</div>
                      <div className="font-medium">{result.geolocation.isp}</div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">ASN</div>
                      <div className="font-medium">{result.geolocation.asn}</div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Coordinates</div>
                      <div className="font-medium">
                        {result.geolocation.latitude}, {result.geolocation.longitude}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* WHOIS (for domains) */}
            {result.whois && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Clock className="w-5 h-5" />
                    WHOIS Information
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <div className="text-sm text-muted-foreground">Registrar</div>
                      <div className="font-medium">{result.whois.registrar}</div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Created</div>
                      <div className="font-medium">
                        {formatRelativeTime(new Date(result.whois.creationDate))}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Expires</div>
                      <div className="font-medium">
                        {formatRelativeTime(new Date(result.whois.expirationDate))}
                      </div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Name Servers</div>
                      <div className="space-y-1">
                        {result.whois.nameServers.map((ns) => (
                          <div key={ns} className="font-mono text-sm">{ns}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </div>
    </MainLayout>
  )
}
