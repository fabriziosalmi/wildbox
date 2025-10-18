'use client'

/**
 * Threat Intel IOC Lookup Page
 * 
 * Provides real-time threat intelligence lookups for:
 * - IP addresses (IPv4/IPv6)
 * - Domain names
 * - File hashes (MD5, SHA1, SHA256)
 * 
 * Features:
 * - Automatic IOC type detection
 * - Real-time API integration with Data service
 * - Comprehensive UI states (pristine, loading, error, empty, success)
 * - Threat severity indicators
 * - Enrichment data display (geolocation, WHOIS, file metadata)
 */

import { useState, FormEvent } from 'react'
import { 
  Search, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Globe, 
  Clock, 
  Tag,
  Hash,
  Network,
  Server,
  X,
  Loader2
} from 'lucide-react'
import { MainLayout } from '@/components/main-layout'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { 
  useThreatLookup,
  detectIOCType,
  getMaxSeverity,
  getAllThreatTypes,
  getReputationVerdict,
  formatConfidence,
  getSeverityColor,
  getConfidenceColor,
  type ThreatIndicator,
  type IPIntelligence,
  type DomainIntelligence,
  type HashIntelligence,
  type IOCType
} from '@/hooks/use-threat-lookup'

// ============================================================================
// Sub-Components
// ============================================================================

/**
 * IOC Type Badge
 */
function IOCTypeBadge({ type }: { type: IOCType }) {
  const config = {
    ip_address: { icon: Network, label: 'IP Address', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100' },
    domain: { icon: Globe, label: 'Domain', color: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-100' },
    file_hash: { icon: Hash, label: 'File Hash', color: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100' },
    unknown: { icon: Shield, label: 'Unknown', color: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100' },
  }
  
  const { icon: Icon, label, color } = config[type] || config.unknown
  
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${color}`}>
      <Icon className="w-4 h-4" />
      <span>{label}</span>
    </div>
  )
}

/**
 * Reputation Badge with severity color
 */
function ReputationBadge({ severity }: { severity: number }) {
  const verdict = getReputationVerdict(severity)
  
  const config = {
    malicious: { 
      icon: AlertTriangle, 
      label: 'Malicious', 
      color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100' 
    },
    suspicious: { 
      icon: AlertTriangle, 
      label: 'Suspicious', 
      color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100' 
    },
    clean: { 
      icon: CheckCircle, 
      label: 'Clean', 
      color: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100' 
    },
  }
  
  const { icon: Icon, label, color } = config[verdict]
  
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${color}`}>
      <Icon className="w-4 h-4" />
      <span>{label}</span>
      <span className="font-bold">({severity}/10)</span>
    </div>
  )
}

/**
 * Individual Threat Indicator Card
 */
function ThreatIndicatorCard({ indicator }: { indicator: ThreatIndicator }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <CardTitle className="text-lg">Threat Indicator</CardTitle>
            <div className="flex items-center gap-2">
              <span className={`font-mono text-sm ${getSeverityColor(indicator.severity)}`}>
                {indicator.value}
              </span>
            </div>
          </div>
          <ReputationBadge severity={indicator.severity} />
        </div>
        <CardDescription>{indicator.description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Threat Types */}
        <div>
          <h4 className="text-sm font-semibold mb-2">Threat Types</h4>
          <div className="flex flex-wrap gap-2">
            {indicator.threat_types.map((type, index) => (
              <Badge key={index} variant="destructive">
                {type}
              </Badge>
            ))}
          </div>
        </div>
        
        {/* Confidence & Severity */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm font-semibold mb-1">Confidence</h4>
            <p className={`text-sm ${getConfidenceColor(indicator.confidence)}`}>
              {formatConfidence(indicator.confidence)}
            </p>
          </div>
          <div>
            <h4 className="text-sm font-semibold mb-1">Severity</h4>
            <p className={`text-sm font-bold ${getSeverityColor(indicator.severity)}`}>
              {indicator.severity}/10
            </p>
          </div>
        </div>
        
        {/* Timestamps */}
        <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">
          <div>
            <div className="flex items-center gap-1 mb-1">
              <Clock className="w-3 h-3" />
              <span className="font-medium">First Seen</span>
            </div>
            <p>{new Date(indicator.first_seen).toLocaleString()}</p>
          </div>
          <div>
            <div className="flex items-center gap-1 mb-1">
              <Clock className="w-3 h-3" />
              <span className="font-medium">Last Seen</span>
            </div>
            <p>{new Date(indicator.last_seen).toLocaleString()}</p>
          </div>
        </div>
        
        {/* Tags */}
        {indicator.tags && indicator.tags.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold mb-2 flex items-center gap-1">
              <Tag className="w-4 h-4" />
              Tags
            </h4>
            <div className="flex flex-wrap gap-2">
              {indicator.tags.map((tag, index) => (
                <Badge key={index} variant="outline">
                  {tag}
                </Badge>
              ))}
            </div>
          </div>
        )}
        
        {/* Status */}
        <div className="pt-2 border-t">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Status</span>
            <Badge variant={indicator.active ? "default" : "secondary"}>
              {indicator.active ? "Active" : "Inactive"}
            </Badge>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

/**
 * IP Enrichment Data Display
 */
function IPEnrichmentCard({ data }: { data: IPIntelligence }) {
  if (!data.enrichment) return null
  
  const { enrichment } = data
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Globe className="w-5 h-5" />
          Geolocation & Network
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {enrichment.country_code && (
          <div>
            <span className="text-sm font-semibold">Location:</span>
            <p className="text-sm text-muted-foreground">
              {enrichment.city && `${enrichment.city}, `}
              {enrichment.country_code}
            </p>
          </div>
        )}
        
        {enrichment.asn && (
          <div>
            <span className="text-sm font-semibold">ASN:</span>
            <p className="text-sm text-muted-foreground">
              {enrichment.asn}
              {enrichment.asn_organization && ` (${enrichment.asn_organization})`}
            </p>
          </div>
        )}
        
        {enrichment.coordinates && (
          <div>
            <span className="text-sm font-semibold">Coordinates:</span>
            <p className="text-sm text-muted-foreground font-mono">
              {enrichment.coordinates.latitude}, {enrichment.coordinates.longitude}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * Domain Enrichment Data Display
 */
function DomainEnrichmentCard({ data }: { data: DomainIntelligence }) {
  if (!data.enrichment) return null
  
  const { enrichment } = data
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="w-5 h-5" />
          Domain Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {enrichment.registrar && (
          <div>
            <span className="text-sm font-semibold">Registrar:</span>
            <p className="text-sm text-muted-foreground">{enrichment.registrar}</p>
          </div>
        )}
        
        {enrichment.creation_date && (
          <div>
            <span className="text-sm font-semibold">Created:</span>
            <p className="text-sm text-muted-foreground">
              {new Date(enrichment.creation_date).toLocaleDateString()}
            </p>
          </div>
        )}
        
        {enrichment.expiration_date && (
          <div>
            <span className="text-sm font-semibold">Expires:</span>
            <p className="text-sm text-muted-foreground">
              {new Date(enrichment.expiration_date).toLocaleDateString()}
            </p>
          </div>
        )}
        
        {enrichment.name_servers && enrichment.name_servers.length > 0 && (
          <div>
            <span className="text-sm font-semibold">Name Servers:</span>
            <ul className="text-sm text-muted-foreground mt-1 space-y-1">
              {enrichment.name_servers.map((ns, index) => (
                <li key={index} className="font-mono">{ns}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * Hash Enrichment Data Display
 */
function HashEnrichmentCard({ data }: { data: HashIntelligence }) {
  if (!data.enrichment) return null
  
  const { enrichment } = data
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Hash className="w-5 h-5" />
          File Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {enrichment.file_type && (
          <div>
            <span className="text-sm font-semibold">File Type:</span>
            <p className="text-sm text-muted-foreground">{enrichment.file_type}</p>
          </div>
        )}
        
        {enrichment.file_size && (
          <div>
            <span className="text-sm font-semibold">File Size:</span>
            <p className="text-sm text-muted-foreground">
              {(enrichment.file_size / 1024).toFixed(2)} KB
            </p>
          </div>
        )}
        
        {enrichment.file_names && enrichment.file_names.length > 0 && (
          <div>
            <span className="text-sm font-semibold">Known File Names:</span>
            <ul className="text-sm text-muted-foreground mt-1 space-y-1">
              {enrichment.file_names.map((name, index) => (
                <li key={index} className="font-mono">{name}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ============================================================================
// Main Page Component
// ============================================================================

export default function ThreatIntelLookupPage() {
  const [inputValue, setInputValue] = useState('')
  const [searchValue, setSearchValue] = useState('')
  
  // Use the custom hook - query only executes when searchValue is set
  const { 
    data, 
    iocType, 
    isLoading, 
    error, 
    isNotFound, 
    isSuccess 
  } = useThreatLookup({ 
    iocValue: searchValue,
    enabled: searchValue.length > 0 
  })
  
  // Handle form submission
  const handleSearch = (e: FormEvent) => {
    e.preventDefault()
    const trimmed = inputValue.trim()
    if (trimmed) {
      setSearchValue(trimmed)
    }
  }
  
  // Clear search
  const handleClear = () => {
    setInputValue('')
    setSearchValue('')
  }
  
  // Determine if we should show results section
  const showResults = searchValue.length > 0
  const detectedType = searchValue ? detectIOCType(searchValue) : 'unknown'
  
  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">IOC Lookup</h1>
            <p className="text-muted-foreground mt-1">
              Analyze indicators of compromise using real-time threat intelligence
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
              Enter an IP address, domain name, or file hash (MD5, SHA1, SHA256)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSearch} className="space-y-4">
              <div className="flex gap-4">
                <div className="flex-1 relative">
                  <Input
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder="e.g., 8.8.8.8, malicious-domain.com, or d41d8cd98f00b204e9800998ecf8427e"
                    className="pr-10"
                    disabled={isLoading}
                  />
                  {inputValue && (
                    <button
                      type="button"
                      onClick={handleClear}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
                <Button
                  type="submit"
                  disabled={!inputValue.trim() || isLoading}
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
              </div>
              
              {/* Type Detection Helper */}
              {inputValue && !isLoading && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <span>Detected type:</span>
                  <IOCTypeBadge type={detectedType} />
                </div>
              )}
            </form>
          </CardContent>
        </Card>
        
        {/* Results Section */}
        {showResults && (
          <>
            {/* Loading State */}
            {isLoading && (
              <Card>
                <CardContent className="py-12">
                  <div className="flex flex-col items-center justify-center space-y-4">
                    <Loader2 className="w-12 h-12 animate-spin text-primary" />
                    <div className="text-center">
                      <p className="font-semibold">Analyzing IOC...</p>
                      <p className="text-sm text-muted-foreground">
                        Querying threat intelligence database
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
            
            {/* Error State */}
            {error && !isNotFound && (
              <Card className="border-red-200 dark:border-red-900">
                <CardContent className="py-12">
                  <div className="flex flex-col items-center justify-center space-y-4 text-center">
                    <AlertTriangle className="w-12 h-12 text-red-600 dark:text-red-400" />
                    <div>
                      <p className="font-semibold text-red-600 dark:text-red-400">
                        Lookup Failed
                      </p>
                      <p className="text-sm text-muted-foreground mt-2">
                        {error.message || 'Unable to query threat intelligence database'}
                      </p>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        className="mt-4"
                        onClick={() => setSearchValue('')}
                      >
                        Try Again
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
            
            {/* Not Found State (404) */}
            {isNotFound && (
              <Card className="border-yellow-200 dark:border-yellow-900">
                <CardContent className="py-12">
                  <div className="flex flex-col items-center justify-center space-y-4 text-center">
                    <Shield className="w-12 h-12 text-yellow-600 dark:text-yellow-400" />
                    <div>
                      <p className="font-semibold text-yellow-600 dark:text-yellow-400">
                        IOC Not Found
                      </p>
                      <p className="text-sm text-muted-foreground mt-2">
                        This indicator is not present in our threat intelligence database.
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        This doesn't necessarily mean it's safe - it may simply be unknown.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
            
            {/* Success State - Show Results */}
            {isSuccess && data && (
              <div className="space-y-6">
                {/* Summary Card */}
                <Card>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="space-y-2">
                        <CardTitle className="text-2xl">Analysis Results</CardTitle>
                        <div className="flex items-center gap-3">
                          <code className="text-lg font-mono bg-muted px-3 py-1 rounded">
                            {searchValue}
                          </code>
                          <IOCTypeBadge type={iocType} />
                        </div>
                      </div>
                      <ReputationBadge severity={getMaxSeverity(data.indicators)} />
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-3 gap-4 text-center">
                      <div>
                        <p className="text-sm text-muted-foreground">Threat Count</p>
                        <p className="text-2xl font-bold">{data.threat_count}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Threat Types</p>
                        <p className="text-2xl font-bold">
                          {getAllThreatTypes(data.indicators).length}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Max Severity</p>
                        <p className={`text-2xl font-bold ${getSeverityColor(getMaxSeverity(data.indicators))}`}>
                          {getMaxSeverity(data.indicators)}/10
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                {/* Threat Types Summary */}
                {data.indicators && data.indicators.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Threat Categories</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {getAllThreatTypes(data.indicators).map((type, index) => (
                          <Badge key={index} variant="destructive" className="text-sm">
                            {type}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
                
                {/* Enrichment Data */}
                {'ip_address' in data && <IPEnrichmentCard data={data as IPIntelligence} />}
                {'domain' in data && <DomainEnrichmentCard data={data as DomainIntelligence} />}
                {'file_hash' in data && <HashEnrichmentCard data={data as HashIntelligence} />}
                
                {/* Individual Indicators */}
                <div className="space-y-4">
                  <h2 className="text-xl font-semibold">Detailed Threat Indicators</h2>
                  <div className="grid gap-4">
                    {data.indicators.map((indicator) => (
                      <ThreatIndicatorCard key={indicator.id} indicator={indicator} />
                    ))}
                  </div>
                </div>
                
                {/* Query Metadata */}
                <Card className="bg-muted/50">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between text-sm text-muted-foreground">
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4" />
                        <span>Query Time: {new Date(data.query_time).toLocaleString()}</span>
                      </div>
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => setSearchValue('')}
                      >
                        New Lookup
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </>
        )}
        
        {/* Pristine State - Show Examples */}
        {!showResults && (
          <Card>
            <CardHeader>
              <CardTitle>How to Use</CardTitle>
              <CardDescription>Try looking up these example indicators:</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-3">
                <button
                  onClick={() => {
                    setInputValue('8.8.8.8')
                    setSearchValue('8.8.8.8')
                  }}
                  className="text-left p-3 rounded-lg border hover:bg-accent transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Network className="w-4 h-4 text-blue-600" />
                    <span className="font-mono text-sm">8.8.8.8</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Example IP address lookup</p>
                </button>
                
                <button
                  onClick={() => {
                    setInputValue('malicious-domain.evil')
                    setSearchValue('malicious-domain.evil')
                  }}
                  className="text-left p-3 rounded-lg border hover:bg-accent transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Globe className="w-4 h-4 text-purple-600" />
                    <span className="font-mono text-sm">malicious-domain.evil</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Example domain name lookup</p>
                </button>
                
                <button
                  onClick={() => {
                    setInputValue('d41d8cd98f00b204e9800998ecf8427e')
                    setSearchValue('d41d8cd98f00b204e9800998ecf8427e')
                  }}
                  className="text-left p-3 rounded-lg border hover:bg-accent transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Hash className="w-4 h-4 text-orange-600" />
                    <span className="font-mono text-sm">d41d8cd98f00b204e9800998ecf8427e</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Example file hash lookup (MD5)</p>
                </button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </MainLayout>
  )
}
